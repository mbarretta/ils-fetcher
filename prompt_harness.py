"""HTML test harness for iterating on the Disclosure Clusters prompt.

Loads the top 2 CNA bulk-submission clusters from the most recent vulnerability
report, lets the user edit the RESEARCH_SYSTEM_PROMPT, and re-runs the Anthropic
research call live to compare before/after output. Also exposes a side chat with
Claude that the user can use to discuss prompt edits.

Run:
    python3 prompt_harness.py
Then open http://localhost:8765
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import traceback
import urllib.parse
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import analyze

REPO_ROOT = Path(__file__).resolve().parent
ANALYZE_PATH = REPO_ROOT / "analyze.py"
OUTPUT_DIR = REPO_ROOT / "output"
REPORT_PATH = OUTPUT_DIR / "vulnerability_report.yaml"
NVD_CACHE_PATH = OUTPUT_DIR / ".nvd_cache.json"
RESEARCH_CACHE_PATH = OUTPUT_DIR / ".world_event_cache.json"

PORT = int(os.environ.get("PROMPT_HARNESS_PORT", "8765"))
TOP_N_CLUSTERS = 2

CHAT_SYSTEM_PROMPT = """\
You are a prompt-engineering assistant helping a vulnerability-report author \
iterate on a system prompt. That prompt drives a separate Claude call that \
produces 4-6 bulletpoints explaining why a cluster of CVE disclosures landed in \
a customer's container vulnerability report.

The user can see, on screen, the current prompt, their modified version, and the \
before/after output for two real disclosure clusters. They will ask you for \
edits, critiques, and rewrites.

Conventions:
- Be concise. Lead with the recommendation. No filler.
- When proposing edits, quote the exact lines you would change and the exact \
replacement text. Don't describe in paragraphs what you would write — write it.
- It's fine to ask one clarifying question if direction is genuinely ambiguous; \
otherwise make the reasonable call and propose.
- Don't propose JSON schema changes unless the user asks — downstream parsing \
expects the existing `narrative_bullets` + `sources` shape.
"""

CHAT_MODEL = "claude-opus-4-7"


# ---------------------------------------------------------------------------
# Cluster loading (one-time at startup, then reused for /run)
# ---------------------------------------------------------------------------

class HarnessState:
    """Single in-process container for everything the HTTP handlers read."""

    def __init__(self) -> None:
        self.original_prompt: str = analyze.RESEARCH_SYSTEM_PROMPT
        self.modified_prompt: str = analyze.RESEARCH_SYSTEM_PROMPT
        self.clusters: list[analyze.Cluster] = []
        self.cluster_payloads: list[dict] = []
        self.chat_history: list[dict] = []
        self.include_images: bool = True
        self.lock = threading.Lock()

    def bootstrap(self) -> None:
        if not REPORT_PATH.exists():
            raise SystemExit(f"Report not found: {REPORT_PATH}. Run analyze.py first.")

        analyze.load_dotenv(REPO_ROOT / ".env")

        print(f"Loading {REPORT_PATH}…")
        meta, findings = analyze.load_report(REPORT_PATH)
        print(f"  {len(findings)} findings")

        # Reuse the on-disk NVD cache — don't hit the network for the harness.
        unique_cves = {f.cve_id for f in findings if f.cve_id}
        nvd_records = analyze.enrich_with_nvd(
            unique_cves, NVD_CACHE_PATH, os.environ.get("NVD_API_KEY")
        )
        print(f"  NVD enrichment: {len(nvd_records)} records")

        metrics = analyze.compute_metrics(meta, findings, nvd_records,
                                          nvd_enriched=bool(nvd_records),
                                          top_n=10)

        bulk = [c for c in metrics.clusters if c.kind == "CNA bulk submission"]
        bulk.sort(key=lambda c: -len(c.members))
        self.clusters = bulk[:TOP_N_CLUSTERS]
        if not self.clusters:
            raise SystemExit("No CNA bulk submission clusters detected in the report.")

        # Pull the cached "before" output (this is what analyze.py last produced
        # with the current prompt; fingerprint is prompt-hashed so it matches).
        cache = {}
        if RESEARCH_CACHE_PATH.exists():
            try:
                cache = json.loads(RESEARCH_CACHE_PATH.read_text())
            except json.JSONDecodeError:
                cache = {}

        for cluster in self.clusters:
            cached = cache.get(cluster.fingerprint) or {}
            self.cluster_payloads.append({
                "fingerprint": cluster.fingerprint,
                "kind": cluster.kind,
                "label": cluster.label,
                "member_count": len(cluster.members),
                "user_prompt_no_images": analyze._build_cluster_prompt(cluster, include_images=False),
                "user_prompt_with_images": analyze._build_cluster_prompt(cluster, include_images=True),
                "distinct_image_count": len({img for r in cluster.members for img in r.affected_images}),
                "before": {
                    "narrative_bullets": cached.get("narrative_bullets", []),
                    "sources": cached.get("sources", []),
                },
                "after": None,
            })
            print(f"  cluster {cluster.fingerprint}: {cluster.label}")


STATE = HarnessState()


# ---------------------------------------------------------------------------
# Anthropic calls
# ---------------------------------------------------------------------------

RESEARCH_TIMEOUT_SECONDS = float(os.environ.get("HARNESS_RESEARCH_TIMEOUT", "300"))


def run_research(system_prompt: str, user_prompt: str) -> dict:
    """Re-run the same web-search call analyze.py makes, but with a custom system prompt.

    Logs each stream event to stderr so a stuck call is visible immediately and
    a hard timeout (HARNESS_RESEARCH_TIMEOUT, default 300s) prevents indefinite hangs.
    """
    import anthropic
    import time

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return {"error": "ANTHROPIC_API_KEY not set"}

    client = anthropic.Anthropic(api_key=api_key, timeout=RESEARCH_TIMEOUT_SECONDS)
    started = time.monotonic()
    text_chars = 0
    tool_uses: list[str] = []
    last_log = started

    def deadline_expired() -> bool:
        return (time.monotonic() - started) > RESEARCH_TIMEOUT_SECONDS

    try:
        with client.messages.stream(
            model=analyze.RESEARCH_MODEL,
            max_tokens=analyze.RESEARCH_MAX_TOKENS,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            cache_control={"type": "ephemeral"},
            system=system_prompt,
            tools=[{"type": "web_search_20260209", "name": "web_search"}],
            messages=[{"role": "user", "content": user_prompt}],
        ) as stream:
            for event in stream:
                if deadline_expired():
                    raise TimeoutError(
                        f"hard timeout after {RESEARCH_TIMEOUT_SECONDS}s "
                        f"({text_chars} chars received, {len(tool_uses)} tool uses)"
                    )
                etype = getattr(event, "type", "")
                if etype == "content_block_start":
                    blk = getattr(event, "content_block", None)
                    btype = getattr(blk, "type", "") if blk else ""
                    if btype == "tool_use":
                        name = getattr(blk, "name", "?")
                        tool_uses.append(name)
                        print(f"    [stream] tool_use start: {name} "
                              f"(t+{time.monotonic()-started:.1f}s)", file=sys.stderr)
                    elif btype == "thinking":
                        print(f"    [stream] thinking start "
                              f"(t+{time.monotonic()-started:.1f}s)", file=sys.stderr)
                elif etype == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    if delta and getattr(delta, "type", "") == "text_delta":
                        text_chars += len(getattr(delta, "text", ""))
                # heartbeat every ~10s
                now = time.monotonic()
                if now - last_log > 10:
                    print(f"    [stream] heartbeat t+{now-started:.1f}s "
                          f"text={text_chars}c tool_uses={len(tool_uses)}", file=sys.stderr)
                    last_log = now
            final = stream.get_final_message()
    except TimeoutError as e:
        return {"error": f"Timed out: {e}"}
    except Exception as e:
        return {"error": f"Anthropic call failed: {e}"}

    elapsed = time.monotonic() - started
    print(f"  cluster done in {elapsed:.1f}s "
          f"({text_chars} text chars, {len(tool_uses)} tool uses: {tool_uses})",
          file=sys.stderr)

    parsed = analyze._parse_research_response(final)
    if not parsed:
        return {"error": "Could not parse JSON from model response",
                "raw": _collect_text(final)}
    return {
        "narrative_bullets": parsed.get("narrative_bullets", []),
        "sources": parsed.get("sources", []),
    }


def _collect_text(message) -> str:
    return "\n".join(b.text for b in message.content if getattr(b, "type", None) == "text")


def chat_with_claude(user_text: str) -> str:
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return "[ANTHROPIC_API_KEY not set]"

    with STATE.lock:
        STATE.chat_history.append({"role": "user", "content": user_text})
        messages = list(STATE.chat_history)

    # Inject the current prompt as context so the assistant sees what's on screen.
    context_block = (
        "Current original prompt:\n```\n" + STATE.original_prompt + "\n```\n\n"
        "Current modified prompt (what the user is editing):\n```\n" +
        STATE.modified_prompt + "\n```\n"
    )
    system = CHAT_SYSTEM_PROMPT + "\n\n" + context_block

    client = anthropic.Anthropic(api_key=api_key)
    try:
        resp = client.messages.create(
            model=CHAT_MODEL,
            max_tokens=4096,
            system=system,
            messages=messages,
        )
    except Exception as e:
        return f"[Anthropic error: {e}]"

    text = "\n".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
    with STATE.lock:
        STATE.chat_history.append({"role": "assistant", "content": text})
    return text


# ---------------------------------------------------------------------------
# Persist prompt back to analyze.py
# ---------------------------------------------------------------------------

# Matches:  RESEARCH_SYSTEM_PROMPT = """...everything until the closing triple-quote..."""
RESEARCH_PROMPT_ASSIGNMENT_RE = re.compile(
    r'^RESEARCH_SYSTEM_PROMPT\s*=\s*"""[\s\S]*?"""',
    re.MULTILINE,
)


def save_prompt_to_analyze(new_prompt: str) -> dict:
    """Rewrite the RESEARCH_SYSTEM_PROMPT assignment in analyze.py to `new_prompt`.

    Returns {"ok": True} on success, or {"error": "..."} if anything looks wrong.
    """
    if '"""' in new_prompt:
        return {"error": 'Prompt contains `"""`, which would break the Python triple-quoted string. Rewrite without it.'}

    body = new_prompt.strip()
    # Reproduce the original style: leading `\` continuation so the string doesn't
    # start with a newline, and a single trailing newline before the closing fence.
    replacement = 'RESEARCH_SYSTEM_PROMPT = """\\\n' + body + '\n"""'

    src = ANALYZE_PATH.read_text()
    matches = RESEARCH_PROMPT_ASSIGNMENT_RE.findall(src)
    if len(matches) != 1:
        return {"error": f"Expected exactly 1 RESEARCH_SYSTEM_PROMPT assignment in analyze.py, found {len(matches)}."}

    new_src, n = RESEARCH_PROMPT_ASSIGNMENT_RE.subn(replacement, src, count=1)
    if n != 1:
        return {"error": "Replacement failed unexpectedly."}

    tmp = ANALYZE_PATH.with_suffix(".py.tmp")
    tmp.write_text(new_src)
    tmp.replace(ANALYZE_PATH)

    # Update in-process so STATE.original_prompt reflects the new on-disk value.
    analyze.RESEARCH_SYSTEM_PROMPT = body + "\n"
    return {"ok": True, "saved_chars": len(body)}


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        return json.loads(raw) if raw else {}

    # ---- routes ----
    def do_GET(self):
        if self.path == "/":
            self._send_html(INDEX_HTML)
            return
        if self.path == "/api/state":
            self._send_json({
                "original_prompt": STATE.original_prompt,
                "modified_prompt": STATE.modified_prompt,
                "clusters": STATE.cluster_payloads,
                "chat_history": STATE.chat_history,
                "include_images": STATE.include_images,
            })
            return
        self.send_error(404)

    def do_POST(self):
        try:
            if self.path == "/api/prompt":
                data = self._read_json()
                with STATE.lock:
                    STATE.modified_prompt = data.get("prompt", STATE.modified_prompt)
                self._send_json({"ok": True})
                return

            if self.path == "/api/run":
                data = self._read_json()
                prompt = data.get("prompt") or STATE.modified_prompt
                include_images = bool(data.get("include_images", STATE.include_images))
                with STATE.lock:
                    STATE.modified_prompt = prompt
                    STATE.include_images = include_images
                results = []
                for payload in STATE.cluster_payloads:
                    user_prompt = (payload["user_prompt_with_images"]
                                   if include_images
                                   else payload["user_prompt_no_images"])
                    print(f"  re-running cluster {payload['fingerprint']} "
                          f"(images={include_images})…", file=sys.stderr)
                    out = run_research(prompt, user_prompt)
                    payload["after"] = out  # cache for state refresh
                    results.append({
                        "fingerprint": payload["fingerprint"],
                        "after": out,
                    })
                self._send_json({"results": results, "include_images": include_images})
                return

            if self.path == "/api/chat":
                data = self._read_json()
                user_text = data.get("message", "").strip()
                if not user_text:
                    self._send_json({"error": "empty message"}, status=400)
                    return
                reply = chat_with_claude(user_text)
                self._send_json({"reply": reply, "history": STATE.chat_history})
                return

            if self.path == "/api/reset-chat":
                with STATE.lock:
                    STATE.chat_history = []
                self._send_json({"ok": True})
                return

            if self.path == "/api/reset-prompt":
                with STATE.lock:
                    STATE.modified_prompt = STATE.original_prompt
                self._send_json({"prompt": STATE.modified_prompt})
                return

            if self.path == "/api/toggle-images":
                data = self._read_json()
                with STATE.lock:
                    STATE.include_images = bool(data.get("include_images", False))
                self._send_json({"include_images": STATE.include_images})
                return

            if self.path == "/api/save-prompt":
                data = self._read_json()
                prompt = data.get("prompt") or STATE.modified_prompt
                with STATE.lock:
                    STATE.modified_prompt = prompt
                result = save_prompt_to_analyze(prompt)
                if "ok" in result:
                    with STATE.lock:
                        STATE.original_prompt = analyze.RESEARCH_SYSTEM_PROMPT
                self._send_json(result, status=200 if "ok" in result else 400)
                return

            self.send_error(404)
        except Exception as e:
            traceback.print_exc()
            self._send_json({"error": str(e)}, status=500)


# ---------------------------------------------------------------------------
# Frontend (embedded so the harness is a single file)
# ---------------------------------------------------------------------------

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Disclosure Clusters — Prompt Harness</title>
<style>
  :root {
    --bg: #0f1115;
    --panel: #161922;
    --panel-2: #1c2030;
    --border: #2a2f40;
    --text: #e6e8ee;
    --muted: #8b93a7;
    --accent: #7aa2ff;
    --accent-2: #5eead4;
    --warn: #f7b955;
    --bad: #ff7a7a;
    --code: #c8d2eb;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; margin: 0; }
  body {
    background: var(--bg); color: var(--text);
    font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Inter", "SF Pro Text",
          Roboto, system-ui, sans-serif;
    display: flex; flex-direction: column;
  }
  header {
    padding: 10px 16px; border-bottom: 1px solid var(--border);
    display: flex; gap: 12px; align-items: center; background: var(--panel);
  }
  header h1 { font-size: 13px; font-weight: 600; margin: 0; }
  header .sub { color: var(--muted); font-size: 12px; }
  header .spacer { flex: 1; }
  button {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer;
  }
  button:hover { border-color: var(--accent); }
  button.primary { background: var(--accent); color: #0b0d12; border-color: var(--accent); font-weight: 600; }
  button.primary:hover { filter: brightness(1.1); }
  button:disabled { opacity: 0.5; cursor: progress; }

  .layout {
    flex: 1; display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: minmax(0, 1fr);
    min-height: 0;
  }
  .col {
    display: flex; flex-direction: column; min-height: 0;
    border-right: 1px solid var(--border);
  }
  .col:last-child { border-right: none; }

  .pane {
    padding: 12px 14px; overflow: auto;
  }
  .pane + .pane { border-top: 1px solid var(--border); }
  .pane h2 {
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin: 0 0 8px; font-weight: 600;
    display: flex; align-items: center; gap: 8px;
  }
  .pane h2 .pill {
    background: var(--panel-2); border: 1px solid var(--border);
    color: var(--text); padding: 2px 8px; border-radius: 999px;
    font-size: 10px; letter-spacing: 0; text-transform: none; font-weight: 500;
  }

  .prompt-area { flex: 1; display: flex; flex-direction: column; min-height: 0; }
  textarea.prompt {
    flex: 1; width: 100%;
    background: var(--panel); color: var(--code);
    border: 1px solid var(--border); border-radius: 6px;
    font: 12px/1.5 ui-monospace, "JetBrains Mono", "SF Mono", Menlo, monospace;
    padding: 10px; resize: none;
    white-space: pre-wrap;
  }
  textarea.prompt:read-only { opacity: 0.92; }

  .col-left { grid-row: 1; }
  .col-right { grid-row: 1; }

  /* left column layout: prompts top, chat bottom */
  .col-left .pane.prompts { flex: 1; min-height: 0; display: grid; grid-template-rows: 1fr 1fr; gap: 10px; }
  .col-left .pane.prompts > div { display: flex; flex-direction: column; min-height: 0; }
  .col-left .pane.chat { flex: 0 0 38%; display: flex; flex-direction: column; min-height: 0; }

  /* right column: clusters stacked */
  .col-right { display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
  .col-right .pane { flex: 1; min-height: 0; }

  .cluster-card {
    border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
    background: var(--panel); margin-bottom: 14px;
  }
  .cluster-card h3 {
    margin: 0 0 6px; font-size: 13px; font-weight: 600;
    display: flex; align-items: baseline; gap: 8px;
  }
  .cluster-card h3 .meta { color: var(--muted); font-weight: 400; font-size: 11px; }

  .diff-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  .out-box {
    border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px;
    background: var(--bg);
  }
  .out-box h4 {
    margin: 0 0 6px; font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase;
    color: var(--muted); font-weight: 600;
  }
  .out-box.after h4 { color: var(--accent-2); }
  .bullet-list { margin: 0 0 6px; padding-left: 18px; }
  .bullet-list li { margin: 0 0 6px; }
  .bullet-list strong { color: var(--text); font-weight: 600; }
  .bullet-list code {
    background: var(--panel-2); border: 1px solid var(--border);
    padding: 0 4px; border-radius: 3px;
    font-family: ui-monospace, Menlo, monospace; font-size: 11px;
  }
  .sub-bullets { margin: 4px 0 0 0; padding-left: 16px; list-style: none; }
  .sub-bullets li { color: var(--muted); margin: 0 0 2px; position: relative; padding-left: 12px; font-size: 12px; }
  .sub-bullets li::before { content: "–"; position: absolute; left: 0; color: var(--accent); }
  .sources { margin: 6px 0 0; padding: 0; list-style: none; font-size: 11px; }
  .sources li { margin: 0 0 3px; }
  .sources a { color: var(--accent); text-decoration: none; }
  .sources a:hover { text-decoration: underline; }
  .empty { color: var(--muted); font-style: italic; font-size: 12px; }
  .error { color: var(--bad); font-size: 12px; white-space: pre-wrap; }

  /* chat */
  #chat-log {
    flex: 1; overflow: auto;
    border: 1px solid var(--border); border-radius: 6px; padding: 10px;
    background: var(--bg); margin-bottom: 6px;
  }
  .chat-msg { margin: 0 0 10px; }
  .chat-msg .who {
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--muted); margin-bottom: 2px;
  }
  .chat-msg.user .who { color: var(--accent); }
  .chat-msg.assistant .who { color: var(--accent-2); }
  .chat-msg .body { white-space: pre-wrap; }
  .chat-msg .body code, pre code {
    background: var(--panel-2); border: 1px solid var(--border);
    padding: 1px 4px; border-radius: 3px;
    font-family: ui-monospace, Menlo, monospace; font-size: 11px;
  }
  .chat-msg .body pre {
    background: var(--panel-2); border: 1px solid var(--border);
    padding: 8px; border-radius: 4px; overflow-x: auto;
  }
  .chat-input-row { display: flex; gap: 6px; }
  #chat-input {
    flex: 1; background: var(--panel); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px;
    padding: 8px; font: inherit; resize: vertical; min-height: 50px;
  }
  .toolbar { display: flex; gap: 6px; margin-top: 6px; }

  .status {
    font-size: 11px; color: var(--muted); margin-left: 8px;
  }
  .status.live { color: var(--warn); }

  /* image toggle */
  .toggle {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--panel-2); border: 1px solid var(--border);
    padding: 4px 10px 4px 8px; border-radius: 6px; font-size: 12px;
    cursor: pointer; user-select: none;
  }
  .toggle input { margin: 0; accent-color: var(--accent); cursor: pointer; }
  .toggle .hint { color: var(--muted); font-size: 11px; }

  details.userprompt {
    margin-top: 8px; border: 1px solid var(--border); border-radius: 6px;
    background: var(--bg);
  }
  details.userprompt > summary {
    cursor: pointer; padding: 6px 10px; font-size: 11px;
    color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em;
    list-style: none;
  }
  details.userprompt > summary::-webkit-details-marker { display: none; }
  details.userprompt > summary::before { content: "▸ "; color: var(--accent); }
  details.userprompt[open] > summary::before { content: "▾ "; }
  details.userprompt pre {
    margin: 0; padding: 8px 10px;
    border-top: 1px solid var(--border);
    font: 11px/1.5 ui-monospace, Menlo, monospace; color: var(--code);
    white-space: pre-wrap; word-break: break-word;
    max-height: 280px; overflow: auto;
  }
</style>
</head>
<body>
<header>
  <h1>Disclosure Clusters Prompt Harness</h1>
  <span class="sub">Top <span id="cluster-count">…</span> CNA bulk submissions</span>
  <span class="status" id="run-status"></span>
  <span class="spacer"></span>
  <label class="toggle">
    <input type="checkbox" id="include-images">
    Include CVE → image mapping
    <span class="hint" id="images-hint"></span>
  </label>
  <button id="reset-prompt-btn">Reset prompt</button>
  <button id="save-prompt-btn" title="Write the modified prompt back into analyze.py on disk">Save to analyze.py</button>
  <button id="run-btn" class="primary">Run modified prompt</button>
</header>

<div class="layout">
  <div class="col col-left">
    <div class="pane prompts">
      <div>
        <h2>Original prompt <span class="pill" id="orig-tokens"></span></h2>
        <div class="prompt-area"><textarea class="prompt" id="original" readonly></textarea></div>
      </div>
      <div>
        <h2>Modified prompt <span class="pill" id="mod-tokens"></span></h2>
        <div class="prompt-area"><textarea class="prompt" id="modified"></textarea></div>
      </div>
    </div>
    <div class="pane chat">
      <h2>Chat — iterate on the prompt</h2>
      <div id="chat-log"></div>
      <div class="chat-input-row">
        <textarea id="chat-input" placeholder="Ask for an edit, critique, or rewrite. Cmd/Ctrl+Enter to send."></textarea>
        <button id="chat-send" class="primary">Send</button>
      </div>
      <div class="toolbar"><button id="chat-reset">Clear chat</button></div>
    </div>
  </div>

  <div class="col col-right">
    <div class="pane">
      <h2>Cluster outputs — before vs after</h2>
      <div id="clusters"></div>
    </div>
  </div>
</div>

<script>
const $ = (s) => document.querySelector(s);
const state = { clusters: [] };

function approxTokens(str) {
  return Math.round(str.length / 3.8); // crude
}

function fmtSources(sources) {
  if (!sources || !sources.length) return '<div class="empty">no sources</div>';
  return '<ul class="sources">' + sources.map(s => {
    const label = (s.label || s.url || '').replace(/[<>]/g, '');
    const url = (s.url || '').replace(/"/g, '&quot;');
    return `<li><a href="${url}" target="_blank" rel="noopener">${label}</a></li>`;
  }).join('') + '</ul>';
}

function inlineMd(s) {
  // Escape, then apply **bold** and `code`, then strip stray cite markers.
  s = escapeHtml(s);
  s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`([^`]+?)`/g, '<code>$1</code>');
  s = s.replace(/&lt;cite[^&]*?&gt;[^&]*?&lt;\/cite&gt;/g, '');
  s = s.replace(/&lt;cite[^&]*?\/?\s*&gt;/g, '');
  return s;
}

function fmtBullets(bullets) {
  if (!bullets || !bullets.length) return '<div class="empty">no bullets</div>';
  return '<ul class="bullet-list">' + bullets.map(b => {
    const lines = (b || '').split('\n').map(l => l.trim()).filter(Boolean);
    if (!lines.length) return '';
    const head = inlineMd(lines[0]);
    const subs = lines.slice(1).map(l => l.startsWith('- ') ? l.slice(2).trim() : l);
    if (!subs.length) return `<li>${head}</li>`;
    const subHtml = '<ul class="sub-bullets">' +
      subs.map(s => `<li>${inlineMd(s)}</li>`).join('') + '</ul>';
    return `<li>${head}${subHtml}</li>`;
  }).join('') + '</ul>';
}

function renderOutput(box) {
  if (!box) return '<div class="empty">not run yet</div>';
  if (box.error) {
    let html = `<div class="error">⚠ ${box.error}</div>`;
    if (box.raw) html += `<details><summary>raw response</summary><pre>${box.raw.replace(/[<>]/g,'')}</pre></details>`;
    return html;
  }
  return fmtBullets(box.narrative_bullets) + fmtSources(box.sources);
}

function renderClusters() {
  const root = $('#clusters');
  const includeImages = $('#include-images').checked;
  root.innerHTML = state.clusters.map(c => {
    const userPrompt = includeImages
      ? c.user_prompt_with_images
      : c.user_prompt_no_images;
    const imgMeta = c.distinct_image_count
      ? ` · ${c.distinct_image_count} images affected`
      : '';
    return `
    <div class="cluster-card">
      <h3>${escapeHtml(c.label)}
        <span class="meta">${c.member_count} CVEs${imgMeta} · fingerprint ${c.fingerprint}</span>
      </h3>
      <div class="diff-grid">
        <div class="out-box before">
          <h4>Before (cached)</h4>
          ${renderOutput(c.before)}
        </div>
        <div class="out-box after">
          <h4>After (modified prompt)</h4>
          ${renderOutput(c.after)}
        </div>
      </div>
      <details class="userprompt">
        <summary>user prompt sent (${includeImages ? 'with' : 'without'} image mapping, ${userPrompt.length} chars)</summary>
        <pre>${escapeHtml(userPrompt)}</pre>
      </details>
    </div>
  `;
  }).join('');
  $('#cluster-count').textContent = state.clusters.length;
}

function renderChat(history) {
  const log = $('#chat-log');
  log.innerHTML = history.map(m => `
    <div class="chat-msg ${m.role}">
      <div class="who">${m.role}</div>
      <div class="body">${escapeHtml(m.content)}</div>
    </div>
  `).join('');
  log.scrollTop = log.scrollHeight;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({
    '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'
  }[c]));
}

async function loadState() {
  const r = await fetch('/api/state'); const d = await r.json();
  $('#original').value = d.original_prompt;
  $('#modified').value = d.modified_prompt;
  $('#orig-tokens').textContent = `~${approxTokens(d.original_prompt)} tok`;
  $('#mod-tokens').textContent = `~${approxTokens(d.modified_prompt)} tok`;
  $('#include-images').checked = !!d.include_images;
  state.clusters = d.clusters;
  updateImagesHint();
  renderClusters();
  renderChat(d.chat_history || []);
}

function updateImagesHint() {
  const on = $('#include-images').checked;
  const totalImgs = state.clusters.reduce((n,c) => n + (c.distinct_image_count || 0), 0);
  $('#images-hint').textContent = on
    ? `(adds ~${totalImgs} image refs to user prompts)`
    : '';
}

let savePromptTimer = null;
$('#modified').addEventListener('input', () => {
  $('#mod-tokens').textContent = `~${approxTokens($('#modified').value)} tok`;
  clearTimeout(savePromptTimer);
  savePromptTimer = setTimeout(async () => {
    await fetch('/api/prompt', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({prompt: $('#modified').value})
    });
  }, 300);
});

$('#include-images').addEventListener('change', async () => {
  updateImagesHint();
  renderClusters();
  await fetch('/api/toggle-images', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({include_images: $('#include-images').checked})
  });
});

$('#run-btn').addEventListener('click', async () => {
  const btn = $('#run-btn'); btn.disabled = true;
  $('#run-status').textContent = 'running both clusters via Claude + web search…';
  $('#run-status').classList.add('live');
  try {
    const r = await fetch('/api/run', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        prompt: $('#modified').value,
        include_images: $('#include-images').checked,
      })
    });
    const d = await r.json();
    for (const res of (d.results || [])) {
      const target = state.clusters.find(c => c.fingerprint === res.fingerprint);
      if (target) target.after = res.after;
    }
    renderClusters();
    $('#run-status').textContent = 'done';
  } catch (e) {
    $('#run-status').textContent = 'error: ' + e;
  } finally {
    btn.disabled = false;
    $('#run-status').classList.remove('live');
    setTimeout(() => { $('#run-status').textContent = ''; }, 3000);
  }
});

$('#reset-prompt-btn').addEventListener('click', async () => {
  const r = await fetch('/api/reset-prompt', {method:'POST'});
  const d = await r.json();
  $('#modified').value = d.prompt;
  $('#mod-tokens').textContent = `~${approxTokens(d.prompt)} tok`;
});

$('#save-prompt-btn').addEventListener('click', async () => {
  const text = $('#modified').value;
  if (!confirm('Write this prompt into analyze.py, replacing the current RESEARCH_SYSTEM_PROMPT?')) return;
  const btn = $('#save-prompt-btn'); btn.disabled = true;
  $('#run-status').textContent = 'saving to analyze.py…';
  try {
    const r = await fetch('/api/save-prompt', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({prompt: text})
    });
    const d = await r.json();
    if (d.error) {
      $('#run-status').textContent = 'save failed: ' + d.error;
    } else {
      $('#original').value = text;
      $('#orig-tokens').textContent = `~${approxTokens(text)} tok`;
      $('#run-status').textContent = `saved (${d.saved_chars} chars) — git diff analyze.py to review`;
    }
  } catch (e) {
    $('#run-status').textContent = 'save error: ' + e;
  } finally {
    btn.disabled = false;
    setTimeout(() => { $('#run-status').textContent = ''; }, 6000);
  }
});

async function sendChat() {
  const input = $('#chat-input');
  const text = input.value.trim();
  if (!text) return;
  const send = $('#chat-send'); send.disabled = true;
  input.value = '';
  // optimistic render
  const log = $('#chat-log');
  log.insertAdjacentHTML('beforeend',
    `<div class="chat-msg user"><div class="who">user</div><div class="body">${escapeHtml(text)}</div></div>` +
    `<div class="chat-msg assistant" id="thinking"><div class="who">assistant</div><div class="body"><em>thinking…</em></div></div>`);
  log.scrollTop = log.scrollHeight;
  try {
    const r = await fetch('/api/chat', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({message: text})
    });
    const d = await r.json();
    document.getElementById('thinking')?.remove();
    renderChat(d.history || []);
  } catch (e) {
    document.getElementById('thinking')?.remove();
    log.insertAdjacentHTML('beforeend',
      `<div class="chat-msg assistant"><div class="who">assistant</div><div class="body error">${e}</div></div>`);
  } finally {
    send.disabled = false;
  }
}

$('#chat-send').addEventListener('click', sendChat);
$('#chat-input').addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') sendChat();
});
$('#chat-reset').addEventListener('click', async () => {
  await fetch('/api/reset-chat', {method:'POST'});
  renderChat([]);
});

loadState();
</script>
</body>
</html>
"""


def main() -> None:
    STATE.bootstrap()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"\nHarness ready at http://127.0.0.1:{PORT}")
    print("  /api/state, /api/run, /api/chat, /api/prompt, /api/reset-chat, /api/reset-prompt")
    print("Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
