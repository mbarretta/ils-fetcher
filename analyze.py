#!/usr/bin/env python3
"""
Analytics narrative reporter for ils-fetcher vulnerability reports.

Reads output/vulnerability_report.yaml and emits a markdown narrative
and a self-contained HTML dashboard explaining the vulnerability posture:
amplification factor, severity breakdown, foundational-package attribution,
fix posture, image hotspots, and external event clusters detected via NVD.

Usage:
    python analyze.py [--input PATH] [--output-dir DIR]
                      [--format md,html] [--top-n N]
                      [--no-enrich]
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

import requests
import yaml


# ---------------------------------------------------------------------------
# Domain model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]

# Foundational packages — broad-impact base layer libraries and language runtimes.
# A CVE in any of these typically lights up many images at once. Used to flag
# amplification in the package attribution table and as a clustering signal.
FOUNDATIONAL_PACKAGES = {
    "glibc", "musl", "openssl", "openssl-config", "busybox",
    "zlib", "libxml2", "libcurl", "curl", "libgcrypt",
    "pcre", "pcre2", "expat", "sqlite", "sqlite-libs",
    "bash", "coreutils", "libgcc", "libstdc++",
    "libxslt", "libffi", "libtasn1", "libgmp",
    "ncurses", "readline", "ca-certificates",
    "openssh", "openssh-client", "openssh-server",
    "krb5", "gnutls", "nettle", "libidn2",
    "perl", "python3",
    "stdlib",  # Go stdlib
}

# Versioned-runtime package patterns. Same fan-out behavior as the literal set,
# but parameterized by version suffix (e.g. python-3.12, nodejs-18). Anchored
# so library names like `python-multipart` don't match.
FOUNDATIONAL_PATTERNS = [
    re.compile(r"^python-\d+(\.\d+)?$"),
    re.compile(r"^nodejs-\d+(\.\d+)?$"),
]


def is_foundational(name: str) -> bool:
    if name in FOUNDATIONAL_PACKAGES:
        return True
    return any(p.match(name) for p in FOUNDATIONAL_PATTERNS)

# CNA homepages — used to give clusters an investigation link to the assigning
# org. Keyed on the lower-cased assigner string returned by NVD.
CNA_HOMEPAGES = {
    "huntr.dev": "https://huntr.com/",
    "@huntr_ai": "https://huntr.com/",
    "github_m": "https://github.com/advisories",
    "github, inc.": "https://github.com/advisories",
    "google llc": "https://security.googleblog.com/",
    "google_inc": "https://security.googleblog.com/",
    "mitre corporation": "https://cve.mitre.org/",
    "redhat": "https://access.redhat.com/security/security-updates/",
    "red hat, inc.": "https://access.redhat.com/security/security-updates/",
    "canonical ltd.": "https://ubuntu.com/security/cves",
    "chainguard": "https://images.chainguard.dev/security",
    "snyk": "https://security.snyk.io/",
    "wordfence": "https://www.wordfence.com/threat-intel/vulnerabilities",
    "patchstack": "https://patchstack.com/database/",
}


@dataclass
class Finding:
    image: str
    tag: str
    vulnerability_id: str
    cve_id: str | None
    severity: str
    fix_available: bool
    fix_version: str | None
    cga_id: str | None
    advisory_status: str | None
    package_name: str
    package_version: str
    data_source: str


@dataclass
class NvdRecord:
    cve_id: str
    published: date | None
    cna: str | None
    cwe_ids: list[str] = field(default_factory=list)


@dataclass
class PackageRow:
    name: str
    is_foundational: bool
    unique_cves: int
    instances: int
    severity_mix: Counter
    affected_images: list[str] = field(default_factory=list)


@dataclass
class CveRow:
    vulnerability_id: str
    cve_id: str | None
    severity: str
    package: str
    instances: int
    fix_available: bool
    cga_id: str | None
    data_source: str
    affected_images: list[str] = field(default_factory=list)


@dataclass
class SeverityContributor:
    severity: str
    # Top single CVE for this severity
    top_cve_id: str
    top_cve_cve_id: str | None  # real CVE-... id if extractable, else None
    top_cve_data_source: str
    top_cve_package: str
    top_cve_findings: int
    top_cve_share: float        # share of this severity's total findings
    top_cve_image_count: int    # distinct images affected
    # Top package for this severity (may differ from the package of the top CVE
    # when the top package's noise comes from several CVEs rather than one)
    top_pkg: str
    top_pkg_unique_cves: int
    top_pkg_findings: int
    top_pkg_share: float
    severity_total: int


@dataclass
class ImageRow:
    image: str
    tag: str
    total: int
    by_severity: Counter


@dataclass
class Cluster:
    kind: str  # "CNA bulk submission" | "Foundational-package follow-on" | "Coordinated disclosure window"
    label: str
    members: list[CveRow]
    investigation_links: list[tuple[str, str]]  # (label, url)
    narrative: str | None = None
    narrative_bullets: list[str] = field(default_factory=list)
    cited_sources: list[tuple[str, str]] = field(default_factory=list)
    fingerprint: str = ""


@dataclass
class Metrics:
    meta: dict
    images_scanned: int          # total fetched from registry (from _meta.image-count)
    images_with_findings: int    # subset that has at least one finding
    tag_count: int
    total_findings: int
    unique_vulns: int
    amplification_factor: float
    fix_available_rate: float
    cga_coverage_rate: float
    critical_high_count: int
    critical_high_pct: float
    severity_matrix: list[tuple[str, int, int]]
    severity_contributors: list[SeverityContributor]
    package_attribution: list[PackageRow]
    top_noisy_cves: list[CveRow]
    image_hotspots: list[ImageRow]
    unfixable_critical_high: list[CveRow]
    clusters: list[Cluster]
    nvd_record_count: int
    nvd_enriched: bool
    headline_narrative: str = ""
    severity_callouts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Load & flatten
# ---------------------------------------------------------------------------

def load_report(path: Path) -> tuple[dict, list[Finding]]:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not raw:
        return {}, []

    meta = raw.pop("_meta", {}) if isinstance(raw, dict) else {}
    findings: list[Finding] = []

    for image_name, image_data in raw.items():
        if not isinstance(image_data, dict):
            continue
        for tag, tag_data in image_data.items():
            if not isinstance(tag_data, dict):
                continue
            vulns = tag_data.get("vulnerabilities") or []
            for v in vulns:
                sev = (v.get("severity") or "Unknown").strip()
                # Normalize casing: GRYPE emits "Critical", advisories sometimes "critical".
                sev = sev[:1].upper() + sev[1:].lower() if sev else "Unknown"
                if sev not in SEVERITY_ORDER:
                    sev = "Unknown"
                cve_id = v.get("cve-id") or _extract_cve(v)
                findings.append(Finding(
                    image=image_name,
                    tag=tag,
                    vulnerability_id=v.get("vulnerability-id", "unknown"),
                    cve_id=cve_id,
                    severity=sev,
                    fix_available=bool(v.get("fix-available")),
                    fix_version=v.get("fix-version"),
                    cga_id=v.get("cga-id"),
                    advisory_status=v.get("advisory-status"),
                    package_name=(v.get("package-name") or "unknown-package").lower(),
                    package_version=v.get("package-version") or "",
                    data_source=v.get("data-source") or "",
                ))
    return meta, findings


def _extract_cve(v: dict) -> str | None:
    """Fall back to scanning vulnerability-id and urls for a CVE pattern.

    GRYPE often returns a GHSA as the primary id with the CVE only mentioned in
    advisory URLs (nvd.nist.gov, access.redhat.com, etc.).
    """
    vid = v.get("vulnerability-id") or ""
    m = CVE_RE.search(vid)
    if m:
        return m.group(0)
    for url in v.get("urls") or []:
        m = CVE_RE.search(url)
        if m:
            return m.group(0)
    return None


# ---------------------------------------------------------------------------
# NVD enrichment
# ---------------------------------------------------------------------------

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def enrich_with_nvd(cve_ids: Iterable[str], cache_path: Path, api_key: str | None) -> dict[str, NvdRecord]:
    """Look up publication date + CNA + CWE for each CVE via the NVD 2.0 API.

    Cached to disk; respects rate limits; degrades gracefully on failure.
    Returns whatever it was able to resolve, never raises.
    """
    cve_ids = sorted({c for c in cve_ids if c and c.startswith("CVE-")})
    if not cve_ids:
        return {}

    cache: dict[str, dict] = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
        except json.JSONDecodeError:
            cache = {}

    headers = {"User-Agent": "ils-fetcher-analyze/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    # 5 req/30s without key, 50 req/30s with key. Use conservative delays.
    delay = 0.7 if api_key else 6.5
    session = requests.Session()
    fetched_this_run = 0

    for cve in cve_ids:
        if cve in cache:
            continue
        try:
            resp = session.get(NVD_API, params={"cveId": cve}, headers=headers, timeout=15)
        except requests.RequestException as e:
            print(f"  NVD lookup failed for {cve}: {e}", file=sys.stderr)
            continue
        if resp.status_code == 404:
            cache[cve] = {"missing": True}
        elif resp.status_code != 200:
            print(f"  NVD returned {resp.status_code} for {cve}; stopping enrichment", file=sys.stderr)
            break
        else:
            cache[cve] = _parse_nvd_payload(resp.json(), cve)
        fetched_this_run += 1
        # Periodically persist cache so a crash doesn't lose work.
        if fetched_this_run % 25 == 0:
            cache_path.write_text(json.dumps(cache))
        time.sleep(delay)

    cache_path.write_text(json.dumps(cache))

    records: dict[str, NvdRecord] = {}
    for cve, payload in cache.items():
        if payload.get("missing"):
            continue
        published = None
        if payload.get("published"):
            try:
                published = datetime.fromisoformat(payload["published"].replace("Z", "+00:00")).date()
            except ValueError:
                published = None
        records[cve] = NvdRecord(
            cve_id=cve,
            published=published,
            cna=payload.get("cna"),
            cwe_ids=payload.get("cwe_ids", []),
        )
    return records


def _parse_nvd_payload(payload: dict, cve_id: str) -> dict:
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return {"missing": True}
    cve = vulns[0].get("cve") or {}
    published = cve.get("published")
    cna = cve.get("sourceIdentifier")
    cwe_ids: list[str] = []
    for w in cve.get("weaknesses") or []:
        for desc in w.get("description") or []:
            val = desc.get("value")
            if val and val.startswith("CWE-"):
                cwe_ids.append(val)
    return {
        "cve_id": cve_id,
        "published": published,
        "cna": cna,
        "cwe_ids": sorted(set(cwe_ids)),
    }


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(meta: dict, findings: list[Finding],
                    nvd_records: dict[str, NvdRecord],
                    nvd_enriched: bool, top_n: int) -> Metrics:
    images = {f.image for f in findings}
    tags = {(f.image, f.tag) for f in findings}
    total = len(findings)
    unique = {f.vulnerability_id for f in findings}
    unique_count = len(unique)

    amp = (total / unique_count) if unique_count else 0.0
    fix_rate = (sum(1 for f in findings if f.fix_available) / total) if total else 0.0
    cga_rate = (sum(1 for f in findings if f.cga_id) / total) if total else 0.0

    # Severity matrix: unique-by-severity vs total-by-severity.
    severity_total = Counter(f.severity for f in findings)
    severity_unique: dict[str, set] = defaultdict(set)
    for f in findings:
        severity_unique[f.severity].add(f.vulnerability_id)
    severity_matrix = [
        (sev, len(severity_unique[sev]), severity_total.get(sev, 0))
        for sev in SEVERITY_ORDER
        if severity_total.get(sev, 0) or severity_unique[sev]
    ]
    critical_high = severity_total.get("Critical", 0) + severity_total.get("High", 0)
    critical_high_pct = (critical_high / total) if total else 0.0

    # Per-severity concentration: top single CVE and top package.
    severity_contributors = _compute_severity_contributors(findings, severity_total)

    # Package attribution.
    pkg_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        pkg_findings[f.package_name].append(f)
    package_attribution = []
    for name, fs in pkg_findings.items():
        package_attribution.append(PackageRow(
            name=name,
            is_foundational=is_foundational(name),
            unique_cves=len({f.vulnerability_id for f in fs}),
            instances=len(fs),
            severity_mix=Counter(f.severity for f in fs),
            affected_images=sorted({f.image for f in fs}),
        ))
    package_attribution.sort(key=lambda r: (-r.instances, -r.unique_cves))

    # Top noisy CVEs by image-tag impact.
    cve_findings: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        cve_findings[f.vulnerability_id].append(f)
    cve_rows: list[CveRow] = []
    for vid, fs in cve_findings.items():
        # Pick representative metadata from the first occurrence.
        rep = fs[0]
        cve_rows.append(CveRow(
            vulnerability_id=vid,
            cve_id=rep.cve_id,
            severity=rep.severity,
            package=rep.package_name,
            instances=len({(f.image, f.tag) for f in fs}),
            fix_available=rep.fix_available,
            cga_id=rep.cga_id,
            data_source=rep.data_source,
            affected_images=sorted({f"{f.image}:{f.tag}" for f in fs}),
        ))
    cve_rows.sort(key=lambda r: (-r.instances, _severity_rank(r.severity)))
    top_noisy = cve_rows[:top_n]

    # Image hotspots — group by image+tag.
    image_findings: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        image_findings[(f.image, f.tag)].append(f)
    image_rows = [
        ImageRow(
            image=img, tag=tag, total=len(fs),
            by_severity=Counter(f.severity for f in fs),
        )
        for (img, tag), fs in image_findings.items()
    ]
    image_rows.sort(key=lambda r: -r.total)
    image_hotspots = image_rows[:top_n]

    # Unfixable Critical/High.
    unfixable = [
        row for row in cve_rows
        if row.severity in ("Critical", "High") and not row.fix_available
    ][:top_n]

    # Event clusters.
    clusters = detect_event_clusters(cve_rows, nvd_records) if nvd_enriched else []

    images_with_findings = len(images)
    images_scanned = int(meta.get("image-count") or images_with_findings)

    headline_narrative = _build_headline_narrative(
        package_attribution, severity_total, total, images_scanned,
        images_with_findings, meta.get("organization"),
    )
    severity_callouts = _build_severity_callouts(severity_contributors)

    return Metrics(
        meta=meta,
        images_scanned=images_scanned,
        images_with_findings=images_with_findings,
        tag_count=len(tags),
        total_findings=total,
        unique_vulns=unique_count,
        amplification_factor=amp,
        fix_available_rate=fix_rate,
        cga_coverage_rate=cga_rate,
        critical_high_count=critical_high,
        critical_high_pct=critical_high_pct,
        severity_matrix=severity_matrix,
        severity_contributors=severity_contributors,
        package_attribution=package_attribution,
        top_noisy_cves=top_noisy,
        image_hotspots=image_hotspots,
        unfixable_critical_high=unfixable,
        clusters=clusters,
        nvd_record_count=len(nvd_records),
        nvd_enriched=nvd_enriched,
        headline_narrative=headline_narrative,
        severity_callouts=severity_callouts,
    )


def _compute_severity_contributors(findings: list[Finding],
                                   severity_total: Counter) -> list[SeverityContributor]:
    contributors: list[SeverityContributor] = []
    for sev in SEVERITY_ORDER:
        sev_total = severity_total.get(sev, 0)
        if sev_total == 0:
            continue
        sev_findings = [f for f in findings if f.severity == sev]

        # Top CVE by # of findings for this severity.
        by_cve: dict[str, list[Finding]] = defaultdict(list)
        for f in sev_findings:
            by_cve[f.vulnerability_id].append(f)
        top_cve_id, top_cve_fs = max(by_cve.items(), key=lambda kv: len(kv[1]))
        rep = top_cve_fs[0]
        top_cve_image_count = len({f.image for f in top_cve_fs})

        # Top package by # of findings for this severity.
        by_pkg: dict[str, list[Finding]] = defaultdict(list)
        for f in sev_findings:
            by_pkg[f.package_name].append(f)
        top_pkg, top_pkg_fs = max(by_pkg.items(), key=lambda kv: len(kv[1]))
        top_pkg_unique = len({f.vulnerability_id for f in top_pkg_fs})

        contributors.append(SeverityContributor(
            severity=sev,
            top_cve_id=top_cve_id,
            top_cve_cve_id=rep.cve_id,
            top_cve_data_source=rep.data_source,
            top_cve_package=rep.package_name,
            top_cve_findings=len(top_cve_fs),
            top_cve_share=len(top_cve_fs) / sev_total,
            top_cve_image_count=top_cve_image_count,
            top_pkg=top_pkg,
            top_pkg_unique_cves=top_pkg_unique,
            top_pkg_findings=len(top_pkg_fs),
            top_pkg_share=len(top_pkg_fs) / sev_total,
            severity_total=sev_total,
        ))
    return contributors


def _build_severity_callouts(contributors: list[SeverityContributor]) -> list[str]:
    """Surface concentration callouts for the severity tiers operators actually care
    about. Critical and High always get a callout (operational priority). Medium gets
    one only when a single CVE or package owns a meaningful share. Low, Negligible,
    and Unknown are skipped — they don't drive remediation priority.
    """
    callouts: list[str] = []
    for c in contributors:
        # Hard cutoff: skip anything below Medium and skip tiny tiers where
        # concentration math is statistical noise.
        if c.severity not in ("Critical", "High", "Medium"):
            continue
        if c.severity_total < 3:
            continue

        # Thresholds: looser for Critical/High (always emit something), stricter
        # for Medium (only emit when one contributor owns a sizable share).
        if c.severity in ("Critical", "High"):
            cve_threshold = 0.30
            pkg_threshold = 0.20
            require_concentration = False
        else:  # Medium
            cve_threshold = 0.40
            pkg_threshold = 0.40
            require_concentration = True

        prefer_cve = c.top_cve_share >= cve_threshold
        prefer_pkg = (
            c.top_pkg_share >= pkg_threshold
            and c.top_pkg_findings >= c.top_cve_findings
        )

        if require_concentration and not (prefer_cve or prefer_pkg):
            continue

        if prefer_cve and c.top_cve_findings > c.top_pkg_findings * 0.8:
            cve_url = _cve_search_url(c.top_cve_id, c.top_cve_cve_id, c.top_cve_data_source)
            link = (f"[{c.top_cve_id}]({cve_url})"
                    if cve_url else f"`{c.top_cve_id}`")
            callouts.append(
                f"**{c.severity}** is dominated by a single CVE — {link} in "
                f"`{c.top_cve_package}` — which alone accounts for "
                f"**{c.top_cve_findings} of {c.severity_total} "
                f"({c.top_cve_share:.0%})** {c.severity} findings, "
                f"across **{c.top_cve_image_count}** images."
            )
        elif prefer_pkg:
            callouts.append(
                f"**{c.severity}** is concentrated in `{c.top_pkg}` — "
                f"**{c.top_pkg_unique_cves}** CVEs in that package produce "
                f"**{c.top_pkg_findings} of {c.severity_total} "
                f"({c.top_pkg_share:.0%})** {c.severity} findings."
            )
        else:
            # Critical/High with no dominant contributor — name the biggest one
            # so the reader still has a starting place to investigate.
            biggest = (
                ("CVE", c.top_cve_id, c.top_cve_data_source, c.top_cve_package,
                 c.top_cve_findings, c.top_cve_share)
                if c.top_cve_share >= c.top_pkg_share
                else ("pkg", c.top_pkg, "", c.top_pkg,
                      c.top_pkg_findings, c.top_pkg_share)
            )
            kind, ident, src, _pkg, findings, share = biggest
            if kind == "CVE":
                cve_url = _cve_search_url(ident, c.top_cve_cve_id, src)
                ref = f"[{ident}]({cve_url})" if cve_url else f"`{ident}`"
                ref += f" in `{c.top_cve_package}`"
            else:
                ref = f"`{ident}`"
            callouts.append(
                f"**{c.severity}** has no single dominant contributor; the "
                f"largest is {ref} at **{findings} of {c.severity_total} "
                f"({share:.0%})**."
            )
    return callouts


def _build_headline_narrative(packages: list[PackageRow], severity_total: Counter,
                              total: int, images_scanned: int,
                              images_with_findings: int,
                              org: str | None) -> str:
    if total == 0 or not packages:
        return ""

    org_label = f"`{org}`" if org else "the scanned"
    parts: list[str] = []

    clean = images_scanned - images_with_findings
    clean_pct = (clean / images_scanned * 100) if images_scanned else 0.0
    parts.append(
        f"Of **{images_scanned}** images in {org_label}, **{images_with_findings}** "
        f"({(images_with_findings / images_scanned * 100):.0f}%) carry at least one "
        f"finding; **{clean}** ({clean_pct:.0f}%) are clean."
    )

    top = packages[0]
    crit_total = severity_total.get("Critical", 0)
    high_total = severity_total.get("High", 0)
    pkg_crit = top.severity_mix.get("Critical", 0)
    pkg_high = top.severity_mix.get("High", 0)
    pkg_pct = (top.instances / total * 100) if total else 0.0
    crit_pct = (pkg_crit / crit_total * 100) if crit_total else 0.0
    high_pct = (pkg_high / high_total * 100) if high_total else 0.0
    img_count = len(top.affected_images)
    parts.append(
        f"Upstream issues in `{top.name}` alone account for "
        f"**{pkg_pct:.1f}%** of all findings "
        f"({crit_pct:.0f}% of Critical, {high_pct:.0f}% of High) "
        f"and impact **{img_count}** of the {images_with_findings} affected images."
    )

    # If a second package is comparably noisy, add it.
    if len(packages) > 1 and packages[1].instances >= top.instances * 0.5:
        second = packages[1]
        second_pct = (second.instances / total * 100) if total else 0.0
        parts.append(
            f"`{second.name}` is the next-largest contributor at "
            f"**{second_pct:.1f}%** of findings across "
            f"**{len(second.affected_images)}** images."
        )

    return " ".join(parts)


def _severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


# ---------------------------------------------------------------------------
# Event clustering
# ---------------------------------------------------------------------------

CLUSTER_MIN_SIZE = 3


def detect_event_clusters(cve_rows: list[CveRow],
                          nvd_records: dict[str, NvdRecord]) -> list[Cluster]:
    """Detect external-event clusters from NVD metadata.

    Three cluster shapes:
      - CNA bulk submission: same week + same CNA (e.g. huntr.dev AI runs)
      - Foundational-package follow-on: same week + same package
      - Coordinated disclosure window: same week, mixed source, large size
    """
    # Index rows that have NVD metadata.
    enriched: list[tuple[CveRow, NvdRecord]] = []
    for row in cve_rows:
        if row.cve_id and row.cve_id in nvd_records:
            rec = nvd_records[row.cve_id]
            if rec.published:
                enriched.append((row, rec))
    if not enriched:
        return []

    by_cna_week: dict[tuple[str, str], list[CveRow]] = defaultdict(list)
    by_pkg_week: dict[tuple[str, str], list[CveRow]] = defaultdict(list)
    by_week: dict[str, list[CveRow]] = defaultdict(list)
    for row, rec in enriched:
        week_key = _iso_week(rec.published)
        by_week[week_key].append(row)
        if rec.cna:
            by_cna_week[(rec.cna, week_key)].append(row)
        by_pkg_week[(row.package, week_key)].append(row)

    clusters: list[Cluster] = []
    seen_cves: set[str] = set()

    # CNA + week clusters (most specific signal first).
    for (cna, week), rows in sorted(by_cna_week.items(), key=lambda kv: -len(kv[1])):
        if len(rows) < CLUSTER_MIN_SIZE:
            continue
        new_rows = [r for r in rows if r.vulnerability_id not in seen_cves]
        if len(new_rows) < CLUSTER_MIN_SIZE:
            continue
        seen_cves.update(r.vulnerability_id for r in new_rows)
        clusters.append(Cluster(
            kind="CNA bulk submission",
            label=f"{cna} — week of {week} — {len(new_rows)} CVEs",
            members=new_rows,
            investigation_links=_links_for_cluster(new_rows, extra={cna: CNA_HOMEPAGES.get(cna.lower())}),
        ))

    # Foundational-pkg + week clusters.
    for (pkg, week), rows in sorted(by_pkg_week.items(), key=lambda kv: -len(kv[1])):
        if len(rows) < CLUSTER_MIN_SIZE or not is_foundational(pkg):
            continue
        new_rows = [r for r in rows if r.vulnerability_id not in seen_cves]
        if len(new_rows) < CLUSTER_MIN_SIZE:
            continue
        seen_cves.update(r.vulnerability_id for r in new_rows)
        clusters.append(Cluster(
            kind="Foundational-package follow-on",
            label=f"{pkg} — week of {week} — {len(new_rows)} CVEs",
            members=new_rows,
            investigation_links=_links_for_cluster(new_rows),
        ))

    # General-disclosure week clusters (catches news-driven research bursts).
    for week, rows in sorted(by_week.items(), key=lambda kv: -len(kv[1])):
        if len(rows) < CLUSTER_MIN_SIZE * 2:
            continue
        new_rows = [r for r in rows if r.vulnerability_id not in seen_cves]
        if len(new_rows) < CLUSTER_MIN_SIZE * 2:
            continue
        seen_cves.update(r.vulnerability_id for r in new_rows)
        clusters.append(Cluster(
            kind="Coordinated disclosure window",
            label=f"Week of {week} — {len(new_rows)} CVEs across multiple packages",
            members=new_rows,
            investigation_links=_links_for_cluster(new_rows),
        ))

    clusters.sort(key=lambda c: -len(c.members))
    for c in clusters:
        c.fingerprint = _cluster_fingerprint(c)
    return clusters


def _cluster_fingerprint(c: Cluster) -> str:
    """Stable identity for caching narrative lookups across runs.

    Includes a hash of RESEARCH_SYSTEM_PROMPT so prompt edits invalidate cached
    narratives — otherwise the schema change here (paragraph → bullets) would
    silently keep returning old paragraphs.
    """
    ids = sorted(r.vulnerability_id for r in c.members)
    import hashlib
    h = hashlib.sha256()
    h.update(c.kind.encode("utf-8"))
    h.update(b"\x00")
    for vid in ids:
        h.update(vid.encode("utf-8"))
        h.update(b"\x00")
    h.update(b"\x00prompt\x00")
    h.update(RESEARCH_SYSTEM_PROMPT.encode("utf-8"))
    return h.hexdigest()[:16]


def _iso_week(d: date) -> str:
    year, week, _ = d.isocalendar()
    monday = d - timedelta(days=d.weekday())
    return f"{year}-W{week:02d} ({monday.isoformat()})"


def _links_for_cluster(rows: list[CveRow], extra: dict | None = None) -> list[tuple[str, str]]:
    # Authoritative-first fallback links shown when LLM research isn't run.
    # Skip aggregators (Google News, HN) and surface primary sources instead.
    first_cve = next((r.cve_id for r in rows if r.cve_id), None)
    first_pkg = rows[0].package if rows else None
    links: list[tuple[str, str] | None] = [
        ("OSV.dev", f"https://osv.dev/vulnerability/{first_cve}") if first_cve else None,
        ("Chainguard advisories",
         f"https://images.chainguard.dev/security?query={urllib.parse.quote(first_cve)}")
            if first_cve else None,
        ("NVD", f"https://nvd.nist.gov/vuln/detail/{first_cve}") if first_cve else None,
        ("GitHub advisory database (issues)",
         "https://github.com/github/advisory-database/issues"),
        ("Google security-research (issues)",
         "https://github.com/google/security-research/issues"),
    ]
    if first_pkg:
        links.append(("OSV (package query)",
                      f"https://osv.dev/list?q={urllib.parse.quote(first_pkg)}"))
    if extra:
        for label, url in extra.items():
            if url:
                links.append((f"{label} (CNA homepage)", url))
    return [l for l in links if l]


# ---------------------------------------------------------------------------
# LLM web-research enrichment (Anthropic API + web_search)
# ---------------------------------------------------------------------------

RESEARCH_SYSTEM_PROMPT = """\
You are a vulnerability analyst writing an EXECUTIVE BRIEF that explains why a cluster of CVE *disclosures* showed up in an operator's container vulnerability scan. The reader is busy and wants a "so what", not a forensic write-up.

CONTEXT:
- Every CVE in the cluster was DETECTED by grype against production images right now — these are OPEN findings, not history.
- The cluster is a *reporting spike*: CVEs published in the same disclosure window that hit this portfolio. Explain the spike — what caused it, who drove it, how much it matters for THIS fleet. Do NOT recap the upstream fix.
- The user message has `Member CVEs` (each with `image:tag` hits), `Distinct packages`, and `Distinct images impacted`. Use these to find groupings: which application families are hit (gitlab, kibana, harbor, kubeflow, airflow, etc.), whether specific variants dominate (FIPS, dev, IAM-guarded), and which packages map to which image sets. Name the image sets and the packages that link them; skip incidental groupings. Never write "multiple images affected".

Typical disclosure events: CNA batch publications (GHSA, apache, python weekly waves); research drops (Big Sleep, huntr.dev, ProtectAI, GitHub Security Lab, Project Zero, Trail of Bits, Snyk); coordinated multi-project embargo windows; news-driven follow-on cascades.

Search the web for evidence of the disclosure event. Prefer disclosure-side sources (advisory pages, researcher blogs, CNA batches, NVD/OSV) over patch-centric release notes. Useful starting points: project security pages, github.com/github/advisory-database, OSV.dev, NVD, security research blogs, news coverage.

OUTPUT FORMAT — strict. A single JSON object inside a fenced ```json code block:

  {"narrative_bullets": ["<bullet 1>", "<bullet 2>", ...],
   "sources": [{"label": "<short title>", "url": "<full https URL you actually retrieved>"}, ...]}

Rules for narrative_bullets:
- 4-5 bullets. Each is normally ONE sentence, MAX ~25 words. Plain English, no security-analyst jargon.
- Each bullet starts with a short bold heading + colon + space, then the content. Format: `"**Disclosure driver:** Routine huntr.dev batch against protobufjs (3 prototype-pollution CVEs, mid-Nov)."`
- Heading menu (2-4 words, vary wording as fits, no repeats per response):
    - **Disclosure driver** — what event / who drove it
    - **Normal or unusual** — routine batch vs. noteworthy
    - **Severity shape** — how bad for this fleet
    - **Image impact** — which image sets + packages (list format below when applicable)
    - **Action signal** — watch vs. move now
  Pick the 4-5 the data actually supports; skip the rest. Do NOT pad.
- LIST EXCEPTION: when 2+ image groups are hit by 2+ package groups, the image-impact bullet may use sub-bullets to group the impact by each image group. Encode sub-bullets as additional lines in the SAME string, each starting with `- ` (a hyphen and a space). Example: `"**Image impact:** Two app classes hit cleanly.\\n- gitlab toolchain (24 images): protobufjs + css_parser\\n- kibana stack (12 images): ws + ip-address"`.
- BANNED jargon: "fan-out", "cohort", "concentrates in", "surface area", "blast radius", "structural pattern", "variant suffix". Say "image sets", "affected images", "hits", "shows up in".
- BANNED fix-centric verbs/phrases: "fixed", "patched", "resolved", "addressed", "remediated", "closed", "to fix", "as fixes for". Use "disclosed", "published", "filed", "minted", "surfaced", "reported", "landed in NVD". An "originally fixed upstream in vX.Y" subordinate clause is OK only when load-bearing.
- CVE IDs, researcher names, dates: brief parentheticals, never the subject of a bullet.
- No bullet about "scans surface these because the vuln DB updated" — obvious, wastes a slot.
- No hedging ("It appears…"), no emoji, no exclamation marks.
- NO inline citation markers in bullet text. Do not emit `<cite>`, `cite index=...`, footnote markers, or any other inline source reference inside `narrative_bullets`. All source attribution belongs in the `sources` array only.
- Anti-example (too long): "The cluster was driven by a coordinated GHSA batch from the protobufjs maintainers on 2024-11-12 covering CVE-2024-xxxxx, CVE-2024-yyyyy, and CVE-2024-zzzzz, all prototype-pollution variants disclosed by Jane Doe via huntr.dev." → "**Disclosure driver:** Routine huntr.dev batch against protobufjs (3 prototype-pollution CVEs, mid-Nov)."

Sources: cite 2-5 you actually fetched. Do NOT fabricate URLs.

If no coordinating disclosure event is findable, say so honestly and list what you searched. Do not invent.
"""

RESEARCH_MODEL = "claude-opus-4-7"
RESEARCH_MAX_TOKENS = 16384


def enrich_clusters_with_research(clusters: list[Cluster], api_key: str | None,
                                  cache_path: Path) -> None:
    """Populate `narrative` and `cited_sources` on each cluster via Anthropic + web search.

    Caches results to disk keyed by cluster fingerprint. Degrades gracefully — if the
    SDK is missing, the API key is unset, or any individual call fails, the cluster
    keeps its static investigation_links fallback.
    """
    if not clusters:
        return
    if not api_key:
        return
    try:
        import anthropic  # imported lazily so analyze.py runs without the SDK installed
    except ImportError:
        print("  anthropic SDK not installed — skipping LLM enrichment "
              "(pip install anthropic)", file=sys.stderr)
        return

    cache: dict[str, dict] = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
        except json.JSONDecodeError:
            cache = {}

    client = anthropic.Anthropic(api_key=api_key)
    calls_made = 0
    for cluster in clusters:
        cached = cache.get(cluster.fingerprint)
        if cached:
            cluster.narrative = cached.get("narrative") or None
            cluster.narrative_bullets = [
                b for b in cached.get("narrative_bullets", []) if isinstance(b, str)
            ]
            cluster.cited_sources = [
                (s["label"], s["url"]) for s in cached.get("sources", [])
            ]
            continue

        prompt = _build_cluster_prompt(cluster)
        try:
            with client.messages.stream(
                model=RESEARCH_MODEL,
                max_tokens=RESEARCH_MAX_TOKENS,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                cache_control={"type": "ephemeral"},
                system=RESEARCH_SYSTEM_PROMPT,
                tools=[{"type": "web_search_20260209", "name": "web_search"}],
                messages=[{"role": "user", "content": prompt}],
            ) as stream:
                final = stream.get_final_message()
        except Exception as e:
            print(f"  LLM research failed for cluster {cluster.fingerprint}: {e}",
                  file=sys.stderr)
            continue

        parsed = _parse_research_response(final)
        if parsed:
            cluster.narrative = parsed.get("narrative") or None
            cluster.narrative_bullets = [
                b for b in parsed.get("narrative_bullets", []) if isinstance(b, str)
            ]
            cluster.cited_sources = [
                (s["label"], s["url"]) for s in parsed.get("sources", [])
                if isinstance(s, dict) and s.get("url", "").startswith("http")
            ]
            cache[cluster.fingerprint] = parsed
            cache_path.write_text(json.dumps(cache, indent=2))
        calls_made += 1
        print(f"  researched cluster {cluster.fingerprint} "
              f"({calls_made} call{'s' if calls_made != 1 else ''} this run)")


def _build_cluster_prompt(cluster: Cluster, include_images: bool = False) -> str:
    lines = [
        f"Cluster type: {cluster.kind}",
        f"Label: {cluster.label}",
        f"Member count: {len(cluster.members)}",
        "",
        "Member CVEs (CVE ID — severity — affected package"
        + (" — images" if include_images else "") + "):",
    ]
    for row in cluster.members:
        vid = row.cve_id or row.vulnerability_id
        line = f"- {vid} — {row.severity} — {row.package}"
        if include_images and row.affected_images:
            line += " — " + ", ".join(row.affected_images)
        lines.append(line)

    pkgs = sorted({r.package for r in cluster.members})
    lines.append("")
    lines.append("Distinct packages: " + ", ".join(f"`{p}`" for p in pkgs))

    if include_images:
        all_images = sorted({img for r in cluster.members for img in r.affected_images})
        lines.append("")
        lines.append(f"Distinct images impacted ({len(all_images)}): "
                     + ", ".join(f"`{img}`" for img in all_images))

    lines.append("")
    lines.append("Question: What real-world event produced this cluster? "
                 "Search the web for evidence and synthesize the explanation.")
    return "\n".join(lines)


STORY_SYSTEM_PROMPT = """\
You are writing the executive **Story** section of a container-image \
vulnerability report **produced by Chainguard**, a supplier of secure container \
images. The audience is engineering and business leadership at the customer \
organization consuming these images — VP/Director of Engineering, CISO, Head \
of Platform, Head of Product Security.

# Critical framing — read this carefully

The CVEs in this report are present in the **upstream open-source projects** \
that Chainguard packages into its images (CPython, Docker, the Go standard \
library, Prometheus, OpenSSL, etc.). A finding here means the upstream project \
has a disclosed vulnerability and **has not yet released a fix**. Chainguard \
cannot ship a patch for a vulnerability upstream has not yet released; once \
upstream fixes land, Chainguard incorporates them into the next image rebuild.

Implications for how you write:

- The image supplier (Chainguard) is **not the source** of these \
vulnerabilities. They are inherited from the open-source ecosystem.
- **Do not frame findings as a quality problem with the images, the supplier, \
or the customer's supply-chain choices.** The findings reflect the current \
state of upstream open-source.
- **Do** frame findings in terms of *upstream ecosystem exposure*, *version \
selection by the customer*, and *upgrade paths the customer can take* to \
reduce exposure without waiting on individual CVE patches.

# Version-comparison / upgrade-path angle

When the data shows multiple versions of the same upstream package family \
(e.g. python-3.10, python-3.11, python-3.12, python-3.13, python-3.14), use \
the `package_families` block in the payload. Look for patterns:

- Older versions often accumulate more open CVEs as upstream attention shifts \
to newer releases and older issues become wont-fix or slow-patch. If the data \
shows that pattern, recommend the upgrade direction.
- Sometimes the newest version has *more* findings because it just received a \
coordinated disclosure. Say that honestly if the data supports it.
- An upgrade path is one of the few exposure-reduction levers the customer \
controls without waiting on upstream. When a clear version delta exists in the \
data, naming it is more useful to leadership than restating CVE counts.

# What to produce

1. **Summary** — 2 to 4 sentences leading with the bottom-line posture. Cover \
how much of the registry is affected versus clean, where in the upstream \
ecosystem exposure is concentrated (which upstream projects, which versions), \
and which customer-controllable levers (upgrading to a newer upstream version, \
consolidating onto a single supported version) could reduce exposure.

2. **Callouts** — 2 to 4 single-sentence findings. Focus exclusively on \
Critical and High tiers. Each callout should:
- Name the upstream project and the version (or version range) involved.
- Quantify blast radius (% of severity tier, # affected images).
- Where applicable, surface a version-comparison or upgrade-path angle.
- Where applicable, note whether the CVE has an upstream fix yet \
(`fix_available`) — this distinguishes "upgrade or rebuild now" from "no \
remediation available until upstream releases a patch".

Skip Low, Negligible, Unknown.

# Style

- Cite CVE IDs, upstream project names, version numbers, and image counts \
concretely.
- Use the **common project name** the audience recognizes — "Python", "Java", \
"Node.js", "Go", "OpenSSL" — and **never** the technical implementation name, \
even when being precise about which entity ships the patch. This includes \
references to releases, patches, or upstream activity. Forbidden terms include \
"CPython", "OpenJDK", "V8", "HotSpot", and similar implementation labels. If \
you need to refer to the entity that will ship a fix, say "upstream Python", \
"the next Python release", "upstream Node.js", etc. Leadership knows these \
projects by their consumer name only.
- Markdown: `code` for package/image names; **bold** for load-bearing numbers \
and conclusions; `[text](url)` for citations using the data_source URLs in the \
payload.
- Skip aggregate Critical+High counts in the summary — those appear in the \
headline numbers section right below the Story.
- Do not lecture, recommend security policy, or critique the customer's \
choices. Report what the data shows with the framing leadership needs to make \
upstream-version and consolidation decisions.
- If the data is genuinely thin or diffuse, say so plainly — invented \
dominance is worse than honest "risk is distributed".

OUTPUT FORMAT — strict. Your final assistant message must contain a single \
JSON object inside a fenced ```json code block:

{"summary": "<2-4 sentence paragraph>",
 "callouts": ["<sentence 1>", "<sentence 2>", ...]}
"""

STORY_MODEL = "claude-opus-4-7"
STORY_MAX_TOKENS = 2048


def enrich_story_with_llm(metrics: Metrics, api_key: str | None,
                          cache_path: Path) -> bool:
    """Replace the template-generated headline_narrative + severity_callouts with
    LLM output. Returns True if it actually populated metrics from the LLM, False
    if it fell through (no key, no SDK, network failure, parse failure).

    Cached by a fingerprint of the input payload so reruns on the same data
    are free; data changes invalidate the cache automatically.
    """
    if not api_key:
        return False
    try:
        import anthropic
    except ImportError:
        print("  anthropic SDK not installed — keeping template Story", file=sys.stderr)
        return False

    payload = _story_payload(metrics)
    payload_json = json.dumps(payload, sort_keys=True)
    import hashlib
    # Cache key includes the prompt text so edits to STORY_SYSTEM_PROMPT
    # automatically invalidate previously-cached narratives.
    fingerprint_input = payload_json + "\n---\n" + STORY_SYSTEM_PROMPT
    fingerprint = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()[:16]

    cache: dict[str, dict] = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
        except json.JSONDecodeError:
            cache = {}

    result = cache.get(fingerprint)
    if not result:
        client = anthropic.Anthropic(api_key=api_key)
        try:
            response = client.messages.create(
                model=STORY_MODEL,
                max_tokens=STORY_MAX_TOKENS,
                thinking={"type": "adaptive"},
                output_config={"effort": "high"},
                cache_control={"type": "ephemeral"},
                system=STORY_SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": "Here is the analytics summary:\n\n```json\n"
                               + json.dumps(payload, indent=2)
                               + "\n```\n\nWrite the Story section."
                }],
            )
        except Exception as e:
            print(f"  LLM story generation failed: {e}", file=sys.stderr)
            return False
        result = _parse_research_response(response)
        if not result or not result.get("summary"):
            print("  LLM story parse failed — keeping template fallback", file=sys.stderr)
            return False
        cache[fingerprint] = result
        cache_path.write_text(json.dumps(cache, indent=2))
        print(f"  generated Story narrative (fingerprint {fingerprint})")
    else:
        print(f"  Story narrative cached (fingerprint {fingerprint})")

    metrics.headline_narrative = result.get("summary", metrics.headline_narrative)
    callouts = result.get("callouts")
    if isinstance(callouts, list):
        metrics.severity_callouts = [str(c) for c in callouts if c]
    return True


PACKAGE_VERSION_RE = re.compile(r"^(.+?)-(\d+(?:\.\d+)*)$")


def _build_package_families(packages: list[PackageRow]) -> list[dict]:
    """Group package rows by family (same base name, different version suffix).

    Returns only families with >1 version present — that's where the
    version-comparison / upgrade-path narrative becomes useful.
    """
    families: dict[str, list[dict]] = defaultdict(list)
    for row in packages:
        m = PACKAGE_VERSION_RE.match(row.name)
        if not m:
            continue
        family, version = m.group(1), m.group(2)
        families[family].append({
            "name": row.name,
            "version": version,
            "findings": row.instances,
            "unique_cves": row.unique_cves,
            "images_affected": len(row.affected_images),
            "severity_mix": dict(row.severity_mix),
        })

    def _version_tuple(v: str) -> tuple[int, ...]:
        try:
            return tuple(int(p) for p in v.split("."))
        except ValueError:
            return (0,)

    out: list[dict] = []
    for fam, versions in families.items():
        if len(versions) < 2:
            continue
        versions.sort(key=lambda v: _version_tuple(v["version"]))
        out.append({"family": fam, "versions": versions})
    out.sort(key=lambda f: -sum(v["findings"] for v in f["versions"]))
    return out


def _story_payload(metrics: Metrics) -> dict:
    """Compact, stable, JSON-serializable view of the metrics for the LLM Story prompt."""
    return {
        "organization": metrics.meta.get("organization"),
        "images_scanned": metrics.images_scanned,
        "images_with_findings": metrics.images_with_findings,
        "image_tag_pairs": metrics.tag_count,
        "total_findings": metrics.total_findings,
        "unique_vulnerabilities": metrics.unique_vulns,
        "amplification_factor": round(metrics.amplification_factor, 2),
        "fix_available_rate": round(metrics.fix_available_rate, 3),
        "cga_coverage_rate": round(metrics.cga_coverage_rate, 3),
        "package_families": _build_package_families(metrics.package_attribution),
        "severity_matrix": [
            {"severity": s, "unique_cves": u, "findings": t}
            for s, u, t in metrics.severity_matrix
        ],
        "severity_contributors": [
            {
                "severity": c.severity,
                "severity_total": c.severity_total,
                "top_cve": {
                    "id": c.top_cve_id,
                    "package": c.top_cve_package,
                    "findings": c.top_cve_findings,
                    "share": round(c.top_cve_share, 3),
                    "images_affected": c.top_cve_image_count,
                    "data_source": c.top_cve_data_source,
                },
                "top_package": {
                    "name": c.top_pkg,
                    "unique_cves": c.top_pkg_unique_cves,
                    "findings": c.top_pkg_findings,
                    "share": round(c.top_pkg_share, 3),
                },
            }
            for c in metrics.severity_contributors
        ],
        "top_packages": [
            {
                "name": r.name,
                "is_foundational": r.is_foundational,
                "unique_cves": r.unique_cves,
                "findings": r.instances,
                "images_affected": len(r.affected_images),
                "severity_mix": dict(r.severity_mix),
            }
            for r in metrics.package_attribution[:10]
        ],
        "top_noisy_cves": [
            {
                "id": r.vulnerability_id,
                "severity": r.severity,
                "package": r.package,
                "image_tag_impacts": r.instances,
                "fix_available": r.fix_available,
                "data_source": r.data_source,
            }
            for r in metrics.top_noisy_cves[:8]
        ],
    }


def _render_bullet_md(bullet: str) -> str:
    """Render a narrative_bullets entry as Markdown.

    Supports `**bold**` (native markdown) and the LIST EXCEPTION where additional
    `- ` lines inside a single bullet string nest as sub-bullets under the parent.
    """
    lines = [ln for ln in (bullet or "").split("\n") if ln.strip()]
    if not lines:
        return ""
    out = [f"- {lines[0].strip()}"]
    for ln in lines[1:]:
        s = ln.strip()
        if s.startswith("- "):
            out.append(f"  {s}")
        else:
            out.append(f"  - {s}")
    return "\n".join(out)


def _bullet_inline_html(s: str, esc) -> str:
    """Escape, then apply `**bold**` and `code` inline markdown. Strip stray cite markers."""
    s = esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`([^`]+?)`", r"<code>\1</code>", s)
    # Belt-and-suspenders: scrub citation artifacts the model might leak through.
    s = re.sub(r"&lt;cite[^&]*?&gt;[^&]*?&lt;/cite&gt;", "", s)
    s = re.sub(r"&lt;cite[^&]*?/?\s*&gt;", "", s)
    return s


def _render_bullet_html(bullet: str, esc) -> str:
    """Render a narrative_bullets entry as a single `<li>...</li>` (with optional nested `<ul>`)."""
    lines = [ln for ln in (bullet or "").split("\n") if ln.strip()]
    if not lines:
        return ""
    head = _bullet_inline_html(lines[0].strip(), esc)
    sub_items = []
    for ln in lines[1:]:
        s = ln.strip()
        if s.startswith("- "):
            sub_items.append(_bullet_inline_html(s[2:].strip(), esc))
        else:
            sub_items.append(_bullet_inline_html(s, esc))
    if sub_items:
        sub = ('<ul class="cg-cluster__subbullets">'
               + "".join(f"<li>{x}</li>" for x in sub_items)
               + "</ul>")
        return f"<li>{head}{sub}</li>"
    return f"<li>{head}</li>"


def _parse_research_response(message: Any) -> dict | None:
    text_parts: list[str] = []
    for block in message.content:
        if getattr(block, "type", None) == "text":
            text_parts.append(block.text)
    raw = "\n".join(text_parts).strip()
    if not raw:
        return None

    # Try, in order:
    #   1. fenced ```json {...} ``` block (cleanest)
    #   2. fenced ```json {... (no closing fence, response possibly truncated)
    #   3. first `{` through balanced-brace-matched `}` anywhere in the text
    candidates: list[str] = []

    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence_match:
        candidates.append(fence_match.group(1))

    unclosed_fence = re.search(r"```(?:json)?\s*(\{.*)$", raw, re.DOTALL)
    if unclosed_fence:
        candidates.append(unclosed_fence.group(1).strip())

    # Brace-balanced outer object scan — finds the first `{` and walks to its
    # matching `}`, ignoring braces inside strings. Robust against the LLM
    # forgetting fences or embedding extra prose after the JSON.
    first_brace = raw.find("{")
    if first_brace >= 0:
        depth = 0
        in_str = False
        esc = False
        end = -1
        for i in range(first_brace, len(raw)):
            ch = raw[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end > first_brace:
            candidates.append(raw[first_brace:end + 1])

    for cand in candidates:
        try:
            return json.loads(cand)
        except json.JSONDecodeError:
            continue

    # All candidates failed — emit a debug dump so a human can investigate.
    debug_dir = Path(os.environ.get("ILS_DEBUG_DIR", "")) if os.environ.get("ILS_DEBUG_DIR") else None
    if debug_dir or os.environ.get("ILS_DEBUG_LLM"):
        target = Path(os.environ.get("ILS_DEBUG_DIR", ".")) / f"llm_parse_fail_{int(time.time())}.txt"
        try:
            target.write_text(raw)
            print(f"  [debug] parse failed; raw response written to {target}", file=sys.stderr)
        except Exception:
            pass
    else:
        print(f"  [warn] LLM parse failed (raw length={len(raw)}); "
              f"set ILS_DEBUG_LLM=1 to dump response", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

CHAINGUARD_DIRECTORY = "https://images.chainguard.dev/directory/image"


def _cve_search_url(vulnerability_id: str | None, cve_id: str | None = None,
                    fallback: str | None = None) -> str:
    # Route all CVE links to Chainguard's security advisory directory so the
    # reader can see remediation status / linked CGA / affected packages in one
    # place. Prefer a real CVE-... identifier; if grype only gave us a GHSA
    # without a CVE, fall back to the GHSA (Chainguard's search handles both).
    query = None
    if cve_id and cve_id.startswith("CVE-"):
        query = cve_id
    elif vulnerability_id and vulnerability_id.startswith("CVE-"):
        query = vulnerability_id
    elif vulnerability_id:
        query = vulnerability_id
    if query:
        return f"https://images.chainguard.dev/security?query={urllib.parse.quote(query)}"
    return fallback or ""


def _image_directory_url(image: str) -> str:
    return f"{CHAINGUARD_DIRECTORY}/{image}/versions"


def _inline_md_to_html(text: str) -> str:
    """Convert the small subset of inline markdown we use (`code`, **bold**, [text](url)) to HTML."""
    escaped = html.escape(text)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', escaped)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


def render_markdown(m: Metrics) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# Vulnerability Analytics Report")
    a("")
    if m.meta.get("generated-at"):
        a(f"_Source report generated_: `{m.meta['generated-at']}`  ")
    if m.meta.get("organization"):
        a(f"_Organization_: `{m.meta['organization']}`  ")
    a(f"_Images scanned_: **{m.images_scanned}** "
      f"(of which **{m.images_with_findings}** had findings) "
      f"across **{m.tag_count}** image-tag pairs with vulnerabilities")
    a("")

    if m.headline_narrative or m.severity_callouts:
        a("## Story")
        a("")
        if m.headline_narrative:
            a(m.headline_narrative)
            a("")
        for callout in m.severity_callouts:
            a(f"- {callout}")
        if m.severity_callouts:
            a("")

    # Critical+High summary in a unique vs findings form.
    ch_unique = sum(u for sev, u, _t in m.severity_matrix if sev in ("Critical", "High"))
    ch_amp = (m.critical_high_count / ch_unique) if ch_unique else 0.0

    # Headline
    a("## Headline numbers")
    a("")
    a(f"- **Total findings**: {m.total_findings:,} _(per image-tag occurrences)_")
    a(f"- **Unique vulnerabilities**: {m.unique_vulns:,}")
    a(f"- **Amplification factor**: {m.amplification_factor:.2f}× "
      f"(each unique CVE shows up on {m.amplification_factor:.1f} image-tag pairs on average)")
    a(f"- **Critical + High findings**: {m.critical_high_count:,} "
      f"({m.critical_high_pct:.1%} of all findings) — "
      f"**{ch_unique} unique CVEs**, amplified {ch_amp:.1f}×")
    a(f"- **Fix available**: {m.fix_available_rate:.1%}")
    a(f"- **Chainguard advisory coverage**: {m.cga_coverage_rate:.1%}")
    a("")

    if m.total_findings == 0:
        a("> No vulnerabilities in this report — the rest of the analytics are intentionally empty.")
        return "\n".join(lines) + "\n"

    # Severity matrix
    a("## Severity: unique CVEs vs total findings")
    a("")
    a("\"Findings\" = per image-tag occurrences (one CVE in many images = many findings). "
      "The gap between unique and findings is the amplification signal. The top-contributor "
      "column shows which CVE or package is concentrating each severity tier.")
    a("")
    a("| Severity | Unique CVEs | Findings | Amplification | Top contributor |")
    a("|---|---:|---:|---:|---|")
    contrib_by_sev = {c.severity: c for c in m.severity_contributors}
    for sev, unique, total in m.severity_matrix:
        amp = (total / unique) if unique else 0
        c = contrib_by_sev.get(sev)
        if c:
            # Pick whichever (CVE or pkg) is more concentrated.
            if c.top_cve_share >= c.top_pkg_share:
                link = (f"[{c.top_cve_id}]({c.top_cve_data_source})"
                        if c.top_cve_data_source else c.top_cve_id)
                contrib = f"{link} ({c.top_cve_share:.0%})"
            else:
                contrib = f"`{c.top_pkg}` ({c.top_pkg_share:.0%})"
        else:
            contrib = ""
        a(f"| {sev} | {unique} | {total} | {amp:.1f}× | {contrib} |")
    a("")

    # Package attribution
    a("## Package attribution (Pareto of noise)")
    a("")
    a("Which packages are driving the findings? Foundational base-layer packages (glibc, "
      "openssl, busybox, etc.) are flagged — a single CVE in one of these fans out across "
      "many images.")
    a("")
    a("| Package | Foundational | Unique CVEs | Findings | Images | Severity mix |")
    a("|---|:---:|---:|---:|---:|---|")
    for row in m.package_attribution[:15]:
        mix = ", ".join(f"{sev[0]}={n}" for sev in SEVERITY_ORDER if (n := row.severity_mix.get(sev)))
        flag = "**yes**" if row.is_foundational else ""
        a(f"| `{row.name}` | {flag} | {row.unique_cves} | {row.instances} | "
          f"{len(row.affected_images)} | {mix} |")
    a("")
    top_n = m.package_attribution[:10]
    if top_n and m.total_findings:
        share = sum(r.instances for r in top_n) / m.total_findings
        a(f"_Top 10 packages account for_ **{share:.1%}** _of all findings._")
        a("")

    # Per-package image attribution for the top contributors.
    notable = [r for r in m.package_attribution[:5] if len(r.affected_images) > 1]
    if notable:
        a("### Images affected by top packages")
        a("")
        for row in notable:
            imgs = ", ".join(f"`{i}`" for i in row.affected_images[:25])
            more = "" if len(row.affected_images) <= 25 else f" _(+{len(row.affected_images) - 25} more)_"
            a(f"- **`{row.name}`** ({row.instances} findings across "
              f"{len(row.affected_images)} images): {imgs}{more}")
        a("")

    # Top noisy CVEs
    a("## Top noisy CVEs (by image impact)")
    a("")
    a("| ID | Severity | Package | Image-tag impacts | Fix? | CGA |")
    a("|---|---|---|---:|:---:|---|")
    for row in m.top_noisy_cves:
        fix = "yes" if row.fix_available else "no"
        cga = row.cga_id or ""
        cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
        link = f"[{row.vulnerability_id}]({cve_url})" if cve_url else row.vulnerability_id
        a(f"| {link} | {row.severity} | `{row.package}` | {row.instances} | {fix} | {cga} |")
    a("")

    # Image hotspots
    a("## Image hotspots")
    a("")
    a("| Image | Tag | Total | Critical | High | Medium | Low |")
    a("|---|---|---:|---:|---:|---:|---:|")
    for row in m.image_hotspots:
        link = f"[`{row.image}`]({_image_directory_url(row.image)})"
        a(f"| {link} | {row.tag} | {row.total} | "
          f"{row.by_severity.get('Critical', 0)} | "
          f"{row.by_severity.get('High', 0)} | "
          f"{row.by_severity.get('Medium', 0)} | "
          f"{row.by_severity.get('Low', 0)} |")
    a("")

    # Fix posture
    if m.unfixable_critical_high:
        a("## Unfixable Critical/High (needs special attention)")
        a("")
        a("| ID | Severity | Package | Impacts | CGA |")
        a("|---|---|---|---:|---|")
        for row in m.unfixable_critical_high:
            cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
            link = f"[{row.vulnerability_id}]({cve_url})" if cve_url else row.vulnerability_id
            cga = row.cga_id or ""
            a(f"| {link} | {row.severity} | `{row.package}` | {row.instances} | {cga} |")
        a("")

    # Event clusters
    a("## Why does this report look the way it does?")
    a("")
    if not m.nvd_enriched:
        a("> NVD enrichment was skipped — event clustering disabled. Re-run without `--no-enrich` "
          "(set `NVD_API_KEY` env var to avoid rate-limit waits).")
        a("")
    elif not m.clusters:
        a("_No clusters detected._ Either the report is too small, or findings are spread across "
          "many unrelated CVE publication windows.")
        a("")
    else:
        for cluster in m.clusters:
            a(f"### {cluster.kind}: {cluster.label}")
            a("")
            if cluster.narrative_bullets:
                for bullet in cluster.narrative_bullets:
                    a(_render_bullet_md(bullet))
                a("")
            elif cluster.narrative:
                a(cluster.narrative)
                a("")
            if (cluster.narrative_bullets or cluster.narrative) and cluster.cited_sources:
                a("**Sources:**")
                for label, url in cluster.cited_sources:
                    a(f"- [{label}]({url})")
                a("")
            a("Member CVEs:")
            sorted_members = sorted(
                cluster.members,
                key=lambda r: (_severity_rank(r.severity), -r.instances, r.vulnerability_id),
            )
            for row in sorted_members:
                cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
                link = f"[{row.vulnerability_id}]({cve_url})" if cve_url else row.vulnerability_id
                a(f"- {link} ({row.severity}, pkg `{row.package}`, {row.instances} impacts)")
            a("")
            if not (cluster.narrative_bullets or cluster.narrative):
                a("Investigate the world-event story:")
                for label, url in cluster.investigation_links:
                    a(f"- [{label}]({url})")
                a("")

    # Interpretation guide
    a("## How to read this report")
    a("")
    a("**Amplification factor.** Total findings divided by unique vulnerabilities. "
      "A value of 1.0 means every CVE hits exactly one image-tag — findings are evenly distributed. "
      "A value of 10× or more means a small number of CVEs (typically in foundational packages) "
      "are doing most of the work, and the absolute finding count overstates the unique problem set.")
    a("")
    a("**Foundational packages.** Libraries like `glibc`, `openssl`, `busybox`, `zlib`, and `libxml2` "
      "sit underneath nearly every container. A single CVE in one of them fans out across many images. "
      "If the top 10 packages cover >70% of findings and several are foundational, the posture is "
      "*concentrated* — fixing a small number of base images resolves a large share of findings.")
    a("")
    a("**Multi-arch fan-out caveat.** GRYPE reports are per-digest. If you fetch both `linux/amd64` and "
      "`linux/arm64`, the same CVE may appear under separate digests for the same image. The current "
      "fetcher targets `latest` and `latest-dev` (one digest each), so this is normally not in play — "
      "but worth keeping in mind for downstream analyses.")
    a("")
    a("**Spike-cause taxonomy.** When a report shows a sudden uptick (visible only once snapshots "
      "accumulate in `output/history/`), common causes are:")
    a("")
    a("- A new CVE published in a foundational package (one CVE → many image impacts)")
    a("- A coordinated research drop (e.g. Project Zero, OSS-Fuzz, huntr.dev) batching dozens of "
      "  CVEs against the same library or family")
    a("- A scanner-database refresh that newly maps an existing CVE to packages it didn't match before")
    a("- A news-driven CVE (Log4Shell-style) triggering follow-on research into adjacent components")
    a("- An image rebuild that pulled in a newer dependency carrying its own CVE backlog")
    a("")
    a("**References.**")
    a("")
    a("- [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)")
    a("- [EPSS — Exploit Prediction Scoring System](https://www.first.org/epss/)")
    a("- [CVSS](https://www.first.org/cvss/)")
    a("- [NVD API](https://nvd.nist.gov/developers/vulnerabilities)")
    a("- [MITRE CVE List](https://www.cve.org/)")
    a("- [CNA list](https://www.cve.org/PartnerInformation/ListofPartners)")
    a("- [OSV.dev](https://osv.dev/)")
    a("- [CVE-Trends](https://cvetrends.com/)")
    a("- [Chainguard advisories](https://images.chainguard.dev/security)")
    a("- [GRYPE](https://github.com/anchore/grype)")
    a("")

    return "\n".join(lines) + "\n"


def render_html(m: Metrics) -> str:
    def esc(s: Any) -> str:
        return html.escape(str(s))

    def sev_class(sev: str) -> str:
        return f"sev-{sev.lower().replace(' ', '-')}"

    def severity_bar(counts: Counter, total: int) -> str:
        if total == 0:
            return '<span class="cg-bar cg-bar--empty" aria-hidden="true"></span>'
        bars = []
        for sev in SEVERITY_ORDER:
            n = counts.get(sev, 0)
            if not n:
                continue
            pct = (n / total) * 100
            bars.append(
                f'<span class="cg-bar__seg {sev_class(sev)}" '
                f'style="width:{pct:.2f}%" title="{sev}: {n}"></span>'
            )
        return f'<span class="cg-bar" role="img" aria-label="Severity breakdown">{"".join(bars)}</span>'

    def fix_pill(yes: bool) -> str:
        if yes:
            return '<span class="cg-pill cg-pill--positive">fixable</span>'
        return '<span class="cg-pill cg-pill--negative">no fix</span>'

    parts: list[str] = []
    rail_nav: list[tuple[str, str]] = []

    # ─── Hero + KPI panels (top of main column, above section cards) ──
    org = m.meta.get("organization") or ""
    generated = m.meta.get("generated-at") or ""
    meta_bits = []
    if org:
        meta_bits.append(f'<span translate="no">{esc(org)}</span>')
    meta_bits.append(f"{m.images_scanned} images · {m.tag_count} tags")
    if generated:
        meta_bits.append(f"as of {esc(generated)}")

    rail_nav.append(("overview", "Overview"))
    parts.append(f"""
<section class="cg-hero" id="overview">
  <p class="cg-eyebrow">Container portfolio briefing</p>
  <h1>Vulnerability landscape</h1>
  <p class="cg-hero__meta">{" · ".join(meta_bits)}</p>
</section>""")

    # KPIs as a panel grid
    ch_unique = sum(u for sev, u, _t in m.severity_matrix if sev in ("Critical", "High"))
    ch_amp = (m.critical_high_count / ch_unique) if ch_unique else 0.0
    clean_count = max(0, m.images_scanned - m.images_with_findings)
    clean_pct = (clean_count / m.images_scanned * 100) if m.images_scanned else 0.0
    affected_pct = (m.images_with_findings / m.images_scanned * 100) if m.images_scanned else 0.0

    parts.append(f"""
<div class="cg-panels">
  <div class="cg-panel">
    <p class="cg-panel__lbl">Clean images</p>
    <p class="cg-panel__num cg-panel__num--brand num">{clean_count}</p>
    <p class="cg-panel__sub">{clean_pct:.0f}% of portfolio · of {m.images_scanned}</p>
  </div>
  <div class="cg-panel">
    <p class="cg-panel__lbl">Images with findings</p>
    <p class="cg-panel__num num">{m.images_with_findings}</p>
    <p class="cg-panel__sub">{affected_pct:.0f}% of portfolio · of {m.images_scanned}</p>
  </div>
  <div class="cg-panel">
    <p class="cg-panel__lbl">Findings</p>
    <p class="cg-panel__num num">{m.total_findings:,}</p>
    <p class="cg-panel__sub">{m.unique_vulns} unique · {m.amplification_factor:.2f}×</p>
  </div>
  <div class="cg-panel">
    <p class="cg-panel__lbl">Critical + high</p>
    <p class="cg-panel__num cg-panel__num--alert num">{m.critical_high_count:,}</p>
    <p class="cg-panel__sub">{m.critical_high_pct:.1%} of total · {ch_unique} unique</p>
  </div>
</div>""")

    # ─── Story ───────────────────────────────────────────────────────
    if m.headline_narrative or m.severity_callouts:
        rail_nav.append(("story", "Story"))
        parts.append('<section class="cg-s" id="story">')
        parts.append('<header class="cg-s__head"><h2>Where the risk concentrates</h2></header>')
        parts.append('<div class="cg-s__body">')
        if m.headline_narrative:
            parts.append(
                f'<div class="cg-story">{_inline_md_to_html(m.headline_narrative)}</div>'
            )
        if m.severity_callouts:
            parts.append('<div class="cg-story-callouts">')
            for callout in m.severity_callouts:
                # Extract a leading bold word as the tag if present.
                parts.append(
                    f'<article class="cg-story-callout">'
                    f'<div class="cg-story-callout__body">{_inline_md_to_html(callout)}</div>'
                    f'</article>'
                )
            parts.append('</div>')
        parts.append('</div></section>')

    # Short-circuit when there are no findings at all.
    if m.total_findings == 0:
        parts.append(
            '<section class="cg-s"><div class="cg-s__body">'
            '<p class="cg-note">No vulnerabilities in this report.</p>'
            '</div></section>'
        )
        return _html_shell(m, "\n".join(parts), rail_nav)

    # ─── Severity ────────────────────────────────────────────────────
    rail_nav.append(("severity", "Severity"))
    contrib_by_sev = {c.severity: c for c in m.severity_contributors}
    sev_rows = []
    for sev, unique, total in m.severity_matrix:
        amp = (total / unique) if unique else 0
        c = contrib_by_sev.get(sev)
        if c:
            if c.top_cve_share >= c.top_pkg_share:
                cve_url = _cve_search_url(c.top_cve_id, c.top_cve_cve_id, c.top_cve_data_source)
                link = (f'<a href="{esc(cve_url)}" translate="no">{esc(c.top_cve_id)}</a>'
                        if cve_url else f'<span translate="no">{esc(c.top_cve_id)}</span>')
                contrib = f'{link} <span class="cg-share">{c.top_cve_share:.0%}</span>'
            else:
                contrib = (f'<code translate="no">{esc(c.top_pkg)}</code> '
                           f'<span class="cg-share">{c.top_pkg_share:.0%}</span>')
        else:
            contrib = '<span class="cg-muted">—</span>'
        sev_rows.append(f"""
        <tr class="{sev_class(sev)}">
          <td><span class="cg-sev-dot {sev_class(sev)}" aria-hidden="true"></span>{esc(sev)}</td>
          <td class="num">{unique}</td>
          <td class="num">{total}</td>
          <td class="num">{amp:.1f}×</td>
          <td>{contrib}</td>
        </tr>""")

    parts.append(f"""
<section class="cg-s" id="severity">
  <header class="cg-s__head">
    <h2>Severity allocation</h2>
    <span class="cg-s__meta">{m.unique_vulns} unique · {m.total_findings:,} findings</span>
  </header>
  <div class="cg-s__body cg-s__body--flush">
    <table class="cg-t">
      <thead>
        <tr>
          <th>Severity</th>
          <th class="num">Unique CVEs</th>
          <th class="num">Findings</th>
          <th class="num">Amp.</th>
          <th>Top contributor</th>
        </tr>
      </thead>
      <tbody>{"".join(sev_rows)}
      </tbody>
    </table>
  </div>
</section>""")

    # ─── Package attribution ─────────────────────────────────────────
    rail_nav.append(("packages", "Packages"))
    pkg_rows = []
    for row in m.package_attribution[:15]:
        flag = ('<span class="cg-pill cg-pill--brand">Foundational</span>'
                if row.is_foundational else '')
        bar = severity_bar(row.severity_mix, row.instances)
        img_count = len(row.affected_images)
        if img_count > 0:
            img_items = "".join(
                f'<li><a href="{esc(_image_directory_url(i))}" translate="no">{esc(i)}</a></li>'
                for i in row.affected_images[:25]
            )
            more = ("" if img_count <= 25
                    else f'<li class="cg-img-list__more">…and {img_count - 25} more</li>')
            images_cell = (
                f'<details class="cg-details"><summary class="num">{img_count}</summary>'
                f'<ul class="cg-img-list">{img_items}{more}</ul></details>'
            )
        else:
            images_cell = '<span class="num cg-muted">0</span>'
        pkg_rows.append(f"""
        <tr>
          <td><code translate="no">{esc(row.name)}</code></td>
          <td>{flag}</td>
          <td class="num">{row.unique_cves}</td>
          <td class="num">{row.instances}</td>
          <td>{images_cell}</td>
          <td class="cg-bar-cell">{bar}</td>
        </tr>""")

    parts.append(f"""
<section class="cg-s" id="packages">
  <header class="cg-s__head">
    <h2>Package attribution</h2>
    <span class="cg-s__meta">Top {min(15, len(m.package_attribution))} by finding volume</span>
  </header>
  <div class="cg-s__body cg-s__body--flush">
    <table class="cg-t">
      <thead>
        <tr>
          <th>Package</th>
          <th></th>
          <th class="num">Unique CVEs</th>
          <th class="num">Findings</th>
          <th class="num">Images</th>
          <th>Severity mix</th>
        </tr>
      </thead>
      <tbody>{"".join(pkg_rows)}
      </tbody>
    </table>
  </div>
</section>""")

    # ─── Top noisy CVEs ──────────────────────────────────────────────
    rail_nav.append(("cves", "CVEs"))
    cve_rows = []
    for row in m.top_noisy_cves:
        cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
        link = (f'<a href="{esc(cve_url)}" translate="no">{esc(row.vulnerability_id)}</a>'
                if cve_url else f'<span translate="no">{esc(row.vulnerability_id)}</span>')
        cve_rows.append(f"""
        <tr class="{sev_class(row.severity)}">
          <td>{link}</td>
          <td><span class="cg-sev-tag {sev_class(row.severity)}">{esc(row.severity)}</span></td>
          <td><code translate="no">{esc(row.package)}</code></td>
          <td class="num">{row.instances}</td>
          <td>{fix_pill(row.fix_available)}</td>
          <td><span translate="no" class="mono">{esc(row.cga_id or "")}</span></td>
        </tr>""")

    parts.append(f"""
<section class="cg-s" id="cves">
  <header class="cg-s__head">
    <h2>Top noisy CVEs</h2>
    <span class="cg-s__meta">Top {len(m.top_noisy_cves)} by impact</span>
  </header>
  <div class="cg-s__body cg-s__body--flush">
    <table class="cg-t">
      <thead>
        <tr>
          <th>CVE</th>
          <th>Severity</th>
          <th>Package</th>
          <th class="num">Impacts</th>
          <th>Fix</th>
          <th>CGA</th>
        </tr>
      </thead>
      <tbody>{"".join(cve_rows)}
      </tbody>
    </table>
  </div>
</section>""")

    # ─── Image hotspots ──────────────────────────────────────────────
    # Collapse rows where the same image appears with multiple tags AND the
    # same `total` — distinct grype scans of latest / latest-dev that produced
    # identical finding counts almost always reflect the same digest, so
    # showing them as separate rows is noise. Preserve original ordering and
    # merge tags into a comma-joined display string.
    rail_nav.append(("images", "Images"))
    collapsed: list[tuple[ImageRow, list[str]]] = []
    seen: dict[tuple[str, int], int] = {}
    for row in m.image_hotspots:
        key = (row.image, row.total)
        if key in seen:
            collapsed[seen[key]][1].append(row.tag)
        else:
            seen[key] = len(collapsed)
            collapsed.append((row, [row.tag]))

    img_rows = []
    for row, tags in collapsed:
        bar = severity_bar(row.by_severity, row.total)
        tag_display = ", ".join(tags)
        img_rows.append(f"""
        <tr>
          <td><a href="{esc(_image_directory_url(row.image))}" translate="no"><code>{esc(row.image)}</code></a></td>
          <td><span translate="no" class="mono">{esc(tag_display)}</span></td>
          <td class="num">{row.total}</td>
          <td class="cg-bar-cell">{bar}</td>
        </tr>""")

    parts.append(f"""
<section class="cg-s" id="images">
  <header class="cg-s__head">
    <h2>Image hotspots</h2>
    <span class="cg-s__meta">Top {len(collapsed)} by total findings</span>
  </header>
  <div class="cg-s__body cg-s__body--flush">
    <table class="cg-t">
      <thead>
        <tr>
          <th>Image</th>
          <th>Tag</th>
          <th class="num">Total</th>
          <th>Severity mix</th>
        </tr>
      </thead>
      <tbody>{"".join(img_rows)}
      </tbody>
    </table>
  </div>
</section>""")

    # ─── Unfixable Critical/High (conditional) ───────────────────────
    if m.unfixable_critical_high:
        rail_nav.append(("unfixable", "Unfixable"))
        unfix_rows = []
        for row in m.unfixable_critical_high:
            cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
            link = (f'<a href="{esc(cve_url)}" translate="no">{esc(row.vulnerability_id)}</a>'
                    if cve_url else f'<span translate="no">{esc(row.vulnerability_id)}</span>')
            unfix_rows.append(f"""
            <tr class="{sev_class(row.severity)}">
              <td>{link}</td>
              <td><span class="cg-sev-tag {sev_class(row.severity)}">{esc(row.severity)}</span></td>
              <td><code translate="no">{esc(row.package)}</code></td>
              <td class="num">{row.instances}</td>
              <td><span translate="no" class="mono">{esc(row.cga_id or "")}</span></td>
            </tr>""")
        parts.append(f"""
<section class="cg-s cg-s--alert" id="unfixable">
  <header class="cg-s__head">
    <h2>Critical &amp; high — no fix yet</h2>
    <span class="cg-s__meta">Awaiting upstream</span>
  </header>
  <div class="cg-s__body cg-s__body--flush">
    <table class="cg-t">
      <thead>
        <tr>
          <th>CVE</th>
          <th>Severity</th>
          <th>Package</th>
          <th class="num">Impacts</th>
          <th>CGA</th>
        </tr>
      </thead>
      <tbody>{"".join(unfix_rows)}
      </tbody>
    </table>
  </div>
</section>""")

    # ─── Event clusters ──────────────────────────────────────────────
    rail_nav.append(("clusters", "Clusters"))
    cluster_meta_bits = []
    if m.clusters:
        researched = sum(1 for c in m.clusters if c.narrative)
        cluster_meta_bits.append(f"{len(m.clusters)} detected")
        if researched:
            cluster_meta_bits.append(f"{researched} with sources")
    cluster_meta = " · ".join(cluster_meta_bits) if cluster_meta_bits else ""

    parts.append(
        f'<section class="cg-s" id="clusters">'
        f'<header class="cg-s__head"><h2>Disclosure clusters</h2>'
        f'<span class="cg-s__meta">{esc(cluster_meta)}</span></header>'
        f'<div class="cg-s__body">'
    )
    if not m.nvd_enriched:
        parts.append(
            '<p class="cg-note">NVD enrichment skipped — event clustering disabled. '
            'Set <code>NVD_API_KEY</code> and re-run without <code>--no-enrich</code>.</p>'
        )
    elif not m.clusters:
        parts.append('<p class="cg-note">No clusters detected.</p>')
    else:
        any_research = any(c.narrative or c.narrative_bullets for c in m.clusters)
        if not any_research:
            parts.append(
                '<p class="cg-note">Web-research skipped — clusters show static fallback links. '
                'Set <code>ANTHROPIC_API_KEY</code> and re-run without <code>--no-research</code> '
                'for a synthesized narrative of the underlying disclosure event with cited sources.</p>'
            )
        for cluster in m.clusters:
            parts.append('<article class="cg-cluster">')
            parts.append(f'<p class="cg-cluster__tag">{esc(cluster.kind)}</p>')
            parts.append(f'<h4>{esc(cluster.label)}</h4>')
            if cluster.narrative_bullets:
                parts.append('<ul class="cg-cluster__bullets">')
                for bullet in cluster.narrative_bullets:
                    parts.append(_render_bullet_html(bullet, esc))
                parts.append('</ul>')
            elif cluster.narrative:
                parts.append(
                    f'<p class="cg-cluster__narrative">{esc(cluster.narrative)}</p>'
                )
            if cluster.narrative_bullets or cluster.narrative:
                if cluster.cited_sources:
                    parts.append('<div class="cg-cluster__sources">')
                    parts.append('<p class="cg-cluster__sources-label">Sources</p>')
                    parts.append('<ul>')
                    for label, url in cluster.cited_sources:
                        parts.append(f'<li><a href="{esc(url)}">{esc(label)}</a></li>')
                    parts.append('</ul></div>')
            else:
                parts.append('<div class="cg-cluster__sources">')
                parts.append('<p class="cg-cluster__sources-label">Investigate</p>')
                parts.append('<ul>')
                for label, url in cluster.investigation_links:
                    parts.append(f'<li><a href="{esc(url)}">{esc(label)}</a></li>')
                parts.append('</ul></div>')
            parts.append('<details class="cg-details cg-cluster__members">')
            parts.append(
                f'<summary><span class="cg-mini-eyebrow">'
                f'{len(cluster.members)} CVEs in this cluster</span></summary>'
            )
            parts.append('<ul class="cg-cluster__list">')
            sorted_members = sorted(
                cluster.members,
                key=lambda r: (_severity_rank(r.severity), -r.instances, r.vulnerability_id),
            )
            for row in sorted_members:
                cve_url = _cve_search_url(row.vulnerability_id, row.cve_id, row.data_source)
                link = (f'<a href="{esc(cve_url)}" translate="no">{esc(row.vulnerability_id)}</a>'
                        if cve_url else f'<span translate="no">{esc(row.vulnerability_id)}</span>')
                parts.append(
                    f'<li>'
                    f'<span class="cl-cve">{link}</span>'
                    f'<span class="cl-sev"><span class="cg-sev-tag {sev_class(row.severity)}">{esc(row.severity)}</span></span>'
                    f'<code class="cl-pkg" translate="no">{esc(row.package)}</code>'
                    f'<span class="cl-impacts cg-muted">{row.instances} impacts</span>'
                    f'</li>'
                )
            parts.append('</ul></details>')
            parts.append('</article>')
    parts.append('</div></section>')

    return _html_shell(m, "\n".join(parts), rail_nav)


def _icon_check() -> str:
    # Pixel-art check, currentColor — matches the Chainguard icon aesthetic.
    return ('<svg class="cg-icon" width="14" height="14" viewBox="0 0 14 14" '
            'fill="currentColor" aria-hidden="true">'
            '<rect x="1" y="6" width="2" height="2"/>'
            '<rect x="3" y="8" width="2" height="2"/>'
            '<rect x="5" y="10" width="2" height="2"/>'
            '<rect x="7" y="8" width="2" height="2"/>'
            '<rect x="9" y="6" width="2" height="2"/>'
            '<rect x="11" y="4" width="2" height="2"/>'
            '</svg>')


def _icon_close() -> str:
    return ('<svg class="cg-icon" width="14" height="14" viewBox="0 0 14 14" '
            'fill="currentColor" aria-hidden="true">'
            '<rect x="1" y="1" width="2" height="2"/>'
            '<rect x="3" y="3" width="2" height="2"/>'
            '<rect x="5" y="5" width="2" height="2"/>'
            '<rect x="7" y="3" width="2" height="2"/>'
            '<rect x="9" y="1" width="2" height="2"/>'
            '<rect x="7" y="7" width="2" height="2"/>'
            '<rect x="9" y="9" width="2" height="2"/>'
            '<rect x="11" y="11" width="2" height="2"/>'
            '<rect x="5" y="9" width="2" height="2"/>'
            '<rect x="3" y="11" width="2" height="2"/>'
            '<rect x="1" y="11" width="2" height="2"/>'
            '<rect x="11" y="1" width="2" height="2"/>'
            '</svg>')


def _chainguard_lockup(class_name: str = "cg-lockup") -> str:
    # Official blurple-lockup.svg (mark + wordmark) from the Chainguard brand
    # library. Inlined so the dashboard stays a single-file artifact.
    return (
        f'<svg class="{class_name}" xmlns="http://www.w3.org/2000/svg" '
        'viewBox="0 0 325 52" fill="none" role="img" aria-label="Chainguard">'
        '<path fill-rule="evenodd" clip-rule="evenodd" '
        'd="M44.3536 28.1295C44.7787 26.6593 45.0097 25.0483 45.0097 23.296C45.0097 12.3361 35.9696 0 26.9406 0C17.9116 0 8.87132 12.3361 8.87132 23.296C8.87132 25.6856 9.30108 27.8126 10.0668 29.6777L4.63944 29.3718C2.4289 29.2472 0.392341 30.8273 0.737115 33.0198C0.870839 33.8702 1.12568 34.7407 1.58082 35.4924C0.0443608 36.576 -0.583269 38.568 0.661683 40.1291C1.91145 41.6961 3.74644 43.14 6.26526 43.14C8.99725 43.14 10.6414 42.4322 11.64 41.5432C11.7129 41.9315 11.8632 42.3137 12.1005 42.675C13.3267 44.5414 15.3575 46.5929 18.3598 46.5929C23.4671 46.5929 24.0367 43.3769 24.3226 41.7632C24.3449 41.6369 24.3655 41.5203 24.3864 41.416L27.7995 39.7048L31.2125 41.416C31.2335 41.5203 31.2541 41.6366 31.2763 41.7629C31.5623 43.3766 32.1318 46.5929 37.2392 46.5929C40.2413 46.5929 42.2723 44.5414 43.4985 42.675C43.5466 42.6017 43.5913 42.5274 43.6322 42.4522C44.5946 42.8693 45.8683 43.14 47.5579 43.14C50.0768 43.14 51.9118 41.6961 53.1617 40.1291C54.6923 38.2095 53.3921 35.6391 51.0523 34.9061L50.2794 34.6639C52.5494 33.4842 52.8836 31.2597 52.6404 29.3102C52.3657 27.1076 49.9721 26.1554 47.8827 26.8895L44.3536 28.1295ZM27.8027 39.6731H27.7966L27.7995 39.6747L27.8027 39.6731Z" fill="currentColor"/>'
        '<path d="M85.3181 41.7438C74.9494 41.7438 68.3194 34.997 68.3194 23.1027C68.3194 11.8581 75.7967 4.96146 85.6669 4.96146C94.1912 4.96146 100.323 9.85909 101.22 18.1551H94.4403C93.7924 13.6073 90.8015 10.5088 85.6669 10.5088C79.4858 10.5088 75.0491 15.2565 75.0491 23.1027C75.0491 31.2487 79.4358 36.1965 85.5175 36.1965C90.7018 36.1965 94.1412 32.8481 94.8391 28.2003H101.369C100.522 36.2965 94.6897 41.7438 85.3181 41.7438ZM106.123 40.8441V5.86102H112.204V17.5554C112.204 18.255 112.154 19.0047 112.005 19.9542C113.351 17.5054 115.644 15.6563 119.482 15.6563C124.866 15.6563 128.056 19.4545 128.056 25.4516V40.8441H121.975V26.3511C121.975 22.7529 120.23 20.504 117.388 20.504C114.398 20.504 112.204 23.1527 112.204 26.551V40.8441H106.123ZM141.144 41.7438C136.907 41.7438 132.769 38.9449 132.769 34.1475C132.769 28.65 137.006 26.7509 142.241 26.0513L145.73 25.6015C147.724 25.3516 148.422 24.602 148.422 23.4026C148.422 21.7034 147.026 20.2041 144.434 20.2041C141.592 20.2041 139.798 21.8033 139.549 24.3521H133.268C133.667 19.2546 137.804 15.6563 144.085 15.6563C151.512 15.6563 154.503 19.6544 154.503 26.5011V40.8441H148.871V39.8445C148.871 39.0449 148.97 38.2953 149.12 37.4957C147.824 39.8947 145.331 41.7438 141.144 41.7438ZM142.789 37.2459C146.029 37.2459 148.621 34.8469 148.621 31.3988V28.75C148.073 29.2497 147.225 29.4996 145.73 29.7995L143.736 30.1993C140.895 30.7489 138.95 31.6987 138.95 33.8975C138.95 36.0464 140.645 37.2459 142.789 37.2459ZM160.45 40.8441V16.4559H166.532V40.8441H160.45ZM160.301 12.7577V6.36079H166.632V12.7577H160.301ZM172.815 40.8441V16.4559H178.897V17.5554C178.897 18.255 178.847 19.0047 178.697 19.9542C180.043 17.5054 182.336 15.6563 186.175 15.6563C191.559 15.6563 194.749 19.4545 194.749 25.4516V40.8441H188.667V26.3511C188.667 22.7529 186.922 20.504 184.081 20.504C181.09 20.504 178.897 23.1527 178.897 26.551V40.8441H172.815ZM211.625 51.9386C204.447 51.9386 200.359 48.0907 200.359 42.5434H206.541C206.64 45.4419 208.485 47.1412 211.775 47.1412C214.965 47.1412 217.657 45.242 217.657 41.5937V38.9449C217.657 37.8457 217.707 36.8461 217.856 35.8966C216.41 38.0954 214.067 39.9445 210.279 39.9445C203.948 39.9445 199.362 35.4968 199.362 27.8004C199.362 20.2041 204.646 15.6563 209.98 15.6563C214.267 15.6563 216.41 17.4055 217.856 19.9542C217.707 19.1046 217.657 18.455 217.657 17.5554V16.4559H223.738V40.0946C223.738 48.0907 218.803 51.9386 211.625 51.9386ZM211.824 35.097C215.413 35.097 218.006 32.0484 218.006 27.8004C218.006 23.5525 215.413 20.504 211.824 20.504C208.135 20.504 205.543 23.5525 205.543 27.8004C205.543 32.0484 208.135 35.097 211.824 35.097ZM238.441 41.7438C233.555 41.7438 229.717 38.3953 229.717 31.9484V16.4559H235.849V30.999C235.849 34.3973 237.344 36.8461 240.285 36.8461C243.376 36.8461 245.569 34.547 245.569 30.9488V16.4559H251.651V40.8441H245.619V39.8445C245.619 39.095 245.719 38.2455 245.868 37.4957C244.622 39.8445 242.478 41.7438 238.441 41.7438ZM264.987 41.7438C260.75 41.7438 256.613 38.9449 256.613 34.1475C256.613 28.65 260.85 26.7509 266.084 26.0513L269.574 25.6015C271.568 25.3516 272.266 24.602 272.266 23.4026C272.266 21.7034 270.87 20.2041 268.278 20.2041C265.436 20.2041 263.642 21.8033 263.392 24.3521H257.111C257.51 19.2546 261.648 15.6563 267.929 15.6563C275.356 15.6563 278.347 19.6544 278.347 26.5011V40.8441H272.714V39.8445C272.714 39.0449 272.814 38.2953 272.964 37.4957C271.667 39.8947 269.175 41.7438 264.987 41.7438ZM266.633 37.2459C269.873 37.2459 272.465 34.8469 272.465 31.3988V28.75C271.917 29.2497 271.069 29.4996 269.574 29.7995L267.58 30.1993C264.738 30.7489 262.794 31.6987 262.794 33.8975C262.794 36.0464 264.489 37.2459 266.633 37.2459ZM284.294 40.8441V16.4559H290.376V18.305C290.376 19.2046 290.326 19.9542 290.176 20.8538C291.472 18.1051 293.666 15.6563 297.304 15.6563C297.803 15.6563 298.202 15.7063 298.601 15.8062V21.7034C298.202 21.6034 297.654 21.5035 296.856 21.5035C293.117 21.5035 290.376 23.4026 290.376 28.75V40.8441H284.294ZM311.491 41.7438C305.061 41.7438 300.375 37.3459 300.375 28.75C300.375 20.0042 305.908 15.6563 311.591 15.6563C315.38 15.6563 317.721 17.6054 319.118 19.9542C318.918 19.0546 318.918 18.305 318.918 17.5554V5.86102H325V40.8441H318.918V39.8445C318.918 38.995 318.918 38.3455 319.118 37.4957C318.171 39.2949 315.977 41.7438 311.491 41.7438ZM312.935 36.9461C316.577 36.9461 319.268 33.5976 319.268 28.7C319.268 23.7024 316.577 20.504 312.935 20.504C309.298 20.504 306.556 23.8524 306.556 28.7C306.556 33.7477 309.298 36.9461 312.935 36.9461Z" fill="currentColor"/>'
        '</svg>'
    )


def _html_shell(m: Metrics, body: str, rail_nav: list[tuple[str, str]]) -> str:
    # Rail navigation: anchor links (numbered) + status block + build block.
    nav_items = []
    for i, (anchor, label) in enumerate(rail_nav, start=1):
        nav_items.append(
            f'<li><a href="#{anchor}">'
            f'<span class="cg-rail__anum">{i:02d}</span>{html.escape(label)}'
            f'</a></li>'
        )
    nav_html = "\n      ".join(nav_items)

    org = html.escape(str(m.meta.get("organization") or ""))
    generated = html.escape(str(m.meta.get("generated-at") or "—"))
    clean_count = max(0, m.images_scanned - m.images_with_findings)
    research_state = "—"
    if m.clusters:
        researched = sum(1 for c in m.clusters if c.narrative)
        research_state = f"{researched} / {len(m.clusters)}"
    enrich_state = f"{m.nvd_record_count} CVEs" if m.nvd_enriched else "skipped"

    topbar_org = (f'<strong translate="no">{org}</strong> · ' if org else '')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ILS Vulnerability Operations — Chainguard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Roboto+Mono:wght@400;500;700&display=swap">
<style>
{_cg_styles()}
</style>
</head>
<body class="cg">
<a class="cg-skip" href="#cg-main">Skip to content</a>
<header class="cg-topstrip">
  <a class="cg-topstrip__brand" href="https://www.chainguard.dev" translate="no" aria-label="Chainguard">
    {_chainguard_lockup('cg-topstrip__lockup')}
  </a>
  <p class="cg-topstrip__title">ILS Vulnerability Operations · {topbar_org}<span>Container portfolio briefing</span></p>
  <p class="cg-topstrip__time">Generated <strong>{generated}</strong></p>
</header>
<div class="cg-shell">
  <aside class="cg-rail" aria-label="Section navigation">
    <h3>Navigation</h3>
    <ul>
      {nav_html}
    </ul>

    <h3>Scan</h3>
    <div class="cg-rail__status">
      <span>SCANNED</span> {m.images_scanned} images<br>
      <span>WITH FINDINGS</span> {m.images_with_findings}<br>
      <span>CLEAN</span> {clean_count}<br>
      <span>TAGS</span> {m.tag_count}<br>
      <span>ENRICHED</span> {enrich_state}<br>
      <span>RESEARCH</span> {research_state}
    </div>

    <h3>References</h3>
    <ul class="cg-rail__refs">
      <li><a href="https://images.chainguard.dev/security" translate="no">CG advisories</a></li>
      <li><a href="https://images.chainguard.dev/directory" translate="no">Image directory</a></li>
      <li><a href="https://nvd.nist.gov/developers/vulnerabilities">NVD API</a></li>
      <li><a href="https://osv.dev/">OSV.dev</a></li>
      <li><a href="https://www.first.org/epss/">EPSS</a></li>
      <li><a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a></li>
    </ul>
  </aside>
  <main id="cg-main" class="cg-main">
{body}
    <footer class="cg-foot">
      Generated by <code translate="no">analyze.py</code> · <span translate="no">© Chainguard, Inc.</span>
    </footer>
  </main>
</div>
</body>
</html>
"""


def _cg_styles() -> str:
    return """
:root {
  --cg-white: #FFFFFF;
  --cg-ink: #1a1f24;
  --cg-ink-soft: #4A5359;
  --cg-ink-faint: #9EA2A4;
  --cg-bg: #ffffff;
  --cg-bg-soft: #F8F9F9;
  --cg-bg-panel: #F3F3F4;
  --cg-rule: #E7E8E8;
  --cg-rule-strong: #1a1f24;

  --cg-blurple:     #5A1FFF;
  --cg-blurple-100: #F1ECFE;
  --cg-blurple-900: #14003D;
  --cg-blurple-700: #4316D6;
  --cg-blurple-50:  #F8F6FE;

  --cg-solar:     #FD3964;
  --cg-solar-100: #FCE0E0;
  --cg-solar-800: #D40555;

  --cg-lime:     #44FD2B;
  --cg-lime-100: #E9FCEA;
  --cg-lime-800: #108000;

  --cg-sev-critical: var(--cg-solar-800);
  --cg-sev-high:     var(--cg-solar);
  --cg-sev-medium:   var(--cg-ink-soft);
  --cg-sev-low:      var(--cg-lime-800);
  --cg-sev-negligible: var(--cg-ink-faint);
  --cg-sev-unknown:    var(--cg-rule);

  --cg-font-display: 'Poppins', system-ui, sans-serif;
  --cg-font-body:    'Poppins', system-ui, sans-serif;
  --cg-font-mono:    'Roboto Mono', ui-monospace, Menlo, monospace;
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }

body.cg {
  margin: 0;
  font-family: var(--cg-font-body);
  font-weight: 400;
  font-size: 14px;
  line-height: 1.55;
  color: var(--cg-ink);
  background: var(--cg-bg-soft);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
}

.cg-skip {
  position: absolute;
  left: -9999px;
  top: 0;
  background: var(--cg-blurple);
  color: white;
  padding: 12px 16px;
  font-weight: 500;
  z-index: 100;
}
.cg-skip:focus { left: 16px; top: 16px; outline: 2px solid white; outline-offset: 2px; }

a {
  color: var(--cg-blurple);
  text-decoration-thickness: 1px;
  text-underline-offset: 0.18em;
}
a:hover { color: var(--cg-blurple-700); }
a:focus-visible {
  outline: 2px solid var(--cg-blurple);
  outline-offset: 2px;
  border-radius: 0;
}

code, .mono {
  font-family: var(--cg-font-mono);
  font-size: 0.88em;
}
code {
  background: var(--cg-rule);
  padding: 1px 5px;
}
.num { font-variant-numeric: tabular-nums; }
.cg-muted { color: var(--cg-ink-soft); }

/* ── Top strip ─────────────────────────────────────────────────── */
.cg-topstrip {
  background: var(--cg-white);
  border-bottom: 1px solid var(--cg-rule);
  padding: 14px 24px;
  display: grid;
  grid-template-columns: auto 1fr auto;
  gap: 24px;
  align-items: center;
  overflow: visible;
}
.cg-topstrip__brand {
  display: inline-flex;
  align-items: center;
  text-decoration: none;
  color: var(--cg-blurple);
}
.cg-topstrip__brand:hover { color: var(--cg-blurple-700); }
.cg-topstrip__lockup {
  display: block;
  height: 22px;
  width: auto;
  min-width: 138px;
  color: currentColor;
  overflow: visible;
}
.cg-topstrip__title {
  font-family: var(--cg-font-mono);
  font-size: 11px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--cg-ink-soft);
  margin: 0;
  font-weight: 500;
}
.cg-topstrip__title strong { color: var(--cg-ink); font-weight: 500; }
.cg-topstrip__title span { color: var(--cg-ink-faint); }
.cg-topstrip__time {
  font-family: var(--cg-font-mono);
  font-size: 10.5px;
  color: var(--cg-ink-faint);
  letter-spacing: 0.08em;
  text-align: right;
  margin: 0;
  font-weight: 500;
}
.cg-topstrip__time strong { color: var(--cg-ink); font-weight: 500; }
@media (max-width: 720px) { .cg-topstrip__title { display: none; } }

/* ── Shell + rail ──────────────────────────────────────────────── */
.cg-shell {
  display: grid;
  grid-template-columns: 220px 1fr;
  gap: 0;
}
@media (max-width: 960px) { .cg-shell { grid-template-columns: 1fr; } }

.cg-rail {
  position: sticky;
  top: 0;
  align-self: start;
  border-right: 1px solid var(--cg-rule);
  background: var(--cg-white);
  padding: 24px 20px;
  height: 100vh;
  overflow-y: auto;
  font-family: var(--cg-font-mono);
  font-size: 12px;
}
@media (max-width: 960px) {
  .cg-rail {
    position: static;
    height: auto;
    border-right: none;
    border-bottom: 1px solid var(--cg-rule);
  }
}

.cg-rail h3 {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--cg-ink-faint);
  font-weight: 500;
  margin: 22px 0 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--cg-rule);
}
.cg-rail h3:first-of-type { margin-top: 0; }
.cg-rail ul { list-style: none; padding: 0; margin: 0; }
.cg-rail li { padding: 0; }
.cg-rail a {
  display: grid;
  grid-template-columns: 32px 1fr;
  gap: 6px;
  padding: 4px 0;
  color: var(--cg-ink);
  text-decoration: none;
  font-weight: 400;
}
.cg-rail a:hover { color: var(--cg-blurple); }
.cg-rail__anum {
  color: var(--cg-ink-faint);
  font-weight: 500;
}
.cg-rail a:hover .cg-rail__anum { color: var(--cg-blurple); }
.cg-rail__status {
  font-size: 11px;
  line-height: 1.85;
  color: var(--cg-ink);
}
.cg-rail__status span {
  color: var(--cg-ink-faint);
  display: inline-block;
  min-width: 92px;
}
.cg-rail__refs li a {
  display: block;
  grid-template-columns: none;
  padding: 3px 0;
  font-size: 11.5px;
  color: var(--cg-ink-soft);
}
.cg-rail__refs li a:hover { color: var(--cg-blurple); }

/* ── Main column ───────────────────────────────────────────────── */
.cg-main {
  padding: 32px 40px 64px;
  max-width: 1200px;
  width: 100%;
}
@media (max-width: 720px) { .cg-main { padding: 24px 16px 56px; } }

/* Hero block */
.cg-hero {
  padding: 0 0 24px;
  border-bottom: 1px solid var(--cg-rule);
  scroll-margin-top: 12px;
}
.cg-eyebrow {
  font-family: var(--cg-font-mono);
  font-weight: 500;
  font-size: 10.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--cg-blurple);
  margin: 0 0 8px;
}
.cg-hero h1 {
  font-family: var(--cg-font-display);
  font-weight: 600;
  font-size: clamp(1.5rem, 1.1rem + 1.2vw, 2rem);
  letter-spacing: -0.015em;
  line-height: 1.15;
  margin: 0 0 8px;
  color: var(--cg-ink);
  text-wrap: balance;
}
.cg-hero__meta {
  font-family: var(--cg-font-mono);
  font-size: 11px;
  color: var(--cg-ink-soft);
  letter-spacing: 0.06em;
  margin: 0;
}

/* KPI panel grid */
.cg-panels {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1px;
  background: var(--cg-rule);
  margin: 24px 0 0;
  border: 1px solid var(--cg-rule);
}
@media (max-width: 1024px) { .cg-panels { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 560px)  { .cg-panels { grid-template-columns: 1fr; } }
.cg-panel {
  background: var(--cg-white);
  padding: 16px 18px;
}
.cg-panel__lbl {
  font-family: var(--cg-font-mono);
  font-size: 9.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--cg-ink-faint);
  margin: 0 0 8px;
  font-weight: 500;
}
.cg-panel__num {
  font-family: var(--cg-font-display);
  font-weight: 600;
  font-size: 26px;
  letter-spacing: -0.015em;
  font-variant-numeric: tabular-nums;
  color: var(--cg-ink);
  margin: 0;
  line-height: 1;
}
.cg-panel__num--alert    { color: var(--cg-solar-800); }
.cg-panel__num--positive { color: var(--cg-lime-800); }
.cg-panel__num--brand    { color: var(--cg-blurple); }
.cg-panel__sub {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  color: var(--cg-ink-faint);
  margin: 6px 0 0;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
}

/* ── Section card ──────────────────────────────────────────────── */
.cg-s {
  margin: 32px 0 0;
  background: var(--cg-white);
  border: 1px solid var(--cg-rule);
  scroll-margin-top: 12px;
}
.cg-s--alert { border-color: var(--cg-solar-800); }
.cg-s--alert .cg-s__head { background: var(--cg-solar-100); }
.cg-s--alert .cg-s__head h2 { color: var(--cg-solar-800); }

.cg-s__head {
  padding: 12px 20px;
  background: var(--cg-white);
  border-bottom: 1px solid var(--cg-rule);
  display: grid;
  grid-template-columns: 1fr auto;
  align-items: center;
  gap: 16px;
}
.cg-s__head h2 {
  font-family: var(--cg-font-mono);
  font-size: 11px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  font-weight: 500;
  color: var(--cg-ink);
  margin: 0;
}
.cg-s__meta {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  color: var(--cg-ink-faint);
  letter-spacing: 0.08em;
}
.cg-s__body { padding: 20px; }
.cg-s__body--flush { padding: 0; }

/* Story prose + callouts */
.cg-story {
  font-size: 14.5px;
  line-height: 1.65;
  max-width: 84ch;
  color: var(--cg-ink);
}
.cg-story strong { color: var(--cg-blurple-900); }
.cg-story p + p { margin-top: 12px; }
.cg-story p { margin: 0; }

.cg-story-callouts {
  margin: 20px 0 0;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
@media (max-width: 720px) { .cg-story-callouts { grid-template-columns: 1fr; } }
.cg-story-callout {
  padding: 14px 16px;
  background: var(--cg-bg-panel);
  border-left: 3px solid var(--cg-blurple);
}
.cg-story-callout__body { font-size: 13px; line-height: 1.55; }
.cg-story-callout__body strong { color: var(--cg-ink); }
.cg-story-callout__body p { margin: 0; }

/* ── Tables ───────────────────────────────────────────────────── */
.cg-t {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
.cg-t thead th {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--cg-ink-faint);
  font-weight: 500;
  text-align: left;
  padding: 8px 14px;
  border-bottom: 1px solid var(--cg-rule);
  background: var(--cg-bg-soft);
}
.cg-t thead th.num { text-align: right; }
.cg-t tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--cg-rule);
  vertical-align: middle;
}
.cg-t tbody td.num { text-align: right; font-variant-numeric: tabular-nums; }
.cg-t tbody tr:hover { background: var(--cg-bg-soft); }
.cg-t tbody tr:last-child td { border-bottom: none; }
.cg-bar-cell { min-width: 160px; }
.cg-share {
  font-family: var(--cg-font-mono);
  font-size: 10.5px;
  color: var(--cg-ink-faint);
  letter-spacing: 0.04em;
  margin-left: 4px;
}

/* Severity dot */
.cg-sev-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 10px;
  vertical-align: middle;
  background: var(--cg-sev-unknown);
}
.cg-sev-dot.sev-critical { background: var(--cg-sev-critical); }
.cg-sev-dot.sev-high     { background: var(--cg-sev-high); }
.cg-sev-dot.sev-medium   { background: var(--cg-sev-medium); }
.cg-sev-dot.sev-low      { background: var(--cg-sev-low); }
.cg-sev-dot.sev-negligible { background: var(--cg-sev-negligible); }
.cg-sev-dot.sev-unknown    { background: var(--cg-sev-unknown); }

/* Severity tag pill (mono uppercase) */
.cg-sev-tag {
  display: inline-block;
  font-family: var(--cg-font-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 2px 7px;
  background: var(--cg-bg-panel);
  color: var(--cg-ink-soft);
  white-space: nowrap;
}
.cg-sev-tag.sev-critical, .cg-sev-tag.sev-high { background: var(--cg-solar-100); color: var(--cg-solar-800); }
.cg-sev-tag.sev-medium { background: var(--cg-bg-panel); color: var(--cg-ink-soft); }
.cg-sev-tag.sev-low { background: var(--cg-lime-100); color: var(--cg-lime-800); }

/* Generic pill (fix/nofix/brand) */
.cg-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: var(--cg-font-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 2px 7px;
  white-space: nowrap;
}
.cg-pill--positive { background: var(--cg-lime-100); color: var(--cg-lime-800); }
.cg-pill--negative { background: var(--cg-solar-100); color: var(--cg-solar-800); }
.cg-pill--brand    { background: var(--cg-blurple-100); color: var(--cg-blurple-900); }
.cg-icon { display: inline-block; vertical-align: -2px; }

/* Severity stacked bar */
.cg-bar {
  display: inline-flex;
  width: 100%;
  min-width: 140px;
  height: 8px;
  background: var(--cg-bg-panel);
  overflow: hidden;
}
.cg-bar__seg { display: block; height: 100%; }
.cg-bar__seg.sev-critical { background: var(--cg-sev-critical); }
.cg-bar__seg.sev-high     { background: var(--cg-sev-high); }
.cg-bar__seg.sev-medium   { background: var(--cg-sev-medium); }
.cg-bar__seg.sev-low      { background: var(--cg-sev-low); }
.cg-bar__seg.sev-negligible { background: var(--cg-sev-negligible); }
.cg-bar__seg.sev-unknown    { background: var(--cg-sev-unknown); }

/* Details / expandable image list */
.cg-details { cursor: pointer; }
.cg-details > summary {
  list-style: none;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--cg-blurple);
  font-weight: 500;
}
.cg-details > summary::-webkit-details-marker { display: none; }
.cg-details > summary::after {
  content: "+";
  font-family: var(--cg-font-mono);
  font-size: 0.85em;
  color: var(--cg-blurple);
}
.cg-details[open] > summary::after { content: "−"; }
.cg-details > summary:focus-visible {
  outline: 2px solid var(--cg-blurple);
  outline-offset: 2px;
}
.cg-img-list {
  list-style: none;
  margin: 12px 0 0;
  padding: 0;
  font-family: var(--cg-font-mono);
  font-size: 12px;
  line-height: 1.6;
  max-width: 720px;
}
.cg-img-list > li { padding: 2px 0; }
.cg-img-list > li::before {
  content: "→ ";
  color: var(--cg-blurple);
  font-weight: 700;
}
.cg-img-list a { color: var(--cg-ink); text-decoration: none; }
.cg-img-list a:hover { color: var(--cg-blurple); }
.cg-img-list__more {
  font-family: var(--cg-font-body);
  color: var(--cg-ink-soft);
  font-style: italic;
}
.cg-img-list__more::before { content: ""; }

/* Mini eyebrow (used in cluster member toggle) */
.cg-mini-eyebrow {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--cg-ink-soft);
  font-weight: 500;
}

/* ── Clusters ─────────────────────────────────────────────────── */
.cg-cluster {
  padding: 16px 0;
  border-bottom: 1px solid var(--cg-rule);
}
.cg-cluster:last-child { border-bottom: none; padding-bottom: 0; }
.cg-cluster:first-child { padding-top: 0; }
.cg-cluster__tag {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--cg-blurple);
  margin: 0 0 6px;
  font-weight: 500;
}
.cg-cluster h4 {
  font-family: var(--cg-font-display);
  font-weight: 500;
  font-size: 15px;
  margin: 0 0 10px;
  line-height: 1.3;
}
.cg-cluster__narrative {
  margin: 0 0 10px;
  font-size: 13.5px;
  line-height: 1.6;
  max-width: 80ch;
  color: var(--cg-ink);
}
.cg-cluster__bullets {
  list-style: none;
  padding: 0;
  margin: 0 0 12px;
  max-width: 84ch;
}
.cg-cluster__bullets > li {
  position: relative;
  padding: 2px 0 2px 18px;
  font-size: 13.5px;
  line-height: 1.55;
  color: var(--cg-ink);
}
.cg-cluster__bullets > li + li { margin-top: 6px; }
.cg-cluster__bullets > li::before {
  content: "";
  position: absolute;
  left: 4px;
  top: 0.65em;
  width: 6px;
  height: 6px;
  background: var(--cg-blurple);
}
.cg-cluster__bullets strong { color: var(--cg-ink); font-weight: 600; }
.cg-cluster__subbullets {
  list-style: none;
  padding: 0;
  margin: 6px 0 0 14px;
}
.cg-cluster__subbullets > li {
  position: relative;
  padding: 1px 0 1px 14px;
  font-size: 13px;
  line-height: 1.5;
  color: var(--cg-muted, var(--cg-ink));
}
.cg-cluster__subbullets > li + li { margin-top: 3px; }
.cg-cluster__subbullets > li::before {
  content: "–";
  position: absolute;
  left: 0;
  top: 0;
  color: var(--cg-blurple);
}
.cg-cluster__sources {
  margin: 12px 0 0;
  padding-top: 10px;
  border-top: 1px solid var(--cg-rule);
}
.cg-cluster__sources-label {
  font-family: var(--cg-font-mono);
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--cg-ink-faint);
  font-weight: 500;
  margin: 0 0 6px;
}
.cg-cluster__sources ul {
  list-style: none;
  padding: 0;
  margin: 0;
}
.cg-cluster__sources li {
  position: relative;
  padding: 2px 0 2px 18px;
  font-family: var(--cg-font-mono);
  font-size: 12px;
  line-height: 1.55;
}
.cg-cluster__sources li::before {
  content: "→";
  position: absolute;
  left: 0;
  color: var(--cg-blurple);
  font-weight: 700;
}
.cg-cluster__members { margin-top: 12px; }
.cg-cluster__list {
  list-style: none;
  padding: 0;
  margin: 10px 0 0;
  font-size: 12.5px;
  border-top: 1px solid var(--cg-rule);
}
.cg-cluster__list > li {
  display: grid;
  grid-template-columns: minmax(180px, 1.4fr) 80px minmax(160px, 2fr) 90px;
  gap: 16px;
  align-items: baseline;
  padding: 6px 0;
  border-bottom: 1px solid var(--cg-rule);
}
.cg-cluster__list > li > * { min-width: 0; overflow-wrap: anywhere; }
.cg-cluster__list > li > .num,
.cg-cluster__list .cl-impacts { text-align: right; font-variant-numeric: tabular-nums; }
.cg-cluster__list code {
  background: transparent;
  padding: 0;
  color: var(--cg-ink-soft);
}
@media (max-width: 640px) {
  .cg-cluster__list > li {
    grid-template-columns: 1fr auto;
    grid-template-areas:
      "cve sev"
      "pkg impacts";
    row-gap: 4px;
  }
  .cg-cluster__list > li > :nth-child(1) { grid-area: cve; }
  .cg-cluster__list > li > :nth-child(2) { grid-area: sev; justify-self: end; }
  .cg-cluster__list > li > :nth-child(3) { grid-area: pkg; }
  .cg-cluster__list > li > :nth-child(4) { grid-area: impacts; }
}

.cg-note {
  font-size: 13px;
  color: var(--cg-ink-soft);
  padding: 14px 18px;
  background: var(--cg-bg-soft);
  border-left: 3px solid var(--cg-ink-faint);
  margin: 0;
}

/* ── Foot ─────────────────────────────────────────────────────── */
.cg-foot {
  margin: 56px 0 0;
  padding: 18px 0;
  border-top: 1px solid var(--cg-rule);
  font-family: var(--cg-font-mono);
  font-size: 10.5px;
  color: var(--cg-ink-soft);
  letter-spacing: 0.06em;
  text-align: left;
}

/* ── Focus rings ───────────────────────────────────────────────── */
button:focus-visible, summary:focus-visible, a:focus-visible {
  outline: 2px solid var(--cg-blurple);
  outline-offset: 2px;
  border-radius: 0;
}

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; animation: none !important; }
}
"""

# ---------------------------------------------------------------------------
# .env loader (no dependency, shell env wins)
# ---------------------------------------------------------------------------

def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        os.environ.setdefault(key, value)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", "-i", default="output/vulnerability_report.yaml",
                        help="Path to vulnerability_report.yaml")
    parser.add_argument("--output-dir", "-o", default="output",
                        help="Directory to write analytics reports")
    parser.add_argument("--format", "-f", default="md,html",
                        help="Comma-separated formats: md, html (default: md,html)")
    parser.add_argument("--top-n", "-n", type=int, default=10,
                        help="Top-N rows for each ranking table (default: 10)")
    parser.add_argument("--no-enrich", action="store_true",
                        help="Skip NVD enrichment (disables event clustering)")
    parser.add_argument("--no-research", action="store_true",
                        help="Skip LLM web research on detected clusters")
    parser.add_argument("--no-llm-story", action="store_true",
                        help="Skip LLM-generated Story section (use template fallback)")
    parser.add_argument("--env-file", default=".env",
                        help="Path to .env file with NVD_API_KEY / ANTHROPIC_API_KEY (default: .env)")
    args = parser.parse_args()

    load_dotenv(Path(args.env_file))

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input report not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}

    print(f"Loading {input_path}…")
    meta, findings = load_report(input_path)
    print(f"  loaded {len(findings)} findings across {len({f.image for f in findings})} images")

    nvd_records: dict[str, NvdRecord] = {}
    nvd_enriched = False
    if not args.no_enrich:
        unique_cves = {f.cve_id for f in findings if f.cve_id}
        if unique_cves:
            cache_path = output_dir / ".nvd_cache.json"
            api_key = os.environ.get("NVD_API_KEY")
            print(f"Enriching {len(unique_cves)} CVEs via NVD"
                  f"{' (with API key)' if api_key else ' (no API key — slower)'}…")
            nvd_records = enrich_with_nvd(unique_cves, cache_path, api_key)
            nvd_enriched = bool(nvd_records)
            print(f"  enriched {len(nvd_records)} CVEs")

    metrics = compute_metrics(meta, findings, nvd_records, nvd_enriched, args.top_n)

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")

    if not args.no_llm_story:
        if anthropic_key:
            print("Generating Story narrative via Anthropic…")
            story_cache = output_dir / ".story_cache.json"
            enrich_story_with_llm(metrics, anthropic_key, story_cache)
        # If no key, the template-generated headline_narrative + severity_callouts
        # already populated by compute_metrics() are used as the fallback.

    if not args.no_research and metrics.clusters:
        if anthropic_key:
            print(f"Researching {len(metrics.clusters)} cluster(s) via Anthropic web search…")
            research_cache = output_dir / ".world_event_cache.json"
            enrich_clusters_with_research(metrics.clusters, anthropic_key, research_cache)
        else:
            print("  ANTHROPIC_API_KEY not set — skipping LLM cluster research "
                  "(static investigation links will be used)")

    if "md" in formats:
        md_path = output_dir / "analytics_report.md"
        md_path.write_text(render_markdown(metrics), encoding="utf-8")
        print(f"Wrote {md_path}")

    if "html" in formats:
        html_path = output_dir / "analytics_dashboard.html"
        html_path.write_text(render_html(metrics), encoding="utf-8")
        print(f"Wrote {html_path}")


if __name__ == "__main__":
    main()
