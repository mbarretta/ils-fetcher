#!/usr/bin/env python3
"""
Generates a YAML report of vulnerabilities for all entitled Chainguard Containers
in an organization, and downloads SBOMs, for 'latest' and 'latest-dev' tags.

Prerequisites:
    - Must be authenticated via `chainctl auth login`
    - Requires: pyyaml, requests

Usage:
    python image_advisories.py [--organization ORG_NAME] [--output OUTPUT_FILE]
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml


def run_chainctl(args: list[str], parse_json: bool = True) -> Any:
    """
    Run a chainctl command and return the output.

    Args:
        args: Command arguments (without 'chainctl' prefix)
        parse_json: If True, parse output as JSON; otherwise return raw string

    Returns:
        Parsed JSON data or raw string output
    """
    try:
        result = subprocess.run(
            ["chainctl"] + args,
            capture_output=True,
            text=True,
            check=True,
        )
        if parse_json:
            return json.loads(result.stdout)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error running chainctl {args[0]}: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: chainctl not found. Please install chainctl first.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error parsing chainctl output: {e}", file=sys.stderr)
        sys.exit(1)


def get_auth_token() -> str:
    """Get the authentication token from chainctl."""
    return run_chainctl(["auth", "token"], parse_json=False)


def get_registry_token(registry: str) -> str | None:
    """
    Get authentication token for a container registry using Docker credential helpers.

    Args:
        registry: Registry hostname (e.g., cgr.dev)

    Returns:
        Bearer token string or None if credentials cannot be obtained.
    """
    try:
        # Use docker-credential-cgr for cgr.dev
        if "cgr.dev" in registry:
            result = subprocess.run(
                ["docker-credential-cgr", "get"],
                input=registry,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            creds = json.loads(result.stdout)
            return creds.get("Secret")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    return None


def parse_image_reference(image_ref: str) -> tuple[str, str, str] | None:
    """
    Parse an image reference into registry, repository, and reference components.

    Args:
        image_ref: Full image reference (e.g., cgr.dev/org/image@sha256:... or cgr.dev/org/image:tag)

    Returns:
        Tuple of (registry, repository, reference) or None if parsing fails.
        Reference is either a digest (sha256:...) or a tag.
    """
    # Handle digest reference (image@sha256:...)
    if "@" in image_ref:
        image_part, reference = image_ref.rsplit("@", 1)
    elif ":" in image_ref and not image_ref.startswith("sha256:"):
        # Handle tag reference (image:tag), but be careful with port numbers
        # Split from the right to handle registry:port/image:tag
        parts = image_ref.rsplit(":", 1)
        if "/" in parts[-1]:
            # The colon was part of registry:port, no tag specified
            image_part = image_ref
            reference = "latest"
        else:
            image_part, reference = parts
    else:
        image_part = image_ref
        reference = "latest"

    # Split into registry and repository
    parts = image_part.split("/", 1)
    if len(parts) != 2:
        return None

    registry = parts[0]
    repository = parts[1]

    return registry, repository, reference


def get_image_platforms(image_ref: str) -> list[str]:
    """
    Get available platforms for a multi-arch image using the OCI Registry API.

    Args:
        image_ref: Full image reference (e.g., cgr.dev/org/image@sha256:...)

    Returns:
        List of platform strings (e.g., ["linux/amd64", "linux/arm64"])
        Returns empty list if not a multi-arch image or on error.
    """
    parsed = parse_image_reference(image_ref)
    if not parsed:
        return []

    registry, repository, reference = parsed

    # Get registry token
    token = get_registry_token(registry)
    if not token:
        return []

    # Build the manifest URL
    url = f"https://{registry}/v2/{repository}/manifests/{reference}"

    # Request manifest with Accept headers for manifest list/index
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": ", ".join([
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
        ]),
    }

    try:
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        manifest = response.json()

        # Check if this is a manifest list/index (multi-arch)
        media_type = manifest.get("mediaType", "")
        if "manifest.list" in media_type or "image.index" in media_type:
            platforms = []
            for m in manifest.get("manifests", []):
                platform_info = m.get("platform", {})
                os_name = platform_info.get("os", "")
                arch = platform_info.get("architecture", "")
                variant = platform_info.get("variant", "")
                if os_name and arch:
                    platform_str = f"{os_name}/{arch}"
                    if variant:
                        platform_str += f"/{variant}"
                    platforms.append(platform_str)
            return platforms
        else:
            # Single-arch image, return empty to signal no platform iteration needed
            return []

    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"Warning: Failed to fetch manifest for {image_ref}: {e}", file=sys.stderr)
        return []


def download_sbom(
    image_ref: str,
    output_path: Path,
    platform: str = "linux/amd64",
) -> bool:
    """
    Download SBOM for a Chainguard image using cosign.

    Args:
        image_ref: Full image reference (e.g., cgr.dev/org/image@sha256:...)
        output_path: Path to save the SBOM JSON file
        platform: Platform to download SBOM for (default: linux/amd64)

    Returns:
        True if successful, False otherwise
    """
    def run_cosign(use_platform: bool) -> subprocess.CompletedProcess | None:
        """Run cosign download attestation command."""
        cmd = ["cosign", "download", "attestation"]
        if use_platform:
            cmd.extend([f"--platform={platform}"])
        cmd.extend([f"--predicate-type=https://spdx.dev/Document", image_ref])

        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=120,
            )
        except subprocess.CalledProcessError:
            return None
        except subprocess.TimeoutExpired:
            return None

    def extract_sbom(result: subprocess.CompletedProcess) -> bool:
        """Extract SBOM from cosign output and save to file."""
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                envelope = json.loads(line)
                payload = envelope.get("payload", "")
                if payload:
                    decoded = base64.b64decode(payload).decode("utf-8")
                    attestation = json.loads(decoded)
                    sbom = attestation.get("predicate", {})
                    if sbom:
                        output_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(output_path, "w", encoding="utf-8") as f:
                            json.dump(sbom, f, indent=2)
                        return True
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        return False

    try:
        # Always use platform flag to ensure we get the actual platform-specific
        # SBOM, not the manifest list attestation for multi-arch images
        result = run_cosign(use_platform=True)
        if result and extract_sbom(result):
            return True

        # Fall back to trying without platform flag (for single-arch images
        # where the platform might not match exactly)
        result = run_cosign(use_platform=False)
        if result and extract_sbom(result):
            return True

        return False

    except FileNotFoundError:
        print(
            "Warning: cosign not found. SBOM download requires cosign to be installed.",
            file=sys.stderr,
        )
        return False


def download_sboms_all_platforms(
    image_ref: str,
    output_dir: Path,
    base_filename: str,
) -> dict[str, str]:
    """
    Download SBOMs for all platforms of a multi-arch image.

    Args:
        image_ref: Full image reference (e.g., cgr.dev/org/image@sha256:...)
        output_dir: Directory to save SBOM files
        base_filename: Base name for output files (e.g., "nginx_latest")

    Returns:
        Dictionary mapping platform to saved file path.
        For single-arch images, returns {"default": path} if successful.
    """
    results: dict[str, str] = {}

    # Detect available platforms
    platforms = get_image_platforms(image_ref)

    if platforms:
        # Multi-arch image: download SBOM for each platform
        for platform in platforms:
            # Create platform-specific filename (e.g., nginx_latest_linux_amd64.spdx.json)
            platform_suffix = platform.replace("/", "_")
            sbom_filename = f"{base_filename}_{platform_suffix}.spdx.json"
            sbom_path = output_dir / sbom_filename

            if download_sbom(image_ref, sbom_path, platform=platform):
                results[platform] = str(sbom_path)
    else:
        # Single-arch image or couldn't detect platforms: try default download
        sbom_filename = f"{base_filename}.spdx.json"
        sbom_path = output_dir / sbom_filename

        if download_sbom(image_ref, sbom_path):
            results["default"] = str(sbom_path)

    return results


def get_organizations() -> list[dict[str, Any]]:
    """Get the list of organizations the user has access to."""
    data = run_chainctl(["iam", "organizations", "list", "-o", "json"])
    if isinstance(data, dict):
        # Wrapped list: {"items": [...]}
        if "items" in data and isinstance(data["items"], list):
            orgs = data["items"]
        # Single org returned as a plain dict (some chainctl versions)
        elif "id" in data or "name" in data:
            orgs = [data]
        else:
            orgs = []
    elif isinstance(data, list):
        orgs = data
    else:
        orgs = []
    return [org for org in orgs if org.get("name", "").lower() != "chainguard"]


def get_images(organization_id: str) -> list[dict[str, Any]]:
    """Get the list of images for an organization."""
    return run_chainctl(["images", "list", "--parent", organization_id, "-o", "json"])


def get_vulnerability_report(
    token: str, digest: str
) -> dict[str, Any] | None:
    """
    Fetch raw vulnerability report for a specific image digest using GRYPE scanner.

    Args:
        token: Authentication token
        digest: Image digest (sha256:...)

    Returns:
        Dictionary containing vulnerability data or None if no vulnerabilities
    """
    url = "https://console-api.enforce.dev/registry/v1/vuln_reports/raw"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    params = {
        "digest": digest,
        "scanner": "GRYPE",
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return None
        print(f"Error fetching vulnerability report: {e}", file=sys.stderr)
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching vulnerability report: {e}", file=sys.stderr)
        return None
    except json.JSONDecodeError:
        print("Error: Failed to parse vulnerability report response.", file=sys.stderr)
        return None


_STATUS_DISPLAY = {
    "Detection":                  "Under investigation",
    "PendingUpstreamFix":          "Pending upstream fix",
    "FixNotPlanned":               "Fix not planned",
    "Fixed":                       "Fixed",
    "FalsePositiveDetermination":  "Not affected",
    "TruePositiveDetermination":   "Affected",
}


def get_image_advisories(image_ref: str) -> dict[str, dict[str, Any]]:
    """
    Fetch advisories for every package in an image via ``chainctl image
    advisories list <image_ref> -o json``.

    This is the documented, supported path: Chainguard's advisory database is
    keyed per-package-per-image, and the ``console-api advisory/v1/documents``
    bulk-CVE endpoint we used previously returns nothing for org-scoped images.

    Returns a dict keyed by ``(package_name, alias)`` -> advisory info. The
    ``alias`` key is whatever appeared in the advisory's ``aliases`` array
    (``CVE-…``, ``GHSA-…``, or ``CGA-…``), so callers can look up by either
    a real CVE id or a GHSA fallback.
    """
    try:
        result = subprocess.run(
            ["chainctl", "images", "advisories", "list", image_ref, "-o", "json"],
            check=True, capture_output=True, text=True, timeout=180,
        )
    except subprocess.CalledProcessError as e:
        if os.environ.get("ILS_DEBUG_CGA"):
            print(f"  [debug] chainctl advisories failed for {image_ref}: "
                  f"{e.stderr.strip()[:200]}", file=sys.stderr)
        return {}
    except subprocess.TimeoutExpired:
        print(f"Warning: chainctl advisories list timed out for {image_ref}",
              file=sys.stderr)
        return {}

    stdout = result.stdout
    # chainctl prints a log line before the JSON; skip to the first bracket.
    start = stdout.find("[")
    if start < 0:
        return {}
    try:
        records = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return {}

    lookup: dict[str, dict[str, Any]] = {}
    for rec in records:
        pkg = rec.get("package") or {}
        pkg_name = pkg.get("name", "")
        pkg_version = pkg.get("version", "")
        for adv in rec.get("advisories") or []:
            aliases = adv.get("aliases", []) or []
            cga_id = next((a for a in aliases if a.startswith("CGA-")), None)
            events = adv.get("events", []) or []

            # Walk events newest-last and pick the latest non-Detection state.
            status = "Under investigation"
            note = ""
            fixed_version = None
            for event in reversed(events):
                ev_type = event.get("Type") or {}
                if not isinstance(ev_type, dict):
                    continue
                # Each event has exactly one Type key, e.g. {"PendingUpstreamFix": {...}}
                for key, data in ev_type.items():
                    if key == "Detection":
                        continue
                    display = _STATUS_DISPLAY.get(key, key)
                    status = display
                    if isinstance(data, dict):
                        note = data.get("note", "") or ""
                        if key == "Fixed":
                            fixed_version = data.get("fixedVersion") or data.get("fixed_version")
                    break
                if status != "Under investigation":
                    break

            info = {
                "cga-id":        cga_id,
                "status":        status,
                "note":          note,
                "package":       pkg_name,
                "package-version": pkg_version,
                "fixed-version": fixed_version,
            }
            for alias in aliases:
                if alias.startswith(("CVE-", "GHSA-", "CGA-")):
                    lookup[f"{pkg_name}:{alias}"] = info

    if os.environ.get("ILS_DEBUG_CGA"):
        probe = os.environ["ILS_DEBUG_CGA"]
        hits = sorted(k for k in lookup if probe in k)
        if hits:
            print(f"  [debug] {image_ref}: {len(lookup)} keys, sample matching "
                  f"{probe!r}: {hits[:8]}", file=sys.stderr)
        else:
            print(f"  [debug] {image_ref}: {len(lookup)} keys, none matching "
                  f"{probe!r}", file=sys.stderr)

    return lookup


def parse_vulnerabilities(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    """
    Parse the raw vulnerability report and extract relevant fields.

    Args:
        report: Raw vulnerability report from the API

    Returns:
        List of vulnerability dictionaries with standardized fields
    """
    if not report:
        return []

    vulnerabilities = []

    # The API returns rawReport as a JSON string that needs to be parsed
    raw_report_str = report.get("rawReport", "")
    if raw_report_str:
        try:
            raw_report = json.loads(raw_report_str)
        except json.JSONDecodeError:
            return []
    else:
        raw_report = report

    # The raw report structure - handle GRYPE format
    matches = raw_report.get("matches", [])

    for match in matches:
        vuln = match.get("vulnerability", {})
        related = match.get("relatedVulnerabilities", [])
        artifact = match.get("artifact", {})

        # Extract fix information
        fix_info = vuln.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        fix_state = fix_info.get("state", "")

        # Determine if fix is available
        fix_available = fix_state == "fixed" or bool(fix_versions)

        # Get all related IDs (CVE, GHSA, etc.)
        main_id = vuln.get("id", "unknown")
        related_ids = [r.get("id") for r in related if r.get("id")]

        # Find CVE ID (prefer CVE over GHSA for advisory lookup)
        cve_id = None
        all_ids = [main_id] + related_ids
        for vid in all_ids:
            if vid and vid.startswith("CVE-"):
                cve_id = vid
                break

        vulnerability_entry = {
            "vulnerability-id": main_id,
            "cve-id": cve_id,  # Store CVE separately for advisory lookup
            "data-source": vuln.get("dataSource", ""),
            "severity": vuln.get("severity", "unknown"),
            "urls": vuln.get("urls", []),
            "description": vuln.get("description", ""),
            "fix-available": fix_available,
            "fix-version": fix_versions[0] if fix_versions else None,
            "package-name": artifact.get("name", "unknown"),
            "package-version": artifact.get("version", ""),
            "package-type": artifact.get("type", ""),
        }

        # If description is empty, try to get it from related vulnerabilities
        if not vulnerability_entry["description"] and related:
            for rel in related:
                if rel.get("description"):
                    vulnerability_entry["description"] = rel.get("description")
                    break

        vulnerabilities.append(vulnerability_entry)

    return vulnerabilities


def process_repo(
    repo_name: str,
    tag_info: dict[str, dict[str, Any]],
    token: str,
    registry_url: str | None = None,
    sbom_dir: Path | None = None,
    skip_advisory: bool = False,
) -> tuple[str, dict[str, Any]]:
    """
    Process a single repository and return its vulnerability report.

    Args:
        repo_name: Name of the repository
        tag_info: Dictionary mapping tag names to {digest, alias_tags}
        token: Authentication token
        registry_url: Base registry URL for SBOM downloads (e.g., cgr.dev/org)
        sbom_dir: Directory to save SBOMs (None to skip SBOM download)
        skip_advisory: Skip fetching advisory data

    Returns:
        Tuple of (repo_name, image_report)
    """
    image_report: dict[str, Any] = {}

    for tag in ("latest", "latest-dev"):
        info = tag_info.get(tag, {})
        digest = info.get("digest")
        alias_tags = info.get("alias_tags", [])

        if not digest:
            image_report[tag] = {"error": "Tag not found"}
            continue

        vuln_report = get_vulnerability_report(token, digest)
        vulnerabilities = parse_vulnerabilities(vuln_report)

        # Enrich vulnerabilities with advisory info (unless skipped)
        if not skip_advisory:
            image_ref = f"{registry_url}/{repo_name}:{tag}"
            advisory_lookup = get_image_advisories(image_ref)

            for vuln in vulnerabilities:
                cve_id = vuln.get("cve-id")
                vuln_id = vuln.get("vulnerability-id")
                pkg_in_image = vuln.get("package-name") or ""
                matched_advisory = None

                if pkg_in_image:
                    # Try CVE id first (the most reliable join), then the raw
                    # grype identifier (often a GHSA), then a base-name fallback
                    # for packages whose grype name carries a trailing version
                    # suffix that the advisory db drops.
                    candidates = [cve_id, vuln_id]
                    pkg_candidates = [pkg_in_image]
                    pkg_base = pkg_in_image.rstrip("-0123456789.")
                    if pkg_base and pkg_base != pkg_in_image:
                        pkg_candidates.append(pkg_base)
                    for pkg in pkg_candidates:
                        for alias in candidates:
                            if not alias:
                                continue
                            hit = advisory_lookup.get(f"{pkg}:{alias}")
                            if hit:
                                matched_advisory = hit
                                break
                        if matched_advisory:
                            break

                if matched_advisory:
                    vuln["cga-id"] = matched_advisory.get("cga-id")
                    vuln["advisory-status"] = matched_advisory.get("status")
                    # Use advisory fix version if GRYPE doesn't have one
                    adv_fixed_version = matched_advisory.get("fixed-version")
                    if adv_fixed_version and not vuln.get("fix-version"):
                        vuln["fix-version"] = adv_fixed_version
                        vuln["fix-available"] = True
                else:
                    vuln["cga-id"] = None
                    vuln["advisory-status"] = None

                # Remove internal cve-id field from output
                vuln.pop("cve-id", None)
        else:
            # Remove cve-id field without adding advisory fields
            for vuln in vulnerabilities:
                vuln.pop("cve-id", None)

        image_report[tag] = {
            "digest": digest,
            "alias-tags": alias_tags,
            "vulnerability-count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
        }

        # Download SBOMs for all platforms if requested
        if sbom_dir and registry_url and digest:
            image_ref = f"{registry_url}/{repo_name}@{digest}"
            base_filename = f"{repo_name}_{tag}".replace("/", "_")
            sbom_paths = download_sboms_all_platforms(image_ref, sbom_dir, base_filename)
            image_report[tag]["sbom-paths"] = sbom_paths if sbom_paths else None

    return repo_name, image_report


def generate_report(
    organization_id: str,
    organization_name: str,
    output_dir: str,
    max_workers: int = 10,
    skip_sbom: bool = False,
    skip_advisory: bool = False,
    limit: int | None = None,
    repo_filter: str | None = None,
) -> None:
    """
    Generate the vulnerability advisory report.

    Args:
        organization_id: Organization ID to query
        organization_name: Organization name for display
        output_dir: Directory to write output files (report and SBOMs)
        max_workers: Maximum number of concurrent workers for API calls
        skip_sbom: Skip downloading SBOMs
        skip_advisory: Skip fetching advisory data
    """
    print(f"Generating vulnerability report for organization: {organization_name}")

    # Get auth token
    print("Getting authentication token...")
    token = get_auth_token()

    # Get images
    print("Fetching image list...")
    images = get_images(organization_id)

    if not images:
        print("No images found for this organization.", file=sys.stderr)
        sys.exit(1)

    # Set up output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    output_file = output_path / "vulnerability_report.yaml"

    # Construct registry URL — used for both SBOM downloads and per-image
    # advisory queries via chainctl.
    registry_url = f"cgr.dev/{organization_name}"
    sbom_path = None
    if not skip_sbom:
        sbom_path = output_path / "sbom"
        sbom_path.mkdir(parents=True, exist_ok=True)
        print(f"SBOM download enabled, saving to: {sbom_path}")

    # Group images by repo name and collect all tags
    # Structure: repos[repo_name] = {tag_name: {"digest": ..., "alias_tags": [...]}}
    repos: dict[str, dict[str, dict[str, Any]]] = {}

    for image in images:
        repo_info = image.get("repo", {})
        repo_name = repo_info.get("name")
        if not repo_name:
            continue

        if repo_name not in repos:
            repos[repo_name] = {
                "latest": {"digest": None, "alias_tags": []},
                "latest-dev": {"digest": None, "alias_tags": []},
            }

        # Collect all tags and their digests for this repo
        all_tags: dict[str, str] = {}
        for tag_data in image.get("tags", []):
            tag_name = tag_data.get("name")
            digest = tag_data.get("digest")
            if tag_name and digest:
                all_tags[tag_name] = digest
                # Set digest for our target tags
                if tag_name in ("latest", "latest-dev"):
                    repos[repo_name][tag_name]["digest"] = digest

        # Find alias tags (tags pointing to same digest as latest/latest-dev)
        for target_tag in ("latest", "latest-dev"):
            target_digest = repos[repo_name][target_tag].get("digest")
            if target_digest:
                alias_tags = [
                    name for name, digest in all_tags.items()
                    if digest == target_digest and name != target_tag
                ]
                repos[repo_name][target_tag]["alias_tags"] = sorted(alias_tags)

    if repo_filter:
        repos = {n: t for n, t in repos.items() if repo_filter in n}
    if limit is not None:
        repos = dict(list(repos.items())[:limit])

    print(f"Found {len(repos)} repositories")
    print(f"Processing with {max_workers} concurrent workers...")

    # Build the report using thread pool for concurrent API calls
    report: dict[str, Any] = {}
    total_repos = len(repos)
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        futures = {
            executor.submit(
                process_repo, repo_name, tag_info, token, registry_url, sbom_path, skip_advisory
            ): repo_name
            for repo_name, tag_info in repos.items()
        }

        # Process results as they complete
        for future in as_completed(futures):
            repo_name = futures[future]
            completed += 1
            try:
                name, image_report = future.result()
                report[name] = image_report
                print(f"Completed [{completed}/{total_repos}]: {name}")
            except Exception as e:
                print(f"Error processing {repo_name}: {e}", file=sys.stderr)
                report[repo_name] = {"error": str(e)}

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output_report = {
        "_meta": {
            "generated-at": generated_at,
            "organization": organization_name,
            "image-count": len(repos),
            "tags-scanned": ["latest", "latest-dev"],
            "skip-sbom": skip_sbom,
            "skip-advisory": skip_advisory,
        },
        **report,
    }

    # Write YAML output
    print(f"Writing report to {output_file}...")
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(
            output_report,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )

    # Write timestamped snapshot for future trend/diff analysis
    history_dir = output_path / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    snapshot_file = history_dir / f"vulnerability_report-{timestamp}.yaml"
    shutil.copy2(output_file, snapshot_file)
    print(f"Snapshot saved to {snapshot_file}")

    print(f"Report generated successfully: {output_file}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate vulnerability advisory report for Chainguard Containers"
    )
    parser.add_argument(
        "--organization",
        "-org",
        help="Organization name or ID (will prompt if not specified)",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default="output",
        help="Output directory for report and SBOMs (default: output)",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=10,
        help="Number of concurrent workers for API calls (default: 10)",
    )
    parser.add_argument(
        "--skip-sbom",
        action="store_true",
        help="Skip downloading SBOMs for images",
    )
    parser.add_argument(
        "--skip-advisory",
        action="store_true",
        help="Skip fetching advisory data (CGA IDs and status)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Process only the first N repositories (for debugging / smoke tests).",
    )
    parser.add_argument(
        "--repo-filter",
        default=None,
        help="Process only repositories whose name contains this substring.",
    )
    args = parser.parse_args()

    # Get organizations
    print("Fetching organizations...")
    orgs = get_organizations()

    if not orgs:
        print("Error: No organizations found (excluding 'chainguard').", file=sys.stderr)
        sys.exit(1)

    # Select organization
    selected_org = None
    if args.organization:
        requested = args.organization.strip()
        # Find by name or ID using progressively looser matching:
        #   1. Exact match on name or ID
        #   2. Case-insensitive match on name
        for org in orgs:
            name = org.get("name", "")
            oid = org.get("id", "")
            if (
                name == requested
                or oid == requested
                or name.lower() == requested.lower()
            ):
                selected_org = org
                break
        if not selected_org:
            print(
                f"Error: Organization '{args.organization}' not found.",
                file=sys.stderr,
            )
            print("Available organizations:", file=sys.stderr)
            for org in orgs:
                print(f"  - {org.get('name')} ({org.get('id')})", file=sys.stderr)
            sys.exit(1)
    elif len(orgs) == 1:
        selected_org = orgs[0]
        print(f"Using organization: {selected_org.get('name')}")
    else:
        # Prompt user to select
        print("Multiple organizations found. Please select one:")
        for i, org in enumerate(orgs, 1):
            print(f"  {i}. {org.get('name')} ({org.get('id')})")
        while True:
            try:
                choice = input("Enter number: ")
                idx = int(choice) - 1
                if 0 <= idx < len(orgs):
                    selected_org = orgs[idx]
                    break
                print("Invalid selection. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except KeyboardInterrupt:
                print("\nAborted.")
                sys.exit(1)

    # Generate report
    generate_report(
        organization_id=selected_org.get("id"),
        organization_name=selected_org.get("name"),
        output_dir=args.output_dir,
        max_workers=args.workers,
        skip_sbom=args.skip_sbom,
        skip_advisory=args.skip_advisory,
        limit=args.limit,
        repo_filter=args.repo_filter,
    )


if __name__ == "__main__":
    main()
