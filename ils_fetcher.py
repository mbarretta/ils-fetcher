#!/usr/bin/env python3
"""
Chainguard Container Vulnerability Advisory Report Generator

Generates a YAML report of vulnerabilities for all entitled Chainguard Containers
in an organization, focusing on 'latest' and 'latest-dev' tags.

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
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests
import yaml


def get_auth_token() -> str:
    """Get the authentication token from chainctl."""
    try:
        result = subprocess.run(
            ["chainctl", "auth", "token"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(
            f"Error: Failed to get auth token. Please run 'chainctl auth login' first.",
            file=sys.stderr,
        )
        print(f"Details: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(
            "Error: chainctl not found. Please install chainctl first.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_image_platforms(image_ref: str) -> list[str]:
    """
    Get available platforms for a multi-arch image.

    Args:
        image_ref: Full image reference (e.g., cgr.dev/org/image@sha256:...)

    Returns:
        List of platform strings (e.g., ["linux/amd64", "linux/arm64"])
        Returns empty list if not a multi-arch image or on error.
    """
    try:
        result = subprocess.run(
            ["crane", "manifest", image_ref],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        manifest = json.loads(result.stdout)

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

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return []
    except FileNotFoundError:
        print(
            "Warning: crane not found. Platform detection requires crane to be installed.",
            file=sys.stderr,
        )
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
    try:
        result = subprocess.run(
            ["chainctl", "iam", "organizations", "list", "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        # Handle the items wrapper in the response
        orgs = data.get("items", []) if isinstance(data, dict) else data
        # Filter out the 'chainguard' organization
        return [org for org in orgs if org.get("name", "").lower() != "chainguard"]
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to list organizations.", file=sys.stderr)
        print(f"Details: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse organizations response.", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def get_images(organization_id: str) -> list[dict[str, Any]]:
    """Get the list of images for an organization."""
    try:
        result = subprocess.run(
            [
                "chainctl",
                "images",
                "list",
                "--parent",
                organization_id,
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to list images.", file=sys.stderr)
        print(f"Details: {e.stderr}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse images response.", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


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


def get_advisories_for_cves(
    token: str, cves: list[str]
) -> dict[str, dict[str, Any]]:
    """
    Fetch Chainguard advisories for a list of CVEs.

    Args:
        token: Authentication token
        cves: List of CVE IDs to query

    Returns:
        Dictionary mapping CVE ID to advisory info including CGA ID and status
    """
    if not cves:
        return {}

    url = "https://console-api.enforce.dev/advisory/v1/documents"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    # Query all CVEs at once - use list of tuples for repeated params
    # This creates: ?cves=CVE-1&cves=CVE-2 instead of ?cves=CVE-1,CVE-2
    params = [("cves", cve) for cve in cves]

    try:
        response = requests.get(url, headers=headers, params=params, timeout=120)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching advisories: {e}", file=sys.stderr)
        return {}
    except json.JSONDecodeError:
        print("Error: Failed to parse advisories response.", file=sys.stderr)
        return {}

    # Build a lookup: (package_name, cve) -> {cga_id, status, note}
    advisory_lookup: dict[str, dict[str, Any]] = {}

    for item in data.get("items", []):
        package_name = item.get("id", "")
        for advisory in item.get("advisories", []):
            cga_id = advisory.get("id", "")
            aliases = advisory.get("aliases", [])
            events = advisory.get("events", [])

            # Determine status from the most recent non-detection event
            status = "Under investigation"
            note = ""
            fixed_version = None
            status_map = {
                "pendingUpstreamFix": "Pending upstream fix",
                "fixNotPlanned": "Fix not planned",
                "fixed": "Fixed",
                "falsePositiveDetermination": "Not affected",
                "truePositiveDetermination": "Affected",
                "detection": "Under investigation",
            }

            for event in reversed(events):
                for event_type, display_status in status_map.items():
                    if event_type in event and event_type != "detection":
                        status = display_status
                        event_data = event.get(event_type, {})
                        if isinstance(event_data, dict):
                            note = event_data.get("note", "")
                            # Extract fixedVersion if this is a "fixed" event
                            if event_type == "fixed":
                                fixed_version = event_data.get("fixedVersion")
                        break
                if status != "Under investigation":
                    break

            # Map each CVE alias to this advisory info
            for alias in aliases:
                if alias.startswith("CVE-") or alias.startswith("GHSA-"):
                    key = f"{package_name}:{alias}"
                    advisory_lookup[key] = {
                        "cga-id": cga_id,
                        "status": status,
                        "note": note,
                        "package": package_name,
                        "fixed-version": fixed_version,
                    }

    return advisory_lookup


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
        }

        # If description is empty, try to get it from related vulnerabilities
        if not vulnerability_entry["description"] and related:
            for rel in related:
                if rel.get("description"):
                    vulnerability_entry["description"] = rel.get("description")
                    break

        vulnerabilities.append(vulnerability_entry)

    return vulnerabilities


def find_tag_digest(
    images: list[dict[str, Any]], repo_name: str, tag: str
) -> str | None:
    """
    Find the digest for a specific tag in the images list.

    Args:
        images: List of images from chainctl
        repo_name: Repository name to search for
        tag: Tag to find (e.g., 'latest', 'latest-dev')

    Returns:
        Digest string or None if not found
    """
    for image in images:
        if image.get("repo", {}).get("name") == repo_name:
            tags = image.get("tags", [])
            for t in tags:
                if t.get("name") == tag:
                    return t.get("digest")
    return None


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
            # Collect unique CVE IDs for advisory lookup (only CVE IDs, not GHSA)
            cve_ids = list(set(
                v.get("cve-id")
                for v in vulnerabilities
                if v.get("cve-id")
            ))

            # Fetch advisories for these CVEs
            advisory_lookup = get_advisories_for_cves(token, cve_ids) if cve_ids else {}

            # Build base name for matching (remove common suffixes)
            base_name = repo_name
            for suffix in ("-iamguarded-fips", "-iamguarded", "-fips"):
                if base_name.endswith(suffix):
                    base_name = base_name[:-len(suffix)]
                    break

            for vuln in vulnerabilities:
                cve_id = vuln.get("cve-id")
                matched_advisory = None

                if cve_id:
                    # Try matching advisory by package name patterns
                    for pkg_key, adv_info in advisory_lookup.items():
                        pkg_name, cve = pkg_key.rsplit(":", 1)
                        if cve != cve_id:
                            continue

                        # Match if:
                        # 1. Exact match (repo_name == pkg_name)
                        # 2. Base name match (base_name == pkg_name)
                        # 3. Advisory pkg starts with base name (airflow-2 starts with airflow)
                        # 4. Base name starts with advisory pkg base (airflow starts with airflow)
                        pkg_base = pkg_name.rstrip("-0123456789")
                        if (pkg_name == repo_name or
                            pkg_name == base_name or
                            pkg_name.startswith(base_name) or
                            base_name.startswith(pkg_base)):
                            matched_advisory = adv_info
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

    # Set up SBOM downloads - construct registry URL from org name
    registry_url = None
    sbom_path = None
    if not skip_sbom:
        sbom_path = output_path / "sbom"
        sbom_path.mkdir(parents=True, exist_ok=True)
        # Construct registry URL: cgr.dev/{org_name}
        registry_url = f"cgr.dev/{organization_name}"
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

    # Write YAML output
    print(f"Writing report to {output_file}...")
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(
            report,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        )

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
        # Find by name or ID
        for org in orgs:
            if (
                org.get("name") == args.organization
                or org.get("id") == args.organization
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
    )


if __name__ == "__main__":
    main()
