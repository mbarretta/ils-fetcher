# ILS Fetcher

A tool for generating vulnerability reports and downloading SBOMs for Chainguard container images. It queries the Chainguard API to collect vulnerability information, advisory data, and software bill of materials (SBOMs) for all entitled container images in an organization.

## Features

- Fetches vulnerability data for `latest` and `latest-dev` tags
- Downloads SPDX SBOMs for all platforms of multi-arch images
- Enriches vulnerabilities with Chainguard advisory data (CGA IDs and status)
- Identifies alias tags pointing to the same digest
- Concurrent processing for fast execution
- Outputs structured YAML reports

## Prerequisites

- **Python 3.10+**
- **chainctl**: Chainguard CLI, installed and authenticated
- **cosign** (optional): Required for SBOM downloads

### Installing chainctl

Follow the [official documentation](https://edu.chainguard.dev/chainguard/chainctl-usage/how-to-install-chainctl/) to install chainctl.

### Installing cosign

```bash
# macOS
brew install cosign

# Or download from https://github.com/sigstore/cosign/releases
```

## Installation

1. Clone this repository:

```bash
git clone <repository-url>
cd image-advisories
```

2. Create a virtual environment and install dependencies:

```bash
# Using uv (recommended)
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt

# Or using pip
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Authenticate with Chainguard:

```bash
chainctl auth login
```

4. Configure Docker for cgr.dev registry access (required for SBOM downloads):

```bash
chainctl auth configure-docker
```

## Usage

### Basic Usage

Run without arguments to be prompted for organization selection:

```bash
python ils_fetcher.py
```

Output is written to `output/` by default:
```
output/
├── vulnerability_report.yaml
└── sbom/
    ├── image1_latest_linux_amd64.spdx.json
    ├── image1_latest_linux_arm64.spdx.json
    ├── image1_latest-dev_linux_amd64.spdx.json
    ├── image1_latest-dev_linux_arm64.spdx.json
    └── ...
```

### Specify Organization

```bash
python ils_fetcher.py --organization my-org
```

### Custom Output Directory

```bash
python ils_fetcher.py --organization my-org --output-dir ./my-report
```

### Skip SBOMs or Advisory Data

```bash
# Skip SBOM downloads (faster)
python ils_fetcher.py --organization my-org --skip-sbom

# Skip advisory lookups (faster)
python ils_fetcher.py --organization my-org --skip-advisory
```

### Adjust Concurrency

For large registries with many images:

```bash
python ils_fetcher.py --organization my-org --workers 20
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--organization` | `-org` | Organization name or ID | Prompts if multiple |
| `--output-dir` | `-o` | Output directory for report and SBOMs | `output` |
| `--workers` | `-w` | Number of concurrent API workers | `10` |
| `--skip-sbom` | | Skip downloading SBOMs | `false` |
| `--skip-advisory` | | Skip fetching advisory data | `false` |

## Output Format

### Vulnerability Report (vulnerability_report.yaml)

```yaml
nginx:
  latest:
    digest: sha256:abc123...
    alias-tags:
    - "1.27"
    - "1.27.3"
    - stable
    vulnerability-count: 2
    vulnerabilities:
    - vulnerability-id: CVE-2024-XXXXX
      data-source: https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX
      severity: High
      urls:
      - https://example.com/advisory
      description: Description of the vulnerability...
      fix-available: true
      fix-version: 1.2.3
      cga-id: CGA-xxxx-xxxx-xxxx
      advisory-status: Fixed
    - vulnerability-id: GHSA-xxxx-xxxx-xxxx
      data-source: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
      severity: Medium
      urls: []
      description: Another vulnerability description...
      fix-available: false
      fix-version: null
      cga-id: null
      advisory-status: null
    sbom-paths:
      linux/amd64: output/sbom/nginx_latest_linux_amd64.spdx.json
      linux/arm64: output/sbom/nginx_latest_linux_arm64.spdx.json
  latest-dev:
    digest: sha256:def456...
    alias-tags:
    - "1.27-dev"
    vulnerability-count: 1
    vulnerabilities:
    - ...
    sbom-paths:
      linux/amd64: output/sbom/nginx_latest-dev_linux_amd64.spdx.json
      linux/arm64: output/sbom/nginx_latest-dev_linux_arm64.spdx.json
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `digest` | Image digest (sha256) |
| `alias-tags` | Other tags pointing to the same digest |
| `vulnerability-count` | Total number of vulnerabilities |
| `vulnerability-id` | CVE or GHSA identifier |
| `data-source` | URL to vulnerability database entry |
| `severity` | Critical, High, Medium, Low, or Unknown |
| `urls` | Related advisory URLs |
| `description` | Vulnerability description |
| `fix-available` | Whether a fix exists (true/false) |
| `fix-version` | Version containing the fix |
| `cga-id` | Chainguard Advisory ID (e.g., CGA-xxxx-xxxx-xxxx) |
| `advisory-status` | Chainguard advisory status (Fixed, Pending upstream fix, etc.) |
| `sbom-paths` | Map of platform to downloaded SBOM file path |

### SBOMs

SBOMs are saved in SPDX 2.3 JSON format with platform-specific naming:
- Multi-arch images: `output/sbom/{image}_{tag}_{os}_{arch}.spdx.json`
- Single-arch images: `output/sbom/{image}_{tag}.spdx.json`

## How It Works

1. **Organization Discovery**: Uses `chainctl iam organizations list` to find available organizations

2. **Image Listing**: Uses `chainctl images list --parent <ORG>` to get all entitled images and their tags

3. **Vulnerability Scanning**: Queries the Chainguard API (`/registry/v1/vuln_reports/raw`) with the GRYPE scanner for each image digest

4. **Advisory Enrichment**: Fetches Chainguard advisory data (`/advisory/v1/documents`) to add CGA IDs and fix status

5. **SBOM Download**: Queries the OCI registry API to detect available platforms for multi-arch images, then uses `cosign download attestation` to fetch SPDX SBOMs for each platform

6. **Report Generation**: Outputs structured YAML report and organizes SBOMs in the output directory

## Troubleshooting

### "Failed to get auth token"

Ensure you're logged in:
```bash
chainctl auth login
```

### "chainctl not found"

Install chainctl following the [official documentation](https://edu.chainguard.dev/chainguard/chainctl-usage/how-to-install-chainctl/).

### "cosign not found"

Install cosign for SBOM downloads, or use `--skip-sbom` to skip SBOM fetching.

### "No organizations found"

Verify your account has access to at least one organization:
```bash
chainctl iam organizations list
```

### SBOMs only downloading for one platform

Ensure Docker is configured for cgr.dev registry access:
```bash
chainctl auth configure-docker
```

This sets up the credential helper needed to query the registry for multi-arch platform information.

### SBOMs not downloading

- Ensure cosign is installed and in your PATH
- Some images may not have SBOM attestations attached
- Ensure Docker is configured for the registry: `chainctl auth configure-docker`
