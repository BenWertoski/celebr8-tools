#!/usr/bin/env python3
"""
Registry generator for BenWertoski/celebr8-tools.

Produces:
  denylist.json
  index.json
  index.json.sig       (64 raw bytes, Ed25519 signature over canonical JSON)
  packages/<id>/<version>.tar.gz   (one per tool)

Tool YAML definitions live in yamls/<id>.yaml (committed to this repo).

Install methods:
  github_release   — downloads platform archives, verifies checksums, stores digests
  go_install       — records a 'go install' path; no binary download
  pip              — records a pip package; no binary download
  system_package   — records brew/apt install instructions; no binary download

For non-binary-download methods, gen.py still resolves the latest GitHub release
tag (when a github field is present) for accurate version tracking, and still builds
a signed package tarball that contains manifest.json + the tool YAML.

Key loading order (first wins):
  1. CELEBR8_REGISTRY_SIGNING_KEY env var — PEM content of the private key
  2. .signing_key.pem in the repo root    — git-ignored local file

Run with --bootstrap to generate a fresh keypair on first setup.
Use --tool <id> to regenerate a single tool.
Use --dry-run to skip writing files.
"""

import gzip
import hashlib
import io
import json
import os
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


# ── Constants ─────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
YAML_DIR = BASE_DIR / "yamls"
PACKAGES_DIR = BASE_DIR / "packages"
MIN_CLI_VERSION = "0.1.0"
PD_OS_MAP = {"darwin": "macOS", "linux": "linux", "windows": "windows"}
LOWER_OS_MAP = {"darwin": "darwin", "linux": "linux", "windows": "windows"}
PLATFORMS = ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"]

# ── Tool registry ─────────────────────────────────────────────────────────────
# Each entry drives version resolution, package building, and index generation.
#
# Required fields (all methods):
#   id, display_name, description, category, tags, homepage, binary_name,
#   version_pin, install, platforms, post_install_check, dependencies
#
# install.method == "github_release" adds:
#   github_repo, asset_pattern, asset_os_map, archive_ext
#
# install.method == "go_install" adds:
#   go_package
#   github (optional — used to resolve version tag)
#
# install.method == "pip" adds:
#   pip_package
#   github (optional — used to resolve version tag)
#
# install.method == "system_package" adds:
#   brew (optional), apt (optional)
#   github (optional — used to resolve version tag)

TOOLS = [
    # ── recon ──────────────────────────────────────────────────────────────────
    {
        "id": "subfinder",
        "display_name": "Subfinder",
        "description": "Fast passive subdomain enumeration tool",
        "category": "recon",
        "tags": ["recon", "subdomain", "passive"],
        "homepage": "https://github.com/projectdiscovery/subfinder",
        "binary_name": "subfinder",
        "version_pin": "v2.13.0",
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/subfinder",
            "asset_pattern": "subfinder_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["subfinder", "-version"],
        "dependencies": [],
    },
    {
        "id": "httpx",
        "display_name": "httpx",
        "description": "Fast and multi-purpose HTTP toolkit for web reconnaissance",
        "category": "web",
        "tags": ["web", "recon", "http", "alive-check"],
        "homepage": "https://github.com/projectdiscovery/httpx",
        "binary_name": "httpx",
        "version_pin": "v1.9.0",
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/httpx",
            "asset_pattern": "httpx_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["httpx", "-version"],
        "dependencies": [],
    },
    {
        "id": "amass",
        "display_name": "Amass",
        "description": "In-depth attack surface mapping and subdomain enumeration (OWASP)",
        "category": "recon",
        "tags": ["recon", "subdomain", "active", "owasp"],
        "homepage": "https://github.com/owasp-amass/amass",
        "binary_name": "amass",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "amass",
            "apt": "amass",
            "github": "owasp-amass/amass",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["amass", "-version"],
        "dependencies": [],
    },
    {
        "id": "assetfinder",
        "display_name": "Assetfinder",
        "description": "Quick passive subdomain discovery from various public sources",
        "category": "recon",
        "tags": ["recon", "subdomain", "passive"],
        "homepage": "https://github.com/tomnomnom/assetfinder",
        "binary_name": "assetfinder",
        "version_pin": None,
        "install": {
            "method": "go_install",
            "go_package": "github.com/tomnomnom/assetfinder@latest",
            "github": "tomnomnom/assetfinder",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["assetfinder", "--help"],
        "dependencies": [],
    },
    {
        "id": "dnsx",
        "display_name": "dnsx",
        "description": "Fast DNS resolver and brute-forcer with wildcard filtering (projectdiscovery)",
        "category": "recon",
        "tags": ["recon", "dns", "active", "projectdiscovery"],
        "homepage": "https://github.com/projectdiscovery/dnsx",
        "binary_name": "dnsx",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/dnsx",
            "asset_pattern": "dnsx_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["dnsx", "-version"],
        "dependencies": [],
    },
    {
        "id": "naabu",
        "display_name": "Naabu",
        "description": "Fast SYN/TCP port scanner (projectdiscovery)",
        "category": "recon",
        "tags": ["recon", "network", "ports", "projectdiscovery"],
        "homepage": "https://github.com/projectdiscovery/naabu",
        "binary_name": "naabu",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/naabu",
            "asset_pattern": "naabu_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["naabu", "-version"],
        "dependencies": [],
    },
    {
        "id": "massdns",
        "display_name": "MassDNS",
        "description": "High-performance bulk DNS resolver for large subdomain lists",
        "category": "recon",
        "tags": ["recon", "dns", "active", "bulk"],
        "homepage": "https://github.com/blechschmidt/massdns",
        "binary_name": "massdns",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "massdns",
            "github": "blechschmidt/massdns",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["massdns", "--help"],
        "dependencies": [],
    },
    {
        "id": "chaos-client",
        "display_name": "Chaos Client",
        "description": "projectdiscovery Chaos DB feed — passive subdomain dataset access",
        "category": "recon",
        "tags": ["recon", "subdomain", "passive", "projectdiscovery"],
        "homepage": "https://github.com/projectdiscovery/chaos-client",
        "binary_name": "chaos",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/chaos-client",
            "asset_pattern": "chaos-client_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["chaos", "-version"],
        "dependencies": [],
    },
    # ── web ────────────────────────────────────────────────────────────────────
    {
        "id": "nuclei",
        "display_name": "Nuclei",
        "description": "Template-based vulnerability scanner (projectdiscovery)",
        "category": "web",
        "tags": ["web", "vuln", "active", "templates", "projectdiscovery"],
        "homepage": "https://github.com/projectdiscovery/nuclei",
        "binary_name": "nuclei",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/nuclei",
            "asset_pattern": "nuclei_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["nuclei", "-version"],
        "dependencies": [],
    },
    {
        "id": "ffuf",
        "display_name": "ffuf",
        "description": "Fast web fuzzer for directories, files, parameters, and vhosts",
        "category": "web",
        "tags": ["web", "fuzzing", "active", "brute-force"],
        "homepage": "https://github.com/ffuf/ffuf",
        "binary_name": "ffuf",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "ffuf/ffuf",
            "asset_pattern": "ffuf_{version_no_v}_{os}_{arch}.tar.gz",
            "asset_os_map": LOWER_OS_MAP,
            "archive_ext": "tar.gz",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["ffuf", "-V"],
        "dependencies": [],
    },
    {
        "id": "feroxbuster",
        "display_name": "Feroxbuster",
        "description": "Fast recursive directory and file brute-forcer for web applications",
        "category": "web",
        "tags": ["web", "fuzzing", "active", "brute-force", "recursive"],
        "homepage": "https://github.com/epi052/feroxbuster",
        "binary_name": "feroxbuster",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "feroxbuster",
            "cargo": "feroxbuster",
            "github": "epi052/feroxbuster",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["feroxbuster", "--version"],
        "dependencies": [],
    },
    {
        "id": "katana",
        "display_name": "Katana",
        "description": "Fast web crawler with JavaScript parsing support (projectdiscovery)",
        "category": "web",
        "tags": ["web", "crawler", "active", "projectdiscovery"],
        "homepage": "https://github.com/projectdiscovery/katana",
        "binary_name": "katana",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/katana",
            "asset_pattern": "katana_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["katana", "-version"],
        "dependencies": [],
    },
    {
        "id": "dalfox",
        "display_name": "Dalfox",
        "description": "Fast parameter-based XSS scanner and utility",
        "category": "web",
        "tags": ["web", "xss", "active", "scanning"],
        "homepage": "https://github.com/hahwul/dalfox",
        "binary_name": "dalfox",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "hahwul/dalfox",
            "asset_pattern": "dalfox_{version_no_v}_{os}_{arch}.tar.gz",
            "asset_os_map": LOWER_OS_MAP,
            "archive_ext": "tar.gz",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["dalfox", "version"],
        "dependencies": [],
    },
    {
        "id": "sqlmap",
        "display_name": "sqlmap",
        "description": "Automatic SQL injection detection and exploitation tool",
        "category": "web",
        "tags": ["web", "sqli", "active", "exploitation"],
        "homepage": "https://github.com/sqlmapproject/sqlmap",
        "binary_name": "sqlmap",
        "version_pin": None,
        "install": {
            "method": "pip",
            "pip_package": "sqlmap",
            "github": "sqlmapproject/sqlmap",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["sqlmap", "--version"],
        "dependencies": [],
    },
    {
        "id": "gau",
        "display_name": "gau",
        "description": "Fetch all known URLs from Wayback Machine, Common Crawl, and other sources",
        "category": "web",
        "tags": ["web", "recon", "passive", "urls", "osint"],
        "homepage": "https://github.com/lc/gau",
        "binary_name": "gau",
        "version_pin": None,
        "install": {
            "method": "go_install",
            "go_package": "github.com/lc/gau/v2/cmd/gau@latest",
            "github": "lc/gau",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["gau", "--version"],
        "dependencies": [],
    },
    {
        "id": "waybackurls",
        "display_name": "Waybackurls",
        "description": "Pull all URLs archived for a domain from the Wayback Machine",
        "category": "web",
        "tags": ["web", "recon", "passive", "urls", "wayback"],
        "homepage": "https://github.com/tomnomnom/waybackurls",
        "binary_name": "waybackurls",
        "version_pin": None,
        "install": {
            "method": "go_install",
            "go_package": "github.com/tomnomnom/waybackurls@latest",
            "github": "tomnomnom/waybackurls",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["waybackurls", "-h"],
        "dependencies": [],
    },
    # ── network ────────────────────────────────────────────────────────────────
    {
        "id": "nmap",
        "display_name": "Nmap",
        "description": "Classic network and port scanner with service detection",
        "category": "network",
        "tags": ["network", "ports", "services", "scanning"],
        "homepage": "https://nmap.org",
        "binary_name": "nmap",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "nmap",
            "apt": "nmap",
            "github": "nmap/nmap",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["nmap", "--version"],
        "dependencies": [],
    },
    {
        "id": "masscan",
        "display_name": "Masscan",
        "description": "High-speed asynchronous port scanner capable of scanning the internet",
        "category": "network",
        "tags": ["network", "ports", "scanning", "high-speed"],
        "homepage": "https://github.com/robertdavidgraham/masscan",
        "binary_name": "masscan",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "masscan",
            "apt": "masscan",
            "github": "robertdavidgraham/masscan",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["masscan", "--version"],
        "dependencies": [],
    },
    {
        "id": "rustscan",
        "display_name": "RustScan",
        "description": "Fast Rust-based port scanner with automatic Nmap integration",
        "category": "network",
        "tags": ["network", "ports", "scanning", "rust"],
        "homepage": "https://github.com/RustScan/RustScan",
        "binary_name": "rustscan",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "rustscan",
            "cargo": "rustscan",
            "github": "RustScan/RustScan",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["rustscan", "--version"],
        "dependencies": [],
    },
    # ── cloud ──────────────────────────────────────────────────────────────────
    {
        "id": "cloudfox",
        "display_name": "CloudFox",
        "description": "Cloud attack surface mapper for AWS, Azure, and GCP environments",
        "category": "cloud",
        "tags": ["cloud", "aws", "azure", "gcp", "recon", "attack-surface"],
        "homepage": "https://github.com/BishopFox/cloudfox",
        "binary_name": "cloudfox",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "BishopFox/cloudfox",
            "asset_pattern": "cloudfox-{os}-{arch}.tar.gz",
            "asset_os_map": {"darwin": "macos", "linux": "linux"},
            "archive_ext": "tar.gz",
        },
        "platforms": ["linux/amd64", "darwin/amd64", "darwin/arm64"],
        "post_install_check": ["cloudfox", "version"],
        "dependencies": [],
    },
    {
        "id": "s3scanner",
        "display_name": "S3Scanner",
        "description": "Public S3 bucket enumerator and content lister",
        "category": "cloud",
        "tags": ["cloud", "aws", "s3", "recon", "passive"],
        "homepage": "https://github.com/sa7mon/S3Scanner",
        "binary_name": "s3scanner",
        "version_pin": None,
        "install": {
            "method": "pip",
            "pip_package": "s3scanner",
            "github": "sa7mon/S3Scanner",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["s3scanner", "version"],
        "dependencies": [],
    },
    {
        "id": "trufflehog",
        "display_name": "TruffleHog",
        "description": "Secrets and credential scanner for git repos, S3, filesystems, and more",
        "category": "cloud",
        "tags": ["cloud", "secrets", "credentials", "git", "passive"],
        "homepage": "https://github.com/trufflesecurity/trufflehog",
        "binary_name": "trufflehog",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "trufflesecurity/trufflehog",
            "asset_pattern": "trufflehog_{version_no_v}_{os}_{arch}.tar.gz",
            "asset_os_map": LOWER_OS_MAP,
            "archive_ext": "tar.gz",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["trufflehog", "--version"],
        "dependencies": [],
    },
    # ── osint ──────────────────────────────────────────────────────────────────
    {
        "id": "theharvester",
        "display_name": "theHarvester",
        "description": "OSINT tool for gathering emails, subdomains, IPs, and URLs from public sources",
        "category": "osint",
        "tags": ["osint", "passive", "email", "subdomain", "recon"],
        "homepage": "https://github.com/laramies/theHarvester",
        "binary_name": "theHarvester",
        "version_pin": None,
        "install": {
            "method": "pip",
            "pip_package": "theHarvester",
            "github": "laramies/theHarvester",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["theHarvester", "-h"],
        "dependencies": [],
    },
    {
        "id": "shodan",
        "display_name": "Shodan CLI",
        "description": "Shodan search engine CLI for passive host and service intelligence",
        "category": "osint",
        "tags": ["osint", "passive", "shodan", "network", "intelligence"],
        "homepage": "https://cli.shodan.io",
        "binary_name": "shodan",
        "version_pin": None,
        "install": {
            "method": "pip",
            "pip_package": "shodan",
            "github": "Shodan/shodan-python",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["shodan", "version"],
        "dependencies": [],
    },
    # ── wifi ───────────────────────────────────────────────────────────────────
    {
        "id": "aircrack-ng",
        "display_name": "Aircrack-ng",
        "description": "WEP and WPA/WPA2 wireless network security audit suite",
        "category": "wifi",
        "tags": ["wifi", "wireless", "wpa", "wep", "cracking", "audit"],
        "homepage": "https://www.aircrack-ng.org",
        "binary_name": "aircrack-ng",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "aircrack-ng",
            "apt": "aircrack-ng",
            "github": "aircrack-ng/aircrack-ng",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["aircrack-ng", "--help"],
        "dependencies": [],
    },
    {
        "id": "hashcat",
        "display_name": "Hashcat",
        "description": "GPU-accelerated password recovery and hash cracking tool",
        "category": "wifi",
        "tags": ["wifi", "cracking", "passwords", "gpu", "hashes"],
        "homepage": "https://hashcat.net",
        "binary_name": "hashcat",
        "version_pin": None,
        "install": {
            "method": "system_package",
            "brew": "hashcat",
            "apt": "hashcat",
            "github": "hashcat/hashcat",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["hashcat", "--version"],
        "dependencies": [],
    },
    # ── util ───────────────────────────────────────────────────────────────────
    {
        "id": "anew",
        "display_name": "anew",
        "description": "Append-only deduplicated output tool for pipeline use",
        "category": "util",
        "tags": ["util", "pipeline", "dedup"],
        "homepage": "https://github.com/tomnomnom/anew",
        "binary_name": "anew",
        "version_pin": None,
        "install": {
            "method": "go_install",
            "go_package": "github.com/tomnomnom/anew@latest",
            "github": "tomnomnom/anew",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["anew", "-h"],
        "dependencies": [],
    },
    {
        "id": "interactsh-client",
        "display_name": "Interactsh Client",
        "description": "Out-of-band interaction testing client (projectdiscovery)",
        "category": "util",
        "tags": ["util", "oob", "oast", "projectdiscovery", "blind"],
        "homepage": "https://github.com/projectdiscovery/interactsh",
        "binary_name": "interactsh-client",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/interactsh",
            "asset_pattern": "interactsh-client_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["interactsh-client", "-version"],
        "dependencies": [],
    },
    {
        "id": "notify",
        "display_name": "Notify",
        "description": "Pipe tool output to Slack, Discord, Telegram, and other channels (projectdiscovery)",
        "category": "util",
        "tags": ["util", "notifications", "pipeline", "projectdiscovery", "slack", "discord"],
        "homepage": "https://github.com/projectdiscovery/notify",
        "binary_name": "notify",
        "version_pin": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/notify",
            "asset_pattern": "notify_{version_no_v}_{os}_{arch}.zip",
            "asset_os_map": PD_OS_MAP,
            "archive_ext": "zip",
        },
        "platforms": PLATFORMS,
        "post_install_check": ["notify", "-version"],
        "dependencies": [],
    },
]


# ── Key management ────────────────────────────────────────────────────────────

KEY_FILE = BASE_DIR / ".signing_key.pem"
_KEY_ENV = "CELEBR8_REGISTRY_SIGNING_KEY"


def load_key(bootstrap: bool = False) -> Ed25519PrivateKey:
    pem_env = os.environ.get(_KEY_ENV)
    if pem_env:
        key = serialization.load_pem_private_key(pem_env.encode(), password=None)
        print(f"[keygen] Loaded key from {_KEY_ENV} env var", file=sys.stderr)
        return key  # type: ignore[return-value]
    if KEY_FILE.exists():
        pem = KEY_FILE.read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        print(f"[keygen] Loaded key from {KEY_FILE}", file=sys.stderr)
        return key  # type: ignore[return-value]
    if not bootstrap:
        print(
            f"[error] No signing key found.\n"
            f"  Set {_KEY_ENV} env var (PEM content) or place key at {KEY_FILE}.\n"
            f"  To generate a fresh keypair: python3 gen.py --bootstrap",
            file=sys.stderr,
        )
        sys.exit(1)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    KEY_FILE.write_bytes(pem)
    KEY_FILE.chmod(0o600)
    print(f"[keygen] Generated new keypair, saved to {KEY_FILE}", file=sys.stderr)
    print(
        f"[keygen] IMPORTANT: back up {KEY_FILE} and store its content in\n"
        f"         the {_KEY_ENV} GitHub Actions secret before publishing.",
        file=sys.stderr,
    )
    return key  # type: ignore[return-value]


def pubkey_rust_array(key: Ed25519PrivateKey) -> str:
    pub = key.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert len(raw) == 32
    hex_pairs = [f"0x{b:02x}" for b in raw]
    row1 = ", ".join(hex_pairs[:16])
    row2 = ", ".join(hex_pairs[16:])
    return (
        "pub const REGISTRY_PUBLIC_KEY: [u8; 32] = [\n"
        f"    {row1},\n"
        f"    {row2},\n"
        "];"
    )


# ── Canonical JSON ────────────────────────────────────────────────────────────

def canonical_json_bytes(value) -> bytes:
    if value is None:
        return b"null"
    elif isinstance(value, bool):
        return b"true" if value else b"false"
    elif isinstance(value, int):
        return str(value).encode()
    elif isinstance(value, float):
        return str(value).encode()
    elif isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    elif isinstance(value, list):
        parts = [canonical_json_bytes(v) for v in value]
        return b"[" + b",".join(parts) + b"]"
    elif isinstance(value, dict):
        sorted_items = sorted(value.items(), key=lambda x: x[0])
        parts = []
        for k, v in sorted_items:
            key_bytes = json.dumps(k, ensure_ascii=False, separators=(",", ":")).encode()
            parts.append(key_bytes + b":" + canonical_json_bytes(v))
        return b"{" + b",".join(parts) + b"}"
    else:
        raise TypeError(f"Unsupported type: {type(value)}")


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_index(key: Ed25519PrivateKey, index_json_bytes: bytes) -> bytes:
    value = json.loads(index_json_bytes)
    canonical = canonical_json_bytes(value)
    sig = key.sign(canonical)
    assert len(sig) == 64
    return sig


# ── SHA-256 helpers ───────────────────────────────────────────────────────────

def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ── GitHub API helpers ────────────────────────────────────────────────────────

def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "celebr8-registry-gen/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "celebr8-registry-gen/1.0"})
    print(f"  [download] {url}", file=sys.stderr)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def get_release_info(repo: str, tag: str | None = None) -> dict | None:
    """Return release info dict, or None if no releases exist."""
    url = (
        f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
        if tag
        else f"https://api.github.com/repos/{repo}/releases/latest"
    )
    try:
        return fetch_json(url)
    except Exception as exc:
        print(f"  [warn] could not resolve release for {repo}: {exc}", file=sys.stderr)
        return None


def get_checksums(release: dict) -> dict[str, str]:
    """Parse checksums.txt from a release. Returns {filename: sha256_hex}."""
    assets = release.get("assets", [])
    csum_asset = next(
        (
            a
            for a in assets
            if a["name"].endswith("_checksums.txt") or a["name"] == "checksums.txt"
        ),
        None,
    )
    if not csum_asset:
        return {}
    text = fetch_bytes(csum_asset["browser_download_url"]).decode()
    result: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            digest, name = parts
            result[name] = digest
    return result


# ── Asset filename builder ────────────────────────────────────────────────────

def make_asset_filename(pattern: str, version_no_v: str, os_: str, arch: str, os_map: dict) -> str:
    """Expand an asset_pattern template to a concrete filename.

    Supported placeholders: {version_no_v}, {os}, {arch}
    The {os} placeholder is replaced using os_map (e.g. "darwin" → "macOS").
    """
    mapped_os = os_map.get(os_, os_)
    return pattern.format(version_no_v=version_no_v, os=mapped_os, arch=arch)


def build_archive_digests(
    tool: dict,
    release: dict,
    version: str,
    checksums: dict[str, str],
) -> dict[str, str]:
    """Return {platform: "sha256:…"} for all supported platforms.

    For each platform, looks up the expected filename in the checksums map.
    Warns (and skips) when no checksum is found for a platform.
    """
    install = tool["install"]
    pattern = install["asset_pattern"]
    os_map = install["asset_os_map"]
    version_no_v = version.lstrip("v")
    digests: dict[str, str] = {}

    for platform in tool["platforms"]:
        os_, arch = platform.split("/")
        filename = make_asset_filename(pattern, version_no_v, os_, arch, os_map)
        hex_digest = checksums.get(filename)
        if hex_digest:
            digests[platform] = f"sha256:{hex_digest}"
        else:
            print(f"  [warn] no checksum for {filename}", file=sys.stderr)

    return digests


# ── Tarball builder ───────────────────────────────────────────────────────────

def build_tarball(manifest: dict, yaml_content: str, tool_id: str) -> bytes:
    """Build a deterministic tar.gz containing manifest.json + <tool_id>.yaml."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tf:  # type: ignore[call-overload]
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(manifest_bytes))

            yaml_bytes = yaml_content.encode()
            info = tarfile.TarInfo(name=f"{tool_id}.yaml")
            info.size = len(yaml_bytes)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(yaml_bytes))

    return buf.getvalue()


# ── Install section builders ──────────────────────────────────────────────────

def build_install_github_release(tool: dict, version: str, archive_digests: dict) -> dict:
    inst = tool["install"]
    section: dict = {
        "method": "github_release",
        "github_repo": inst["github_repo"],
        "binary_name": tool["binary_name"],
        "asset_pattern": inst["asset_pattern"],
        "archive_digests": archive_digests,
    }
    # Only include asset_os_map when it differs from the default PD mapping.
    if inst["asset_os_map"] != PD_OS_MAP:
        section["asset_os_map"] = inst["asset_os_map"]
    return section


def build_install_go(tool: dict) -> dict:
    return {
        "method": "go_install",
        "go_package": tool["install"]["go_package"],
        "binary_name": tool["binary_name"],
    }


def build_install_pip(tool: dict) -> dict:
    return {
        "method": "pip",
        "pip_package": tool["install"]["pip_package"],
        "binary_name": tool["binary_name"],
    }


def build_install_system(tool: dict) -> dict:
    inst = tool["install"]
    section: dict = {"method": "system_package", "binary_name": tool["binary_name"]}
    if "brew" in inst:
        section["brew"] = inst["brew"]
    if "apt" in inst:
        section["apt"] = inst["apt"]
    if "cargo" in inst:
        section["cargo"] = inst["cargo"]
    return section


# ── Per-tool processing ───────────────────────────────────────────────────────

def process_tool(tool: dict, now: str, dry_run: bool) -> dict | None:
    """Build the package for one tool and return its index entry, or None on failure."""
    tool_id = tool["id"]
    method = tool["install"]["method"]
    print(f"\n[tool] {tool_id} ({method})", file=sys.stderr)

    # ── Load YAML ──
    yaml_path = YAML_DIR / f"{tool_id}.yaml"
    if not yaml_path.exists():
        # Try the display_name variation (e.g. theHarvester.yaml)
        alt = YAML_DIR / f"{tool['display_name']}.yaml"
        if alt.exists():
            yaml_path = alt
        else:
            print(f"  [error] YAML not found at {yaml_path} or {alt}", file=sys.stderr)
            return None
    yaml_content = yaml_path.read_text()

    # ── Resolve version ──
    version_pin = tool["version_pin"]
    version = version_pin

    if method == "github_release":
        github_repo = tool["install"]["github_repo"]
        print(
            f"  [github] resolving {'pinned ' + version_pin if version_pin else 'latest'}"
            f" for {github_repo}...",
            file=sys.stderr,
        )
        release = get_release_info(github_repo, version_pin)
        if release is None:
            print(f"  [error] could not resolve release for {tool_id}, skipping", file=sys.stderr)
            return None
        version = release["tag_name"]
        print(f"  [github] resolved {version}", file=sys.stderr)

        print(f"  [checksums] fetching checksums for {tool_id}...", file=sys.stderr)
        checksums = get_checksums(release)
        if not checksums:
            print(f"  [warn] no checksums.txt found for {tool_id}", file=sys.stderr)

        archive_digests = build_archive_digests(tool, release, version, checksums)
        install_section = build_install_github_release(tool, version, archive_digests)

    else:
        # For non-binary tools, try to resolve version from GitHub for tracking.
        github_ref = tool["install"].get("github")
        if github_ref and not version_pin:
            release = get_release_info(github_ref)
            if release:
                version = release["tag_name"]
                print(f"  [github] resolved version {version} from {github_ref}", file=sys.stderr)
        if version is None:
            version = "v0.0.0+external"
            print(f"  [warn] no version resolved for {tool_id}, using {version}", file=sys.stderr)

        if method == "go_install":
            install_section = build_install_go(tool)
        elif method == "pip":
            install_section = build_install_pip(tool)
        elif method == "system_package":
            install_section = build_install_system(tool)
        else:
            print(f"  [error] unknown install method '{method}' for {tool_id}", file=sys.stderr)
            return None

    # ── Build manifest ──
    manifest: dict = {
        "registry_schema_version": 1,
        "package_schema_version": 1,
        "tool_id": tool_id,
        "version": version,
        "min_cli_version": MIN_CLI_VERSION,
        "max_cli_version": None,
        "install": install_section,
        "dependencies": tool["dependencies"],
        "post_install_check": {
            "argv": tool["post_install_check"],
            "expect_exit_code": 0,
        },
        "platforms": tool["platforms"],
    }

    # ── Build tarball ──
    tarball = build_tarball(manifest, yaml_content, tool_id)
    pkg_path = PACKAGES_DIR / tool_id / f"{version}.tar.gz"

    if not dry_run:
        pkg_path.parent.mkdir(parents=True, exist_ok=True)
        pkg_path.write_bytes(tarball)
    print(
        f"  [tarball] {'(dry-run) ' if dry_run else ''}wrote {pkg_path} ({len(tarball)} bytes)",
        file=sys.stderr,
    )

    digest = sha256_of(tarball)

    # ── Build index entry ──
    # Determine github owner/repo for the index entry.
    if method == "github_release":
        gh_owner, gh_repo = tool["install"]["github_repo"].split("/", 1)
    elif "github" in tool["install"]:
        gh_ref = tool["install"]["github"]
        gh_owner, gh_repo = gh_ref.split("/", 1)
    else:
        gh_owner, gh_repo = "", tool_id

    entry = {
        "id": tool_id,
        "display_name": tool["display_name"],
        "description": tool["description"],
        "category": tool["category"],
        "tags": tool["tags"],
        "homepage": tool["homepage"],
        "latest_version": version,
        "versions": [
            {
                "version": version,
                "package_schema_version": 1,
                "package_url": f"packages/{tool_id}/{version}.tar.gz",
                "digest": digest,
                "size": len(tarball),
                "status": "active",
                "min_cli_version": MIN_CLI_VERSION,
                "max_cli_version": None,
                "published_at": now,
            }
        ],
        "platforms": tool["platforms"],
        "dependencies": tool["dependencies"],
        "github": {"owner": gh_owner, "repo": gh_repo},
    }

    return entry


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate the celebr8-tools registry.")
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Generate a fresh Ed25519 keypair on first setup.",
    )
    parser.add_argument(
        "--tool",
        metavar="ID",
        action="append",
        dest="tools",
        help="Only process the named tool(s). Repeatable.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip writing files; print what would be done.",
    )
    args = parser.parse_args()

    # Filter tool list when --tool is specified.
    tools_to_run = TOOLS
    if args.tools:
        ids = set(args.tools)
        tools_to_run = [t for t in TOOLS if t["id"] in ids]
        missing = ids - {t["id"] for t in tools_to_run}
        if missing:
            print(f"[error] Unknown tool ID(s): {', '.join(sorted(missing))}", file=sys.stderr)
            sys.exit(1)

    # 1. Key
    key = load_key(bootstrap=args.bootstrap)
    print("\n[pubkey] Rust array for signature.rs:")
    print(pubkey_rust_array(key))
    print()

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # 2. Process each tool
    index_entries: list[dict] = []
    failed: list[str] = []

    for tool in tools_to_run:
        entry = process_tool(tool, now, dry_run=args.dry_run)
        if entry is None:
            failed.append(tool["id"])
        else:
            index_entries.append(entry)

    if failed:
        print(f"\n[warn] {len(failed)} tool(s) failed: {', '.join(failed)}", file=sys.stderr)

    if not index_entries:
        print("[error] No tools produced index entries; aborting.", file=sys.stderr)
        sys.exit(1)

    # 3. Denylist
    denylist = {"schema_version": 1, "entries": []}
    denylist_bytes = json.dumps(denylist, separators=(",", ":")).encode()
    denylist_digest = sha256_of(denylist_bytes)
    if not args.dry_run:
        (BASE_DIR / "denylist.json").write_bytes(denylist_bytes)
    print(f"\n[denylist] digest: {denylist_digest}", file=sys.stderr)

    # 4. Index
    index = {
        "schema_version": 1,
        "generated_at": now,
        "denylist_digest": denylist_digest,
        "tools": index_entries,
    }
    index_bytes = json.dumps(index, indent=2).encode()
    if not args.dry_run:
        (BASE_DIR / "index.json").write_bytes(index_bytes)
    print(f"[index] {'(dry-run) ' if args.dry_run else ''}wrote index.json ({len(index_bytes)} bytes)", file=sys.stderr)

    # 5. Sign
    sig_bytes = sign_index(key, index_bytes)
    if not args.dry_run:
        (BASE_DIR / "index.json.sig").write_bytes(sig_bytes)
    print(f"[sign] {'(dry-run) ' if args.dry_run else ''}wrote index.json.sig (64 bytes)", file=sys.stderr)

    # 6. Summary
    print(f"\n=== UPDATE src/registry/signature.rs with this constant ===")
    print(pubkey_rust_array(key))
    print("=== END ===\n")

    print(f"[done] Registry rebuilt: {len(index_entries)} tool(s), {len(failed)} failed.")
    for entry in index_entries:
        print(f"  {entry['id']:30s} {entry['latest_version']}")
    if failed:
        print(f"\nFailed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
