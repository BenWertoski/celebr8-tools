#!/usr/bin/env python3
"""
Registry generator for BenWertoski/celebr8-tools.

Produces:
  denylist.json
  index.json
  index.json.sig   (64 raw bytes, Ed25519 signature over canonical JSON)
  packages/subfinder/<version>.tar.gz
  packages/httpx/<version>.tar.gz

Key loading order (first wins):
  1. CELEBR8_REGISTRY_SIGNING_KEY env var  — PEM content of the private key
  2. .signing_key.pem in the repo root     — git-ignored local file

The signing key is NEVER committed to this repo. Missing key material is a
hard error — run with --bootstrap to generate a fresh keypair on first setup.

Tarballs are deterministic: gzip mtime=0, tar entry mtime=0, JSON keys sorted.
Identical inputs produce bit-identical packages and therefore identical digests.
Only index.json's generated_at and the signature change between runs.
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

# ── Pinned tool versions ───────────────────────────────────────────────────────
# Set a version string to pin to that exact release.
# Set to None to resolve the latest release from GitHub (and update the pin).
SUBFINDER_VERSION: str | None = "v2.13.0"
HTTPX_VERSION: str | None = "v1.9.0"

# ── Key management ─────────────────────────────────────────────────────────────

KEY_FILE = Path(__file__).parent / ".signing_key.pem"
_KEY_ENV = "CELEBR8_REGISTRY_SIGNING_KEY"


def load_key(bootstrap: bool = False) -> Ed25519PrivateKey:
    """Load the signing key from env var or local file.

    Args:
        bootstrap: If True and no key is found, generate a new keypair, save
                   it to .signing_key.pem, and print the Rust public key literal.
                   If False (default) and no key is found, exit with an error.

    Raises:
        SystemExit: When no key material is available and bootstrap=False.
    """
    # 1. Env var (CI / GitHub Actions secret)
    pem_env = os.environ.get(_KEY_ENV)
    if pem_env:
        key = serialization.load_pem_private_key(pem_env.encode(), password=None)
        print(f"[keygen] Loaded key from {_KEY_ENV} env var", file=sys.stderr)
        return key  # type: ignore[return-value]

    # 2. Local git-ignored file
    if KEY_FILE.exists():
        pem = KEY_FILE.read_bytes()
        key = serialization.load_pem_private_key(pem, password=None)
        print(f"[keygen] Loaded key from {KEY_FILE}", file=sys.stderr)
        return key  # type: ignore[return-value]

    # 3. No key found
    if not bootstrap:
        print(
            f"[error] No signing key found.\n"
            f"  Set {_KEY_ENV} env var (PEM content) or place key at {KEY_FILE}.\n"
            f"  To generate a fresh keypair on first setup: python3 gen.py --bootstrap",
            file=sys.stderr,
        )
        sys.exit(1)

    # Bootstrap: generate and save
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
    """Return the Rust array literal for the 32-byte public key."""
    pub = key.public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert len(raw) == 32
    hex_pairs = [f"0x{b:02x}" for b in raw]
    # Format in two rows of 16
    row1 = ", ".join(hex_pairs[:16])
    row2 = ", ".join(hex_pairs[16:])
    return (
        "pub const REGISTRY_PUBLIC_KEY: [u8; 32] = [\n"
        f"    {row1},\n"
        f"    {row2},\n"
        "];"
    )


# ── Canonical JSON (matches Rust impl) ────────────────────────────────────────

def canonical_json_bytes(value) -> bytes:
    """Produce canonical JSON bytes with sorted object keys, no whitespace."""
    if value is None:
        return b"null"
    elif isinstance(value, bool):
        return b"true" if value else b"false"
    elif isinstance(value, int):
        return str(value).encode()
    elif isinstance(value, float):
        return str(value).encode()
    elif isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    elif isinstance(value, list):
        parts = [canonical_json_bytes(v) for v in value]
        return b"[" + b",".join(parts) + b"]"
    elif isinstance(value, dict):
        sorted_items = sorted(value.items(), key=lambda x: x[0])
        parts = []
        for k, v in sorted_items:
            key_bytes = json.dumps(k, ensure_ascii=False, separators=(',', ':')).encode()
            parts.append(key_bytes + b":" + canonical_json_bytes(v))
        return b"{" + b",".join(parts) + b"}"
    else:
        raise TypeError(f"Unsupported type: {type(value)}")


# ── Signing ────────────────────────────────────────────────────────────────────

def sign_index(key: Ed25519PrivateKey, index_json_bytes: bytes) -> bytes:
    """Sign canonical JSON bytes of index.json. Returns 64 raw signature bytes."""
    value = json.loads(index_json_bytes)
    canonical = canonical_json_bytes(value)
    sig = key.sign(canonical)
    assert len(sig) == 64
    return sig


# ── SHA-256 helpers ────────────────────────────────────────────────────────────

def sha256_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ── GitHub release info ────────────────────────────────────────────────────────

def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "celebr8-registry-gen/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "celebr8-registry-gen/1.0"})
    print(f"  [download] {url}", file=sys.stderr)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def get_release_info(repo: str, tag: str | None = None) -> dict:
    if tag:
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    else:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
    return fetch_json(url)


def get_checksums(release: dict) -> dict[str, str]:
    """Parse checksums.txt from a release. Returns {filename: sha256_hex}."""
    assets = release.get("assets", [])
    csum_asset = next(
        (a for a in assets if a["name"].endswith("_checksums.txt") or a["name"] == "checksums.txt"),
        None,
    )
    if not csum_asset:
        return {}
    text = fetch_bytes(csum_asset["browser_download_url"]).decode()
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            digest, name = parts
            result[name] = digest
    return result


# ── Package tarball builder ────────────────────────────────────────────────────

def build_tarball(manifest: dict, yaml_content: str, tool_id: str) -> bytes:
    """Build a deterministic tar.gz with exactly manifest.json and <tool_id>.yaml.

    Determinism guarantees:
    - gzip header mtime=0 (via GzipFile(mtime=0))
    - tar entry mtime=0 on every TarInfo
    - manifest.json serialized with sorted keys and no trailing whitespace variation

    Identical inputs produce bit-identical output, so digests are stable across runs.
    """
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w|") as tf:
            # manifest.json — sort_keys ensures deterministic field order
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
            info = tarfile.TarInfo(name="manifest.json")
            info.size = len(manifest_bytes)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(manifest_bytes))

            # <tool_id>.yaml
            yaml_bytes = yaml_content.encode()
            info = tarfile.TarInfo(name=f"{tool_id}.yaml")
            info.size = len(yaml_bytes)
            info.mtime = 0
            info.type = tarfile.REGTYPE
            tf.addfile(info, io.BytesIO(yaml_bytes))

    return buf.getvalue()


# ── Tool specs ────────────────────────────────────────────────────────────────

SUBFINDER_YAML = """\
id: subfinder
version: 1
name: Subfinder
description: Fast passive subdomain enumeration tool
binary: subfinder
category: recon
risk_level: low
requires_scope: true
requires_confirmation: false
max_runtime_secs: 300
tags: [recon, subdomain, passive]

verify:
  argv: ["subfinder", "-version"]

ai_context:
  summary: >
    Use Subfinder to enumerate subdomains passively for a scoped domain.
    It queries multiple OSINT sources without sending requests to the target.
  when_to_use:
    - initial recon phase before active scanning
    - building a subdomain inventory for a target domain
    - discovering asset scope before web/API testing
  expected_output: text
  follow_up_hints:
    - pipe discovered subdomains to httpx for live host detection
    - store subdomain list as evidence artifact before proceeding

policy:
  allow_in_auto: true
  approval_mode: inherit
  capture_stdout: true
  capture_stderr: true
  retain_artifacts: true
  redact_patterns: []

parameters:
  - name: domain
    type: target
    required: true
    positional: false
    flag: "-d"
    description: Target domain to enumerate subdomains for

  - name: output
    type: string
    required: false
    flag: "-o"
    description: Output file path for discovered subdomains

  - name: silent
    type: bool
    required: false
    flag: "-silent"
    description: Only print subdomains in output

artifacts:
  - kind: raw_stdout
    label: subdomain-list
"""

HTTPX_YAML = """\
id: httpx
version: 1
name: httpx
description: Fast and multi-purpose HTTP toolkit for web reconnaissance
binary: httpx
category: web
risk_level: low
requires_scope: true
requires_confirmation: false
max_runtime_secs: 300
tags: [web, recon, http, alive-check]

verify:
  argv: ["httpx", "-version"]

ai_context:
  summary: >
    Use httpx to probe a list of hosts or URLs for live HTTP/HTTPS services,
    status codes, titles, and technology fingerprints.
  when_to_use:
    - after subdomain enumeration to identify live web hosts
    - checking which discovered hosts are serving HTTP/HTTPS
    - gathering basic web metadata (status, title, tech) at scale
  expected_output: text
  follow_up_hints:
    - combine with subfinder output for full recon pipeline
    - filter 200/302 responses for further web testing

policy:
  allow_in_auto: true
  approval_mode: inherit
  capture_stdout: true
  capture_stderr: true
  retain_artifacts: true
  redact_patterns: []

parameters:
  - name: list
    type: string
    required: false
    flag: "-l"
    description: Input file containing list of hosts or URLs to probe

  - name: url
    type: target
    required: false
    positional: false
    flag: "-u"
    description: Single target URL or host to probe

  - name: status_code
    type: bool
    required: false
    flag: "-sc"
    description: Display response status code

  - name: title
    type: bool
    required: false
    flag: "-title"
    description: Display page title

  - name: tech_detect
    type: bool
    required: false
    flag: "-tech-detect"
    description: Enable technology detection

  - name: silent
    type: bool
    required: false
    flag: "-silent"
    description: Silent mode, only print results

artifacts:
  - kind: raw_stdout
    label: http-probe-results
"""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate the celebr8-tools registry.")
    parser.add_argument(
        "--bootstrap",
        action="store_true",
        help="Generate a fresh Ed25519 keypair on first setup (hard error otherwise).",
    )
    args = parser.parse_args()

    base_dir = Path(__file__).parent
    cli_version = "0.1.0"

    # 1. Key
    key = load_key(bootstrap=args.bootstrap)
    print("\n[pubkey] Rust array for signature.rs:")
    print(pubkey_rust_array(key))
    print()

    # 2. Fetch release info (use pinned versions when set)
    print(
        f"[github] Resolving subfinder "
        f"{'pinned ' + SUBFINDER_VERSION if SUBFINDER_VERSION else 'latest'}...",
        file=sys.stderr,
    )
    sf_release = get_release_info("projectdiscovery/subfinder", SUBFINDER_VERSION)
    sf_version = sf_release["tag_name"]
    print(f"[github] subfinder: {sf_version}", file=sys.stderr)

    print(
        f"[github] Resolving httpx "
        f"{'pinned ' + HTTPX_VERSION if HTTPX_VERSION else 'latest'}...",
        file=sys.stderr,
    )
    hx_release = get_release_info("projectdiscovery/httpx", HTTPX_VERSION)
    hx_version = hx_release["tag_name"]
    print(f"[github] httpx: {hx_version}", file=sys.stderr)

    # 3. Checksums (sha256 of each platform zip, from checksums.txt)
    print("[checksums] Fetching subfinder checksums...", file=sys.stderr)
    sf_checksums = get_checksums(sf_release)
    print("[checksums] Fetching httpx checksums...", file=sys.stderr)
    hx_checksums = get_checksums(hx_release)

    # Platform zip filenames for the archive_digests map
    # Key in manifest: "darwin/amd64", "darwin/arm64", "linux/amd64"
    # Zip filename: <tool>_<version>_<os>_<arch>.zip
    # (version tag includes 'v' prefix in filename)
    platforms = [
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
    ]

    # OS name used in zip filename (archive_digests map key uses 'darwin', zip uses 'macOS')
    OS_ASSET_NAME = {"darwin": "macOS", "linux": "linux", "windows": "windows"}

    def zip_name(tool: str, version_no_v: str, os_: str, arch: str) -> str:
        asset_os = OS_ASSET_NAME.get(os_, os_)
        return f"{tool}_{version_no_v}_{asset_os}_{arch}.zip"

    def archive_digests(tool: str, version: str, checksums: dict) -> dict:
        version_no_v = version.lstrip("v")
        result = {}
        for os_, arch in platforms:
            name = zip_name(tool, version_no_v, os_, arch)
            digest = checksums.get(name)
            if digest:
                result[f"{os_}/{arch}"] = f"sha256:{digest}"
            else:
                print(f"  [warn] no checksum for {name}", file=sys.stderr)
        return result

    sf_archive_digests = archive_digests("subfinder", sf_version, sf_checksums)
    hx_archive_digests = archive_digests("httpx", hx_version, hx_checksums)

    print(f"[digests] subfinder platforms: {list(sf_archive_digests.keys())}", file=sys.stderr)
    print(f"[digests] httpx platforms: {list(hx_archive_digests.keys())}", file=sys.stderr)

    # 4. Build manifests
    # NOTE: asset_pattern uses {version_no_v} (strips leading 'v') and {os} which the
    # lifecycle code maps darwin → macOS. So the expanded filename for darwin/arm64 is:
    #   subfinder_2.13.0_macOS_arm64.zip
    sf_manifest = {
        "registry_schema_version": 1,
        "package_schema_version": 1,
        "tool_id": "subfinder",
        "version": sf_version,
        "min_cli_version": cli_version,
        "max_cli_version": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/subfinder",
            "binary_name": "subfinder",
            "asset_pattern": "subfinder_{version_no_v}_{os}_{arch}.zip",
            "archive_digests": sf_archive_digests,
        },
        "dependencies": [],
        "post_install_check": {
            "argv": ["subfinder", "-version"],
            "expect_exit_code": 0,
        },
        "platforms": [f"{os_}/{arch}" for os_, arch in platforms],
    }

    hx_manifest = {
        "registry_schema_version": 1,
        "package_schema_version": 1,
        "tool_id": "httpx",
        "version": hx_version,
        "min_cli_version": cli_version,
        "max_cli_version": None,
        "install": {
            "method": "github_release",
            "github_repo": "projectdiscovery/httpx",
            "binary_name": "httpx",
            "asset_pattern": "httpx_{version_no_v}_{os}_{arch}.zip",
            "archive_digests": hx_archive_digests,
        },
        "dependencies": [],
        "post_install_check": {
            "argv": ["httpx", "-version"],
            "expect_exit_code": 0,
        },
        "platforms": [f"{os_}/{arch}" for os_, arch in platforms],
    }

    # 5. Build tarballs
    sf_tarball = build_tarball(sf_manifest, SUBFINDER_YAML, "subfinder")
    hx_tarball = build_tarball(hx_manifest, HTTPX_YAML, "httpx")

    sf_pkg_path = base_dir / "packages" / "subfinder" / f"{sf_version}.tar.gz"
    hx_pkg_path = base_dir / "packages" / "httpx" / f"{hx_version}.tar.gz"
    sf_pkg_path.parent.mkdir(parents=True, exist_ok=True)
    hx_pkg_path.parent.mkdir(parents=True, exist_ok=True)
    sf_pkg_path.write_bytes(sf_tarball)
    hx_pkg_path.write_bytes(hx_tarball)
    print(f"[tarball] wrote {sf_pkg_path} ({len(sf_tarball)} bytes)", file=sys.stderr)
    print(f"[tarball] wrote {hx_pkg_path} ({len(hx_tarball)} bytes)", file=sys.stderr)

    sf_digest = sha256_of(sf_tarball)
    hx_digest = sha256_of(hx_tarball)

    # 6. Denylist
    denylist = {"schema_version": 1, "entries": []}
    denylist_bytes = json.dumps(denylist, separators=(",", ":")).encode()
    denylist_digest = sha256_of(denylist_bytes)
    (base_dir / "denylist.json").write_bytes(denylist_bytes)
    print(f"[denylist] digest: {denylist_digest}", file=sys.stderr)

    # 7. Index
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    index = {
        "schema_version": 1,
        "generated_at": now,
        "denylist_digest": denylist_digest,
        "tools": [
            {
                "id": "subfinder",
                "display_name": "Subfinder",
                "description": "Fast passive subdomain enumeration tool",
                "category": "recon",
                "tags": ["recon", "subdomain", "passive"],
                "homepage": "https://github.com/projectdiscovery/subfinder",
                "latest_version": sf_version,
                "versions": [
                    {
                        "version": sf_version,
                        "package_schema_version": 1,
                        "package_url": f"packages/subfinder/{sf_version}.tar.gz",
                        "digest": sf_digest,
                        "size": len(sf_tarball),
                        "status": "active",
                        "min_cli_version": cli_version,
                        "max_cli_version": None,
                        "published_at": now,
                    }
                ],
                "platforms": ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"],
                "dependencies": [],
                "github": {
                    "owner": "projectdiscovery",
                    "repo": "subfinder",
                },
            },
            {
                "id": "httpx",
                "display_name": "httpx",
                "description": "Fast and multi-purpose HTTP toolkit for web reconnaissance",
                "category": "web",
                "tags": ["web", "recon", "http", "alive-check"],
                "homepage": "https://github.com/projectdiscovery/httpx",
                "latest_version": hx_version,
                "versions": [
                    {
                        "version": hx_version,
                        "package_schema_version": 1,
                        "package_url": f"packages/httpx/{hx_version}.tar.gz",
                        "digest": hx_digest,
                        "size": len(hx_tarball),
                        "status": "active",
                        "min_cli_version": cli_version,
                        "max_cli_version": None,
                        "published_at": now,
                    }
                ],
                "platforms": ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"],
                "dependencies": [],
                "github": {
                    "owner": "projectdiscovery",
                    "repo": "httpx",
                },
            },
        ],
    }

    index_bytes = json.dumps(index, indent=2).encode()
    (base_dir / "index.json").write_bytes(index_bytes)
    print(f"[index] wrote index.json ({len(index_bytes)} bytes)", file=sys.stderr)

    # 8. Sign
    sig_bytes = sign_index(key, index_bytes)
    (base_dir / "index.json.sig").write_bytes(sig_bytes)
    print(f"[sign] wrote index.json.sig (64 bytes)", file=sys.stderr)

    # 9. Output Rust key update
    print("\n=== UPDATE src/registry/signature.rs with this constant ===")
    print(pubkey_rust_array(key))
    print("=== END ===\n")

    print("[done] Registry artifacts built successfully.")
    print(f"  subfinder: {sf_version}")
    print(f"  httpx:     {hx_version}")
    print(f"  denylist:  {denylist_digest}")


if __name__ == "__main__":
    main()
