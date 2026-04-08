# celebr8-tools

Official tool registry for [celebr8-cli](https://github.com/BenWertoski/celebr8-cli).

## Layout

```
index.json           registry index (signed)
index.json.sig       64-byte raw Ed25519 signature over canonical index JSON
denylist.json        revoked/blocked tool versions
packages/
  subfinder/<version>.tar.gz
  httpx/<version>.tar.gz
gen.py               reproducible generator (see below)
```

Each package tarball contains exactly two files:
- `manifest.json` — install spec (method, github_repo, asset_pattern, archive_digests)
- `<tool-id>.yaml` — execution spec consumed by the celebr8 agent runtime

## Regenerating the registry

**Requirements:** Python 3.11+, `cryptography` package (`pip install cryptography`)

### First-time bootstrap

```sh
python3 gen.py
```

The script will generate a new Ed25519 keypair, save it to `.signing_key.pem`
(git-ignored), and print the Rust public key literal to embed in
`src/registry/signature.rs` in celebr8-cli.

### Subsequent runs

```sh
python3 gen.py
```

The script loads the key from, in order:
1. `CELEBR8_REGISTRY_SIGNING_KEY` env var (PEM content — use this in CI/GitHub Actions)
2. `.signing_key.pem` in the repo root (local development)

### Adding a new tool version

1. Update the version constant or release lookup in `gen.py`.
2. Run `python3 gen.py` to rebuild tarballs, re-sign, and rewrite `index.json`.
3. Commit the updated artifacts.

## Signature scheme

`index.json.sig` is a 64-byte raw Ed25519 signature over the canonical JSON
representation of `index.json` (RFC 8785 subset: keys sorted lexicographically,
no whitespace, applied recursively). The matching public key is embedded in
`src/registry/signature.rs` in celebr8-cli.

`denylist.json` is integrity-protected via `denylist_digest` (SHA-256) in
`index.json`, so the signature over `index.json` transitively covers it.
