# AutoEQ Remote Catalog Tools

Tools for generating, validating, and cryptographically signing the `catalog.v1.json` remote manifest and associated EQ profile files for IfSilence-DSP, based on [jaakkopasanen/AutoEq](https://github.com/jaakkopasanen/AutoEq).

---

## 1. Overview

The remote AutoEQ system uses a detached ECDSA P-256 signature over the uncompressed `catalog.v1.json` manifest. The Android app authenticates the manifest using `AutoEqManifestSignatureVerifier` and parses it with `AutoEqManifestParser` before caching or downloading profile files.

```
Upstream jaakkopasanen/AutoEq
          │
          ▼
┌───────────────────────────┐
│ generate_catalog.py       │ ──► dist/catalog.v1.json
│ (scan results, sanitize,  │ ──► dist/profiles/...
│  enforce size limits)     │
└───────────────────────────┘
          │
          ▼
┌───────────────────────────┐
│ sign_catalog.py / openssl │ ──► dist/catalog.v1.json.sig
│ (ECDSA P-256 / SHA256)    │
└───────────────────────────┘
          │
          ▼
  Hosting (CDN / R2 / Pages)
```

---

## 2. Directory Layout & Tools

- `generate_catalog.py`: Scans `results/`, normalizes names, extracts `FixedBandEQ.txt` & `ParametricEQ.txt`, derives `remote:` IDs, and outputs deterministic JSON.
- `sign_catalog.py`: Signs the manifest using ECDSA P-256 (`SHA256withECDSA`), outputting the ASN.1 DER signature and optional SPKI public key.
- `keygen.sh`: Shell helper using OpenSSL to generate `private_key.pem`, `public_key.pem`, and `public_key.der`.
- `.gitignore`: Prevents accidental commits of private keys or build outputs.

---

## 3. Prerequisites

```bash
python3 -m pip install cryptography
# OpenSSL is also supported for shell automation
```

---

## 4. Key Generation & Management

### Generating Keys
Run `keygen.sh` or use `sign_catalog.py`:
```bash
bash keygen.sh ./keys
```
This generates:
- `private_key.pem`: PKCS#8 private key (**NEVER commit to version control**, restrict to `chmod 600`).
- `public_key.pem`: X.509 public key in PEM format.
- `public_key.der`: X.509 SubjectPublicKeyInfo (SPKI) in binary DER format (used directly by Android app).

### Zero-Downtime Key Rotation Protocol
The Android client's `AutoEqManifestSignatureVerifier` supports up to 2 active public keys simultaneously:
1. **Preparation**: Generate a new keypair (`key_v2`).
2. **Dual-Key App Release**: Add `key_v2.der` as the secondary public key in `AutoEqRemoteConfig` alongside `key_v1.der`. Release the app update to users.
3. **Switch Signer**: Configure CI / signing pipeline to sign new manifests using `key_v2`. Both newly updated and transition clients verify successfully.
4. **Retirement**: In the next release cycle, deprecate `key_v1` and keep `key_v2` as the primary key.

---

## 5. Generating & Publishing the Catalog

### Step 1: Sparse Checkout AutoEq
```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/jaakkopasanen/AutoEq.git autoeq-source
cd autoeq-source
git sparse-checkout set results INDEX.md
git checkout <COMMIT_SHA_OR_TAG>
cd ..
```

### Step 2: Generate Catalog & Export Profiles
```bash
python3 tools/autoeq-catalog/generate_catalog.py \
    --results-dir autoeq-source/results \
    --index-file autoeq-source/INDEX.md \
    --output dist/catalog.v1.json \
    --export-profiles-dir dist \
    --pretty
```

### Step 3: Sign Manifest
```bash
python3 tools/autoeq-catalog/sign_catalog.py \
    --manifest dist/catalog.v1.json \
    --private-key keys/private_key.pem \
    --signature dist/catalog.v1.json.sig \
    --public-key-der dist/public_key.der
```

### Step 4: Verify Signature Locally
```bash
python3 tools/autoeq-catalog/sign_catalog.py \
    --manifest dist/catalog.v1.json \
    --signature dist/catalog.v1.json.sig \
    --public-key-der dist/public_key.der \
    --verify-only
```

---

## 6. Hosting Infrastructure

The generated `dist/` directory can be deployed to any static HTTPS host or CDN:
- **Cloudflare R2 / AWS S3**: Backed by a custom CDN domain (e.g. `https://autoeq.ifsilence.com/catalog.v1.json`).
- **GitHub Pages / Releases**: Suitable for staging and public release hosting.
Ensure standard caching headers are configured:
- `catalog.v1.json` & `catalog.v1.json.sig`: `Cache-Control: public, max-age=3600, must-revalidate` (with ETag support).
- `profiles/**/*.txt`: `Cache-Control: public, max-age=31536000, immutable` (since paths include content hashes / immutable slugs).
