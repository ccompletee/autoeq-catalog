#!/usr/bin/env python3
"""
AutoEQ Remote Catalog Signer (v1)

Digitally signs catalog.v1.json using an ECDSA P-256 (secp256r1) private key
with SHA-256 (SHA256withECDSA), producing a detached ASN.1 DER signature
verifiable by Android's java.security.Signature.
"""

import argparse
import os
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
        load_der_public_key,
        Encoding,
        PublicFormat,
        PrivateFormat,
        NoEncryption,
    )
except ImportError:
    print("Error: 'cryptography' library is required. Install via: pip install cryptography", file=sys.stderr)
    sys.exit(1)


def generate_keypair(private_pem_path: str, public_pem_path: str, public_der_path: str):
    print(f"Generating new NIST P-256 (secp256r1) keypair...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption()
    )
    pub_pem = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    pub_der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    os.makedirs(os.path.dirname(os.path.abspath(private_pem_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(public_pem_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(public_der_path)), exist_ok=True)

    with open(private_pem_path, "wb") as f:
        f.write(priv_bytes)
    os.chmod(private_pem_path, 0o600)

    with open(public_pem_path, "wb") as f:
        f.write(pub_pem)

    with open(public_der_path, "wb") as f:
        f.write(pub_der)

    print(f"Generated private key: {private_pem_path} (mode 0600)")
    print(f"Generated public key PEM: {public_pem_path}")
    print(f"Generated public key SPKI DER: {public_der_path} ({len(pub_der)} bytes)")


def sign_manifest(manifest_path: str, private_key_path: str, sig_path: str):
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    if not os.path.isfile(private_key_path):
        raise FileNotFoundError(f"Private key file not found: {private_key_path}")

    with open(manifest_path, "rb") as f:
        manifest_bytes = f.read()

    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Sign exact manifest bytes with SHA256withECDSA (ASN.1 DER format)
    signature = private_key.sign(manifest_bytes, ec.ECDSA(hashes.SHA256()))

    # Verify immediately with corresponding public key
    public_key = private_key.public_key()
    public_key.verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))

    os.makedirs(os.path.dirname(os.path.abspath(sig_path)), exist_ok=True)
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"Successfully signed '{manifest_path}'")
    print(f"Signature output: '{sig_path}' ({len(signature)} bytes)")


def verify_manifest(manifest_path: str, sig_path: str, pub_key_path: str):
    with open(manifest_path, "rb") as f:
        manifest_bytes = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    with open(pub_key_path, "rb") as f:
        key_data = f.read()

    try:
        if pub_key_path.endswith(".der"):
            public_key = load_der_public_key(key_data)
        else:
            public_key = load_pem_public_key(key_data)
    except Exception:
        # Fallback to DER if PEM fails
        public_key = load_der_public_key(key_data)

    try:
        public_key.verify(signature, manifest_bytes, ec.ECDSA(hashes.SHA256()))
        print(f"Verification SUCCESS: Signature matches public key '{pub_key_path}'")
        return True
    except Exception as e:
        print(f"Verification FAILED: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Sign or verify AutoEQ catalog manifest (ECDSA P-256)")
    parser.add_argument("--manifest", default="catalog.v1.json", help="Path to manifest JSON")
    parser.add_argument("--private-key", default="private_key.pem", help="Path to EC private key PEM")
    parser.add_argument("--signature", default="catalog.v1.json.sig", help="Path to output signature file")
    parser.add_argument("--public-key-der", help="Path to output or input public key SPKI DER")
    parser.add_argument("--public-key-pem", help="Path to output or input public key PEM")
    parser.add_argument("--generate-keys", action="store_true", help="Generate keypair if private key is missing")
    parser.add_argument("--verify-only", action="store_true", help="Verify signature only")

    args = parser.parse_args()

    if args.verify_only:
        pub_path = args.public_key_der or args.public_key_pem
        if not pub_path:
            print("Error: --verify-only requires --public-key-der or --public-key-pem", file=sys.stderr)
            sys.exit(1)
        valid = verify_manifest(args.manifest, args.signature, pub_path)
        sys.exit(0 if valid else 1)

    if not os.path.exists(args.private_key):
        if args.generate_keys:
            key_dir = os.path.dirname(args.private_key) or "."
            pub_pem = args.public_key_pem or os.path.join(key_dir, "public_key.pem")
            pub_der = args.public_key_der or os.path.join(key_dir, "public_key.der")
            generate_keypair(args.private_key, pub_pem, pub_der)
        else:
            print(f"Error: Private key '{args.private_key}' not found. Use --generate-keys to generate a new keypair.", file=sys.stderr)
            sys.exit(1)
    elif args.generate_keys:
        print(f"Private key '{args.private_key}' already exists, skipping generation.")

    sign_manifest(args.manifest, args.private_key, args.signature)

    if args.public_key_der or args.public_key_pem:
        with open(args.private_key, "rb") as f:
            priv = load_pem_private_key(f.read(), password=None)
        pub_key = priv.public_key()
        if args.public_key_pem:
            pub_pem = pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            os.makedirs(os.path.dirname(os.path.abspath(args.public_key_pem)), exist_ok=True)
            with open(args.public_key_pem, "wb") as f:
                f.write(pub_pem)
            print(f"Exported public key PEM: {args.public_key_pem}")
        if args.public_key_der:
            pub_der = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            os.makedirs(os.path.dirname(os.path.abspath(args.public_key_der)), exist_ok=True)
            with open(args.public_key_der, "wb") as f:
                f.write(pub_der)
            print(f"Exported public key SPKI DER: {args.public_key_der}")


if __name__ == "__main__":
    main()
