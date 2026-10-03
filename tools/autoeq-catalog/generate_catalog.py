#!/usr/bin/env python3
"""
AutoEQ Remote Catalog Generator (v1)

Scans the jaakkopasanen/AutoEq results directory, validates metadata and EQ files
according to the AutoEQ Remote Catalog Specification (v1), derives stable remote IDs,
and deterministically generates catalog.v1.json.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1
MAX_MANIFEST_SIZE_BYTES = 8 * 1024 * 1024  # 8 MB
MAX_CATALOG_ENTRIES = 20_000
MAX_NAME_LENGTH = 128
MAX_FILE_SIZE_BYTES = 100 * 1024  # 100 KB
ALLOWED_PATH_REGEX = re.compile(r"^[a-zA-Z0-9_\-./]+$")
BIDI_CHARS = {0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}


def sanitize_name(name: str) -> str:
    """Sanitizes headphone display name by stripping ASCII control and BiDi chars."""
    cleaned = "".join(
        ch for ch in name
        if not (0 <= ord(ch) <= 31 or ord(ch) == 127 or ord(ch) in BIDI_CHARS)
    )
    return cleaned[:MAX_NAME_LENGTH]


def slugify_path_segment(segment: str) -> str:
    """Converts a segment (author, target, headphone name) into a safe path segment without dots or invalid chars."""
    slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", segment)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug.lower() if slug else "unnamed"


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def compute_remote_id(author: str, target: str, name: str) -> str:
    """Formula: 'remote:' + hex(sha256(author/target/name))"""
    key = f"{author}/{target}/{name}".encode("utf-8")
    return f"remote:{hashlib.sha256(key).hexdigest().lower()}"


def resolve_commit_metadata(repo_dir: str, commit_sha: Optional[str] = None) -> Tuple[str, Optional[int], Optional[str]]:
    """Resolves commit SHA, unix timestamp, and ISO-8601 UTC timestamp from git."""
    try:
        cmd = ["git", "rev-parse", "HEAD"] if not commit_sha else ["git", "rev-parse", commit_sha]
        resolved_sha = subprocess.check_output(cmd, cwd=repo_dir, stderr=subprocess.DEVNULL).decode("utf-8").strip()
        ts_str = subprocess.check_output(
            ["git", "show", "-s", "--format=%ct", resolved_sha],
            cwd=repo_dir,
            stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
        commit_ts = int(ts_str)
        commit_iso = datetime.datetime.fromtimestamp(commit_ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return resolved_sha, commit_ts, commit_iso
    except Exception:
        pass
    fallback_sha = commit_sha if commit_sha and len(commit_sha) == 40 else "0000000000000000000000000000000000000000"
    return fallback_sha, None, None


def parse_index_md(index_path: str) -> Dict[Tuple[str, str, str], str]:
    """Parses AutoEq root INDEX.md to map (author, target, name_lower) -> rig."""
    rig_map = {}
    if not os.path.isfile(index_path):
        return rig_map
    try:
        with open(index_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.startswith("|") or "---" in line or "Headphone" in line:
                    continue
                parts = [p.strip() for p in line.split("|")[1:-1]]
                # AutoEq INDEX.md columns: Headphone | Source | Target | Form | Rig | ...
                if len(parts) >= 5:
                    name, author, target, _, rig = parts[:5]
                    m = re.match(r"^\[(.*?)\]", name)
                    if m:
                        name = m.group(1).strip()
                    clean_name = sanitize_name(name)
                    if rig and rig.lower() not in {"-", "none", "unknown", ""}:
                        key = (author.strip().lower(), target.strip().lower(), clean_name.strip().lower())
                        rig_map[key] = rig.strip()
    except Exception:
        pass
    return rig_map


def extract_rig(
    model_dir: str,
    author: str,
    target: str,
    name: str,
    index_rigs: Optional[Dict[Tuple[str, str, str], str]] = None
) -> Optional[str]:
    """Extracts measurement rig metadata from index map, README.md, or directory context."""
    if index_rigs:
        key = (author.strip().lower(), target.strip().lower(), name.strip().lower())
        if key in index_rigs:
            return index_rigs[key][:64]

    # Check model_dir/README.md
    readme_path = os.path.join(model_dir, "README.md")
    if os.path.isfile(readme_path):
        try:
            with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(4096)
                m = re.search(r"(?i)\b(?:measurement\s*(?:system|rig)?|rig)\s*:\s*([A-Za-z0-9_\-/\s]+)", content)
                if m:
                    rig_val = m.group(1).strip().split("\n")[0].strip("*_ ")
                    if rig_val and rig_val.lower() not in {"-", "none", "unknown"}:
                        return rig_val[:64]
                m_known = re.search(r"\b(GRAS\s*45CA[A-Z0-9\-]*|711|IEC[0-9]+|Type\s*4128C?|KB0065|5128)\b", content, re.IGNORECASE)
                if m_known:
                    return m_known.group(1).strip()[:64]
        except Exception:
            pass

    # Contextual hints in target or model name (e.g. "711", "GRAS 45CA")
    for text in (target, name):
        m_hint = re.search(r"\b(GRAS\s*45CA[A-Z0-9\-]*|711|5128)\b", text, re.IGNORECASE)
        if m_hint:
            return m_hint.group(1).strip()[:64]

    return None


def process_eq_file(
    file_path: str,
    kind: str,
    relative_path: str
) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(file_path):
        return None

    size = os.path.getsize(file_path)
    if size <= 0 or size > MAX_FILE_SIZE_BYTES:
        print(f"Skipping {file_path}: invalid size ({size} bytes)", file=sys.stderr)
        return None

    with open(file_path, "rb") as f:
        content = f.read()

    if not ALLOWED_PATH_REGEX.match(relative_path):
        print(f"Error: path '{relative_path}' violates path whitelist regex", file=sys.stderr)
        return None

    return {
        "kind": kind,
        "path": relative_path,
        "sha256": compute_sha256(content),
        "size": size,
    }


def scan_results_dir(
    results_dir: str,
    export_profiles_dir: Optional[str] = None,
    index_file: Optional[str] = None,
    default_license: str = "MIT"
) -> List[Dict[str, Any]]:
    entries = []
    seen_ids = set()
    seen_paths = set()

    # results structure: <results_dir>/<author>/<target>/<headphone_name>/
    if not os.path.isdir(results_dir):
        raise ValueError(f"Results directory '{results_dir}' does not exist")

    # Resolve index file if available
    resolved_index = index_file
    if not resolved_index:
        candidate = os.path.join(results_dir, "..", "INDEX.md")
        if os.path.isfile(candidate):
            resolved_index = candidate
        elif os.path.isfile(os.path.join(results_dir, "INDEX.md")):
            resolved_index = os.path.join(results_dir, "INDEX.md")

    index_rigs = parse_index_md(resolved_index) if resolved_index else None

    for author in sorted(os.listdir(results_dir)):
        author_dir = os.path.join(results_dir, author)
        if not os.path.isdir(author_dir) or author.startswith("."):
            continue

        for target in sorted(os.listdir(author_dir)):
            target_dir = os.path.join(author_dir, target)
            if not os.path.isdir(target_dir) or target.startswith("."):
                continue

            for model in sorted(os.listdir(target_dir)):
                model_dir = os.path.join(target_dir, model)
                if not os.path.isdir(model_dir) or model.startswith("."):
                    continue

                clean_name = sanitize_name(model)
                if not clean_name:
                    continue

                entry_id = compute_remote_id(author, target, clean_name)
                if entry_id in seen_ids:
                    print(f"Duplicate entry ID {entry_id} for '{clean_name}', skipping duplicate", file=sys.stderr)
                    continue

                author_slug = slugify_path_segment(author)
                target_slug = slugify_path_segment(target)
                model_slug = slugify_path_segment(clean_name)
                base_profile_path = f"profiles/{author_slug}/{target_slug}/{model_slug}"
                if base_profile_path in seen_paths:
                    base_profile_path = f"{base_profile_path}_{entry_id[7:15]}"
                seen_paths.add(base_profile_path)

                files = []

                # Find EQ files in model_dir matching *FixedBandEQ.txt or *ParametricEQ.txt
                fixed_band_path = None
                parametric_path = None
                if os.path.isdir(model_dir):
                    for fname in os.listdir(model_dir):
                        if fname.endswith("FixedBandEQ.txt"):
                            fixed_band_path = os.path.join(model_dir, fname)
                        elif fname.endswith("ParametricEQ.txt"):
                            parametric_path = os.path.join(model_dir, fname)

                # 1. FixedBandEQ.txt
                if fixed_band_path and os.path.exists(fixed_band_path):
                    rel_path = f"{base_profile_path}/FixedBandEQ.txt"
                    file_info = process_eq_file(fixed_band_path, "FIXED_BAND_TXT", rel_path)
                    if file_info:
                        files.append(file_info)
                        if export_profiles_dir:
                            dest = os.path.join(export_profiles_dir, rel_path)
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            with open(fixed_band_path, "rb") as src_f, open(dest, "wb") as dst_f:
                                dst_f.write(src_f.read())

                # 2. ParametricEQ.txt
                if parametric_path and os.path.exists(parametric_path):
                    rel_path = f"{base_profile_path}/ParametricEQ.txt"
                    file_info = process_eq_file(parametric_path, "PARAMETRIC_EQ_TXT", rel_path)
                    if file_info:
                        files.append(file_info)
                        if export_profiles_dir:
                            dest = os.path.join(export_profiles_dir, rel_path)
                            os.makedirs(os.path.dirname(dest), exist_ok=True)
                            with open(parametric_path, "rb") as src_f, open(dest, "wb") as dst_f:
                                dst_f.write(src_f.read())

                if not files:
                    continue

                rig = extract_rig(model_dir, author, target, clean_name, index_rigs=index_rigs)

                seen_ids.add(entry_id)
                entries.append({
                    "id": entry_id,
                    "name": clean_name,
                    "author": author,
                    "target": target,
                    "rig": rig,
                    "license": default_license,
                    "files": files,
                })

    # Sort deterministically by entry ID
    entries.sort(key=lambda e: e["id"])
    return entries


def generate_manifest(
    results_dir: str,
    source_commit: Optional[str] = None,
    catalog_version: Optional[int] = None,
    generated_at: Optional[str] = None,
    export_profiles_dir: Optional[str] = None,
    index_file: Optional[str] = None,
    default_license: str = "MIT"
) -> Dict[str, Any]:
    resolved_sha, commit_ts, commit_iso = resolve_commit_metadata(results_dir, source_commit)
    final_source_commit = source_commit if source_commit and len(source_commit) == 40 else resolved_sha

    if catalog_version is None:
        catalog_version = commit_ts if commit_ts is not None else int(datetime.datetime.now(datetime.timezone.utc).timestamp())

    if generated_at is None:
        generated_at = commit_iso if commit_iso is not None else datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    entries = scan_results_dir(
        results_dir,
        export_profiles_dir=export_profiles_dir,
        index_file=index_file,
        default_license=default_license
    )

    if len(entries) > MAX_CATALOG_ENTRIES:
        raise ValueError(f"Generated {len(entries)} entries, exceeding maximum limit {MAX_CATALOG_ENTRIES}")

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "catalogVersion": catalog_version,
        "generatedAt": generated_at,
        "sourceCommit": final_source_commit,
        "entries": entries,
    }
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate AutoEQ remote catalog manifest (v1)")
    parser.add_argument("--results-dir", required=True, help="Path to AutoEq results directory")
    parser.add_argument("--output", "-o", default="catalog.v1.json", help="Output path for catalog manifest JSON")
    parser.add_argument("--source-commit", help="Explicit source AutoEq git commit SHA")
    parser.add_argument("--catalog-version", type=int, help="Catalog revision version (default: commit timestamp or unix epoch)")
    parser.add_argument("--generated-at", help="Explicit ISO-8601 generated timestamp (default: commit date or UTC now)")
    parser.add_argument("--index-file", help="Path to AutoEq INDEX.md to parse rig and metadata")
    parser.add_argument("--license", default="MIT", help="License string for generated catalog entries (default: MIT)")
    parser.add_argument("--export-profiles-dir", help="Directory to export sanitized profile files for hosting")
    parser.add_argument("--pretty", action="store_true", help="Format JSON with 2 spaces indentation")

    args = parser.parse_args()

    manifest = generate_manifest(
        results_dir=args.results_dir,
        source_commit=args.source_commit,
        catalog_version=args.catalog_version,
        generated_at=args.generated_at,
        export_profiles_dir=args.export_profiles_dir,
        index_file=args.index_file,
        default_license=args.license
    )

    indent = 2 if args.pretty else None
    json_bytes = json.dumps(manifest, indent=indent, ensure_ascii=False).encode("utf-8")

    if len(json_bytes) > MAX_MANIFEST_SIZE_BYTES:
        raise ValueError(f"Manifest size {len(json_bytes)} bytes exceeds maximum {MAX_MANIFEST_SIZE_BYTES} bytes")

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "wb") as f:
        f.write(json_bytes)

    print(f"Successfully generated catalog manifest: {args.output}")
    print(f"Total entries: {len(manifest['entries'])}")
    print(f"Manifest size: {len(json_bytes)} bytes")
    print(f"Source commit: {manifest['sourceCommit']}")
    print(f"Catalog version: {manifest['catalogVersion']}")
    print(f"Generated at: {manifest['generatedAt']}")


if __name__ == "__main__":
    main()
