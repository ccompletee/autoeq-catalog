#!/usr/bin/env python3
"""
Unit and determinism tests for AutoEQ Remote Catalog Tools.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

# Add script directory to sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from generate_catalog import generate_manifest


class TestAutoEqCatalogGenerator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.results_dir = os.path.join(self.temp_dir.name, "results")

        # Create dummy AutoEQ structure
        # Model 1: oratory1990 / harman_over_ear_2018 / Sennheiser HD 600
        model1_dir = os.path.join(self.results_dir, "oratory1990", "harman_over_ear_2018", "Sennheiser HD 600")
        os.makedirs(model1_dir, exist_ok=True)
        with open(os.path.join(model1_dir, "Sennheiser HD 600 FixedBandEQ.txt"), "w", encoding="utf-8") as f:
            f.write("Preamp: -2.5 dB\nFilter 1: ON PK Fc 31.25 Hz Gain 0.0 dB Q 1.41\n")
        with open(os.path.join(model1_dir, "Sennheiser HD 600 ParametricEQ.txt"), "w", encoding="utf-8") as f:
            f.write("Preamp: -2.5 dB\nFilter 1: ON PK Fc 100 Hz Gain 1.0 dB Q 2.0\n")

        # Model 2: crinacle / harman_in_ear_2019v2 / Sony WH-1000XM4
        model2_dir = os.path.join(self.results_dir, "crinacle", "harman_in_ear_2019v2", "Sony WH-1000XM4")
        os.makedirs(model2_dir, exist_ok=True)
        with open(os.path.join(model2_dir, "Sony WH-1000XM4 FixedBandEQ.txt"), "w", encoding="utf-8") as f:
            f.write("Preamp: -4.0 dB\nFilter 1: ON PK Fc 62.5 Hz Gain -1.0 dB Q 1.41\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_manifest_determinism(self):
        dummy_commit = "a" * 40
        catalog_version = 1700000000
        generated_at = "2026-10-01T00:00:00Z"

        manifest1 = generate_manifest(
            results_dir=self.results_dir,
            source_commit=dummy_commit,
            catalog_version=catalog_version,
            generated_at=generated_at,
            default_license="MIT"
        )
        bytes1 = json.dumps(manifest1, indent=2, ensure_ascii=False).encode("utf-8")
        sha256_1 = hashlib.sha256(bytes1).hexdigest()

        manifest2 = generate_manifest(
            results_dir=self.results_dir,
            source_commit=dummy_commit,
            catalog_version=catalog_version,
            generated_at=generated_at,
            default_license="MIT"
        )
        bytes2 = json.dumps(manifest2, indent=2, ensure_ascii=False).encode("utf-8")
        sha256_2 = hashlib.sha256(bytes2).hexdigest()

        self.assertEqual(sha256_1, sha256_2, "Manifest generation must be deterministic across identical runs")
        self.assertEqual(bytes1, bytes2)
        self.assertEqual(len(manifest1["entries"]), 2)

    def test_generate_manifest_custom_license(self):
        dummy_commit = "b" * 40
        manifest = generate_manifest(
            results_dir=self.results_dir,
            source_commit=dummy_commit,
            catalog_version=1700000000,
            generated_at="2026-10-01T00:00:00Z",
            default_license="Custom-License-1.0"
        )
        self.assertTrue(len(manifest["entries"]) > 0)
        for entry in manifest["entries"]:
            self.assertEqual(entry["license"], "Custom-License-1.0")

    def test_sign_catalog_fails_without_key_and_no_generate_flag(self):
        sign_script = os.path.join(SCRIPT_DIR, "sign_catalog.py")
        non_existent_key = os.path.join(self.temp_dir.name, "missing_key.pem")
        manifest_file = os.path.join(self.temp_dir.name, "catalog.v1.json")

        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write("{}")

        result = subprocess.run(
            [sys.executable, sign_script, "--manifest", manifest_file, "--private-key", non_existent_key],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        self.assertNotEqual(result.returncode, 0, "sign_catalog.py must fail when private key is missing and --generate-keys is omitted")
        self.assertIn("not found", result.stderr.lower())

    def test_sign_catalog_exports_both_pem_and_der(self):
        sign_script = os.path.join(SCRIPT_DIR, "sign_catalog.py")
        key_path = os.path.join(self.temp_dir.name, "test_key.pem")
        manifest_file = os.path.join(self.temp_dir.name, "catalog.v1.json")
        sig_file = os.path.join(self.temp_dir.name, "catalog.v1.json.sig")
        pub_pem = os.path.join(self.temp_dir.name, "exported_pub.pem")
        pub_der = os.path.join(self.temp_dir.name, "exported_pub.der")

        with open(manifest_file, "w", encoding="utf-8") as f:
            f.write('{"test": true}')

        # 1. Generate key and sign
        res1 = subprocess.run(
            [sys.executable, sign_script, "--manifest", manifest_file, "--private-key", key_path,
             "--signature", sig_file, "--generate-keys"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.assertEqual(res1.returncode, 0)
        self.assertTrue(os.path.exists(key_path))
        self.assertTrue(os.path.exists(sig_file))

        # 2. Sign with existing key and export both PEM and DER
        res2 = subprocess.run(
            [sys.executable, sign_script, "--manifest", manifest_file, "--private-key", key_path,
             "--signature", sig_file, "--public-key-pem", pub_pem, "--public-key-der", pub_der],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.assertEqual(res2.returncode, 0)
        self.assertTrue(os.path.exists(pub_pem), "public_key.pem must be exported when requested")
        self.assertTrue(os.path.exists(pub_der), "public_key.der must be exported when requested")
        self.assertGreater(os.path.getsize(pub_pem), 0)
        self.assertGreater(os.path.getsize(pub_der), 0)

        # 3. Verify signature using exported DER
        res3 = subprocess.run(
            [sys.executable, sign_script, "--manifest", manifest_file, "--signature", sig_file,
             "--public-key-der", pub_der, "--verify-only"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        self.assertEqual(res3.returncode, 0)


if __name__ == "__main__":
    unittest.main()
