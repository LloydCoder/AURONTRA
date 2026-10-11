from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "build.py"


def run_build(*args: str, **updates: str) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("AURONTRA_")}
    env.update(updates)
    return subprocess.run(
        [sys.executable, str(BUILDER), *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class FrontendBuildTests(unittest.TestCase):
    def test_source_check_passes_without_runtime_dependencies(self) -> None:
        result = run_build("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source checks passed", result.stdout)

    def test_production_build_rejects_http_api_origin(self) -> None:
        result = run_build(AURONTRA_ENVIRONMENT="production", AURONTRA_API_BASE_URL="http://api.example")
        self.assertEqual(result.returncode, 2)
        self.assertIn("must use HTTPS", result.stderr)

    def test_test_build_allows_only_explicit_test_http_origin_and_emits_security_headers(self) -> None:
        result = run_build(
            AURONTRA_ENVIRONMENT="test",
            AURONTRA_API_BASE_URL="http://api.test",
            AURONTRA_OIDC_ISSUER="https://identity.test",
            AURONTRA_OIDC_CLIENT_ID="aurontra-e2e-client",
            AURONTRA_OIDC_REDIRECT_URI="http://127.0.0.1:4173/",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        headers = (ROOT / "dist" / "_headers").read_text(encoding="utf-8")
        self.assertIn("connect-src 'self' http://api.test https://identity.test", headers)
        self.assertIn("frame-ancestors 'none'", headers)
        self.assertIn("object-src 'none'", headers)
        self.assertIn("X-Content-Type-Options: nosniff", headers)
        self.assertIn("Cache-Control: no-store", headers)

    def test_build_manifest_is_deterministic_and_verifiable(self) -> None:
        first = run_build(AURONTRA_ENVIRONMENT="production")
        self.assertEqual(first.returncode, 0, first.stderr)
        manifest = (ROOT / "dist" / "manifest.sha256").read_text(encoding="utf-8")
        second = run_build(AURONTRA_ENVIRONMENT="production")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(manifest, (ROOT / "dist" / "manifest.sha256").read_text(encoding="utf-8"))
        verify = run_build("--verify")
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_manifest_verification_detects_tampering(self) -> None:
        built = run_build(AURONTRA_ENVIRONMENT="production")
        self.assertEqual(built.returncode, 0, built.stderr)
        asset = ROOT / "dist" / "app.js"
        asset.write_text(asset.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")
        verify = run_build("--verify")
        self.assertEqual(verify.returncode, 2)
        self.assertIn("do not match manifest", verify.stderr)
        rebuilt = run_build(AURONTRA_ENVIRONMENT="production")
        self.assertEqual(rebuilt.returncode, 0, rebuilt.stderr)


if __name__ == "__main__":
    unittest.main()
