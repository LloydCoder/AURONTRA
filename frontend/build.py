#!/usr/bin/env python3
"""Deterministic, dependency-free builder for the AURONTRA static console."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
ASSETS = ("index.html", "app.js", "styles.css")
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def fail(message: str) -> None:
    print(f"frontend build error: {message}", file=sys.stderr)
    raise SystemExit(2)


def canonical_url(value: str, name: str, *, allow_path: bool = False, allow_http_test: bool = False) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        fail(f"{name} must be a valid URL")
    test_http = (
        allow_http_test
        and os.environ.get("AURONTRA_ENVIRONMENT") == "test"
        and parsed.scheme == "http"
        and parsed.hostname is not None
        and (parsed.hostname.endswith(".test") or parsed.hostname in {"localhost", "127.0.0.1"})
    )
    if parsed.scheme != "https" and not test_http:
        fail(f"{name} must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail(f"{name} must be a canonical URL without credentials, query, or fragment")
    if not allow_path and parsed.path not in {"", "/"}:
        fail(f"{name} must be an origin without a path")
    if CONTROL_CHARS.search(value):
        fail(f"{name} contains control characters")
    # Reject non-ASCII hostnames unless they are already punycode; this avoids
    # mismatches between browser URL parsing and deployment CSP allowlists.
    if not parsed.hostname.isascii():
        fail(f"{name} hostname must be ASCII/punycode")
    return value.rstrip("/") if parsed.path == "/" and not allow_path else value


def validate_config() -> dict[str, str]:
    environment = os.environ.get("AURONTRA_ENVIRONMENT", "production")
    if environment not in {"production", "test"}:
        fail("AURONTRA_ENVIRONMENT must be 'production' or 'test'")
    api = canonical_url(
        os.environ.get("AURONTRA_API_BASE_URL", "").strip(),
        "AURONTRA_API_BASE_URL",
        allow_http_test=True,
    )
    issuer = canonical_url(
        os.environ.get("AURONTRA_OIDC_ISSUER", "").strip(),
        "AURONTRA_OIDC_ISSUER",
        allow_path=True,
    )
    client_id = os.environ.get("AURONTRA_OIDC_CLIENT_ID", "").strip()
    redirect_uri = canonical_url(
        os.environ.get("AURONTRA_OIDC_REDIRECT_URI", "").strip(),
        "AURONTRA_OIDC_REDIRECT_URI",
        allow_path=True,
        allow_http_test=True,
    )
    audience = os.environ.get("AURONTRA_OIDC_AUDIENCE", "").strip()
    for name, value in (("AURONTRA_OIDC_CLIENT_ID", client_id), ("AURONTRA_OIDC_AUDIENCE", audience)):
        if len(value) > 512 or CONTROL_CHARS.search(value):
            fail(f"{name} contains invalid characters or exceeds 512 characters")
    if issuer and not client_id:
        fail("AURONTRA_OIDC_CLIENT_ID is required when an OIDC issuer is configured")
    if redirect_uri and not client_id:
        fail("AURONTRA_OIDC_CLIENT_ID is required when a redirect URI is configured")
    if client_id and (not issuer or not redirect_uri):
        fail("issuer and redirect URI are required when an OIDC client ID is configured")
    return {
        "environment": environment,
        "apiBaseUrl": api,
        "oidcIssuer": issuer,
        "oidcClientId": client_id,
        "oidcRedirectUri": redirect_uri,
        "oidcAudience": audience,
    }


def origin_of(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    return f"{parsed.scheme}://{parsed.netloc}"


def security_headers(config: dict[str, str]) -> str:
    connect_sources = ["'self'"]
    for value in (config["apiBaseUrl"], config["oidcIssuer"]):
        origin = origin_of(value)
        if origin and origin not in connect_sources:
            connect_sources.append(origin)
    form_sources = ["'self'"]
    issuer_origin = origin_of(config["oidcIssuer"])
    if issuer_origin:
        form_sources.append(issuer_origin)
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        f"connect-src {' '.join(connect_sources)}; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        f"form-action {' '.join(form_sources)}; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests"
    )
    return (
        "/*\n"
        f"  Content-Security-Policy: {csp}\n"
        "  X-Content-Type-Options: nosniff\n"
        "  Referrer-Policy: no-referrer\n"
        "  X-Frame-Options: DENY\n"
        "  Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
        "  Cache-Control: no-store\n"
    )


def nginx_config(config: dict[str, str]) -> str:
    headers = security_headers(config).splitlines()
    csp = next(line.strip()[len("Content-Security-Policy: "):] for line in headers if "Content-Security-Policy:" in line)
    return (
        "server {\n"
        "  listen 8080;\n"
        "  server_name _;\n"
        "  root /usr/share/nginx/html;\n"
        "  index index.html;\n"
        f'  add_header Content-Security-Policy "{csp}" always;\n'
        '  add_header X-Content-Type-Options "nosniff" always;\n'
        '  add_header Referrer-Policy "no-referrer" always;\n'
        '  add_header X-Frame-Options "DENY" always;\n'
        '  add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;\n'
        '  add_header Cache-Control "no-store" always;\n'
        "  location / { try_files $uri $uri/ /index.html; }\n"
        "  location ~* \\.(?:js|css)$ { expires -1; add_header Cache-Control \"no-store\" always; }\n"
        "}\n"
    )


def digest_manifest(directory: Path) -> str:
    rows = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "manifest.sha256"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(directory).as_posix()}")
    return "\n".join(rows) + "\n"


def verify(directory: Path) -> None:
    manifest = directory / "manifest.sha256"
    if not manifest.is_file():
        fail("manifest.sha256 is missing; build the console first")
    expected = manifest.read_text(encoding="utf-8")
    actual = digest_manifest(directory)
    if expected != actual:
        fail("generated files do not match manifest.sha256")
    print("frontend build manifest verified")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="validate source files without building")
    parser.add_argument("--verify", action="store_true", help="verify the generated SHA-256 manifest")
    args = parser.parse_args()

    if args.verify:
        verify(DIST)
        return 0

    missing = [name for name in ASSETS if not (ROOT / name).is_file()]
    if missing:
        fail("missing source assets: " + ", ".join(missing))
    # These strings are deliberately forbidden in production UI source: customer
    # records must come from authenticated APIs, never hard-coded demonstration data.
    source = "\n".join((ROOT / name).read_text(encoding="utf-8") for name in ASSETS)
    forbidden = ("prod-server-01", "mockThreats", "seedDevices", "DEMO_CUSTOMER_DATA")
    if any(marker in source for marker in forbidden):
        fail("sample customer data marker found in production source")
    if args.check:
        print("frontend source checks passed")
        return 0

    config = validate_config()
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir(parents=True)
    for name in ASSETS:
        shutil.copy2(ROOT / name, DIST / name)
    config_js = "window.AURONTRA_CONFIG = Object.freeze(" + json.dumps(config, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c") + ");\n"
    (DIST / "config.js").write_text(config_js, encoding="utf-8")
    (DIST / "_headers").write_text(security_headers(config), encoding="utf-8")
    (DIST / "nginx.conf").write_text(nginx_config(config), encoding="utf-8")
    (DIST / "manifest.sha256").write_text(digest_manifest(DIST), encoding="utf-8")
    verify(DIST)
    print(f"built {len(list(DIST.iterdir()))} deterministic static assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
