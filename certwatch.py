#!/usr/bin/env python3
"""certwatch — check TLS certificate expiry for a list of domains before they take a service down.

Expired certificates are one of the most preventable causes of outages: the failure is
total (browsers hard-block the site, APIs refuse the handshake) and the warning signs
were visible for months. certwatch is a small, dependency-free checker you can run by
hand, in cron, or in CI so an expiry date never surprises you again.

Usage:
    python3 certwatch.py example.com github.com
    python3 certwatch.py --file domains.txt --warn-days 45
    python3 certwatch.py --file domains.txt --json
    python3 certwatch.py example.com --fail-on warn     # exit 1 if anything is inside the warn window
    python3 certwatch.py example.com --fail-on expired  # exit 1 only if something is already expired

Exit codes: 0 = everything outside the warn window (or failures tolerated by --fail-on),
            1 = at least one domain at the --fail-on level,
            2 = at least one domain could not be checked at all.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_PORT = 443
DEFAULT_WARN_DAYS = 30
DEFAULT_TIMEOUT = 10


def _open_tcp(host, port, timeout):
    """Open a TCP connection, honoring the standard HTTPS_PROXY env var via HTTP CONNECT.

    Plenty of corporate networks only allow egress through a proxy — a checker that
    can't run there is useless exactly where fleets are biggest. Direct connection
    when no proxy is configured.
    """
    proxy_url = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("ALL_PROXY")
        or os.environ.get("all_proxy")
    )
    if not proxy_url:
        return socket.create_connection((host, port), timeout=timeout)
    proxy = urlparse(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    sock = socket.create_connection((proxy.hostname, proxy.port or 8080), timeout=timeout)
    connect = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
    if proxy.username:
        creds = base64.b64encode(
            f"{proxy.username}:{proxy.password or ''}".encode()
        ).decode()
        connect += f"Proxy-Authorization: Basic {creds}\r\n"
    connect += "\r\n"
    sock.sendall(connect.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    status_line = response.split(b"\r\n", 1)[0].decode("latin-1")
    if " 200 " not in status_line:
        sock.close()
        raise OSError(f"proxy CONNECT failed: {status_line}")
    return sock


def check_domain(domain, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Return a result dict for one domain: status, expiry, days_left, issuer, error."""
    host = domain.strip().split("/")[0].split(":")[0]
    result = {"domain": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with _open_tcp(host, port, timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_after = cert.get("notAfter")
        expires = ssl.cert_time_to_seconds(not_after)
        expires_dt = datetime.fromtimestamp(expires, tz=timezone.utc)
        days_left = (expires_dt - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        result.update(
            {
                "status": "ok",
                "expires": expires_dt.strftime("%Y-%m-%d"),
                "days_left": days_left,
                "issuer": issuer.get("organizationName", "unknown"),
            }
        )
    except Exception as exc:  # DNS failure, refused connection, bad cert, timeout...
        result.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
    return result


def classify(result, warn_days):
    if result["status"] == "error":
        return "ERROR"
    if result["days_left"] < 0:
        return "EXPIRED"
    if result["days_left"] <= warn_days:
        return "WARN"
    return "OK"


def load_domains(args):
    domains = list(args.domains)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    return domains


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check TLS certificate expiry for one or more domains."
    )
    parser.add_argument("domains", nargs="*", help="Domains to check (hostnames only).")
    parser.add_argument("--file", help="Text file with one domain per line (# comments allowed).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TLS port (default 443).")
    parser.add_argument(
        "--warn-days",
        type=int,
        default=DEFAULT_WARN_DAYS,
        help=f"Warn when a cert expires within this many days (default {DEFAULT_WARN_DAYS}).",
    )
    parser.add_argument("--json", action="store_true", help="Output JSON instead of a table.")
    parser.add_argument(
        "--fail-on",
        choices=["warn", "expired"],
        default="warn",
        help="Exit 1 when a cert is at this level or worse (default: warn).",
    )
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-domain timeout in seconds.")
    args = parser.parse_args(argv)

    domains = load_domains(args)
    if not domains:
        parser.error("give at least one domain, or --file with domains in it")

    with ThreadPoolExecutor(max_workers=min(16, len(domains))) as pool:
        results = list(pool.map(lambda d: check_domain(d, args.port, args.timeout), domains))

    for r in results:
        r["level"] = classify(r, args.warn_days)
    results.sort(key=lambda r: (r.get("days_left") is None, r.get("days_left", 0)))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            if r["status"] == "error":
                print(f"{r['level']:<8} {r['domain']:<35} could not check — {r['error']}")
            else:
                print(
                    f"{r['level']:<8} {r['domain']:<35} expires {r['expires']} "
                    f"({r['days_left']} days left, issuer: {r['issuer']})"
                )

    levels = {r["level"] for r in results}
    if "ERROR" in levels:
        return 2
    if "EXPIRED" in levels:
        return 1
    if args.fail_on == "warn" and "WARN" in levels:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
