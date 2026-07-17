#!/usr/bin/env python3
"""Run the native full-tier client with a loopback-only HTTPS origin."""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import threading


ARTIFACT_DIR = Path(os.environ.get("ARTIFACT_DIR", "/artifacts"))
CERT_PATH = Path(os.environ.get("ORIGIN_CERT", "/artifacts/origin-cert.pem"))
KEY_PATH = Path(os.environ.get("ORIGIN_KEY", "/artifacts/origin-key.pem"))
CLIENT_PATH = os.environ.get("FULL_TIER_CLIENT", "/browser/hns-runtime-full-tier")
ORIGIN_PORT = int(os.environ.get("FULL_TIER_ORIGIN_PORT", "18443"))


def probe_dns_blocked(host: str, timeout: float = 0.5) -> dict[str, bool]:
    # relaytest. A, recursion desired. A reply from either transport is a
    # topology failure regardless of its RCODE.
    query = bytes.fromhex(
        "613201000001000000000000"
        "0972656c61797465737400"
        "00010001"
    )
    udp_blocked = True
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(timeout)
    try:
        udp.sendto(query, (host, 53))
        udp.recvfrom(4096)
        udp_blocked = False
    except (OSError, TimeoutError):
        pass
    finally:
        udp.close()

    tcp_blocked = True
    try:
        channel = socket.create_connection((host, 53), timeout=timeout)
    except (OSError, TimeoutError):
        pass
    else:
        tcp_blocked = False
        channel.close()

    return {"udp_blocked": udp_blocked, "tcp_blocked": tcp_blocked}


class OriginState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests = 0

    def contact(self) -> None:
        with self.lock:
            self.requests += 1
            self.persist()

    def persist(self) -> None:
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        target = ARTIFACT_DIR / "full-browser-origin-metrics.json"
        temporary = target.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(
                {
                    "requests": self.requests,
                    "request_paths_logged": 0,
                    "request_headers_logged": 0,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)


def main() -> int:
    state = OriginState()
    authority_probe = probe_dns_blocked(os.environ.get("AUTH_DNS_IP", "172.31.20.53"))
    external_probe = probe_dns_blocked(os.environ.get("EXTERNAL_DNS_PROBE", "1.1.1.1"))
    if not all(authority_probe.values()) or not all(external_probe.values()):
        raise RuntimeError("browser namespace unexpectedly reached UDP/TCP port 53")
    network_evidence = {
        "authoritative_dns": authority_probe,
        "external_dns": external_probe,
        "browser_joined_dns_network": False,
    }
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / "full-browser-network.json").write_text(
        json.dumps(network_evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            state.contact()
            body = b"full hsd regtest DNSSEC DANE origin\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_PATH, KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    state.persist()
    (ARTIFACT_DIR / "full-browser-origin.ready").write_text("ready\n", encoding="ascii")
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    child = subprocess.Popen([CLIENT_PATH])

    def forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    signal.signal(signal.SIGINT, forward)
    signal.signal(signal.SIGTERM, forward)

    try:
        return child.wait()
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        state.persist()


if __name__ == "__main__":
    raise SystemExit(main())
