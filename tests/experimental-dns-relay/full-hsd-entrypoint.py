#!/usr/bin/env python3
"""Start one isolated full hsd regtest node from the mounted host checkout."""

from __future__ import annotations

import os


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def main() -> None:
    host_node = required("HOST_NODE_CONTAINER")
    hsd_root = required("HSD_ROOT")
    role = required("HSD_ROLE")
    control_host = required("HSD_CONTROL_HOST")
    identity_key = required("HSD_IDENTITY_KEY")
    relay = os.environ.get("HSD_EXPERIMENTAL_RELAY") == "1"
    allow_private = os.environ.get("HSD_ALLOW_PRIVATE_AUTHORITIES") == "1"
    wallet = os.environ.get("HSD_OWNER_WALLET") == "1"
    relay_timeout = os.environ.get("HSD_RELAY_TIMEOUT_MS", "3000")

    arguments = [
        host_node,
        os.path.join(hsd_root, "bin", "hsd"),
        "--network=regtest",
        "--prefix=/data",
        "--listen=true",
        "--host=0.0.0.0",
        "--port=14038",
        f"--http-host={control_host}",
        "--http-port=14037",
        "--no-auth=true",
        "--workers=false",
        "--upnp=false",
        "--log-file=false",
        "--log-console=true",
        "--log-level=debug",
        f"--agent={role}:1",
        f"--identity-key={identity_key}",
    ]

    for peer in os.environ.get("HSD_NODES", "").split(","):
        peer = peer.strip()
        if peer:
            arguments.append(f"--nodes={peer}")

    if wallet:
        arguments.extend([
            f"--wallet-http-host={control_host}",
            "--wallet-http-port=14039",
            "--wallet-no-auth=true",
        ])
    else:
        arguments.append("--no-wallet=true")

    if relay:
        arguments.extend([
            "--ns-host=127.0.0.1",
            "--rs-host=127.0.0.1",
            "--rs-no-unbound=true",
            "--experimental-dns-relay=true",
            f"--experimental-dns-relay-timeout={relay_timeout}",
        ])
        if allow_private:
            arguments.append("--experimental-dns-relay-allow-private-authorities=true")
    else:
        arguments.append("--no-dns=true")

    os.execv(host_node, arguments)


if __name__ == "__main__":
    main()
