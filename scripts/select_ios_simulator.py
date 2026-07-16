#!/usr/bin/env python3
"""Select a deterministic iPhone from an available iOS runtime."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any


_IOS_RUNTIME = re.compile(r"(?:^|\.)iOS-(\d+(?:-\d+)*)$")
_REQUESTED_RUNTIME = re.compile(r"^\d+(?:\.\d+)*$")


class SimulatorSelectionError(ValueError):
    """The simctl document does not contain an eligible iPhone."""


def _runtime_version(identifier: str) -> tuple[int, ...] | None:
    match = _IOS_RUNTIME.search(identifier)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("-"))


def _requested_runtime_version(value: str) -> tuple[int, ...]:
    if _REQUESTED_RUNTIME.fullmatch(value) is None:
        raise SimulatorSelectionError(
            f"requested iOS runtime must be numeric dotted notation: {value!r}"
        )
    return tuple(int(part) for part in value.split("."))


def select_simulator(document: Any, exact_runtime: str | None = None) -> str:
    if not isinstance(document, dict) or not isinstance(document.get("devices"), dict):
        raise SimulatorSelectionError("simctl JSON does not contain a devices object")

    requested_version = (
        _requested_runtime_version(exact_runtime)
        if exact_runtime is not None
        else None
    )

    candidates: list[tuple[tuple[int, ...], str, str]] = []
    for runtime_identifier, devices in document["devices"].items():
        if not isinstance(runtime_identifier, str) or not isinstance(devices, list):
            continue
        version = _runtime_version(runtime_identifier)
        if version is None or (
            requested_version is not None and version != requested_version
        ):
            continue
        for device in devices:
            if not isinstance(device, dict) or device.get("isAvailable") is not True:
                continue
            name = device.get("name")
            udid = device.get("udid")
            if (
                isinstance(name, str)
                and name.startswith("iPhone")
                and isinstance(udid, str)
                and udid
            ):
                candidates.append((version, name, udid))

    if not candidates:
        suffix = f" for iOS {exact_runtime}" if exact_runtime is not None else ""
        raise SimulatorSelectionError(
            f"no available iPhone simulator was found{suffix}"
        )

    selected_version = requested_version or max(candidate[0] for candidate in candidates)
    selected_devices = [
        candidate for candidate in candidates if candidate[0] == selected_version
    ]
    # Device names and UDIDs make the choice stable even if simctl changes its
    # dictionary or device ordering between hosted-runner image revisions.
    _, _, udid = min(selected_devices, key=lambda candidate: candidate[1:3])
    return udid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runtime",
        help="require this exact dotted iOS runtime version (for example, 26.5)",
    )
    arguments = parser.parse_args()
    try:
        document = json.load(sys.stdin)
        print(select_simulator(document, exact_runtime=arguments.runtime))
    except (json.JSONDecodeError, SimulatorSelectionError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
