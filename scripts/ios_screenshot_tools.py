#!/usr/bin/env python3
"""Deterministic helpers for the iOS App Store screenshot workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import sys
from pathlib import Path
from typing import Any, Iterable


SCREENSHOTS = (
    (
        "APPSTORE_SCREENSHOT_01_HNS_DANE_VERIFIED",
        "01-hns-dane-verified",
    ),
    (
        "APPSTORE_SCREENSHOT_02_BROWSER_SETTINGS",
        "02-browser-settings",
    ),
    (
        "APPSTORE_SCREENSHOT_03_PROOF_DETAILS",
        "03-proof-details",
    ),
    (
        "APPSTORE_SCREENSHOT_04_WEBPKI",
        "04-webpki",
    ),
)

DEVICE_PRIORITY = (
    "iPhone 14 Plus",
    "iPhone 13 Pro Max",
    "iPhone 12 Pro Max",
)


class ScreenshotToolError(ValueError):
    """Raised for malformed simulator or screenshot artifacts."""


def load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def select_runtime(document: Any, version: str) -> str:
    if not isinstance(document, dict) or not isinstance(document.get("runtimes"), list):
        raise ScreenshotToolError("simctl document must contain a runtimes array")
    matches = []
    for runtime in document["runtimes"]:
        if not isinstance(runtime, dict) or runtime.get("isAvailable") is not True:
            continue
        identifier = runtime.get("identifier")
        runtime_version = runtime.get("version")
        if not isinstance(identifier, str):
            continue
        normalized_identifier = identifier.rsplit(".", 1)[-1]
        normalized_version = normalized_identifier.removeprefix("iOS-").replace("-", ".")
        if runtime_version == version or normalized_version == version:
            matches.append(identifier)
    if not matches:
        raise ScreenshotToolError(f"no available iOS {version} simulator runtime was found")
    return sorted(matches)[0]


def select_device_type(document: Any) -> tuple[str, str]:
    if not isinstance(document, dict) or not isinstance(document.get("devicetypes"), list):
        raise ScreenshotToolError("simctl document must contain a devicetypes array")
    by_name = {}
    for device in document["devicetypes"]:
        if not isinstance(device, dict):
            continue
        name = device.get("name")
        identifier = device.get("identifier")
        if isinstance(name, str) and isinstance(identifier, str):
            by_name[name] = identifier
    for name in DEVICE_PRIORITY:
        if name in by_name:
            return by_name[name], name
    expected = ", ".join(DEVICE_PRIORITY)
    raise ScreenshotToolError(
        f"no 1284 x 2778 iPhone device type was found; expected one of: {expected}"
    )


def iter_attachment_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if "suggestedHumanReadableName" in value and "exportedFileName" in value:
            yield value
        for child in value.values():
            yield from iter_attachment_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_attachment_records(child)


def normalized_attachment_name(value: str) -> str:
    return Path(value).stem if Path(value).suffix.lower() in {".png", ".jpg", ".jpeg"} else value


def collect_attachments(
    manifest: Any,
    attachments_dir: Path,
    output_dir: Path,
) -> list[Path]:
    expected = {attachment: basename for attachment, basename in SCREENSHOTS}
    found: dict[str, list[Path]] = {name: [] for name in expected}
    attachments_root = attachments_dir.resolve()

    for record in iter_attachment_records(manifest):
        suggested_name = record.get("suggestedHumanReadableName")
        exported_name = record.get("exportedFileName")
        if not isinstance(suggested_name, str) or not isinstance(exported_name, str):
            continue
        normalized_name = normalized_attachment_name(suggested_name)
        if normalized_name not in expected:
            continue
        source = (attachments_dir / exported_name).resolve()
        try:
            source.relative_to(attachments_root)
        except ValueError as error:
            raise ScreenshotToolError(
                f"attachment path escapes the export directory: {exported_name}"
            ) from error
        found[normalized_name].append(source)

    problems = []
    for attachment_name, paths in found.items():
        if len(paths) != 1:
            problems.append(f"{attachment_name}: expected 1 attachment, found {len(paths)}")
    if problems:
        raise ScreenshotToolError("; ".join(problems))

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for attachment_name, basename in SCREENSHOTS:
        source = found[attachment_name][0]
        if not source.is_file():
            raise ScreenshotToolError(f"exported attachment does not exist: {source}")
        if source.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n":
            raise ScreenshotToolError(f"attachment is not a PNG: {source.name}")
        destination = output_dir / f"{basename}.png"
        shutil.copyfile(source, destination)
        outputs.append(destination)
    return outputs


def jpeg_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 4 or data[:2] != b"\xff\xd8":
        raise ScreenshotToolError(f"file is not a JPEG: {path.name}")

    start_of_frame = {
        0xC0,
        0xC1,
        0xC2,
        0xC3,
        0xC5,
        0xC6,
        0xC7,
        0xC9,
        0xCA,
        0xCB,
        0xCD,
        0xCE,
        0xCF,
    }
    offset = 2
    while offset < len(data):
        while offset < len(data) and data[offset] != 0xFF:
            offset += 1
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]
        offset += 1
        if marker in {0x01, 0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if offset + 2 > len(data):
            break
        segment_length = struct.unpack(">H", data[offset : offset + 2])[0]
        if segment_length < 2 or offset + segment_length > len(data):
            break
        if marker in start_of_frame:
            if segment_length < 7:
                break
            height, width = struct.unpack(">HH", data[offset + 3 : offset + 7])
            return width, height
        offset += segment_length
    raise ScreenshotToolError(f"JPEG dimensions could not be read: {path.name}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(
    directory: Path,
    width: int,
    height: int,
    commit: str,
    xcode: str,
    sdk: str,
    device: str,
) -> Path:
    expected_files = [f"{basename}.jpg" for _, basename in SCREENSHOTS]
    actual_files = sorted(path.name for path in directory.glob("*.jpg"))
    if actual_files != sorted(expected_files):
        raise ScreenshotToolError(
            f"expected JPEG set {sorted(expected_files)}, found {actual_files}"
        )

    screenshots = []
    for attachment_name, basename in SCREENSHOTS:
        path = directory / f"{basename}.jpg"
        actual_width, actual_height = jpeg_dimensions(path)
        if (actual_width, actual_height) != (width, height):
            raise ScreenshotToolError(
                f"{path.name} is {actual_width} x {actual_height}; "
                f"expected {width} x {height}"
            )
        screenshots.append(
            {
                "attachment": attachment_name,
                "file": path.name,
                "height": actual_height,
                "sha256": sha256(path),
                "width": actual_width,
            }
        )

    document = {
        "capture": {
            "commit": commit,
            "device": device,
            "iosSdk": sdk,
            "xcode": xcode,
        },
        "schemaVersion": 1,
        "screenshots": screenshots,
    }
    output = directory / "manifest.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    runtime = subparsers.add_parser("select-runtime")
    runtime.add_argument("--runtime", required=True)
    runtime.add_argument("--input", default="-")

    device = subparsers.add_parser("select-device-type")
    device.add_argument("--input", default="-")

    collect = subparsers.add_parser("collect")
    collect.add_argument("--manifest", required=True)
    collect.add_argument("--attachments-dir", required=True)
    collect.add_argument("--output-dir", required=True)

    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--directory", required=True)
    manifest.add_argument("--width", type=int, required=True)
    manifest.add_argument("--height", type=int, required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--xcode", required=True)
    manifest.add_argument("--sdk", required=True)
    manifest.add_argument("--device", required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "select-runtime":
            print(select_runtime(load_json(args.input), args.runtime))
        elif args.command == "select-device-type":
            identifier, name = select_device_type(load_json(args.input))
            print(f"{identifier}\t{name}")
        elif args.command == "collect":
            manifest = load_json(args.manifest)
            for output in collect_attachments(
                manifest,
                Path(args.attachments_dir),
                Path(args.output_dir),
            ):
                print(output)
        elif args.command == "manifest":
            print(
                write_manifest(
                    Path(args.directory),
                    args.width,
                    args.height,
                    args.commit,
                    args.xcode,
                    args.sdk,
                    args.device,
                )
            )
    except (OSError, json.JSONDecodeError, ScreenshotToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
