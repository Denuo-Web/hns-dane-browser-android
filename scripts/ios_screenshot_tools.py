#!/usr/bin/env python3
"""Validation and provenance helpers for iOS screenshot workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import sys
from pathlib import Path
from typing import Any, Iterable


LIVE_SCREENSHOTS = (
    (
        "LIVE_APPSTORE_SCREENSHOT_01_HNS_PAGE",
        "01-hns-page",
    ),
    (
        "LIVE_APPSTORE_SCREENSHOT_02_SETTINGS",
        "02-settings",
    ),
    (
        "LIVE_APPSTORE_SCREENSHOT_03_PROOF_DETAILS",
        "03-proof-details",
    ),
    (
        "LIVE_APPSTORE_SCREENSHOT_04_WEBPKI",
        "04-webpki",
    ),
)

FIXTURE_SCREENSHOTS = (
    ("UI_REGRESSION_FIXTURE_01_HNS", "fixture-01-hns"),
    ("UI_REGRESSION_FIXTURE_02_PROOF_DETAILS", "fixture-02-proof-details"),
    ("UI_REGRESSION_FIXTURE_03_WEBPKI", "fixture-03-webpki"),
)

# Submission tooling defaults to the live set. The old fixture set must always
# be requested explicitly and is never accepted by verify-live.
SCREENSHOTS = LIVE_SCREENSHOTS
SCREENSHOT_PROFILES = {
    "live": LIVE_SCREENSHOTS,
    "fixture-regression": FIXTURE_SCREENSHOTS,
}
LIVE_PROVENANCE_ATTACHMENT = "LIVE_APPSTORE_PROVENANCE"
LIVE_CAPTURE_MODE = "live-production-runtime"
LIVE_TARGETS = {
    "hnsNavigation": "https://denuoweb/",
    "settings": "https://denuoweb/",
    "proofDetails": "https://denuoweb/",
    "webPKINavigation": "https://denuoweb.com/work/hns-dane-browser",
}

DEVICE_PRIORITY = (
    "iPhone 14 Plus",
    "iPhone 13 Pro Max",
    "iPhone 12 Pro Max",
)

XCRESULT_ATTACHMENT_SUFFIX = re.compile(
    r"_\d+_[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
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
    path = Path(value)
    name = path.stem if path.suffix else value
    return XCRESULT_ATTACHMENT_SUFFIX.sub("", name)


def attachment_sources(
    manifest: Any,
    attachments_dir: Path,
) -> dict[str, list[Path]]:
    attachments_root = attachments_dir.resolve()
    sources: dict[str, list[Path]] = {}
    for record in iter_attachment_records(manifest):
        suggested_name = record.get("suggestedHumanReadableName")
        exported_name = record.get("exportedFileName")
        if not isinstance(suggested_name, str) or not isinstance(exported_name, str):
            continue
        source = (attachments_dir / exported_name).resolve()
        try:
            source.relative_to(attachments_root)
        except ValueError as error:
            raise ScreenshotToolError(
                f"attachment path escapes the export directory: {exported_name}"
            ) from error
        name = normalized_attachment_name(suggested_name)
        sources.setdefault(name, []).append(source)
    return sources


def collect_attachments(
    manifest: Any,
    attachments_dir: Path,
    output_dir: Path,
    screenshot_specs: tuple[tuple[str, str], ...] = SCREENSHOTS,
    provenance_output: Path | None = None,
) -> list[Path]:
    expected = {attachment: basename for attachment, basename in screenshot_specs}
    found: dict[str, list[Path]] = {name: [] for name in expected}
    sources = attachment_sources(manifest, attachments_dir)
    for name in expected:
        found[name] = sources.get(name, [])

    problems = []
    for attachment_name, paths in found.items():
        if len(paths) != 1:
            problems.append(f"{attachment_name}: expected 1 attachment, found {len(paths)}")
    if problems:
        raise ScreenshotToolError("; ".join(problems))

    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for attachment_name, basename in screenshot_specs:
        source = found[attachment_name][0]
        if not source.is_file():
            raise ScreenshotToolError(f"exported attachment does not exist: {source}")
        if source.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n":
            raise ScreenshotToolError(f"attachment is not a PNG: {source.name}")
        destination = output_dir / f"{basename}.png"
        shutil.copyfile(source, destination)
        outputs.append(destination)

    if provenance_output is not None:
        provenance_sources = sources.get(LIVE_PROVENANCE_ATTACHMENT, [])
        if len(provenance_sources) != 1:
            raise ScreenshotToolError(
                f"{LIVE_PROVENANCE_ATTACHMENT}: expected 1 attachment, "
                f"found {len(provenance_sources)}"
            )
        source = provenance_sources[0]
        if not source.is_file():
            raise ScreenshotToolError(
                f"exported provenance attachment does not exist: {source}"
            )
        provenance = load_json(str(source))
        validate_live_provenance(provenance)
        provenance_output.parent.mkdir(parents=True, exist_ok=True)
        provenance_output.write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
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


def validate_live_provenance(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ScreenshotToolError("live runtime provenance must be a JSON object")
    if document.get("schemaVersion") != 1:
        raise ScreenshotToolError("live runtime provenance schemaVersion must be 1")
    if document.get("captureMode") != LIVE_CAPTURE_MODE:
        raise ScreenshotToolError(
            f"live runtime provenance captureMode must be {LIVE_CAPTURE_MODE!r}"
        )
    if document.get("configuration") != "Release":
        raise ScreenshotToolError("live screenshots must be captured in Release")
    if document.get("fixtureEnvironmentInjected") is not False:
        raise ScreenshotToolError("live provenance must prove fixture injection was false")

    for section, requested_url in LIVE_TARGETS.items():
        evidence = document.get(section)
        if not isinstance(evidence, dict):
            raise ScreenshotToolError(f"live provenance is missing {section}")
        request_key = (
            "sourceRequestedURL"
            if section in {"settings", "proofDetails"}
            else "requestedURL"
        )
        if evidence.get(request_key) != requested_url:
            raise ScreenshotToolError(
                f"{section}.{request_key} must be {requested_url!r}"
            )

    for section in ("hnsNavigation", "webPKINavigation"):
        evidence = document[section]
        final_address = evidence.get("finalAddress")
        security_label = evidence.get("securityLabel")
        if not isinstance(final_address, str) or not final_address.strip():
            raise ScreenshotToolError(f"{section}.finalAddress must be non-empty")
        if not isinstance(security_label, str) or not security_label.strip():
            raise ScreenshotToolError(f"{section}.securityLabel must be non-empty")
        if security_label in {"Security pending", "Waiting for a verified response"}:
            raise ScreenshotToolError(f"{section} captured a pending security state")

    hns_runtime_status = document["hnsNavigation"].get(
        "runtimeStatusBeforeNavigation"
    )
    if not isinstance(hns_runtime_status, str) or not hns_runtime_status.startswith(
        "Handshake headers current"
    ):
        raise ScreenshotToolError(
            "hnsNavigation.runtimeStatusBeforeNavigation must prove current Handshake headers"
        )

    proof_label = document["proofDetails"].get("contentAccessibilityLabel")
    if not isinstance(proof_label, str) or not proof_label.strip():
        raise ScreenshotToolError(
            "proofDetails.contentAccessibilityLabel must be non-empty"
        )
    expected_settings_row = "settings.hns-resolution.stateless-dane-certificates"
    if document["settings"].get("statelessDANERowIdentifier") != expected_settings_row:
        raise ScreenshotToolError("settings provenance is missing the stateless DANE row")
    expected_settings_toggle = f"{expected_settings_row}.toggle"
    if (
        document["settings"].get("statelessDANEToggleIdentifier")
        != expected_settings_toggle
    ):
        raise ScreenshotToolError("settings provenance is missing the stateless DANE switch")
    return document


def write_manifest(
    directory: Path,
    width: int,
    height: int,
    commit: str,
    xcode: str,
    sdk: str,
    device: str,
    screenshot_specs: tuple[tuple[str, str], ...] = SCREENSHOTS,
    configuration: str = "Release",
    runtime_provenance: dict[str, Any] | None = None,
) -> Path:
    expected_files = [f"{basename}.jpg" for _, basename in screenshot_specs]
    actual_files = sorted(path.name for path in directory.glob("*.jpg"))
    if actual_files != sorted(expected_files):
        raise ScreenshotToolError(
            f"expected JPEG set {sorted(expected_files)}, found {actual_files}"
        )

    screenshot_records = []
    for attachment_name, basename in screenshot_specs:
        path = directory / f"{basename}.jpg"
        actual_width, actual_height = jpeg_dimensions(path)
        if (actual_width, actual_height) != (width, height):
            raise ScreenshotToolError(
                f"{path.name} is {actual_width} x {actual_height}; "
                f"expected {width} x {height}"
            )
        screenshot_records.append(
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
            "configuration": configuration,
            "commit": commit,
            "device": device,
            "fixtureEnvironmentInjected": False,
            "iosSdk": sdk,
            "mode": LIVE_CAPTURE_MODE,
            "xcode": xcode,
        },
        "schemaVersion": 1,
        "screenshots": screenshot_records,
    }
    if runtime_provenance is not None:
        document["runtimeEvidence"] = validate_live_provenance(runtime_provenance)
    output = directory / "manifest.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def verify_live_set(directory: Path, manifest: Any) -> list[Path]:
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 1:
        raise ScreenshotToolError("live screenshot manifest schemaVersion must be 1")
    capture = manifest.get("capture")
    if not isinstance(capture, dict):
        raise ScreenshotToolError("live screenshot manifest is missing capture provenance")
    if capture.get("mode") != LIVE_CAPTURE_MODE:
        raise ScreenshotToolError("fixture screenshots cannot be staged for App Store use")
    if capture.get("configuration") != "Release":
        raise ScreenshotToolError("only Release screenshots can be staged")
    if capture.get("fixtureEnvironmentInjected") is not False:
        raise ScreenshotToolError("fixture-injected screenshots cannot be staged")
    for field in ("commit", "device", "iosSdk", "xcode"):
        value = capture.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ScreenshotToolError(f"live screenshot manifest is missing capture.{field}")
    validate_live_provenance(manifest.get("runtimeEvidence"))

    expected_files = [f"{basename}.jpg" for _, basename in LIVE_SCREENSHOTS]
    actual_files = sorted(path.name for path in directory.glob("*.jpg"))
    if actual_files != sorted(expected_files):
        raise ScreenshotToolError(
            f"expected live JPEG set {sorted(expected_files)}, found {actual_files}"
        )

    records = manifest.get("screenshots")
    if not isinstance(records, list) or len(records) != len(LIVE_SCREENSHOTS):
        raise ScreenshotToolError("live screenshot manifest has the wrong image count")
    records_by_file = {
        record.get("file"): record for record in records if isinstance(record, dict)
    }
    verified = []
    expected_by_file = {
        f"{basename}.jpg": attachment for attachment, basename in LIVE_SCREENSHOTS
    }
    for filename in expected_files:
        path = directory / filename
        record = records_by_file.get(filename)
        if not isinstance(record, dict):
            raise ScreenshotToolError(f"manifest has no record for {filename}")
        dimensions = jpeg_dimensions(path)
        if dimensions != (1284, 2778):
            raise ScreenshotToolError(
                f"{filename} is {dimensions[0]} x {dimensions[1]}; expected 1284 x 2778"
            )
        if dimensions != (record.get("width"), record.get("height")):
            raise ScreenshotToolError(f"manifest dimensions do not match {filename}")
        if record.get("attachment") != expected_by_file[filename]:
            raise ScreenshotToolError(f"manifest attachment does not match {filename}")
        if sha256(path) != record.get("sha256"):
            raise ScreenshotToolError(f"manifest digest does not match {filename}")
        verified.append(path)
    return verified


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
    collect.add_argument(
        "--profile", choices=sorted(SCREENSHOT_PROFILES), default="live"
    )
    collect.add_argument("--provenance-output")

    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--directory", required=True)
    manifest.add_argument("--width", type=int, required=True)
    manifest.add_argument("--height", type=int, required=True)
    manifest.add_argument("--commit", required=True)
    manifest.add_argument("--xcode", required=True)
    manifest.add_argument("--sdk", required=True)
    manifest.add_argument("--device", required=True)
    manifest.add_argument("--configuration", default="Release")
    manifest.add_argument("--runtime-provenance", required=True)

    verify = subparsers.add_parser("verify-live")
    verify.add_argument("--directory", required=True)
    verify.add_argument("--manifest")
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
            if args.profile == "live" and not args.provenance_output:
                raise ScreenshotToolError(
                    "live attachment collection requires --provenance-output"
                )
            manifest = load_json(args.manifest)
            for output in collect_attachments(
                manifest,
                Path(args.attachments_dir),
                Path(args.output_dir),
                screenshot_specs=SCREENSHOT_PROFILES[args.profile],
                provenance_output=(
                    Path(args.provenance_output) if args.provenance_output else None
                ),
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
                    configuration=args.configuration,
                    runtime_provenance=load_json(args.runtime_provenance),
                )
            )
        elif args.command == "verify-live":
            directory = Path(args.directory)
            manifest_path = Path(args.manifest) if args.manifest else directory / "manifest.json"
            for output in verify_live_set(directory, load_json(str(manifest_path))):
                print(output)
    except (OSError, json.JSONDecodeError, ScreenshotToolError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
