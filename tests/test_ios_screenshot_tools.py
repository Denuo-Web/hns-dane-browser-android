import json
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.ios_screenshot_tools import (
    LIVE_CAPTURE_MODE,
    SCREENSHOTS,
    ScreenshotToolError,
    collect_attachments,
    jpeg_dimensions,
    select_device_type,
    select_runtime,
    validate_live_provenance,
    verify_live_set,
    write_manifest,
)


PNG = b"\x89PNG\r\n\x1a\nfixture"


def live_provenance() -> dict:
    return {
        "captureMode": LIVE_CAPTURE_MODE,
        "configuration": "Release",
        "fixtureEnvironmentInjected": False,
        "hnsNavigation": {
            "requestedURL": "https://denuoweb/",
            "finalAddress": "https://denuoweb/",
            "runtimeStatusBeforeNavigation":
                "Handshake headers current. Local height 336000 · peer height 336000",
            "securityLabel": "DANE verified · authoritative DoH",
        },
        "proofDetails": {
            "sourceRequestedURL": "https://denuoweb/",
            "contentAccessibilityLabel": "Handshake proof details for denuoweb",
        },
        "schemaVersion": 1,
        "settings": {
            "sourceRequestedURL": "https://denuoweb/",
            "statelessDANERowIdentifier":
                "settings.hns-resolution.stateless-dane-certificates",
            "statelessDANEToggleIdentifier":
                "settings.hns-resolution.stateless-dane-certificates.toggle",
        },
        "webPKINavigation": {
            "requestedURL": "https://denuoweb.com/work/hns-dane-browser",
            "finalAddress": "https://denuoweb.com/work/hns-dane-browser",
            "securityLabel": "System WebPKI via the Rust whole-browser proxy",
        },
    }


def minimal_jpeg(width: int, height: int) -> bytes:
    frame = b"\x08" + struct.pack(">HH", height, width) + b"\x01\x01\x11\x00"
    return b"\xff\xd8\xff\xc0" + struct.pack(">H", len(frame) + 2) + frame + b"\xff\xd9"


class SimulatorSelectionTests(unittest.TestCase):
    def test_selects_exact_available_runtime(self) -> None:
        document = {
            "runtimes": [
                {
                    "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-27-0",
                    "version": "27.0",
                    "isAvailable": True,
                },
                {
                    "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26-5",
                    "version": "26.5",
                    "isAvailable": True,
                },
            ]
        }
        self.assertEqual(
            select_runtime(document, "26.5"),
            "com.apple.CoreSimulator.SimRuntime.iOS-26-5",
        )

    def test_rejects_unavailable_runtime(self) -> None:
        with self.assertRaisesRegex(ScreenshotToolError, "no available iOS 26.5"):
            select_runtime(
                {
                    "runtimes": [
                        {
                            "identifier": "com.apple.CoreSimulator.SimRuntime.iOS-26-5",
                            "version": "26.5",
                            "isAvailable": False,
                        }
                    ]
                },
                "26.5",
            )

    def test_prefers_iphone_14_plus(self) -> None:
        identifier, name = select_device_type(
            {
                "devicetypes": [
                    {"name": "iPhone 13 Pro Max", "identifier": "thirteen"},
                    {"name": "iPhone 14 Plus", "identifier": "fourteen"},
                ]
            }
        )
        self.assertEqual((identifier, name), ("fourteen", "iPhone 14 Plus"))

    def test_rejects_device_with_wrong_screenshot_size(self) -> None:
        with self.assertRaisesRegex(ScreenshotToolError, "1284 x 2778"):
            select_device_type(
                {"devicetypes": [{"name": "iPhone 17", "identifier": "seventeen"}]}
            )


class AttachmentCollectionTests(unittest.TestCase):
    def create_export(self, root: Path, duplicate: bool = False) -> dict:
        records = []
        for index, (attachment, _) in enumerate(SCREENSHOTS):
            exported = f"attachment-{index}.png"
            (root / exported).write_bytes(PNG)
            records.append(
                {
                    "suggestedHumanReadableName": f"{attachment}.png",
                    "exportedFileName": exported,
                    "isAssociatedWithFailure": False,
                }
            )
        if duplicate:
            records.append(dict(records[0]))
        return [{"testIdentifier": "screenshots", "attachments": records}]

    def test_collects_only_named_png_attachments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exported = root / "exported"
            output = root / "raw"
            exported.mkdir()
            manifest = self.create_export(exported)
            paths = collect_attachments(manifest, exported, output)
            self.assertEqual(
                [path.name for path in paths],
                [f"{basename}.png" for _, basename in SCREENSHOTS],
            )
            self.assertTrue(all(path.read_bytes() == PNG for path in paths))

    def test_collects_xcode_suffixed_attachment_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exported = root / "exported"
            output = root / "raw"
            exported.mkdir()
            manifest = self.create_export(exported)
            suffix = "_0_984BD1B2-59A4-43E9-9564-B84A7717B69B.png"
            for record, (attachment, _) in zip(
                manifest[0]["attachments"], SCREENSHOTS, strict=True
            ):
                record["suggestedHumanReadableName"] = f"{attachment}{suffix}"

            paths = collect_attachments(manifest, exported, output)

            self.assertEqual(
                [path.name for path in paths],
                [f"{basename}.png" for _, basename in SCREENSHOTS],
            )

    def test_rejects_missing_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.create_export(root)
            manifest[0]["attachments"].pop()
            with self.assertRaisesRegex(ScreenshotToolError, "expected 1 attachment"):
                collect_attachments(manifest, root, root / "raw")

    def test_rejects_duplicate_attachment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self.create_export(root, duplicate=True)
            with self.assertRaisesRegex(ScreenshotToolError, "found 2"):
                collect_attachments(manifest, root, root / "raw")

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exported = root / "exported"
            exported.mkdir()
            manifest = self.create_export(exported)
            manifest[0]["attachments"][0]["exportedFileName"] = "../outside.png"
            with self.assertRaisesRegex(ScreenshotToolError, "escapes"):
                collect_attachments(manifest, exported, root / "raw")

    def test_collects_and_validates_live_runtime_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            exported = root / "exported"
            output = root / "raw"
            provenance_output = root / "runtime-provenance.json"
            exported.mkdir()
            manifest = self.create_export(exported)
            provenance_file = exported / "runtime.json"
            provenance_file.write_text(
                json.dumps(live_provenance()), encoding="utf-8"
            )
            manifest[0]["attachments"].append(
                {
                    "suggestedHumanReadableName": "LIVE_APPSTORE_PROVENANCE.json",
                    "exportedFileName": provenance_file.name,
                    "isAssociatedWithFailure": False,
                }
            )

            collect_attachments(
                manifest,
                exported,
                output,
                provenance_output=provenance_output,
            )

            self.assertEqual(
                json.loads(provenance_output.read_text(encoding="utf-8")),
                live_provenance(),
            )


class ScreenshotManifestTests(unittest.TestCase):
    def test_reads_jpeg_dimensions_and_writes_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for _, basename in SCREENSHOTS:
                (directory / f"{basename}.jpg").write_bytes(minimal_jpeg(1284, 2778))

            self.assertEqual(
                jpeg_dimensions(directory / f"{SCREENSHOTS[0][1]}.jpg"),
                (1284, 2778),
            )
            path = write_manifest(
                directory,
                1284,
                2778,
                "abcdef",
                "Xcode 26.5",
                "26.5",
                "iPhone 14 Plus",
                runtime_provenance=live_provenance(),
            )
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["capture"]["commit"], "abcdef")
            self.assertEqual(len(document["screenshots"]), 4)
            self.assertTrue(
                all(len(item["sha256"]) == 64 for item in document["screenshots"])
            )
            self.assertEqual(document["capture"]["mode"], LIVE_CAPTURE_MODE)
            self.assertFalse(document["capture"]["fixtureEnvironmentInjected"])
            self.assertEqual(
                [path.name for path in verify_live_set(directory, document)],
                [f"{basename}.jpg" for _, basename in SCREENSHOTS],
            )

    def test_rejects_wrong_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for _, basename in SCREENSHOTS:
                (directory / f"{basename}.jpg").write_bytes(minimal_jpeg(1179, 2556))
            with self.assertRaisesRegex(ScreenshotToolError, "expected 1284 x 2778"):
                write_manifest(
                    directory,
                    1284,
                    2778,
                    "abcdef",
                    "Xcode 26.5",
                    "26.5",
                    "iPhone 17",
                )

    def test_rejects_fixture_or_pending_runtime_provenance(self) -> None:
        provenance = live_provenance()
        provenance["fixtureEnvironmentInjected"] = True
        with self.assertRaisesRegex(ScreenshotToolError, "fixture injection"):
            validate_live_provenance(provenance)

        provenance = live_provenance()
        provenance["hnsNavigation"]["securityLabel"] = "Waiting for a verified response"
        with self.assertRaisesRegex(ScreenshotToolError, "pending security state"):
            validate_live_provenance(provenance)

        provenance = live_provenance()
        provenance["settings"].pop("statelessDANEToggleIdentifier")
        with self.assertRaisesRegex(ScreenshotToolError, "stateless DANE switch"):
            validate_live_provenance(provenance)

        provenance = live_provenance()
        provenance["hnsNavigation"]["runtimeStatusBeforeNavigation"] = (
            "Syncing Handshake headers"
        )
        with self.assertRaisesRegex(ScreenshotToolError, "current Handshake headers"):
            validate_live_provenance(provenance)

    def test_staging_gate_rejects_missing_or_fixture_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(ScreenshotToolError, "schemaVersion"):
                verify_live_set(directory, {})

            fixture_manifest = {
                "capture": {
                    "configuration": "Debug",
                    "fixtureEnvironmentInjected": True,
                    "mode": "offline-fixture-regression",
                },
                "schemaVersion": 1,
                "screenshots": [],
            }
            with self.assertRaisesRegex(ScreenshotToolError, "cannot be staged"):
                verify_live_set(directory, fixture_manifest)


if __name__ == "__main__":
    unittest.main()
