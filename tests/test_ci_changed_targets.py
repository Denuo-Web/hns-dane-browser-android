#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci-changed-targets.sh"


def parse_outputs(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


class CiChangedTargetsTests(unittest.TestCase):
    def classify(self, *paths: str) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("GITHUB_OUTPUT", None)
        env.pop("GITHUB_STEP_SUMMARY", None)
        result = subprocess.run(
            [str(SCRIPT), "--classify", *paths],
            check=True,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        return parse_outputs(result.stdout)

    def assert_targets(
        self,
        paths: tuple[str, ...],
        *,
        rust: bool,
        android: bool,
        ios: bool,
    ) -> None:
        self.assertEqual(
            self.classify(*paths),
            {
                "rust": str(rust).lower(),
                "android": str(android).lower(),
                "ios": str(ios).lower(),
            },
        )

    def test_shared_rust_runs_every_target(self) -> None:
        for path in (
            "rust/Cargo.toml",
            "rust/Cargo.lock",
            "rust/crates/hns-browser-runtime/src/lib.rs",
            "android/app/src/main/assets/hns_headers_300000.snapshot.gzip",
        ):
            with self.subTest(path=path):
                self.assert_targets((path,), rust=True, android=True, ios=True)

    def test_platform_ffi_does_not_build_opposing_shell(self) -> None:
        self.assert_targets(
            ("rust/crates/android-ffi/src/lib.rs",),
            rust=True,
            android=True,
            ios=False,
        )
        self.assert_targets(
            ("rust/crates/ios-ffi/Cargo.toml",),
            rust=True,
            android=False,
            ios=True,
        )

    def test_android_only_change_skips_apple(self) -> None:
        self.assert_targets(
            ("android/app/src/main/java/com/denuoweb/hnsdane/ui/MainActivity.kt",),
            rust=False,
            android=True,
            ios=False,
        )

    def test_shared_notice_builds_both_application_shells(self) -> None:
        for path in (
            "android/app/src/main/assets/third_party_notices.txt",
            "scripts/generate-third-party-notices.py",
            "scripts/third-party-notices.sha256",
        ):
            with self.subTest(path=path):
                self.assert_targets(
                    (path,),
                    rust=False,
                    android=True,
                    ios=True,
                )

    def test_ios_only_change_skips_android(self) -> None:
        for path in (
            "ios/HnsDaneBrowser/App/AppDelegate.swift",
            "scripts/upload-ios-testflight.sh",
        ):
            with self.subTest(path=path):
                self.assert_targets(
                    (path,),
                    rust=False,
                    android=False,
                    ios=True,
                )

    def test_rust_tooling_does_not_build_apps(self) -> None:
        for path in (
            "rust/fuzz/fuzz_targets/dns_message.rs",
            "rust/deny.toml",
            "tools/hns-header-snapshot-exporter/src/main.rs",
        ):
            with self.subTest(path=path):
                self.assert_targets((path,), rust=True, android=False, ios=False)

    def test_policy_files_do_not_start_native_builds(self) -> None:
        self.assert_targets(
            (
                "README.md",
                "docs/architecture.md",
                "dist/play-store/metadata/en-US/release-notes.txt",
            ),
            rust=False,
            android=False,
            ios=False,
        )

    def test_workflow_and_shared_policy_changes_run_every_target(self) -> None:
        for path in (
            ".github/workflows/ci.yml",
            "scripts/ci-changed-targets.sh",
            "scripts/check-runtime-boundaries.sh",
            "scripts/verify-supply-chain.sh",
            "tests/test_ci_changed_targets.py",
        ):
            with self.subTest(path=path):
                self.assert_targets((path,), rust=True, android=True, ios=True)

    def test_unknown_path_fails_safe(self) -> None:
        self.assert_targets(
            ("new-product-surface/config.toml",),
            rust=True,
            android=True,
            ios=True,
        )

    def test_multiple_platform_paths_are_unioned(self) -> None:
        self.assert_targets(
            (
                "android/app/src/main/AndroidManifest.xml",
                "ios/HnsDaneBrowser/Support/Info.plist",
            ),
            rust=False,
            android=True,
            ios=True,
        )

    def init_repository(self) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        temporary = tempfile.TemporaryDirectory()
        repository = Path(temporary.name)
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(
            ["git", "config", "user.email", "ci-test@example.invalid"],
            cwd=repository,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "CI Test"], cwd=repository, check=True
        )
        (repository / "README.md").write_text("initial\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repository, check=True)
        base = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        return temporary, repository, base

    def run_event(self, repository: Path, **environment: str) -> dict[str, str]:
        output = repository / "github-output.txt"
        summary = repository / "github-summary.md"
        env = os.environ.copy()
        env.update(environment)
        env["GITHUB_OUTPUT"] = str(output)
        env["GITHUB_STEP_SUMMARY"] = str(summary)
        subprocess.run(
            [str(SCRIPT)],
            check=True,
            cwd=repository,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertIn("CI target selection", summary.read_text(encoding="utf-8"))
        return parse_outputs(output.read_text(encoding="utf-8"))

    def test_pull_request_uses_complete_base_to_head_diff(self) -> None:
        temporary, repository, base = self.init_repository()
        with temporary:
            path = repository / "android/app/src/main/AndroidManifest.xml"
            path.parent.mkdir(parents=True)
            path.write_text("<manifest />\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "android"], cwd=repository, check=True)
            head = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip()
            self.assertEqual(
                self.run_event(
                    repository,
                    CI_EVENT_NAME="pull_request",
                    CI_PR_BASE_SHA=base,
                    CI_PR_HEAD_SHA=head,
                ),
                {"rust": "false", "android": "true", "ios": "false"},
            )

    def test_push_uses_before_to_current_diff(self) -> None:
        temporary, repository, before = self.init_repository()
        with temporary:
            path = repository / "ios/HnsDaneBrowser/App/AppDelegate.swift"
            path.parent.mkdir(parents=True)
            path.write_text("import UIKit\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-qm", "ios"], cwd=repository, check=True)
            current = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository, text=True
            ).strip()
            self.assertEqual(
                self.run_event(
                    repository,
                    CI_EVENT_NAME="push",
                    CI_BEFORE_SHA=before,
                    CI_CURRENT_SHA=current,
                ),
                {"rust": "false", "android": "false", "ios": "true"},
            )

    def test_initial_push_classifies_root_commit(self) -> None:
        temporary, repository, current = self.init_repository()
        with temporary:
            self.assertEqual(
                self.run_event(
                    repository,
                    CI_EVENT_NAME="push",
                    CI_BEFORE_SHA="0" * 40,
                    CI_CURRENT_SHA=current,
                ),
                {"rust": "false", "android": "false", "ios": "false"},
            )

    def test_manual_dispatch_and_invalid_comparison_force_all(self) -> None:
        temporary, repository, _ = self.init_repository()
        with temporary:
            self.assertEqual(
                self.run_event(repository, CI_EVENT_NAME="workflow_dispatch"),
                {"rust": "true", "android": "true", "ios": "true"},
            )
            self.assertEqual(
                self.run_event(
                    repository,
                    CI_EVENT_NAME="pull_request",
                    CI_PR_BASE_SHA="not-a-sha",
                    CI_PR_HEAD_SHA="also-not-a-sha",
                ),
                {"rust": "true", "android": "true", "ios": "true"},
            )


if __name__ == "__main__":
    unittest.main()
