#!/usr/bin/env python3
"""Generate the reviewed in-app third-party notices asset from locked inputs.

Generation is deliberately offline. Rust package metadata and license files come
from Cargo's checksum-verified registry cache; Android license metadata and
artifacts come from Gradle's dependency-verification cache. The lightweight
``--check`` mode verifies the complete asset digest, committed input
fingerprints, and locked Android runtime inventory, so it is suitable for a
clean CI checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
import zipfile


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "android/app/src/main/assets/third_party_notices.txt"
OUTPUT_SHA256 = ROOT / "scripts/third-party-notices.sha256"
SCHEMA = "2"
LOCKED_INPUT_PATHS = (
    "scripts/generate-third-party-notices.py",
    "rust/Cargo.toml",
    "rust/Cargo.lock",
    "android/gradle/libs.versions.toml",
    "android/app/gradle.lockfile",
    "android/gradle/verification-metadata.xml",
)
RUST_MANIFEST_INPUTS = tuple(
    path.relative_to(ROOT).as_posix()
    for path in sorted((ROOT / "rust/crates").glob("*/Cargo.toml"))
)
INPUT_PATHS = LOCKED_INPUT_PATHS + RUST_MANIFEST_INPUTS
LICENSE_FILE_PREFIXES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")
MAX_NOTICE_FILE_SIZE = 512 * 1024
RUST_SHIPPING_TARGETS = (
    ("aarch64-linux-android", "android-ffi"),
    ("x86_64-linux-android", "android-ffi"),
    ("aarch64-apple-ios", "ios-ffi"),
    ("aarch64-apple-ios-sim", "ios-ffi"),
    ("x86_64-apple-ios", "ios-ffi"),
)

# These registry packages are published without their workspace-level license
# files. The companion packages are from the same upstream project and release
# family and contain the project license texts named by the package manifest.
RUST_LICENSE_FILE_FALLBACKS = {
    ("asn1-rs-impl", "0.2.0"): ("asn1-rs", "0.7.2"),
    ("jni-sys-macros", "0.4.1"): ("jni-sys", "0.4.1"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def input_fingerprints() -> dict[str, str]:
    return {
        relative: sha256_bytes((ROOT / relative).read_bytes())
        for relative in INPUT_PATHS
    }


def android_runtime_coordinates() -> list[str]:
    coordinates: list[str] = []
    lockfile = ROOT / "android/app/gradle.lockfile"
    for line in lockfile.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        coordinate, configurations = line.split("=", 1)
        if coordinate == "empty":
            continue
        if "releaseRuntimeClasspath" in configurations.split(","):
            if coordinate.count(":") != 2:
                raise RuntimeError(f"Unexpected locked Android coordinate: {coordinate}")
            coordinates.append(coordinate)
    if not coordinates:
        raise RuntimeError("No releaseRuntimeClasspath dependencies were found in the Gradle lockfile.")
    return sorted(set(coordinates))


def check_committed_asset() -> int:
    if not OUTPUT.is_file():
        print(f"Missing generated third-party notices asset: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
        return 1

    text = OUTPUT.read_text(encoding="utf-8")
    failures: list[str] = []
    expected_output_digest = ""
    if not OUTPUT_SHA256.is_file():
        failures.append(f"the committed digest file {OUTPUT_SHA256.relative_to(ROOT)} is missing")
    else:
        digest_fields = OUTPUT_SHA256.read_text(encoding="utf-8").strip().split()
        if len(digest_fields) != 2 or digest_fields[1] != OUTPUT.relative_to(ROOT).as_posix():
            failures.append("the committed asset digest record is malformed")
        elif not re.fullmatch(r"[0-9a-f]{64}", digest_fields[0]):
            failures.append("the committed asset digest is not a SHA-256 value")
        else:
            expected_output_digest = digest_fields[0]
    if expected_output_digest and sha256_bytes(OUTPUT.read_bytes()) != expected_output_digest:
        failures.append("the complete generated notices asset does not match its committed SHA-256")
    if not text.startswith("HNS DANE BROWSER THIRD-PARTY SOFTWARE NOTICES\n"):
        failures.append("the generated marker is missing")
    if f"Generator schema: {SCHEMA}\n" not in text:
        failures.append("the generator schema is stale")
    for relative, digest in input_fingerprints().items():
        if f"  {relative} = {digest}\n" not in text:
            failures.append(f"the fingerprint for {relative} is stale")

    expected_android = {
        f"  {coordinate} | Apache-2.0" for coordinate in android_runtime_coordinates()
    }
    match = re.search(
        r"^ANDROID RUNTIME COMPONENTS \(\d+\)\n(?P<body>.*?)\n\nRUST COMPONENTS",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    actual_android = set(match.group("body").splitlines()) if match else set()
    if actual_android != expected_android:
        failures.append("the Android release runtime inventory is stale")

    if failures:
        print("Third-party notices are stale:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(
            "Resolve the locked Cargo and Gradle dependencies, then run "
            "python3 scripts/generate-third-party-notices.py.",
            file=sys.stderr,
        )
        return 1

    print("Third-party notices match the locked dependency inputs.")
    return 0


def cargo_metadata(target: str) -> dict:
    command = [
        "cargo",
        "+1.92.0",
        "metadata",
        "--offline",
        "--locked",
        "--manifest-path",
        str(ROOT / "rust/Cargo.toml"),
        "--filter-platform",
        target,
        "--format-version",
        "1",
    ]
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    try:
        output = subprocess.check_output(command, cwd=ROOT, env=environment)
    except (FileNotFoundError, subprocess.CalledProcessError) as error:
        raise RuntimeError(
            "Unable to read pinned Cargo metadata offline. Build the locked Rust workspace "
            "once to populate Cargo's verified registry cache."
        ) from error
    return json.loads(output)


def shipping_rust_packages(metadata: dict, root_package: str) -> list[dict]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == root_package and package["source"] is None
    ]
    if len(roots) != 1:
        raise RuntimeError(
            f"Expected one workspace {root_package} package, found {len(roots)}."
        )

    reachable: set[str] = set()
    pending = roots[:]
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        reachable.add(package_id)
        node = nodes[package_id]
        for dependency in node["deps"]:
            if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])

    third_party = [
        packages[package_id]
        for package_id in reachable
        if packages[package_id]["source"] is not None
    ]
    third_party.sort(key=lambda package: (package["name"].casefold(), package["version"]))
    if not third_party:
        raise RuntimeError(
            f"The {root_package} Rust dependency closure unexpectedly contains no registry packages."
        )
    for package in third_party:
        if not package.get("license"):
            raise RuntimeError(
                f"Rust package {package['name']} {package['version']} has no declared license expression."
            )
    return third_party


def shipping_rust_packages_for_targets() -> tuple[list[dict], dict[str, int]]:
    packages_by_id: dict[str, dict] = {}
    target_counts: dict[str, int] = {}
    for target, root_package in RUST_SHIPPING_TARGETS:
        target_packages = shipping_rust_packages(cargo_metadata(target), root_package)
        target_counts[target] = len(target_packages)
        for package in target_packages:
            package_id = package["id"]
            existing = packages_by_id.get(package_id)
            if existing is not None and existing != package:
                raise RuntimeError(
                    f"Cargo returned conflicting metadata for package {package_id} "
                    f"across shipped application targets."
                )
            packages_by_id[package_id] = package

    packages = sorted(
        packages_by_id.values(),
        key=lambda package: (package["name"].casefold(), package["version"], package["id"]),
    )
    if not packages:
        raise RuntimeError("The shipped Rust target closures contain no registry packages.")
    return packages, target_counts


def local_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def element_child_text(element: ElementTree.Element, name: str) -> str | None:
    for child in element:
        if local_name(child) == name and child.text:
            return child.text.strip()
    return None


def gradle_module_dir(group: str, artifact: str, version: str) -> Path:
    gradle_home = Path(os.environ.get("GRADLE_USER_HOME", Path.home() / ".gradle"))
    return gradle_home / "caches/modules-2/files-2.1" / group / artifact / version


def one_cached_pom(group: str, artifact: str, version: str) -> Path:
    module_dir = gradle_module_dir(group, artifact, version)
    poms = sorted(module_dir.glob("*/*.pom"))
    if not poms:
        raise RuntimeError(
            f"Missing cached POM for locked Android dependency {group}:{artifact}:{version}. "
            "Resolve the locked releaseRuntimeClasspath once before generating notices."
        )
    contents = {pom.read_bytes() for pom in poms}
    if len(contents) != 1:
        raise RuntimeError(f"Conflicting cached POMs found for {group}:{artifact}:{version}.")
    return poms[0]


def pom_license_metadata(
    group: str,
    artifact: str,
    version: str,
    visited: set[tuple[str, str, str]] | None = None,
) -> list[tuple[str, str]]:
    coordinate = (group, artifact, version)
    visited = set() if visited is None else visited
    if coordinate in visited:
        raise RuntimeError(f"Cyclic Maven parent chain while reading {':'.join(coordinate)}.")
    visited.add(coordinate)

    root = ElementTree.parse(one_cached_pom(*coordinate)).getroot()
    licenses: list[tuple[str, str]] = []
    for child in root:
        if local_name(child) != "licenses":
            continue
        for license_element in child:
            if local_name(license_element) != "license":
                continue
            licenses.append((
                element_child_text(license_element, "name") or "",
                element_child_text(license_element, "url") or "",
            ))
    if licenses:
        return licenses

    parent = next((child for child in root if local_name(child) == "parent"), None)
    if parent is None:
        return []
    parent_group = element_child_text(parent, "groupId")
    parent_artifact = element_child_text(parent, "artifactId")
    parent_version = element_child_text(parent, "version")
    if not all((parent_group, parent_artifact, parent_version)):
        return []
    return pom_license_metadata(
        parent_group or "",
        parent_artifact or "",
        parent_version or "",
        visited,
    )


def require_apache_android_licenses(coordinates: list[str]) -> None:
    for coordinate in coordinates:
        group, artifact, version = coordinate.rsplit(":", 2)
        licenses = pom_license_metadata(group, artifact, version)
        if not licenses:
            raise RuntimeError(f"No POM license metadata was found for {coordinate}.")
        for name, url in licenses:
            normalized = f"{name} {url}".lower()
            if "apache" not in normalized or not (
                "2.0" in normalized or "version 2" in normalized or "license-2.0" in normalized
            ):
                raise RuntimeError(
                    f"Unreviewed Android license for {coordinate}: name={name!r}, url={url!r}"
                )


def apache_license_text(coordinates: list[str]) -> str:
    candidates: set[str] = set()
    for coordinate in coordinates:
        group, artifact, version = coordinate.rsplit(":", 2)
        module_dir = gradle_module_dir(group, artifact, version)
        for artifact_file in sorted(module_dir.glob("*/*")):
            if artifact_file.suffix not in {".aar", ".jar"}:
                continue
            try:
                with zipfile.ZipFile(artifact_file) as archive:
                    for entry in sorted(archive.namelist()):
                        if not Path(entry).name.upper().startswith(LICENSE_FILE_PREFIXES):
                            continue
                        info = archive.getinfo(entry)
                        if not 0 <= info.file_size <= MAX_NOTICE_FILE_SIZE:
                            continue
                        text = archive.read(entry).decode("utf-8").replace("\r\n", "\n").strip()
                        if "Apache License" in text and "Version 2.0" in text:
                            candidates.add(text)
            except zipfile.BadZipFile:
                continue
    if not candidates:
        raise RuntimeError("No Apache-2.0 license text was found in the verified Android artifacts.")
    return sorted(candidates, key=lambda value: (len(value), value))[0]


def registry_license_files(package: dict) -> list[tuple[str, str]]:
    package_dir = Path(package["manifest_path"]).resolve().parent
    files: list[Path] = []
    for candidate in sorted(package_dir.rglob("*")):
        if candidate.is_symlink() or not candidate.is_file():
            continue
        if candidate.name.upper().startswith(LICENSE_FILE_PREFIXES):
            files.append(candidate)
    license_file = package.get("license_file")
    if license_file:
        candidate = Path(license_file).resolve()
        try:
            candidate.relative_to(package_dir)
        except ValueError as error:
            raise RuntimeError(
                f"License file for {package['name']} escapes its verified registry package."
            ) from error
        if candidate not in files:
            files.append(candidate)

    result: list[tuple[str, str]] = []
    for candidate in sorted(files):
        size = candidate.stat().st_size
        if not 0 <= size <= MAX_NOTICE_FILE_SIZE:
            raise RuntimeError(f"License file has an unexpected size: {candidate}")
        try:
            content = candidate.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
        except UnicodeDecodeError as error:
            raise RuntimeError(f"License file is not UTF-8 text: {candidate}") from error
        if content:
            result.append((candidate.relative_to(package_dir).as_posix(), content))
    return result


def sqlite_public_domain_notice(rust_packages: list[dict]) -> tuple[str, str] | None:
    package = next(
        (package for package in rust_packages if package["name"] == "libsqlite3-sys"),
        None,
    )
    if package is None:
        return None
    source = Path(package["manifest_path"]).parent / "sqlite3/sqlite3.c"
    if not source.is_file():
        raise RuntimeError("Bundled libsqlite3-sys is missing sqlite3/sqlite3.c.")
    source_text = source.read_text(encoding="utf-8")
    version_match = re.search(r"SQLite\n\*\* version ([0-9]+(?:\.[0-9]+)*)", source_text)
    notice_match = re.search(
        r"\*\* The author disclaims copyright.*?\*\*    May you share freely, never taking more than you give\.",
        source_text,
        flags=re.DOTALL,
    )
    if not version_match or not notice_match:
        raise RuntimeError("Unable to locate the bundled SQLite public-domain notice.")
    lines = []
    for line in notice_match.group(0).splitlines():
        lines.append(re.sub(r"^\s*\*\* ?", "", line).rstrip())
    return (
        f"SQLite {version_match.group(1)} public-domain dedication",
        "\n".join(lines).strip(),
    )


def generate() -> str:
    android_coordinates = android_runtime_coordinates()
    require_apache_android_licenses(android_coordinates)
    rust_packages, rust_target_counts = shipping_rust_packages_for_targets()

    notice_groups: dict[str, dict[str, object]] = {}

    def add_notice(applies_to: str, source_name: str, content: str) -> None:
        normalized = content.replace("\r\n", "\n").strip()
        digest = sha256_bytes(normalized.encode("utf-8"))
        group = notice_groups.setdefault(
            digest,
            {"content": normalized, "applies_to": set(), "source_names": set()},
        )
        group["applies_to"].add(applies_to)  # type: ignore[union-attr]
        group["source_names"].add(source_name)  # type: ignore[union-attr]

    android_license = apache_license_text(android_coordinates)
    for coordinate in android_coordinates:
        add_notice(coordinate, "Apache-2.0 license text from a locked Android artifact", android_license)

    package_license_files: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for package in rust_packages:
        key = (package["name"], package["version"])
        package_license_files[key] = registry_license_files(package)
    for key, fallback in RUST_LICENSE_FILE_FALLBACKS.items():
        if key in package_license_files and not package_license_files[key]:
            fallback_files = package_license_files.get(fallback)
            if not fallback_files:
                raise RuntimeError(
                    f"Missing reviewed companion license files for {key[0]} {key[1]}."
                )
            package_license_files[key] = [
                (f"companion {fallback[0]} {fallback[1]}/{name}", content)
                for name, content in fallback_files
            ]

    for package in rust_packages:
        key = (package["name"], package["version"])
        label = f"Rust crate {package['name']} {package['version']}"
        files = package_license_files[key]
        if not files:
            raise RuntimeError(
                f"No license/notice text is available for {package['name']} {package['version']}."
            )
        for name, content in files:
            add_notice(label, name, content)

    sqlite_notice = sqlite_public_domain_notice(rust_packages)
    if sqlite_notice:
        source_name, content = sqlite_notice
        add_notice("Bundled SQLite used by libsqlite3-sys", source_name, content)

    lines = [
        "HNS DANE BROWSER THIRD-PARTY SOFTWARE NOTICES",
        "",
        "This app includes open-source components. The inventories below are generated from the",
        "locked Android release runtime classpath and the non-development Cargo dependency closures",
        "reachable from the Android and iOS native libraries for each shipped Rust target. The Rust",
        "inventory is the union of the Android and Apple device/simulator closures. Cargo build-time",
        "dependencies are retained conservatively. Workspace-owned HNS DANE Browser crates and",
        "test-only, lint, platform build-tool, fuzz, and snapshot-exporter dependencies are excluded.",
        "",
        "Shipped Rust target closure counts:",
        *(
            f"  {target}: {rust_target_counts[target]} registry components"
            for target, _ in RUST_SHIPPING_TARGETS
        ),
        "",
        "License expressions are the declarations in the verified package metadata. The reproduced",
        "texts come from the checksum-verified Cargo packages or dependency-verified Android",
        "artifacts. Inclusion here does not imply endorsement by the component authors.",
        "",
        f"Generator schema: {SCHEMA}",
        "Generated input SHA-256:",
    ]
    for relative, digest in input_fingerprints().items():
        lines.append(f"  {relative} = {digest}")

    lines.extend(["", f"ANDROID RUNTIME COMPONENTS ({len(android_coordinates)})"])
    lines.extend(f"  {coordinate} | Apache-2.0" for coordinate in android_coordinates)

    lines.extend(["", f"RUST COMPONENTS ({len(rust_packages)})"])
    for package in rust_packages:
        lines.append(f"  {package['name']} {package['version']} | {package['license']}")

    lines.extend(["", "LICENSE AND NOTICE TEXTS"])
    for digest in sorted(notice_groups):
        group = notice_groups[digest]
        applies_to = sorted(  # type: ignore[arg-type]
            group["applies_to"],
            key=lambda value: (value.casefold(), value),
        )
        source_names = sorted(  # type: ignore[arg-type]
            group["source_names"],
            key=lambda value: (value.casefold(), value),
        )
        lines.extend([
            "",
            "=" * 80,
            f"Notice SHA-256: {digest}",
            "Applies to:",
        ])
        lines.extend(f"  - {value}" for value in applies_to)
        lines.append("Source file names:")
        lines.extend(f"  - {value}" for value in source_names)
        lines.extend(["-" * 80, str(group["content"])])

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the full asset digest, fingerprints, and inventory without dependency caches",
    )
    arguments = parser.parse_args()
    if arguments.check:
        return check_committed_asset()

    try:
        generated = generate()
    except RuntimeError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    OUTPUT_SHA256.write_text(
        f"{sha256_bytes(generated.encode('utf-8'))}  {OUTPUT.relative_to(ROOT).as_posix()}\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Wrote {OUTPUT.relative_to(ROOT)} and {OUTPUT_SHA256.relative_to(ROOT)} "
        f"({len(generated.encode('utf-8'))} bytes)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
