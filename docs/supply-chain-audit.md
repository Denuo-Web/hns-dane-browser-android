# Build and Supply-Chain Audit

Last audited: 2026-07-14

## Configured and Local Gates

- The checked-in GitHub Actions workflow is configured to run the shipping Rust workspace, fuzz workspace, header-snapshot exporter, cargo-deny policy, Android unit tests, lint, debug assembly, and unsigned release bundle build. Its permissions are read-only, release secrets are not provided, every non-local `uses:` reference is pinned to a full commit SHA, checkout credentials are not persisted, and concurrent runs on the same ref are cancelled. This is configuration evidence only: Actions is currently disabled for the GitHub repository, so the workflow has no successful remote run and is not an enforced merge gate.
- Dependabot watches GitHub Actions, Gradle, and all three Cargo lockfile roots weekly.
- Rust uses toolchain `1.92.0`; build, clippy, test, metadata, Android cross-compile, and cargo-deny commands use committed lockfiles with `--locked`. No Cargo lockfile contains a Git dependency, and registry packages carry Cargo checksums.
- cargo-deny covers all three manifests. The fuzz and exporter packages now declare the repository license. `NCSA` is allowed specifically because `libfuzzer-sys` combines its MIT/Apache-2.0 code with LLVM libFuzzer code under the University of Illinois/NCSA license.
- Gradle 9.6.1 has an official distribution checksum in `gradle-wrapper.properties`; the checked-in wrapper JAR is independently compared with the official wrapper-JAR SHA-256. Android dependency locking runs in strict mode, and Gradle verification metadata pins SHA-256 hashes for resolved artifacts and metadata.
- `scripts/verify-supply-chain.sh` checks the exact wrapper distribution URL and hashes, required lock/verification files, Cargo lock consistency and absence of Git sources, shell syntax, immutable Action references, tracked secret-bearing filenames, and high-confidence secret patterns. Root-invoked Rust scripts explicitly select toolchain `1.92.0` instead of relying on rustup to discover a toolchain file beside a manifest in another directory.
- Android JNI release builds reject unknown profiles, compiler/linker/profile overrides, and unexpected cargo-ndk/NDK versions; use `--locked`; force the release profile; require both ABI outputs; and restrict cleanup to `android/app/build`. Path-prefix maps remove checkout, home, Cargo, Rustup, and NDK paths while retaining line-table debug information for AGP. Gradle pins AGP to NDK `28.2.13676358`, treats the NDK location and `source.properties` as incremental inputs, and includes Rust `.txt` data files such as the ICANN TLD snapshot.
- The unsigned bundle gate requires an exact two-library ABI inventory, `PAGE_ALIGNMENT_16K`, bounds-safe ELF64 ET_DYN files with the expected machine, 16 KiB PT_LOAD alignment, RELRO, one non-executable GNU stack, immediate binding, no text relocations, SHA-1 Build IDs, stripped shipping libraries, matching FULL debug metadata, no local paths, a non-empty R8 mapping, and non-empty third-party notices.
- The signed Play bundle gate reads every content entry through Java's verifying `JarFile`, rejects bad digests, unsigned entries, mixed signers, or a signer that does not match `HNS_DANE_BROWSER_UPLOAD_CERTIFICATE_SHA256`, and depends on the unsigned structural gate.
- The third-party notices generator derives the Android release-runtime and shipping Rust dependency inventories from locked, integrity-verified inputs, reproduces available license/notice text, commits a full-asset SHA-256, and is checked by `scripts/check.sh` without requiring dependency resolution in CI.
- Keystores, signing properties, service-account files, environment files, private-key formats, local Android properties, and generated APK/AAB artifacts are ignored. The Play API helper keeps its bearer token out of curl's process arguments, validates URL path inputs and release status, and enforces HTTPS/TLS timeouts.

## Audit Results

- `scripts/check.sh` passed locally on 2026-07-14, including supply-chain/version checks, formatting, clippy with warnings denied, all three cargo-deny scopes, 398 Rust tests, fuzz-target compilation, and the header-snapshot exporter.
- A clean Android build passed 190 unit tests, debug assembly, debug and release lint with zero errors, R8/resource shrinking, upload signing, and both release-bundle gates. It used Gradle 9.6.1 / AGP 9.2.1, compile/target SDK 37, NDK `28.2.13676358`, and build-tools AAPT2 36.0.0.
- Independent artifact inspection confirmed both installed JNI libraries were NDK r28c API 34 ET_DYN files, stripped, 16 KiB-aligned, RELRO, non-executable-stack, immediate-binding, text-relocation-free, and paired with unstripped `.dbg` files carrying the same Build IDs. No checkout/home/NDK path was found; the debug APK passed 16 KiB zip alignment.
- cargo-deny reports no known advisory, source, or license-policy failures for the shipping workspace, fuzz workspace, or exporter. Duplicate transitive versions and unused allow-list entries remain warnings.
- No high-confidence secret or secret-bearing filename was found among tracked files.
- The locally configured upload certificate SHA-256 matches the retained signed `0.3.8`, `0.3.9`, and `0.3.10` bundles. It still needs an out-of-band comparison with the upload certificate shown by Play Console.
- GitHub Actions is disabled for the repository, the workflow has no runs, and `main` has neither branch protection nor a ruleset. Until those hosting controls are enabled and a workflow succeeds, local passes are the only execution evidence.
- Release signing and Play upload remain intentional secret-dependent gates. CI should build and structurally verify the release variant without signing credentials and must not publish.

## Residual Risks

- This audit pins inputs but does not establish bit-for-bit reproducible APK/AAB output. Runner images, the JDK 21 patch release selected by setup-java, Android SDK packaging, archive timestamps, and signing can still vary. A future release process should compare independently built unsigned artifacts before signing.
- Gradle verification metadata was generated from artifacts already obtained over the configured HTTPS repositories. Future checksum changes require a deliberate review; the metadata is an integrity pin, not independent provenance proof.
- cargo-deny relies on the current RustSec advisory database at check time. CI availability or an upstream advisory-database outage can affect results.
- The local JNI script defaults to and enforces NDK `28.2.13676358`; `HNS_ANDROID_NDK_VERSION` may override that expectation only for an intentional, reviewed toolchain change.
- The exact-toolchain audit pass was performed before the `0.3.13` version increment. The version change alters committed notice-integrity inputs, so regenerate notices and repeat the signed structural gate for the final upload artifact.
- The upload certificate fingerprint is public configuration, but its approved value still needs an out-of-band comparison with the Play Console upload certificate before the next release.
