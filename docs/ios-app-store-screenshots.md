# iOS App Store screenshots

The `iOS App Store Screenshots` workflow creates four reviewable iPhone screenshots without an iPhone, signing credentials, or live network access. It runs automatically on pull requests that change the iOS shell or its shared Rust inputs and can also be started manually:

```sh
gh workflow run ios-screenshots.yml \
  --repo Denuo-Web/hns-dane-browser \
  --ref main
```

Open the completed workflow run and download the artifact named
`ios-app-store-screenshots-COMMIT_SHA`. It contains:

- `01-hns-dane-verified.jpg`
- `02-browser-settings.jpg`
- `03-proof-details.jpg`
- `04-webpki.jpg`
- `manifest.json`, containing the commit, Xcode/SDK/device provenance,
  dimensions, and SHA-256 digest for every image

Each JPEG is exactly `1284 x 2778`, has no alpha channel, and fits App Store
Connect's 6.5-inch iPhone screenshot slot. The workflow creates a fresh iPhone
14 Plus simulator, with 13 Pro Max and 12 Pro Max as equivalent fallbacks.

## Accuracy and isolation

The capture uses the shipping browser chrome, menus, Proof Details viewer, and
the exact security labels emitted by the production policy. Page content is a
deterministic, developer-controlled, offline document rendered by WebKit, so a
site outage or mutable third-party page cannot change the images. The fixture
exists only in Debug simulator builds behind `#if DEBUG &&
targetEnvironment(simulator)`. The generator also builds Release and fails if
the fixture environment key appears in the Release executable.

This is artwork generation, not a live resolver/device-validation run. The
complete unsigned iOS gate runs first, and `docs/ios-device-validation.md`
remains the separate optional real-device test matrix.

## Approve and stage the images

1. Inspect all four images at full size. Confirm text is not clipped, the menu
   is open in image 02, Proof Details is legible in image 03, and no simulator
   alerts or test overlays appear.
2. Confirm `manifest.json` reports `1284` by `2778` for every file and the
   expected source commit.
3. Copy the approved JPEGs into `dist/app-store/screenshots/en-US/` unchanged.
4. Run `python3 dist/app-store/validate.py` and resolve every error.
5. Upload one to ten approved images to the 6.5-inch iPhone slot in App Store
   Connect. The first three are the most prominent; the recommended order is
   HNS/DANE, Browser Settings, Proof Details, then WebPKI.

The workflow never contacts App Store Connect and never uses the protected
`app-store` environment. Upload remains a deliberate, manual step after human
review.

On a compatible Mac, the same capture can be run locally after
`scripts/run-ios-gate.sh`:

```sh
./scripts/generate-ios-app-store-screenshots.sh
```

The local output is written to `build/app-store-screenshots/`.
