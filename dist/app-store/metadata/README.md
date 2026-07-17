# App Store metadata

This directory is the reviewed source for the first iOS App Store record. It is not uploaded automatically by the TestFlight workflow.

## App record

- Platform: iOS
- Name: `HNS DANE Browser`
- Primary language: English (U.S.)
- Bundle ID: `com.denuoweb.hnsdane.ios`
- SKU: `hns-dane-browser-ios`
- Apple Team ID: `45NQQK3G3S`
- User access: Full Access
- Version: `0.5.0`
- Primary category: Utilities
- Price: Free

The first release is iPhone-only. Native iPad support can be enabled in a later version after adding iPad screenshots and validation coverage.

## Before submission

1. Publish the current cross-platform privacy policy at the URL in `en-US/privacy-policy-url.txt`.
2. Complete App Store Connect's app-privacy, age-rating, content-rights, and export-compliance questionnaires from the app's actual behavior. Do not answer the encryption question by assumption: the Rust runtime implements industry-standard TLS, DNSSEC, and DANE cryptography outside Apple's operating-system crypto APIs.
3. Generate current iPhone simulator screenshots from the iOS shell. Do not reuse Android screenshots.
4. Add at least one external TestFlight tester with an iPhone for the recommended real-device release pass.
5. Supply App Review with the notes in `en-US/review-notes.txt`; no login is required.

The API private key used by CI must exist only in the protected GitHub `app-store` environment and must never be committed or uploaded as a workflow artifact.
