# iOS App Store release

The release path uses the standard `macos-26` GitHub-hosted runner in this public repository. Standard GitHub-hosted runners are free for public repositories, so MacInCloud is not part of the normal release path.

The committed application identity is:

- Team ID: `45NQQK3G3S`
- Bundle ID: `com.denuoweb.hnsdane.ios`
- Display name: `HNS DANE Browser`
- Deployment floor: iOS 17.0
- First iOS version/build: `0.5.0` (`40`)
- Device family: iPhone

## One-time Apple setup

1. In Apple Developer, accept all current agreements and register an explicit App ID for `com.denuoweb.hnsdane.ios`. No optional capabilities are currently required.
2. In App Store Connect, create the iOS app record using the fixed values in `dist/app-store/metadata/README.md`.
3. In App Store Connect **Users and Access → Integrations → App Store Connect API**, enable API access if needed and create a **team** API key for CI.
4. Download the `.p8` private key once. Record its 10-character Key ID and issuer UUID. Never commit the key, attach it to an issue, paste it into chat, or publish it as a workflow artifact.
5. Create an Apple Distribution certificate and an App Store provisioning profile for the explicit App ID. Export the certificate and private key as a password-protected `.p12` that macOS Keychain can import. Use Keychain Access, or OpenSSL 3's legacy-compatible PKCS#12 export mode instead of its default PBES2/AES encoding. App Store profiles contain no registered devices, so this setup does not require an iPhone.

Apple's export-compliance questionnaire must be completed deliberately. The app embeds Rust implementations of industry-standard TLS, DNSSEC, and DANE cryptography rather than limiting encryption to Apple's operating-system APIs, so the answer and any required documentation must come from App Store Connect's current questionnaire.

## One-time GitHub setup

Create an environment named exactly `app-store`, restrict deployment branches to `main`, and require approval if the repository plan exposes that control. Add these environment secrets:

- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_API_ISSUER_ID`
- `APP_STORE_CONNECT_API_PRIVATE_KEY` — the complete downloaded `.p8` file
- `IOS_DISTRIBUTION_P12_BASE64` — the macOS-compatible, password-protected Apple Distribution `.p12`, base64 encoded on one line
- `IOS_DISTRIBUTION_P12_PASSWORD` — the `.p12` password, with no trailing newline
- `IOS_APP_STORE_PROFILE_BASE64` — the App Store `.mobileprovision` file, base64 encoded on one line

From a trusted local shell with `gh` authenticated as a repository administrator:

```sh
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_KEY_ID
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_ISSUER_ID
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_PRIVATE_KEY < /trusted/path/AuthKey_KEYID.p8
base64 -w0 /trusted/path/apple-distribution.p12 | gh secret set --repo Denuo-Web/hns-dane-browser --env app-store IOS_DISTRIBUTION_P12_BASE64
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store IOS_DISTRIBUTION_P12_PASSWORD < /trusted/path/p12-password.txt
base64 -w0 /trusted/path/app-store.mobileprovision | gh secret set --repo Denuo-Web/hns-dane-browser --env app-store IOS_APP_STORE_PROFILE_BASE64
```

## Upload a build

The workflow is manual, refuses non-`main` refs, has read-only GitHub permissions, runs the complete unsigned simulator/device-link gate before credentials are materialized, and uploads without retaining a public IPA artifact.

```sh
gh workflow run ios-testflight.yml \
  --repo Denuo-Web/hns-dane-browser \
  --ref main \
  -f confirm_upload=true
```

The workflow then:

1. runs `scripts/run-ios-gate.sh` with Xcode 26.5/26.6 and the iOS 26.5 SDK;
2. writes the API key, distribution identity, and App Store profile only to the ephemeral runner's private temporary directory;
3. verifies the identity and profile against the fixed team and bundle IDs, then creates a Release archive using manual App Store distribution signing in a disposable keychain;
4. validates/exports the archive with App Store Connect authentication and uploads build `40`;
5. deletes the temporary keychain, installed profile, API key, `.p12`, and profile while GitHub discards the runner.

Apple associates the uploaded build with the app record using its bundle ID, version, and build number. A rerun after Apple accepts build `40` requires a higher build number.

## Release gate after upload

Complete the metadata in `dist/app-store/metadata/en-US`, publish the revised privacy policy, generate current iPhone screenshots, answer App Privacy/age-rating/content-rights/export-compliance questions, and distribute the build through TestFlight.

Owning an iPhone is not required to archive, sign, upload, or submit. Before final App Review, arrange one external TestFlight pass on a real iPhone and record the applicable matrix from `docs/ios-device-validation.md`. MacInCloud is only a fallback if an account-specific problem cannot be resolved through the developer portals and GitHub Actions logs.
