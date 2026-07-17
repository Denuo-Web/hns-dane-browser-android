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
3. In App Store Connect **Users and Access → Integrations → App Store Connect API**, enable API access if needed and create a **team** API key for CI. The Account Holder/Admin key needs cloud-managed distribution-certificate access for the initial automatic-signing workflow.
4. Download the `.p8` private key once. Record its 10-character Key ID and issuer UUID. Never commit the key, attach it to an issue, paste it into chat, or publish it as a workflow artifact.

Apple's export-compliance questionnaire must be completed deliberately. The app embeds Rust implementations of industry-standard TLS, DNSSEC, and DANE cryptography rather than limiting encryption to Apple's operating-system APIs, so the answer and any required documentation must come from App Store Connect's current questionnaire.

## One-time GitHub setup

Create an environment named exactly `app-store`, restrict deployment branches to `main`, and require approval if the repository plan exposes that control. Add these environment secrets:

- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_API_ISSUER_ID`
- `APP_STORE_CONNECT_API_PRIVATE_KEY` — the complete downloaded `.p8` file

From a trusted local shell with `gh` authenticated as a repository administrator:

```sh
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_KEY_ID
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_ISSUER_ID
gh secret set --repo Denuo-Web/hns-dane-browser --env app-store APP_STORE_CONNECT_API_PRIVATE_KEY < /trusted/path/AuthKey_KEYID.p8
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
2. writes the API key only to the ephemeral runner's private temporary directory;
3. creates a Release archive using automatic signing and Apple's cloud-managed distribution certificate;
4. validates/exports the archive with App Store Connect authentication and uploads build `40`;
5. deletes the temporary API key while GitHub discards the runner.

Apple associates the uploaded build with the app record using its bundle ID, version, and build number. A rerun after Apple accepts build `40` requires a higher build number.

## Release gate after upload

Complete the metadata in `dist/app-store/metadata/en-US`, publish the revised privacy policy, generate current iPhone screenshots, answer App Privacy/age-rating/content-rights/export-compliance questions, and distribute the build through TestFlight.

Owning an iPhone is not required to archive, sign, upload, or submit. Before final App Review, arrange one external TestFlight pass on a real iPhone and record the applicable matrix from `docs/ios-device-validation.md`. MacInCloud is only a fallback if Apple cloud signing exposes an account-specific problem that cannot be resolved through the developer portals and GitHub Actions logs.
