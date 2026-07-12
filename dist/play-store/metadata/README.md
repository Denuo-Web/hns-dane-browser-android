# Google Play Metadata Package

This directory contains the source text and field checklist for the Google Play Console listing for package `com.denuoweb.hnsdane`.

## Listing Text

- App name: `en-US/title.txt`
- Short description: `en-US/short-description.txt`
- Full description: `en-US/full-description.txt`
- 0.3.10 release notes: `en-US/release-notes.txt`

## Store Assets

- App icon: `../hns-dane-browser-play-icon-512.png`
- Feature graphic: `../hns-dane-browser-feature-graphic-1024x500.png`
- Phone screenshots: `../screenshots/*.png`

## Console Fields

- Package name: `com.denuoweb.hnsdane`
- App category: Tools
- Ads declaration: No ads
- Privacy policy URL: `https://denuoweb.com/work/hns-dane-browser/privacy`
- Default closed-testing upload artifact: `../hns-dane-browser-v0.3.10-play-upload-signed.aab`
- Foreground service type: none; remove any stale `dataSync` declaration because sync is activity-scoped and the manifest declares no service.

The Android App Bundle is generated during release builds and is intentionally not committed.
