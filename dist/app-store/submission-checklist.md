# App Store submission checklist

Canonical first-release values: iOS version `0.5.0`, build `43`, bundle ID
`com.denuoweb.hnsdane.ios`, iPhone only, Utilities, Free, manual release.

## Public listing

- [ ] The support and marketing page describes the iOS release and visibly lists
  `info@denuoweb.com` for support.
- [ ] The live privacy URL contains the current cross-platform policy and does not
  direct users to post personal information in a public issue.
- [ ] The app's in-app Privacy Policy and Support actions open those live pages.
- [ ] Paste the first-release fields listed in `metadata/README.md`; leave **What's
  New in This Version** empty.
- [ ] Set the version to `0.5.0`, select build `43`, and leave Routing App Coverage
  empty.

## Screenshots

- [ ] Add one to ten real iPhone screenshots to `screenshots/en-US/`; three is the
  recommended first set.
- [ ] Use one accepted 6.9-inch or 6.5-inch resolution throughout, with no alpha
  channel or transparency.
- [ ] Show: ordinary WebPKI browsing, a developer-controlled Handshake page with
  its security path, and Proof Details or Browser Settings. Do not use a splash or
  empty start screen.
- [ ] Run `python3 dist/app-store/validate.py` successfully.

## App Store questionnaires

- [ ] **App Privacy:** No tracking. Select **No, we do not collect data** only after
  confirming that Denuo Web and any non-open-web service treated as a partner do
  not retain app-originated data. On-device storage and user-directed open-web
  traffic are not collection under Apple's definitions. If a bundled resolver
  retains query/IP logs, disclose the applicable Browsing History data instead.
- [ ] **Age Rating:** Unrestricted Web Access = Yes. The app itself has no ads,
  chat, social feed, gambling, loot boxes, parental controls, or age assurance;
  answer the content-frequency questions accordingly. Do not select Made for Kids.
- [ ] **Content Rights:** Third-party content = Yes. Confirm it is accessed by a
  user-directed browser and is not bundled or curated by the app.
- [ ] **App Access:** Sign-in required = No. There is no account, subscription,
  in-app purchase, wallet, or payment flow.
- [ ] **Export Compliance:** Uses encryption = Yes; limited to Apple OS encryption
  = No; proprietary or non-standard encryption = No; industry-standard encryption
  outside the OS = Yes. Complete any documentation App Store Connect requests for
  the selected storefronts, including France when applicable.
- [ ] **EU DSA:** Declare the correct trader status. If distributing in the EU,
  verify the organization phone number and email requested by Apple.

## Review and release

- [ ] Enter a real review contact name, phone number, and email address.
- [ ] Paste `metadata/en-US/review-notes.txt`; do not enable the sign-in fields.
- [ ] Confirm build `43` has finished processing and its export-compliance status is
  resolved.
- [ ] Confirm the metadata, privacy answers, age rating, content rights, pricing,
  availability, screenshots, and build are all attached to the same submission.
- [ ] Choose **Manually release this version**, save, then add the app version and
  build for review.
- [ ] Record whether an optional external-TestFlight real-iPhone pass was available.
  If none was available, record that limitation; it does not block App Store
  submission.
