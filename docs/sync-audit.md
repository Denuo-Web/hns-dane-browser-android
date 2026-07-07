# Sync Startup Audit

## Current First-Run Path

- `MainActivity.onStart` starts `HnsSyncForegroundService` automatically, so first install no longer depends on opening Diagnostics and pressing `Run sync now`.
- `HnsSyncScheduler` runs immediately, then uses active polling while the local `bestHeight` is below the known or estimated target, retry polling for peer/seed discovery failures, and a 10-minute idle poll after the app is caught up.
- The native Android sync tick requests up to 192 header batches per peer per run, which is enough to cover current mainnet-scale catch-up in one or a small number of foreground ticks when a healthy peer serves full batches.
- Android native sync also prefetches one 2000-header page from published HSD mainnet checkpoint anchors at 50,000, 100,000, 160,000, 200,000, 225,000, and 258,026. These prefetched pages are staged only; they are inserted and counted after the local chain has validated the page's parent, so the optimization does not trust out-of-order peer data.
- Seeded peers are persisted before the long header run starts, DNS seeds are refreshed while the peer table is below target, sync attempts use up to eight outbound peers per tick, and successful plus additional unqueried peers are queried with bounded `getaddr` discovery toward the 64-peer table target, so a killed or interrupted first run does not leave the peer database empty after headers have already advanced.
- Native status reports `syncing` whenever persisted peer height or the estimated mainnet tip is still ahead of local best height, even if the current tick accepted headers. `synced` is reserved for ticks that accepted headers and reached the known peer target; no-network status reports `up_to_date` when stored peers are not ahead.

## User-Visible Progress

- The main browser screen shows a horizontal sync progress bar directly under the omnibox toolbar.
- The main browser screen polls lightweight native sync status while visible, so `bestHeight` and the progress bar move during long native header runs instead of waiting for the foreground-service tick to finish.
- The status line under the progress bar shows status, `bestHeight`, a single `target` height while syncing, peer count, and the latest accepted header count when present; `bestPeerHeight` is shown only after the known peer target has been reached.
- A second horizontal loading bar sits below the block-sync info and tracks WebView page-load progress while HNS proof/DANE/origin work is running.
- HNS gateway error bodies include the requested URL above the status line so repeated 502 pages can be distinguished at a glance.
- The foreground notification uses the same parsed sync progress so Android’s persistent sync notification reflects catch-up progress instead of a generic running state.

## Remaining Speed Bottlenecks

- Initial sync still downloads and validates headers from live peers at first run; checkpoint prefetch overlaps some later 2000-header pages but the APK does not yet ship a recent signed/checkpointed header snapshot that would let it skip earlier history.
- Proof data is still fetched on demand for requested HNS names rather than prefetching popular names.
- Peer quality dominates first-run time. The current path seeds peers automatically, expands the peer table from successful and additional unqueried peers through bounded `getaddr` discovery, and retries quickly while behind, but poor peers can still slow catch-up until peer scoring rotates to better peers.
