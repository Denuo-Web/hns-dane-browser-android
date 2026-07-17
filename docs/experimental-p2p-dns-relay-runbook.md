# Experimental HNS P2P DNS-relay verification and canary runbook

This runbook covers the private proof-of-concept identifiers only. It does not
authorize a public deployment, claim a permanent service bit or packet number,
or turn the relay into a general resolver.

## Local commands

From `hns-dane-browser`, with the sibling `hsd` checkout at `../hsd`:

```sh
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh --preflight
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay.sh --load
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay-full.sh --preflight
HSD_REPO=../hsd ./scripts/test-experimental-p2p-dns-relay-full.sh
```

The preflight needs Python 3 and OpenSSL. It validates every shared fixture and
digest in both repositories, generates and structurally checks a disposable
`www.relaytest` self-signed certificate, asks Compose to parse the topology,
and requires a Compose plugin whose `up` command supports `--wait`. The isolated
tier additionally needs a running Docker daemon
accessible to the invoking user. It pulls
`python:3.12-alpine` when absent; set `EXPERIMENTAL_RELAY_ALLOW_PULL=0` to
require a pre-cached image. `PYTHON_IMAGE` may select an internally pinned
mirror or digest. One-shot client output is retained as `browser-e2e.log` and,
with `--load`, `browser-load.log`; long-lived service output is retained as
`compose.log`. JSON results are written to the reported temporary artifact
directory. To support Docker `userns-remap`, the runner temporarily makes that
random directory sticky and container-writable, then restores its original
mode after teardown. `--keep` retains containers for inspection and necessarily
leaves the artifact directory container-writable until that project is stopped.
If `EXPERIMENTAL_RELAY_ARTIFACT_DIR` is supplied, it must name an empty
directory so stale readiness or result files cannot satisfy a new run.
After that empty-directory check, each runner generates a fresh certificate and
private key in the artifact directory. No reusable TLS private key is stored in
the repository. The generated key is removed after normal teardown; an explicit
`--keep` retains it only because the live origin still needs it.

The default command starts these separate roles:

| Role | Relay bit | Networks | Fast-tier behavior |
| --- | --- | --- | --- |
| `hsd-proof` | no | P2P | Handshake/proof-source role; never receives a relay request |
| `hsd-relay-good` | yes | P2P + DNS | Reuses one connection and follows truncated UDP with TCP |
| `hsd-relay-bad` | yes | P2P | Returns deterministic mismatch/disconnect/timeout/BUSY/oversize cases |
| `hsd-legacy` | no | P2P | Handshakes without the bit and never receives the private packet |

The browser-test container joins only the internal P2P and origin bridges. The
authoritative server exists only on the internal DNS bridge. The good relay is
the only P2P role on both bridges. The test sends real UDP and TCP probes from
the browser namespace and requires both to fail, requires external port-53
probes to fail, and confirms that the good relay used both transports. The
legacy-DoH sentinel is reachable on the P2P bridge but must retain a zero
connection count. All three bridges use Docker's `internal` boundary, so the
test namespace has no external egress.

The fast tier speaks the actual nine-byte Handshake frame, regtest magic,
version/verack sequence, low 32-bit services word, and private `0xf0`/`0xf1`
payloads. It parses the raw DNS message, rejects the bad peer's question
mismatch, ignores the relayed AD bit as a trust signal, compares a TLSA
full-certificate SHA-256 association against the received TLS certificate, and
fetches the HTTPS origin. Normal service artifacts contain only aggregate
counters/statuses; they contain no qnames, raw DNS, paths, or HTTP headers.

### Fast-tier scope boundary

The four `hsd-*` fast-tier roles are deterministic scripted Handshake peers,
not blockchain-owning `hsd` processes. The authoritative answers are syntactic
DNS/TLSA fixtures, not a signed delegated zone. Consequently, this tier does
not claim:

- a current locally validated Handshake header chain;
- an Urkel proof from a deterministic registered regtest name;
- DS-to-DNSKEY/RRSIG or NSEC/NSEC3 validation through the runtime;
- execution through an Android or iOS application binary.

Do not relabel a result from this command as the full tier. The separate full
runner below is the only local command that may produce those claims, and only
when its controller and native runtime result artifacts both pass.

## Real four-`hsd` regtest tier

`test-experimental-p2p-dns-relay-full.sh` uses four actual patched `hsd`
FullNode processes. Each has an independent persistent prefix and fixed test
identity. The owner/good node mines the fixed `relaytest` rollout and complete
OPEN/BID/REVEAL/REGISTER lifecycle; the controller then mines one Urkel tree
interval plus the 12-block regtest safe-root window (17 post-update blocks in
total) and requires all four nodes to report the same height, tip, and tree
root. It then calls `getnameproof relaytest` on every node and requires each
current-root proof to be `TYPE_EXISTS`, with a decodable registered name state
whose non-empty resource matches the NS/GLUE4/DS delegation, before publishing
`full-target-height.txt`.

The registered resource contains NS, GLUE4, and DS records. A real bns
authoritative UDP/TCP server serves the child zone with a fixed ECDSA P-256
DNSKEY and live RRSIGs over DNSKEY, SOA, NS, A, HTTPS, and TLSA RRsets. The
TLSA owner is `_18443._tcp.www.relaytest.` and binds the test certificate by
full-certificate SHA-256. The certificate is freshly generated
for each run with a `www.relaytest` subject alternative name, and the acceptance
runner requires the provisioner and authority TLSA digests to match that exact
per-run certificate without hard-coding its digest. The authority uses
`172.31.20.53` on a Docker-internal bridge. A regtest-only explicit `hsd`
control permits this private authority on `hsd-owner-good`; the same option is
rejected outside regtest. `hsd-relay-bad` retains the production public-only
policy and deterministically refuses the private referral, causing the native
client to retry the good relay. The browser is not attached to the bridge and
has no route to it. Browser-side UDP and TCP probes must fail for both that
address and an external resolver address.

The four real roles are:

| Role | Relay | DNS bridge | Purpose |
| --- | --- | --- | --- |
| `hsd-owner-good` | yes | yes | Mines/registers the name, supplies proofs, and completes recursive relay DNS |
| `hsd-proof` | no | no | Independent synchronized proof-capable FullNode |
| `hsd-relay-bad` | yes | no | Advertises the relay but applies the default private-authority refusal |
| `hsd-legacy` | no | no | Independent synchronized node without the experimental capability |

The native `hns-runtime-full-tier` binary first requires a real failed exchange
through `hsd-relay-bad` and a successful retry through `hsd-owner-good`. It then
synchronizes and validates the current Handshake header chain, fetches and
verifies the current-tip Urkel inclusion proof, derives the delegation from the
registered resource, validates the child DS/DNSKEY/RRSIG chain locally, matches
TLSA/DANE locally, and receives HTTPS 200 from a loopback origin. Strict mode
and the experimental relay are enabled; legacy compatibility is disabled even
though a reachable sentinel URL is configured. The sentinel must observe zero
connections.

The Linux runner reuses the cached `python:3.12-alpine` image and mounts the
host's Node executable, ELF interpreter, multiarch glibc directory, local `hsd`
checkout, and matching `node_modules` read-only. It performs no `hsd` image
build. Override `FULL_TIER_CLIENT` to reuse an existing native binary; otherwise
the runner builds it offline. As with the fast tier, a supplied
`EXPERIMENTAL_RELAY_FULL_ARTIFACT_DIR` must be empty.

For a physical Android check, retain the topology with `--keep`, then map its
loopback endpoints before selecting Regtest in the separate relay-test app.
The owner and HTTPS origin alone also join a narrow non-internal Docker bridge,
because Docker does not activate published ports for containers attached only
to internal networks. Management listeners remain bound exclusively to the
internal control network, and the browser remains confined to the internal P2P
network. The runner fails before provisioning unless both Android endpoints are
actually published on `127.0.0.1`.
The runner prints the exact commands on exit; with the default host ports they
are:

```sh
adb reverse tcp:14038 tcp:14038
adb reverse tcp:18443 tcp:18443
```

While `--keep` is active, do not move or delete the reported artifact directory:
it contains the disposable certificate/key pair shared by the retained signed
zone and Android-facing HTTPS origin. Stopping the Compose project ends its only
intended use; delete the disposable key when the retained topology is no longer
needed.

The registered A record is `127.0.0.1`, so the same DNSSEC/TLSA data reaches the
device-side forwarded HTTPS origin. Enable strict HNS mode and the experimental
peer relay and disable legacy HNS DoH. The Docker/native pass does not by itself
claim Android application-binary execution; record the device result
separately, then remove the two `adb reverse` mappings and stop the kept Compose
project.

The existing local cryptographic coverage should still be run independently:

```sh
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml -p hns-dnssec
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml -p hns-resolver
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml -p hns-transport
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml -p hns-p2p
cargo +1.92.0 test --locked --manifest-path rust/Cargo.toml -p hns-browser-runtime
```

These tests are necessary but do not by themselves convert the fast topology
into an end-to-end DNSSEC result. Only the real-node controller plus native
runtime result establishes that local acceptance claim.

The `hns-p2p` and `hns-browser-runtime` regression suites are also the protocol
gate for four requester invariants: the complete HIP type/flag/EDNS query
profile is enforced before transmission; relay-only handshakes advertise zero
local services; automatic and static-relay handshakes cannot promote their
advertised version height into sync currentness; and a future unknown transport
status closes the affected exchange/connection without an automatic peer-score
change or cooldown.

## Reading artifacts

`e2e-result.json` records capability observations, enforced network failures,
bad-to-good failover, P2P provenance, connection reuse, AD distrust, TLSA match,
HTTPS status, and the explicit full-stack false claims. `load-result.json`
contains median, p95, and p99 ordinary-request latency plus warm-identical,
cold-unique, all-successful concurrent-client, pipelined peer/global boundary,
rate-notice suppression, and concurrent fault-pressure scenarios. Its
peer/global maxima must equal the configured 16/32 test bounds, not merely
remain below them. The scripted rate bucket disables refill so the 40 accepted
requests, one `BUSY`, and seven suppressed notices are independent of host
speed. `hsd-relay-good-metrics.json` records those in-flight, rate, and cache
bounds. `third-party-sentinel.json` must contain `"contacts": 0`.

For the real-node tier, `full-regtest-state.json` records the converged four-node
height/tip/tree root, each node's positive proof and decoded-resource evidence,
the registered resource, and signed-zone parameters;
`full-tier-proof.json` is the runtime's current-tip proof evidence; and
`full-tier-result.json` records Urkel, DNSSEC, DANE, HTTPS, real-relay failover,
and legacy-zero-contact outcomes. `full-browser-network.json` must show blocked
UDP and TCP port 53 for both authoritative and external probes.

If a run fails, retain the artifact directory and rerun with `--keep`. Check
Compose service state before interpreting protocol results. A Docker permission
error means the isolated tier did not run; a passing preflight is not a network
test.

## Controlled public canary (manual only)

Do not deploy this automatically. Before Stage 1, freeze the exact private
builds and fixture manifest, independently review request admission and resource
bounds, verify that normal logs cannot include qnames/raw DNS, and document the
ordinary TCP P2P listener's lack of confidentiality. Prefer an already-supported
Brontide connection where interoperable; never describe the one-hop relay as
ODoH.

The canary topology is two or three explicitly enabled patched `hsd` relays,
ideally run by different operators in different regions/networks. Each uses its
existing recursive backend and cache, exposes no new DNS/HTTP listener, limits
per-peer rate and in-flight work, and exports aggregate counters only. Browser
distribution is restricted to development/internal builds. Testers may add a
known peer in Settings using a numeric `IPv4:port` or `[IPv6]:port`; the runtime
applies the network endpoint policy and persists it only after a live handshake
advertises the relay capability. Ordinary discovered peers remain available,
and arbitrary public peers must not be assumed to support the private
identifiers. The relay-only requester advertises no local services, and the
remote version height observed by this capability check does not affect sync
target/currentness. P2P relay and legacy DoH remain independently configurable.

### Stage 1: synthetic shadow

Use only project-controlled test HNS names. Do not duplicate real user-domain
queries for measurement. Verify cross-implementation bytes, response limits,
local DNSSEC/DANE outcomes, alternate-peer failover, and aggregate latency and
availability. No user browsing traffic is eligible.

### Stage 2: development-build fallback

Use the enforced order: proof-declared authoritative DoH, direct authoritative
53, experimental relay, then separately enabled legacy DoH. Confirm that a
successful authoritative DoH or direct exchange suppresses all later paths.
Review aggregate BUSY, timeout, malformed, retry, and validation-failure counts.

### Stage 3: tester builds without legacy DoH

For explicitly consenting testers only, enable the relay while disabling legacy
DoH. Demonstrate that port-53-only HNS sites remain usable through at least two
independent relays and that invalid DNSSEC/TLSA/DANE remains fail-closed. Provide
an immediate in-app off switch and a documented fallback/rollback route.

### Stage 4: wider opt-in

Expand only after relay diversity, stable rate/concurrency limits, reliable
failover, measured tail latency, privacy review, and confirmed qname-free normal
logging. Keep this opt-in while identifiers remain private.

## Stop, rollback, and eventual legacy-DoH removal

Stop a stage on any trust regression, qname/raw-DNS logging, unbounded pending
work or memory, repeated cross-implementation decode failure, material DNSSEC or
DANE discrepancy, single-relay dependency, or inability to distinguish
provenance. Disable the browser relay setting first, then disable the `hsd`
experimental option. The legacy path remains a separate setting and is not
removed by rollback. Purge only ephemeral aggregate canary data according to its
published retention policy; do not preserve query data that should never have
been logged.

Removing legacy DoH from default behavior requires measured independent relay
diversity, availability and failure rates, median/p95/p99 latency, successful
alternate-peer failover, adequate authoritative-DoH adoption, no centralized
discovery requirement, stable interoperability, and a completed protocol and
privacy review. Permanent service/packet assignments, exact wire behavior,
admission, limits, retry/scoring, encryption expectations, AD treatment,
logging, and a possible future oblivious mode belong in a future HIP; this
runbook does not create one.
