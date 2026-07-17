# Experimental HNS P2P DNS relay

Status: private proof of concept. The service bit and packet identifiers in
this document are temporary, are not Handshake protocol assignments, and must
not be advertised as standardized.

## Purpose and resolution order

The browser already verifies Handshake headers and Urkel name proofs locally,
derives an HNS delegation from that verified state, validates delegated DNSSEC,
and applies TLSA/DANE policy locally. This experiment adds an untrusted DNS
transport for proof-backed names whose authoritative servers are reachable by
a relay peer but not from the browser network.

The resolution order is:

1. validated local header and proof/resource caches (the current PoC does not
   cache relayed DNS answers across gateway requests);
2. locally verified current Handshake root state and name proof;
3. proof-declared authoritative DoH;
4. direct authoritative UDP/TCP DNS;
5. the HNS P2P recursive relay (enabled by default for Android new installs);
6. the independently controlled legacy third-party HNS recursive DoH path.

A successful authoritative DoH exchange suppresses direct DNS, P2P relay, and
legacy DoH. A successful direct authoritative exchange suppresses both
fallbacks. The P2P path is never considered before a current, locally verified
proof has produced an acceptable delegation.

## Temporary negotiation and framing

Current `hsd` version messages serialize services in an eight-byte field. The
JavaScript implementation consumes the low 32 bits and ignores the high word;
only bits 0 and 1 are currently assigned. P2P frames use a nine-byte header:
four-byte little-endian network magic, one-byte packet type, and four-byte
little-endian payload length. Assigned public packet types occupy 0 through 29.
Unknown types are preserved as unknown packets and logged without corrupting or
closing an otherwise valid connection.

This experiment uses:

| Item | Temporary value |
| --- | ---: |
| `EXPERIMENTAL_DNS_RELAY_SERVICE` | `0x40000000` (bit 30) |
| `EXPERIMENTAL_GET_DNS_RELAY` | `0xf0` |
| `EXPERIMENTAL_DNS_RELAY` | `0xf1` |

Bit 30 avoids current assignments and JavaScript's signed bit-31 behavior. The
high packet range is private to this experiment. A client sends `0xf0` only on
a fully handshaken connection whose current version message contains the bit.
Cached capability observations never override the current handshake.

The Rust requester uses a relay-only version handshake with
`version.services = 0`, including no `SERVICE_NETWORK`. It is consuming an
untrusted DNS transport, not advertising that it can serve headers, proofs, or
relay requests on that connection. This does not relax the requirement that the
remote peer's current handshake advertise the relay capability.

The remote version height observed by an automatic relay connection or a manual
static-relay capability probe is not authenticated as a sync target. Those paths
record only membership/liveness and never promote that height into persisted
peer currentness; observed heights remain owned by header-sync sessions.

Handshake's ordinary TCP P2P listener is plaintext. The optional Brontide
listener is encrypted. This implementation does not claim query confidentiality
when the ordinary listener is used; a relay always sees the qname and qtype.
Deployments should prefer an already-supported encrypted peer connection where
available, but this experiment does not define a new transport.

## Packet payloads

All integer fields below are little-endian. DNS messages retain DNS network byte
order internally.

```text
GetDnsRelay {
    request_id: u64,
    query_length: u16,
    query: [u8; query_length]
}

DnsRelay {
    request_id: u64,
    status: u8,
    response_length: u16,
    response: [u8; response_length]
}
```

The packet must end immediately after the declared byte string. Parsers reject
trailing data, non-canonical structure, zero request IDs, and declared sizes
outside the limits before copying the body. The limits are 4,096 query bytes
and 65,535 response bytes. The server gives admission plus backend work a
three-second deadline. The client gives each TCP-connect-plus-handshake attempt
and each complete relay exchange one three-second absolute deadline. It may
probe up to four handshakes plus one alternate, so three seconds is not a hard
end-to-end browser deadline.

Statuses are transport statuses, not DNS RCODEs:

| Value | Name | Meaning |
| ---: | --- | --- |
| 0 | `OK` | a raw DNS response is present |
| 1 | `REFUSED` | admission policy refused the question |
| 2 | `UNSUPPORTED` | peer/backend does not support the operation |
| 3 | `BUSY` | a rate or concurrency bound was reached |
| 4 | `INVALID_QUERY` | malformed or disallowed query |
| 5 | `RESOLVER_UNAVAILABLE` | recursive backend is not ready |
| 6 | `TIMEOUT` | recursive deadline expired |
| 7 | `INTERNAL_ERROR` | bounded internal failure |

NOERROR, NXDOMAIN, NODATA, SERVFAIL, REFUSED, truncation, and all DNSSEC proof
records remain in an `OK` raw DNS response. `OK` with an empty body and an error
status with a non-empty body are invalid.

Values 8 through 255 are reserved for possible future assignments. An unknown
value makes the current exchange unusable and its body never reaches DNS
processing. The requester closes the affected relay connection and may retry an
alternate peer, but the unknown value alone causes no peer-score change and no
cooldown because it may come from a later protocol version.

## Query and response rules

The requester enforces the HIP query profile before sending any packet:

- the query is one complete DNS message of at most 4,096 bytes with no trailing
  bytes;
- `QR` is clear, the opcode is standard `QUERY`, the header RCODE is zero, and
  `AA`, `TC`, `RA`, and the reserved header `Z` bit are clear;
- `RD` is set, and this browser requester also sets `CD` so the backend returns
  validation material for local checking;
- there is exactly one `IN`-class question, with empty answer and authority
  sections, and its rightmost label is a syntactically valid Handshake name;
- the additional section is exactly one root-owner EDNS(0) OPT with EDNS version
  and extended RCODE zero, `DO` set, an advertised size from 512 through 4,096,
  and all reserved EDNS flags clear; and
- the EDNS option list is empty or contains only well-formed Padding. ECS and
  every other option are rejected.

The exact question-type allowlist is A, AAAA, CNAME, DNAME, NS, SOA, DS,
DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, TLSA, SVCB, HTTPS, TXT, MX, SRV, and
CAA. The server refuses every other type, including ANY, AXFR, IXFR, TKEY, and
TSIG, as well as UPDATE, NOTIFY, local/private infrastructure names,
ICANN-rooted questions, and HNS roots that do not exist in the node's current
name tree. This classification is an abuse control, not a trust anchor. The
request contains no destination address or port.

The client accepts a response only for a live request on the same connection.
It checks the request ID, status, size, DNS parse, DNS transaction ID, QR/opcode,
and exact question tuple. Unsolicited, duplicate, late, mismatched, and malformed
responses are rejected and may penalize the peer. A future unknown transport
status follows the compatibility rule above instead of the malformed-response
penalty path. The relay's AD bit is preserved only as raw DNS syntax and is
never used to set `secure`.

## Server bounds and privacy

The opt-in `hsd` server uses a 20-attempt/second per-peer token bucket with a
40-query burst, a 16-request per-peer in-flight limit, a 64-request global
in-flight limit, and a three-second recursive deadline. Disconnect and timeout
remove logical request state and suppress late replies. Admission or resolver
work that cannot be physically cancelled remains charged to the originating
peer and the global bound until it settles. Concurrency backpressure returns
`BUSY`; rate-limit notices are capped at one `BUSY` response per peer per second
to avoid response amplification.
Responses travel over the established TCP connection, so this feature does not
create a UDP reflection surface.

Normal relay logs and persisted diagnostics omit full qnames, raw DNS messages,
URL paths, request headers, and stable browser identifiers. Android's persisted
gateway-event log retains only the sanitized HNS root label. The bounded
resolution trace shown inside the app is ephemeral and can contain the queried
name; it must not be persisted or sent as telemetry. Aggregate status counts,
latency/size buckets, retry count, transport type, and validation stage are
permitted. No ECS, telemetry, speculative prefetch, or duplicate measurement
query is introduced. Explicit `hsd` spam-level DNS debugging remains capable of
printing DNS messages and is not suitable for a privacy-preserving canary.

## Client selection, reuse, and validation

Eligible relay peers are fully handshaken, currently advertise the capability,
are not banned or cooling down, and are ordered by the existing score and
address-group diversity rules. A peer other than the proof supplier is preferred
when practical. One capable peer is still sufficient. A transport or malformed
response failure penalizes the peer; a known temporary status can apply bounded
backoff; and a successful exchange rewards it. A future unknown status is the
explicit exception: it closes the exchange/connection without automatic score
or cooldown. Before selection, the runtime refreshes relay membership,
discovery, removals, and bans from the shared peer store. Concurrent snapshots
conservatively preserve the higher penalty, so a success reward can remain
session-local until stored peer state converges; a newer ban is never relaxed by
that merge.

Android Settings also accepts a manual relay endpoint in IP-literal
`IPv4:port` or `[IPv6]:port` form. Hostnames are rejected so this bootstrap path
does not use system DNS. The endpoint is persisted only after a live HSD
handshake completes and the peer's current version message advertises the relay
capability; a stale capability observation is insufficient. The version height
from this capability probe is discarded rather than becoming a persisted sync
target.

The runtime owns a bounded reusable connection set. Live identical wire
questions are coalesced across gateway requests after normalizing the DNS
transaction ID; each waiting caller gets its own ID restored before local
parsing, and the entry is removed when that live exchange completes. The
current PoC does not keep a cross-request cache of relayed DNS answers, so its
relay layer also never caches transport failures or DNS negatives. A future
validated answer cache must use DNS TTLs, bind entries to the verified proof
anchor, and admit negative answers only after local NSEC/NSEC3 validation.

Raw relayed bytes enter the existing validation chain unchanged:

```text
validated headers -> verified Urkel proof -> proof-derived NS/DS
  -> raw relayed DNS -> DS/DNSKEY/RRSIG and denial validation
  -> HTTPS/SVCB policy -> TLSA -> DANE certificate validation
```

The relay cannot compensate for unavailable or stale root state, a proof/name or
proof/root mismatch, an invalid delegation, an unverified nameserver address,
invalid DNSSEC, invalid negative proof, invalid TLSA, or a failed DANE match.

## Controls and diagnostics

Android new installs enable `Experimental HNS peer DNS relay` and the
independent `Legacy third-party HNS DoH compatibility` fallback by default;
explicit preferences from existing installations are preserved. The isolated
proof-of-concept acceptance configuration enables the relay while disabling
legacy DoH so a successful test cannot silently use the later fallback. Relay
provenance is `p2p_dns_relay`; authoritative DoH, direct authoritative DNS, and
legacy DoH retain distinct provenance. A relayed result may be displayed as
`DANE via HNS P2P`, never as third-party DoH. Serving remains separate: the
companion `hsd` responder starts only when its operator explicitly enables the
experimental relay service.

Settings can add a known relay peer by numeric `IPv4:port` or `[IPv6]:port`.
The runtime applies the selected network's endpoint policy, completes a live
Handshake/version exchange, requires the current relay capability, and only
then persists the peer. Hostnames are deliberately not accepted, so this
manual path cannot invoke the host operating system's DNS.

## Verification topology and current boundary

The checked-in fast topology has four separate *scripted Handshake peer roles*:
`hsd-proof` (no relay bit), `hsd-relay-good` (ready relay with DNS-network
access), `hsd-relay-bad` (deterministic failure), and `hsd-legacy` (ordinary
capability behavior). It uses the real nine-byte Handshake framing, regtest
magic, version/verack negotiation, and the private packet bytes, but those four
containers are not blockchain-owning `hsd` processes. The authoritative
answers are deterministic DNS/TLSA wire fixtures rather than a DNSSEC-signed
delegated zone derived from a registered regtest name.

Docker internal networks still enforce the transport property under test: the
browser role can reach P2P and HTTPS but has no route to authoritative UDP/TCP
53; only the good relay joins the DNS network; external resolver egress is
absent; and a local legacy-DoH sentinel must observe zero connections. The fast
tier also exercises bad-to-good failover, UDP truncation followed by relay-side
TCP, TLSA/certificate matching, HTTPS, connection reuse, bounded load, and
qname-free aggregate artifacts.

The fixtures in `fixtures/experimental-dns-relay/` are generated
deterministically and checked byte-for-byte by Rust and JavaScript. The scripted
load harness pipelines one connection to reach the 16-request peer bound and
four connections to reach the 32-request test-global bound, requiring the exact
accepted/`BUSY` split and zero pending work afterward. Ordinary concurrent
clients must all succeed. Disconnect, timeout, and oversized-response failures
are each observed while a separate delayed good-peer pipeline succeeds. The
scripted rate case disables token refill, consumes the exact 40-query burst,
then requires one `BUSY` notice and seven suppressed notices in the same
one-second window. The real `hsd` default remains 20 attempts/second; its timing
and service implementation are covered separately by the JavaScript tests.

This fast tier does **not** prove a current validated header chain, an Urkel
proof for a registered fixture name, DS-to-DNSKEY/RRSIG or NSEC/NSEC3 validation
through the runtime, or an application-binary execution. A separate checked-in
full runner uses four blockchain-owning `hsd` FullNodes with independent
prefixes, mines the complete `relaytest` regtest name lifecycle, commits its
NS/GLUE4/DS resource through the safe-root window, and requires a current
`TYPE_EXISTS` Urkel proof with a non-empty registered resource from every node.
Its native runtime follows bad-to-good relay failover, validates the positive
DS/DNSKEY/RRSIG chain, HTTPS and TLSA/DANE locally, and requires zero legacy-DoH
contacts. That full positive-answer path does not claim an NSEC/NSEC3 denial
case or Android application-binary execution.

The exact commands, artifact requirements, and physical-device follow-up are
recorded in `docs/experimental-p2p-dns-relay-runbook.md`. A scripted fast-tier
result must not be reported as the real four-`hsd` DNSSEC/DANE end-to-end tier;
the full claim requires both the real-node controller and native runtime result
artifacts to pass.

## Canary and rollback

No public responder node is deployed by this repository. A future operator
canary starts with two or three explicitly enabled patched nodes in different
networks/administrative domains, aggregate-only logging, project-controlled
synthetic names, and development builds. It then progresses through ordinary
fallback and tester builds with legacy DoH disabled only after diversity,
reliability, privacy, and resource bounds are demonstrated. The Android client
default does not opt any `hsd` operator into serving relay queries.

Rollback is immediate: disable the browser relay setting and the operator's
`hsd` relay flag.
Legacy DoH remains separately available. Removing legacy DoH from defaults
requires measured independent relay diversity, availability and failure rate,
median/tail latency, reliable alternate failover, authoritative-DoH adoption,
no centralized discovery dependency, and stable interoperability.

## Future standardization and `hnsd`

Standardization requires permanent service and packet assignments, exact
framing, negotiation, sizes and flags, allowed types/classes, HNS-root
admission, local validation and AD treatment, cache rules, rate/concurrency
limits, peer scoring, retry behavior, encryption expectations, logging/privacy
requirements, compatibility behavior, authoritative-DoH precedence, and a
possible oblivious two-hop extension. The temporary values above remain
nonstandard until an accepted HIP assigns them.

Future `hnsd` work would independently add the codec, capability, optional
recursive backend interface, admission/rate limiting, these wire fixtures, and
interoperability tests. `hnsd` is not modified here.
