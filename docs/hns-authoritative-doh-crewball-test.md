# HNS Authoritative DoH Crewball Test

This is the live-test runbook for proof-anchored bootstrap or RFC 9461 DNS-server SVCB discovery of an RFC 8484 authoritative DoH endpoint for a delegated HNS nameserver.

## Model

The HNS resource stays a delegation, not an origin-answer capsule:

```text
crewball. delegates to ns1.crewball.
ns1.crewball. has GLUE4 <nameserver-ip>
crewball. has DS <child-zone-ds>
crewball. may have TXT "hnsdns=1;ns=ns1.crewball.;doh=https://crewball:8443/dns-query;tlsa=3,1,1,<spki-sha256>"
_dns.ns1.crewball. has SVCB 1 doh.example. alpn=h2 dohpath=/dns-query{?dns}
```

The browser resolves in this order:

```text
1. Verify the HNS proof for crewball.
2. Extract NS, GLUE4/GLUE6 or SYNTH4/SYNTH6, DS, and any `hnsdns=1` transport declaration from the HNS resource.
3. If proof-anchored DoH metadata is present, try that owner-operated authoritative DoH (ADoH) endpoint first, using the HNS-proven glue IP as the connect address; no port 53 bootstrap is required. A `tlsa=3,1,1,...` field authenticates a self-signed HNS certificate from the verified proof without ICANN DNS or WebPKI.
4. If no proof-anchored endpoint is present, the browser may query `_dns.ns1.crewball. SVCB` through authoritative port 53, require `alpn=h2` plus `dohpath`, and try the DNSSEC-validated endpoint it discovers.
5. If owner ADoH is absent, malformed, unavailable, or fails authentication, query the authoritative nameserver directly over UDP/TCP 53.
6. If both owner paths fail, Compatibility mode may try the user's configured third-party HNS DoH resolver. Strict HNS mode fails instead of making this final compatibility fallback.
7. Validate every DNSKEY, A/AAAA, HTTPS, and TLSA answer against the HNS-proven DS regardless of transport.
```

The TXT/SVCB metadata only declares nameserver transport. It cannot contain or synthesize origin A/AAAA, HTTPS, or TLSA data.

## HNS Resource Shape

Use this shape after the child DNSSEC zone and nameserver are ready:

```json
{
  "records": [
    { "type": "NS", "ns": "ns1.crewball." },
    { "type": "GLUE4", "ns": "ns1.crewball.", "address": "<nameserver-ipv4>" },
    { "type": "DS", "keyTag": 29398, "algorithm": 13, "digestType": 2, "digest": "<sha256-digest>" },
    { "type": "TXT", "txt": ["hnsdns=1;ns=ns1.crewball.;transport=doh;doh=https://crewball:8443/dns-query;tlsa=3,1,1,<spki-sha256>"] }
  ]
}
```

Keep the serialized resource under the HNS 512-byte resource limit and keep the entire declaration in one TXT character-string of at most 255 bytes. The `tlsa` value is the browser's proof-bootstrap convention using standard TLSA `3/1/1` semantics: DANE-EE, SPKI, SHA-256. It is not a DNS TLSA RR. One additional `tlsa=3,1,1,...` field may be included during key rollover. Publish both old and new pins before changing the served key, wait for the HNS update and resolver caches to advance, switch the endpoint key, and remove the old pin in a later update. A malformed, unsupported, or excess pin rejects that ADoH declaration but does not suppress direct port 53 or Compatibility-mode fallback.

## Authoritative Zone Shape

If you also want signed-zone service metadata, publish it as an optional consistency record:

```zone
_dns.ns1.crewball. 3600 IN SVCB 1 doh.example. alpn=h2 dohpath=/dns-query{?dns}
_8443._tcp.crewball. 3600 IN TLSA 3 1 1 <spki-sha256>
```

The `_8443._tcp.crewball.` TLSA RR is not used to bootstrap proof-pinned ADoH; the verified HNS `tlsa=` field does that before any authoritative DNS query is possible. Website DANE remains a separate `_443._tcp.crewball.` TLSA RR, or the TLSA owner for whatever web-origin port HTTPS/SVCB selects.
The `_dns` SVCB line shows the older optional RFC 9461/WebPKI discovery path; it is not required by the HNS-only proof-pinned setup above.

## Endpoint Checks

The endpoint is RFC 8484 DoH: HTTPS, path `/dns-query`, DNS wire-format request/response bodies, and `Content-Type: application/dns-message`.

Example POST check:

```sh
NAME=crewball
NS=crewball
IP=<nameserver-ipv4>

dig +dnssec +bufsize=1232 "$NAME" A @"$IP"
dig +dnssec +tcp "$NAME" DNSKEY @"$IP"
dig +dnssec "_dns.$NS" SVCB @"$IP"

python3 - <<'PY'
import dns.message

name = "crewball."
query = dns.message.make_query(name, "A", want_dnssec=True)
query.id = 0
open("/tmp/crewball-a-query.bin", "wb").write(query.to_wire())
PY

curl --insecure --http2 --resolve "$NS:8443:$IP" \
  -H 'Accept: application/dns-message' \
  -H 'Content-Type: application/dns-message' \
  --data-binary @/tmp/crewball-a-query.bin \
  --output /tmp/crewball-a-response.bin \
  "https://$NS:8443/dns-query"

python3 - <<'PY'
import dns.message

print(dns.message.from_wire(open("/tmp/crewball-a-response.bin", "rb").read()))
PY
```

The `--resolve` flag mirrors the browser's separation of identity from routing: SNI and HTTP authority use the HNS endpoint name, while the TCP connection uses HNS-proven glue. `curl --insecure` checks only endpoint mechanics; independently compute the served certificate's SHA-256 SPKI and compare it with the proof-anchored `tlsa=3,1,1,...` value. The browser performs that comparison during the TLS handshake and does not disable certificate validation.

## Browser Expectations

Test after the update confirms and the tree interval has passed. Use Compatibility mode to exercise the complete availability ladder, then repeat in Strict HNS mode to confirm only the final third-party fallback is disabled:

- `https://crewball/`
- Resolver trace `hnsProof`: `verified`
- Resolver trace `delegation`: `true`
- Resolver trace `authoritativeDns.udp53` or `authoritativeDns.tcp53`: `ok` when port 53 is reachable
- Resolver trace `authoritativeDns.doh`: `ok` when the proof-bootstrapped or RFC 9461-discovered endpoint validated
- A proof-pinned endpoint is identified as `HNS-proof TLSA`; failure proceeds to authoritative UDP/TCP 53
- Resolver trace `port53Interception`: `detected` only when a matching reply came from the unroutable TEST-NET sentinel; `not_detected` is not proof that the path is clean
- Resolver trace `resolutionSource`: `authoritative_dns` for port 53, or `authoritative_doh` for the encrypted path
- Status: `DANE via ADoH`, `DANE via DNS53`, or `DANE via 3rd DoH` must identify the path that supplied the validated origin TLSA record; certificate-carried proof is reported separately as `Stateless DANE`
- DNSSEC: `secure`
- TLS/DANE state: SPKI or certificate match from `_443._tcp.crewball. TLSA`
