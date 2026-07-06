# HNS Authoritative DoH Crewball Test

This is the live-test runbook for RFC 9461 DNS-server SVCB discovery of an RFC 8484 authoritative DoH endpoint for a delegated HNS nameserver.

## Model

The HNS resource stays a delegation, not an origin-answer capsule:

```text
crewball. delegates to ns1.crewball.
ns1.crewball. has GLUE4 <nameserver-ip>
crewball. has DS <child-zone-ds>
_dns.ns1.crewball. has SVCB 1 ns1.crewball. alpn=h2 dohpath=/dns-query{?dns}
```

The browser resolves in this order:

```text
1. Verify the HNS proof for crewball.
2. Extract NS, GLUE4/GLUE6 or SYNTH4/SYNTH6, and DS from the HNS resource.
3. Try authoritative UDP/TCP 53 at the HNS-proven nameserver address.
4. Query `_dns.ns1.crewball. SVCB` through the strict authoritative path and require `alpn=h2` plus `dohpath`.
5. If the endpoint is discovered, POST DNS wire messages to https://ns1.crewball/dns-query using the HNS-proven glue IP as the connect address.
6. Validate DNSKEY, A/AAAA, HTTPS, and TLSA answers against the HNS-proven DS.
```

The SVCB record only declares a nameserver transport. It must not contain origin A/AAAA, HTTPS, or TLSA data.

## HNS Resource Shape

Use this shape after the child DNSSEC zone and nameserver are ready:

```json
{
  "records": [
    { "type": "NS", "ns": "ns1.crewball." },
    { "type": "GLUE4", "ns": "ns1.crewball.", "address": "<nameserver-ipv4>" },
    { "type": "DS", "keyTag": 29398, "algorithm": 13, "digestType": 2, "digest": "<sha256-digest>" }
  ]
}
```

Keep the serialized resource under the HNS 512-byte resource limit.

## Authoritative Zone Shape

Publish DoH discovery in the signed authoritative zone:

```zone
_dns.ns1.crewball. 3600 IN SVCB 1 ns1.crewball. alpn=h2 dohpath=/dns-query{?dns}
```

RFC 9539 is a separate experimental mechanism for opportunistic recursive-to-authoritative DoT/DoQ on port 853. It is not the DoH discovery format used in this runbook.

## Endpoint Checks

The endpoint is RFC 8484 DoH: HTTPS, path `/dns-query`, DNS wire-format request/response bodies, and `Content-Type: application/dns-message`.

Example POST check:

```sh
NAME=crewball
NS=ns1.crewball
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

curl --resolve "$NS:443:$IP" \
  -H 'Accept: application/dns-message' \
  -H 'Content-Type: application/dns-message' \
  --data-binary @/tmp/crewball-a-query.bin \
  --output /tmp/crewball-a-response.bin \
  "https://$NS/dns-query"

python3 - <<'PY'
import dns.message

print(dns.message.from_wire(open("/tmp/crewball-a-response.bin", "rb").read()))
PY
```

Use the nameserver hostname for certificate/SNI validation. The `--resolve` flag only forces the HNS-proven glue address for the TCP connection.

## Browser Expectations

Test in Strict HNS mode after the update confirms and the tree interval has passed:

- `https://crewball/`
- Resolver trace `hnsProof`: `verified`
- Resolver trace `delegation`: `true`
- Resolver trace `authoritativeDns.udp53` or `authoritativeDns.tcp53`: `ok` when port 53 is reachable
- Resolver trace `authoritativeDns.doh`: `ok` when UDP/TCP 53 failed and the RFC 9461-discovered DoH endpoint validated
- Resolver trace `resolutionSource`: `authoritative_dns` for port 53, or `authoritative_doh` for the RFC 9461-discovered DoH path
- DNSSEC: `secure`
- TLS/DANE state: SPKI or certificate match from `_443._tcp.crewball. TLSA`

Do not publish legacy `hnsb=1` or `hnsdns=1` TXT data. The browser ignores those removed experiments and resolves only through delegated DNS plus optional RFC 9461-discovered authoritative DoH.
