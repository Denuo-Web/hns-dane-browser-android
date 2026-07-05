# HNS Browser Capsule Crewball Test

This is the live-test runbook for the experimental `hnsb=1` HNS browser TXT capsule.

## Read-Only Observations

- Date checked: 2026-07-05.
- HSD tools: `/home/den/Backups/Documents/handshake/hsd/bin`.
- Test name: `crewball`.
- Expected owner supplied for the test: `hs1qxftun0udxr2yvx8kwg2m7jmx4rvjvhtvpvshkh`.
- GCloud project: `denuo-web-site`.
- VM: `denuoweb-vm`, zone `us-west1-b`, status `RUNNING`.
- VM public IP: `35.212.156.128`.
- `hsw-rpc getnameresource crewball` returned `null` locally.
- `hsd-cli rpc getnameresource crewball` returned existing legacy delegation data:

```json
{
  "records": [
    {
      "type": "GLUE4",
      "ns": "ns1.crewball.",
      "address": "44.231.6.183"
    },
    {
      "type": "NS",
      "ns": "ns1.crewball."
    }
  ]
}
```

The `44.231.6.183` address appears to be historical Namebase-era delegation data, not a usable origin shortcut. It returned no authoritative `crewball` data during the test and must not be treated as an origin address.

The live HTTPS endpoint at `35.212.156.128:443` presents a self-signed `denuoweb` certificate. DANE `TLSA 3 1 1` pins the SPKI, so WebPKI naming is not the deciding check for this browser path.

Current SPKI SHA-256:

```text
369e0dbba20489bdee1a963239716dd16c6fecc6efc30116889ab6ad6dc18bae
```

Transport checks after adding `crewball` and `crewball.` to the Denuo Web nginx vhost:

- `curl --resolve crewball:443:35.212.156.128 -k -I --http1.1 https://crewball/` returned `HTTP/1.1 200`.
- `curl --resolve crewball:443:35.212.156.128 -k -I --http2 https://crewball/` returned `HTTP/2 200`.
- `curl --http3-only --resolve crewball:443:35.212.156.128 -k -I https://crewball/` returned `HTTP/3 200`.

## Capsule

Use this capsule for the current VM certificate and transport config:

```text
hnsb=1;host=@;a=35.212.156.128;alpn=h2,h3;tlsa=3,1,1,369e0dbba20489bdee1a963239716dd16c6fecc6efc30116889ab6ad6dc18bae
```

Merged HSD resource JSON used for the first broadcast:

```json
{"records":[{"type":"GLUE4","ns":"ns1.crewball.","address":"44.231.6.183"},{"type":"NS","ns":"ns1.crewball."},{"type":"TXT","txt":["hnsb=1;host=@;a=35.212.156.128;alpn=h2,h3;tlsa=3,1,1,369e0dbba20489bdee1a963239716dd16c6fecc6efc30116889ab6ad6dc18bae"]}]}
```

Current compact JSON size:

```text
255 bytes
```

Keep the serialized resource under the HNS 512-byte resource limit. A later cleanup update can remove stale legacy NS/GLUE after confirming it is not needed by any compatibility path.

## Recompute The Capsule

```sh
HSD_BIN=/home/den/Backups/Documents/handshake/hsd/bin
NAME=crewball
IP=35.212.156.128

SPKI="$(
  openssl s_client -connect "$IP:443" -servername "$NAME" < /dev/null 2>/dev/null |
    openssl x509 -pubkey -noout |
    openssl pkey -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -binary |
    od -An -tx1 -v |
    tr -d ' \n'
)"

CAPSULE="hnsb=1;host=@;a=$IP;alpn=h2,h3;tlsa=3,1,1,$SPKI"

CURRENT="$("$HSD_BIN/hsd-cli" rpc getnameresource "$NAME")"

NEXT="$(
  printf '%s' "$CURRENT" |
    jq -c --arg capsule "$CAPSULE" '
      def capsule_txt:
        (((.txt // .text // []) | map(startswith("hnsb=1")) | any));
      .records = (
        ((.records // []) | map(select(.type != "TXT" or (capsule_txt | not)))) +
        [{"type":"TXT","txt":[ $capsule ]}]
      )
    '
)"

printf '%s\n' "$NEXT"
printf '%s' "$NEXT" | wc -c
```

The `jq` filter preserves existing non-capsule records, removes any older `hnsb=1` capsule, and adds one fresh capsule. That avoids the resolver's intentional fail-closed multiple-capsule behavior.

## Dry Run And Broadcast

Broadcast completed from wallet `recovered2` on 2026-07-05.

```text
txid: 22af4ea7678a1fe97d354c6b4f47b0cf9408b72eba4b9f0529129a65eda275b0
mempool fee: 0.0388 HNS
```

Create the update transaction first:

```sh
"$HSD_BIN/hsw-rpc" createupdate "$NAME" "$NEXT"
```

Broadcast only after reviewing the transaction and confirming the wallet controls `crewball`:

```sh
"$HSD_BIN/hsw-rpc" sendupdate "$NAME" "$NEXT"
```

After confirmation and the tree interval:

```sh
"$HSD_BIN/hsd-cli" rpc getnameresource "$NAME"
```

Then test in the browser with Strict HNS mode:

- `https://crewball/`
- Resolver trace `resolutionSource`: `hns_resource_capsule`
- `crewball A`: `35.212.156.128`
- `crewball HTTPS`: ALPN includes `h2` and `h3`
- `_443._tcp.crewball TLSA`: `3 1 1 369e0dbba20489bdee1a963239716dd16c6fecc6efc30116889ab6ad6dc18bae`
- TLS/DANE state: SPKI match

Do not publish a second matching `hnsb=1` TXT record. The browser rejects multiple matching capsules so ambiguity fails closed.
