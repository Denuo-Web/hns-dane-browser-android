#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)); then
  printf 'usage: %s ARTIFACT_DIR\n' "${0##*/}" >&2
  exit 2
fi

artifact_dir=$1
certificate="$artifact_dir/origin-cert.pem"
private_key="$artifact_dir/origin-key.pem"

if [[ ! -d "$artifact_dir" || "$artifact_dir" != /* ]]; then
  printf 'certificate artifact directory must be an existing absolute path: %s\n' \
    "$artifact_dir" >&2
  exit 1
fi
if [[ -e "$certificate" || -e "$private_key" ]]; then
  printf 'refusing to replace an existing relay test certificate or key\n' >&2
  exit 1
fi

temporary_certificate="$certificate.tmp"
temporary_key="$private_key.tmp"

cleanup_failure() {
  local status=$?
  trap - EXIT
  rm -f -- "$temporary_certificate" "$temporary_key"
  exit "$status"
}
trap cleanup_failure EXIT

# This disposable key exists only for the isolated acceptance topology. A new
# identity on every run prevents a reusable private key from entering source
# control while the certificate's SAN exercises the same www.relaytest path.
if ! openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout "$temporary_key" \
  -out "$temporary_certificate" \
  -days 30 \
  -subj '/CN=www.relaytest' \
  -addext 'subjectAltName=DNS:www.relaytest' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
  -addext 'extendedKeyUsage=serverAuth' \
  >/dev/null 2>&1
then
  printf 'failed to generate the disposable relay test certificate\n' >&2
  exit 1
fi

chmod 0644 "$temporary_certificate"
chmod 0600 "$temporary_key"

if ! openssl x509 -in "$temporary_certificate" -noout -checkend 0 \
    >/dev/null 2>&1 \
  || ! openssl x509 -in "$temporary_certificate" -noout \
    -checkhost www.relaytest >/dev/null 2>&1 \
  || ! openssl verify -CAfile "$temporary_certificate" \
    "$temporary_certificate" >/dev/null 2>&1
then
  printf 'generated relay test certificate failed validity, SAN, or self-signature checks\n' >&2
  exit 1
fi

certificate_public_key=$({
  openssl x509 -in "$temporary_certificate" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl sha256 2>/dev/null
})
private_public_key=$({
  openssl pkey -in "$temporary_key" -pubout -outform DER 2>/dev/null \
    | openssl sha256 2>/dev/null
})
if [[ -z "$certificate_public_key" \
      || "$certificate_public_key" != "$private_public_key" ]]; then
  printf 'generated relay test certificate and private key do not match\n' >&2
  exit 1
fi

mv -- "$temporary_certificate" "$certificate"
mv -- "$temporary_key" "$private_key"
trap - EXIT
