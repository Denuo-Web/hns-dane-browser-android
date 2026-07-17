#!/usr/bin/env node
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const path = require('path');

const HSD_ROOT = process.env.HSD_ROOT || '/opt/hsd';
const BNS_ROOT = path.join(HSD_ROOT, 'node_modules', 'bns', 'lib');
const constants = require(path.join(BNS_ROOT, 'constants'));
const dnssec = require(path.join(BNS_ROOT, 'dnssec'));
const wire = require(path.join(BNS_ROOT, 'wire'));
const {classes, hashes, types} = constants;
const {Record, UNKNOWNRecord} = wire;

const ZONE_NAME = 'relaytest.';
const WWW_NAME = 'www.relaytest.';
const NS_NAME = 'ns.relaytest.';
const TLSA_NAME = '_18443._tcp.www.relaytest.';
const AUTHORITY_ADDRESS = '172.31.20.53';
const ORIGIN_ADDRESS = '127.0.0.1';
const ORIGIN_PORT = 18443;
const HTTPS_TYPE = 65;
const TTL = 300;

// Fixed test-only ECDSA P-256 key. The public key and DS are stable across
// runs; RRSIG inception and expiry deliberately follow the current clock.
const ZONE_PRIVATE_KEY = Buffer.from(
  '7f148e4f0a13ccd74a04fb9581b8b6c898486f9c92d70fc12d66b22ec973b764',
  'hex'
);

function certificateDigest(pem) {
  const certificate = new crypto.X509Certificate(pem);
  return crypto.createHash('sha256').update(certificate.raw).digest();
}

function unknownRecord(name, type, data) {
  const record = new Record();
  const rdata = new UNKNOWNRecord();

  record.name = name;
  record.type = type;
  record.class = classes.IN;
  record.ttl = TTL;
  rdata.data = data;
  record.data = rdata;

  return record;
}

function groupRrsets(records) {
  const groups = new Map();

  for (const record of records) {
    if (record.type === types.RRSIG)
      continue;

    const key = `${record.name.toLowerCase()}|${record.type}`;
    const group = groups.get(key) || [];
    group.push(record);
    groups.set(key, group);
  }

  return groups.values();
}

function makeZone(certificatePem) {
  assert(Buffer.isBuffer(certificatePem));

  const digest = certificateDigest(certificatePem);
  const key = dnssec.makeKey(
    ZONE_NAME,
    constants.algs.ECDSAP256SHA256,
    ZONE_PRIVATE_KEY,
    constants.keyFlags.ZONE | constants.keyFlags.SEP
  );
  key.ttl = TTL;

  const records = wire.fromZone([
    `${ZONE_NAME} ${TTL} IN SOA ${NS_NAME} hostmaster.${ZONE_NAME} 1 300 60 604800 60`,
    `${ZONE_NAME} ${TTL} IN NS ${NS_NAME}`,
    `${NS_NAME} ${TTL} IN A ${AUTHORITY_ADDRESS}`,
    `${WWW_NAME} ${TTL} IN A ${ORIGIN_ADDRESS}`,
    `${TLSA_NAME} ${TTL} IN TLSA 3 0 1 ${digest.toString('hex')}`
  ].join('\n'), ZONE_NAME);

  // HTTPS service mode, target owner, default HTTP/1.1 ALPN, no parameters.
  // bns 0.16 predates the HTTPS mnemonic but preserves and signs unknown RRs.
  records.push(unknownRecord(WWW_NAME, HTTPS_TYPE, Buffer.from([0x00, 0x01, 0x00])));
  records.push(key);

  const unsigned = records.slice();
  for (const rrset of groupRrsets(unsigned))
    records.push(dnssec.sign(key, ZONE_PRIVATE_KEY, rrset, 30 * 24 * 60 * 60));

  const ds = dnssec.createDS(key, hashes.SHA256);
  assert(ds);

  return {
    records,
    delegation: {
      records: [
        {type: 'NS', ns: NS_NAME},
        {type: 'GLUE4', ns: NS_NAME, address: AUTHORITY_ADDRESS},
        {
          type: 'DS',
          keyTag: ds.data.keyTag,
          algorithm: ds.data.algorithm,
          digestType: ds.data.digestType,
          digest: ds.data.digest.toString('hex')
        }
      ]
    },
    evidence: {
      zone: ZONE_NAME,
      authorityAddress: AUTHORITY_ADDRESS,
      originAddress: ORIGIN_ADDRESS,
      originPort: ORIGIN_PORT,
      tlsaOwner: TLSA_NAME,
      certificateSha256: digest.toString('hex'),
      dnskeyTag: key.data.keyTag(),
      dsDigest: ds.data.digest.toString('hex'),
      dnssecAlgorithm: ds.data.algorithm,
      dsDigestType: ds.data.digestType,
      signedTypes: [...new Set(unsigned.map(record => record.type))].sort((a, b) => a - b)
    }
  };
}

module.exports = {
  AUTHORITY_ADDRESS,
  ORIGIN_ADDRESS,
  ORIGIN_PORT,
  TLSA_NAME,
  WWW_NAME,
  ZONE_NAME,
  makeZone
};
