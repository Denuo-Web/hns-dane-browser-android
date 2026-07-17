#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const HSD_ROOT = process.env.HSD_ROOT || '/opt/hsd';
const bns = require(path.join(HSD_ROOT, 'node_modules', 'bns'));
const {AUTHORITY_ADDRESS, makeZone} = require('./full-zone');

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || '/artifacts';
const CERT_PATH = process.env.ORIGIN_CERT
  || path.join(ARTIFACT_DIR, 'origin-cert.pem');
const PORT = Number.parseInt(process.env.AUTHORITY_PORT || '53', 10);

function artifactPath(name) {
  fs.mkdirSync(ARTIFACT_DIR, {recursive: true});
  return path.join(ARTIFACT_DIR, name);
}

function writeJson(name, value) {
  const target = artifactPath(name);
  const temporary = `${target}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`);
  fs.renameSync(temporary, target);
}

async function main() {
  const certificate = fs.readFileSync(CERT_PATH);
  const {records, evidence} = makeZone(certificate);

  if (process.argv.includes('--selftest')) {
    process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
    return;
  }

  const server = new bns.AuthServer({
    tcp: true,
    edns: true,
    dnssec: true
  });
  server.setOrigin(evidence.zone);
  for (const record of records)
    server.zone.insert(record);

  const metrics = {
    queries: 0,
    udpQueries: 0,
    tcpQueries: 0,
    queryTypes: {},
    qnamesLogged: 0,
    rawDnsLogged: 0
  };
  const persist = () => writeJson('full-authority-metrics.json', metrics);

  server.on('query', (request, response, remote) => {
    metrics.queries += 1;
    if (remote.tcp)
      metrics.tcpQueries += 1;
    else
      metrics.udpQueries += 1;
    if (request.question.length === 1) {
      const type = String(request.question[0].type);
      metrics.queryTypes[type] = (metrics.queryTypes[type] || 0) + 1;
    }
    persist();
  });
  server.on('error', error => {
    process.stderr.write(`signed authority error: ${error.message}\n`);
  });

  await server.open(PORT, '0.0.0.0');
  writeJson('full-zone-evidence.json', evidence);
  persist();
  fs.writeFileSync(artifactPath('full-signed-authority.ready'), 'ready\n');
  process.stdout.write(`signed DNSSEC authority ready on ${AUTHORITY_ADDRESS}:${PORT}\n`);

  const close = async signal => {
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
    await server.close();
    process.exit(signal === 'SIGINT' ? 130 : 143);
  };
  process.on('SIGINT', () => void close('SIGINT'));
  process.on('SIGTERM', () => void close('SIGTERM'));
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
