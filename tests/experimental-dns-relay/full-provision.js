#!/usr/bin/env node
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HSD_ROOT = process.env.HSD_ROOT || '/opt/hsd';
const NodeClient = require(path.join(HSD_ROOT, 'lib', 'client', 'node'));
const WalletClient = require(path.join(HSD_ROOT, 'lib', 'client', 'wallet'));
const Network = require(path.join(HSD_ROOT, 'lib', 'protocol', 'network'));
const rules = require(path.join(HSD_ROOT, 'lib', 'covenants', 'rules'));
const NameState = require(path.join(HSD_ROOT, 'lib', 'covenants', 'namestate'));
const {Resource} = require(path.join(HSD_ROOT, 'lib', 'dns', 'resource'));
const {makeZone, ZONE_NAME} = require('./full-zone');

const ARTIFACT_DIR = process.env.ARTIFACT_DIR || '/artifacts';
const CERT_PATH = process.env.ORIGIN_CERT
  || path.join(ARTIFACT_DIR, 'origin-cert.pem');
const NAME = ZONE_NAME.slice(0, -1);
const OWNER_HOST = process.env.HSD_OWNER_HOST || 'hsd-owner-good';
const NODE_HOSTS = (process.env.HSD_NODE_HOSTS
  || 'hsd-owner-good,hsd-proof,hsd-relay-bad,hsd-legacy').split(',');
const NODE_PORT = 14037;
const WALLET_PORT = 14039;
const WAIT_MILLISECONDS = 90_000;
const SAFE_ROOT_BLOCKS = 12;

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

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

async function retry(label, operation, timeout = WAIT_MILLISECONDS) {
  const deadline = Date.now() + timeout;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      await delay(250);
    }
  }

  throw new Error(`${label}: ${lastError ? lastError.message : 'timed out'}`);
}

function nodeClient(host) {
  return new NodeClient({host, port: NODE_PORT});
}

async function nodeInfos() {
  return Promise.all(NODE_HOSTS.map(async host => {
    const info = await nodeClient(host).getInfo();
    return {
      role: host,
      height: info.chain.height,
      tip: info.chain.tip,
      treeRoot: info.chain.treeRoot,
      treeRootHeight: info.chain.treeRootHeight
    };
  }));
}

async function waitForConvergence(targetHeight) {
  return retry('four hsd nodes did not converge', async () => {
    const infos = await nodeInfos();
    const first = infos[0];
    const converged = infos.every(info =>
      info.height === targetHeight
      && info.tip === first.tip
      && info.treeRoot === first.treeRoot
      && info.treeRoot !== '00'.repeat(32));

    if (!converged)
      throw new Error(`tips differ: ${JSON.stringify(infos)}`);

    return infos;
  });
}

async function collectNodeProofs(nodes, delegation, expectedKey) {
  const shared = nodes[0];

  return Promise.all(nodes.map(async node => {
    const response = await nodeClient(node.role).execute('getnameproof', [NAME]);
    const proof = response.proof;

    if (response.height !== node.height || response.hash !== node.tip) {
      throw new Error(
        `${node.role} proof was not produced at its converged chain tip: `
        + JSON.stringify(response)
      );
    }

    if (response.root !== shared.treeRoot || response.root !== node.treeRoot) {
      throw new Error(
        `${node.role} proof root does not match the shared current tree root: `
        + JSON.stringify({proofRoot: response.root, node})
      );
    }

    if (response.name !== NAME || response.key !== expectedKey) {
      throw new Error(
        `${node.role} proof identity does not match ${NAME}: `
        + JSON.stringify({name: response.name, key: response.key})
      );
    }

    if (!proof || proof.type !== 'TYPE_EXISTS') {
      throw new Error(
        `${node.role} returned a non-inclusion Urkel proof: `
        + JSON.stringify(proof)
      );
    }

    if (typeof proof.value !== 'string'
        || proof.value.length === 0
        || (proof.value.length & 1) !== 0
        || !/^[0-9a-f]+$/i.test(proof.value)) {
      throw new Error(`${node.role} existence proof has no encoded value`);
    }

    const proofValue = Buffer.from(proof.value, 'hex');
    const nameState = NameState.decode(proofValue);

    if (!nameState.registered || nameState.data.length === 0) {
      throw new Error(
        `${node.role} existence proof does not contain a registered resource`
      );
    }

    const decodedResource = Resource.decode(nameState.data).getJSON(NAME);

    if (decodedResource.records.length === 0)
      throw new Error(`${node.role} proof contains an empty resource`);

    assert.deepStrictEqual(decodedResource, delegation);

    return {
      role: node.role,
      height: response.height,
      tip: response.hash,
      root: response.root,
      key: response.key,
      type: proof.type,
      depth: proof.depth,
      proofNodes: proof.nodes.length,
      proofValueBytes: proofValue.length,
      proofValueSha256: crypto.createHash('sha256').update(proofValue).digest('hex'),
      registered: nameState.registered,
      resourceBytes: nameState.data.length,
      resourceRecords: decodedResource.records.length,
      resourceMatchesDelegation: true
    };
  }));
}

async function main() {
  const ownerNode = nodeClient(OWNER_HOST);
  const wallet = new WalletClient({host: OWNER_HOST, port: WALLET_PORT});
  const network = Network.get('regtest');
  const certificate = fs.readFileSync(CERT_PATH);
  const {delegation, evidence} = makeZone(certificate);
  const nameHash = rules.hashName(NAME);
  const [rolloutHeight, rolloutWeek] = rules.getRollout(nameHash, network);

  assert.strictEqual(rolloutHeight, 52);
  assert.strictEqual(rolloutWeek, 26);

  await retry('owner node HTTP is unavailable', () => ownerNode.getInfo());
  const address = await wallet.execute('getnewaddress', []);
  const start = await ownerNode.getInfo();
  if (start.chain.height !== 0)
    throw new Error(`full-tier owner prefix is not empty (height=${start.chain.height})`);

  await ownerNode.execute('generatetoaddress', [rolloutHeight, address]);
  await wallet.execute('sendopen', [NAME]);
  await ownerNode.execute('generatetoaddress', [network.names.treeInterval + 1, address]);
  await wallet.execute('sendbid', [NAME, 1, 2]);
  await ownerNode.execute('generatetoaddress', [network.names.biddingPeriod, address]);
  await wallet.execute('sendreveal', [NAME]);
  await ownerNode.execute('generatetoaddress', [network.names.revealPeriod + 1, address]);
  await wallet.execute('sendupdate', [NAME, delegation]);
  const postUpdateBlocks = network.names.treeInterval + SAFE_ROOT_BLOCKS;
  assert.strictEqual(postUpdateBlocks, 17);
  await ownerNode.execute(
    'generatetoaddress',
    [postUpdateBlocks, address]
  );

  const ownerInfo = await ownerNode.getInfo();
  const targetHeight = ownerInfo.chain.height;
  const nodes = await waitForConvergence(targetHeight);
  const nameInfo = await ownerNode.execute('getnameinfo', [NAME, true]);
  const resource = await ownerNode.execute('getnameresource', [NAME, true]);

  if (!nameInfo.info || nameInfo.info.state !== 'CLOSED' || !nameInfo.info.registered)
    throw new Error(`name did not reach registered CLOSED state: ${JSON.stringify(nameInfo)}`);
  assert.deepStrictEqual(resource, delegation);
  const nodeProofs = await collectNodeProofs(
    nodes,
    delegation,
    nameHash.toString('hex')
  );

  const state = {
    status: 'pass',
    network: 'regtest',
    name: NAME,
    nameHash: nameHash.toString('hex'),
    rolloutHeight,
    rolloutWeek,
    safeRootBlocks: SAFE_ROOT_BLOCKS,
    postUpdateBlocks,
    targetHeight,
    tip: ownerInfo.chain.tip,
    treeRoot: ownerInfo.chain.treeRoot,
    treeRootHeight: ownerInfo.chain.treeRootHeight,
    nameState: nameInfo.info.state,
    registered: nameInfo.info.registered,
    proofType: nodeProofs[0].type,
    proofRootMatchesTip: nodeProofs.every(proof =>
      proof.root === ownerInfo.chain.treeRoot
    ),
    delegation,
    zoneEvidence: evidence,
    nodes,
    nodeProofs
  };

  writeJson('full-regtest-state.json', state);
  fs.writeFileSync(artifactPath('full-target-height.txt'), `${targetHeight}\n`);
  process.stdout.write(`registered ${NAME} at regtest height ${targetHeight}\n`);
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
