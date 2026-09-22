'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const kp = require('ripple-keypairs');
const evernode = require('evernode-js-client');

const PORT = Number(process.env.EVERSMARTNODE_PORT || process.env.EXTERNAL_GPTCP1_PORT || 8443);
const HOST = process.env.EVERSMARTNODE_HOST || '0.0.0.0';
const DATA_DIR = process.env.EVERSMARTNODE_DATA_DIR || '/var/lib/eversmartnode';
const SECRET_DIR = process.env.EVERSMARTNODE_SECRET_DIR || '/var/lib/eversmartnode/secrets';
const SECRET_HELPER = process.env.EVERSMARTNODE_SECRET_HELPER || '';
const SEED_SECRET = path.join(SECRET_DIR, 'cluster-master.seed');
const WALLET_META = path.join(DATA_DIR, 'cluster-wallet.json');
const WALLET_STATUS_CACHE = path.join(DATA_DIR, 'cluster-wallet-status-cache.json');
const AUTOCLUSTER_STATUS_CACHE = path.join(DATA_DIR, 'autocluster-status-cache.json');
const XAHAU_RPC_STICKY_FILE = path.join(DATA_DIR, 'xahau-rpc-sticky.json');
const AUTOCLUSTER_STATUS_CACHE_MAX_AGE_MS = 15 * 60 * 1000;
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.log');
const HANDOVER_PENDING_FILE = path.join(DATA_DIR, 'handover-pending.json');
const READY_CONTROLLER_LEGACY_SECRET = path.join(SECRET_DIR, 'autocluster-ready-controller.key');
const READY_CONTROLLER_SECRET = process.env.EVERSMARTNODE_READY_CONTROLLER_SECRET || '/contract/cfg/autocluster-ready-controller.key';
const READY_CONTROLLER_META = process.env.EVERSMARTNODE_READY_CONTROLLER_META || '/contract/cfg/autocluster-ready-controller.json';
const CANDIDATE_RELAY_SECRET = process.env.EVERSMARTNODE_CANDIDATE_RELAY_SECRET || '/contract/cfg/autocluster-candidate-relay.key';
const CANDIDATE_RELAY_META = process.env.EVERSMARTNODE_CANDIDATE_RELAY_META || '/contract/cfg/autocluster-candidate-relay.json';
// Separate read-only HotPocket user identity for candidate STAT/MESH sockets.
// HotPocket user identities are cluster-wide doorway identities; reusing the READY
// controller key on a candidate stat socket and Bootstrap A submit socket at the
// same time can cause the submit doorway to be displaced/closed.
const READY_STAT_PROBE_SECRET_DIR = path.join(SECRET_DIR, 'autocluster-stat-probes');
const READY_STAT_PROBE_META_DIR = path.join(DATA_DIR, 'autocluster-stat-probes');
const HANDOVER_QUEUE_HOLD_MS = 3 * 60 * 1000;
const ALLOW_UNSAFE_SMALL = process.env.EVERSMARTNODE_ALLOW_UNSAFE_SMALL_CLUSTER === '1';
const XAHAU_FEE_SETTINGS_INDEX = '4BC50C9B0D8515D3EAAE1E74B29A95804346C491EE1A95BF25E4AAB854A6A651';
const RESERVE_FEE_BUFFER_DROPS = 100000; // 0.1 XAH safety buffer above next-object reserve.
const XAHAU_GENESIS_REWARD_ISSUER = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const XAHAU_TX_LEDGER_OFFSET = 20;

class FundingRequiredError extends Error {
  constructor(message, wallet = null, stage = 'funding') {
    super(message);
    this.name = 'FundingRequiredError';
    this.code = 'FUNDING_REQUIRED';
    this.httpStatus = 409;
    this.wallet = wallet;
    this.stage = stage;
  }
}
function looksLikeFundingError(error) {
  const text = String(error && error.message ? error.message : error || '');
  return /(tecINSUFFICIENT_RESERVE|tecINSUF_RESERVE|tecNO_LINE_INSUF_RESERVE|tecINSUFF_FEE|terINSUF_FEE|tecUNFUNDED|insufficient|not enough|unfunded|reserve|balance)/i.test(text);
}
function looksLikeTerQueued(error) {
  const text = String(error && error.message ? error.message : error || '');
  return /\bterQUEUED\b/i.test(text);
}
function signerListMatches(status, signers, quorum) {
  const sl = status && status.signerList;
  if (!sl || Number(sl.quorum) !== Number(quorum)) return false;
  const a = (sl.signers || []).map(x => `${x.account}:${Number(x.weight || 0)}`).sort();
  const b = (signers || []).map(x => `${x.account}:${Number(x.weight || 0)}`).sort();
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function rewardTrackingInitialized(status) {
  const reward = status && status.rewardTracking;
  return !!(reward && reward.initialized === true);
}
function requiredAdmissionPeers(unlSize) {
  const n = Math.max(1, Number(unlSize) || 1);
  return Math.max(1, Math.min(2, n));
}

async function submitMasterSignedInitialClaimReward(tenant, address) {
  // evernode-js-client 0.6.61 has no first-class ClaimReward helper. Build the
  // native Xahau transaction using the same preparation/sign/submit primitives
  // its XrplAccount helpers use. A's treasury master key is deliberately still
  // enabled at this point; the final managed SignerListSet is already visible.
  const api = tenant && tenant.xrplApi;
  const account = tenant && tenant.xrplAcc;
  if (!api || !account || !api.xrplHelper || typeof api.xrplHelper.encode !== 'function' ||
      typeof api.getTransactionFee !== 'function' || typeof account.getSequence !== 'function' ||
      typeof account.signAndSubmit !== 'function') {
    throw new Error('ClaimReward preparation is unavailable from the connected Xahau client.');
  }
  const ledgerIndex = Number(api.ledgerIndex || 0);
  if (!Number.isFinite(ledgerIndex) || ledgerIndex <= 0) {
    throw new Error('ClaimReward cannot be prepared because the connected Xahau ledger index is unavailable.');
  }
  const networkID = Number(evernode && evernode.Defaults && evernode.Defaults.values && evernode.Defaults.values.networkID);
  if (!Number.isFinite(networkID) || networkID <= 0) {
    throw new Error('ClaimReward cannot be prepared because the Xahau NetworkID is unavailable.');
  }
  const tx = {
    TransactionType: 'ClaimReward',
    Account: address,
    Issuer: XAHAU_GENESIS_REWARD_ISSUER,
    NetworkID: networkID,
    Sequence: await account.getSequence(),
    LastLedgerSequence: ledgerIndex + XAHAU_TX_LEDGER_OFFSET,
    SigningPubKey: '',
    Fee: '0'
  };
  const feeBlob = api.xrplHelper.encode(tx);
  tx.Fee = String(await api.getTransactionFee(feeBlob));
  delete tx.SigningPubKey;
  const submissionRef = {};
  const result = await account.signAndSubmit(tx, submissionRef);
  return { result, submissionRef, tx };
}
function readHandoverPending() { return readJson(HANDOVER_PENDING_FILE, null); }
function writeHandoverPending(stage, detail = {}) {
  writeJson(HANDOVER_PENDING_FILE, { stage, submittedAt:Date.now(), ...detail });
}
function clearHandoverPending() { try { fs.rmSync(HANDOVER_PENDING_FILE, { force:true }); } catch {} }

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(SECRET_DIR, { recursive: true });
// alpha53.7 no longer uses the single shared STAT identity from alpha53.5.
// Remove the legacy artifacts so an upgrade cannot accidentally resurrect one
// HotPocket user key across multiple candidate sockets.
for (const legacy of [
  path.join(SECRET_DIR, 'autocluster-stat-probe.key'),
  path.join(DATA_DIR, 'autocluster-stat-probe.json')
]) { try { fs.rmSync(legacy, { force:true }); } catch {} }
// Keep exactly one READY-controller identity artifact. Older experimental builds
// used different suffixes under this prefix; remove those stale local-only files so
// an upgrade cannot leave competing credentials behind.
for (const [dir, keep, suffix] of [[SECRET_DIR, READY_CONTROLLER_SECRET, '.key'], [DATA_DIR, READY_CONTROLLER_META, '.json']]) {
  try {
    for (const name of fs.readdirSync(dir)) {
      if (!name.startsWith('autocluster-ready-') || !name.endsWith(suffix)) continue;
      const file = path.join(dir, name);
      if (path.resolve(file) === path.resolve(keep)) continue;
      try { fs.unlinkSync(file); } catch {}
    }
  } catch {}
}

function logEvent(kind, detail = {}) {
  const rec = { at: new Date().toISOString(), kind, ...detail };
  fs.appendFileSync(EVENTS_FILE, JSON.stringify(rec) + '\n', { mode: 0o600 });
  console.log(`[eversmartnode-api] ${kind}`, detail);
}
function logFundingEvent(kind, stage, wallet = {}, reason = '') {
  logEvent(kind, {
    stage: stage || 'funding',
    address: wallet && wallet.address || null,
    xah: wallet && wallet.xah != null ? wallet.xah : null,
    spendableXah: wallet && wallet.spendableXah != null ? wallet.spendableXah : null,
    reserveRequiredXah: wallet && wallet.reserveRequiredXah != null ? wallet.reserveRequiredXah : null,
    reserveNextObjectXah: wallet && wallet.reserveNextObjectXah != null ? wallet.reserveNextObjectXah : null,
    reserveBootstrapReadyXah: wallet && wallet.reserveBootstrapReadyXah != null ? wallet.reserveBootstrapReadyXah : null,
    suggestedTopUpXah: wallet && wallet.suggestedTopUpXah != null ? wallet.suggestedTopUpXah : null,
    suggestedBootstrapTopUpXah: wallet && wallet.suggestedBootstrapTopUpXah != null ? wallet.suggestedBootstrapTopUpXah : null,
    evrBalance: wallet && wallet.evrBalance != null ? wallet.evrBalance : null,
    reason: clean(reason, 1000)
  });
}
function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, mode); } catch {}
}
function clampInt(v, fallback, min, max) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}
function clean(v, max = 512) { return String(v == null ? '' : v).trim().slice(0, max); }
function clampNumber(v, fallback, min, max) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
}

const RPC_CHAIN_KEYS = ['xahau','xrpl','solana','stellar','ethereum','bitcoin'];
function defaultXahauRpc(network) {
  if (network === 'mainnet') return 'wss://xahau.network';
  if (network === 'testnet') return 'wss://xahau-test.net';
  return null;
}
function normalizeRpcUrl(value, chain) {
  const raw = clean(value, 512);
  if (!raw) return null;
  try {
    const u = new URL(raw);
    const protocol = String(u.protocol || '').toLowerCase();
    const allowed = (chain === 'xahau' || chain === 'xrpl')
      ? ['ws:','wss:']
      : ['http:','https:','ws:','wss:'];
    if (!allowed.includes(protocol) || !u.hostname) return null;
    return u.toString().replace(/\/$/, '');
  } catch { return null; }
}
function normalizeRpcPool(raw, chain) {
  let source = raw;
  if (typeof source === 'string') source = source.split(/\r?\n/).map((line, i) => {
    const t = line.trim(); if (!t) return null;
    const m = t.match(/^(\d+)\s*(?:\||\s)\s*(.+)$/);
    return m ? { priority:Number(m[1]), url:m[2] } : { priority:(i + 1) * 10, url:t };
  }).filter(Boolean);
  if (!Array.isArray(source)) source = [];
  const byUrl = new Map();
  source.forEach((item, i) => {
    const obj = item && typeof item === 'object' ? item : { url:item };
    const url = normalizeRpcUrl(obj.url || obj.endpoint || obj.server, chain);
    if (!url) return;
    const priority = clampInt(obj.priority, (i + 1) * 10, 1, 1000000);
    const prior = byUrl.get(url);
    if (!prior || priority < prior.priority) byUrl.set(url, { priority, url });
  });
  return [...byUrl.values()].sort((a,b) => a.priority - b.priority || a.url.localeCompare(b.url)).slice(0, 32);
}
function normalizeRpcPools(rawPools, legacyRippleServer = '', network = 'mainnet') {
  rawPools = rawPools && typeof rawPools === 'object' ? rawPools : {};
  const out = {};
  for (const chain of RPC_CHAIN_KEYS) out[chain] = normalizeRpcPool(rawPools[chain], chain);
  const legacy = normalizeRpcUrl(legacyRippleServer, 'xahau');
  if (!out.xahau.length && legacy) out.xahau = [{ priority:10, url:legacy }];
  if (!out.xahau.length) {
    const def = defaultXahauRpc(network);
    if (def) out.xahau = [{ priority:10, url:def }];
  }
  return out;
}
function rpcPoolUrls(obj, chain) {
  return normalizeRpcPool(obj && obj.rpcPools && obj.rpcPools[chain], chain).map(x => x.url);
}
function orderedStickyXahauUrls(urls) {
  const cleanUrls = [...new Set((Array.isArray(urls) ? urls : []).map(x => normalizeRpcUrl(x, 'xahau')).filter(Boolean))];
  const sticky = readJson(XAHAU_RPC_STICKY_FILE, null);
  const preferred = normalizeRpcUrl(sticky && sticky.url, 'xahau');
  if (!preferred || !cleanUrls.includes(preferred)) return cleanUrls;
  return [preferred, ...cleanUrls.filter(x => x !== preferred)];
}
async function connectXahauRpcSequential(urls, network, label = 'control-plane') {
  await evernode.Defaults.useNetwork(network || 'mainnet');
  const ordered = orderedStickyXahauUrls(urls);
  if (!ordered.length) throw new Error('Xahau RPC pool is empty.');
  const failures = [];
  for (let i = 0; i < ordered.length; i++) {
    const url = ordered[i];
    let api = null;
    try {
      console.log(`[eversmartnode-api] Xahau RPC try ${i + 1}/${ordered.length}: ${url}`);
      // Force one endpoint per XrplApi instance. The upstream class otherwise
      // starts its primary reconnect path every time a short-lived TenantClient
      // is created, which produces misleading reconnect spam even when fallback
      // succeeds. We own the ordered failover here instead.
      api = new evernode.XrplApi('-', { fallbackRippledServers:[url], autoReconnect:false });
      await api.connect();
      // Control-plane fee policy mirrors AutoCluster: every fee returned by the
      // connected Xahau API is the calculated network fee plus exactly 13 drops.
      // This happens before signing, so signatures always cover the bumped Fee.
      if (typeof api.getTransactionFee === 'function' && !api.__everSmartNodeFeePlus13) {
        const originalGetTransactionFee = api.getTransactionFee.bind(api);
        api.getTransactionFee = async (...args) => {
          const calculated = await originalGetTransactionFee(...args);
          try {
            const bumped = BigInt(String(calculated)) + 13n;
            console.log(`[eversmartnode-api] Xahau fee bump ${String(calculated)} -> ${bumped.toString()} drops (+13)`);
            return bumped.toString();
          } catch {
            throw new Error(`XAHAU_FEE_INVALID: expected integer drops, got ${String(calculated)}`);
          }
        };
        api.__everSmartNodeFeePlus13 = true;
      }
      writeJson(XAHAU_RPC_STICKY_FILE, { url, connectedAt:new Date().toISOString(), label });
      console.log(`[eversmartnode-api] Xahau RPC connected: ${url} (sticky until failure or pool change)`);
      return { xrplApi:api, url };
    } catch (e) {
      const msg = clean(e && e.message ? e.message : e, 500);
      failures.push(`${url}: ${msg || 'connect failed'}`);
      console.warn(`[eversmartnode-api] Xahau RPC failed: ${url}; trying next configured endpoint. ${msg}`);
      try { if (api) await api.disconnect(); } catch {}
      const sticky = readJson(XAHAU_RPC_STICKY_FILE, null);
      if (sticky && normalizeRpcUrl(sticky.url, 'xahau') === url) {
        try { fs.rmSync(XAHAU_RPC_STICKY_FILE, { force:true }); } catch {}
      }
    }
  }
  throw new Error(`All configured Xahau RPC endpoints failed: ${failures.join(' | ')}`);
}

function normalizeSettings(raw = {}) {
  const target = clampInt(raw.targetManagedNodes, 5, 1, 16);
  const defaultQuorum = Math.max(1, Math.floor(target / 2) + 1);
  const network = ['mainnet', 'testnet', 'devnet'].includes(raw.network) ? raw.network : 'mainnet';
  const rpcPools = normalizeRpcPools(raw.rpcPools, raw.rippleServer, network);
  const admissionTimeoutInput = raw.candidateAdmissionTimeoutMs;
  return {
    network,
    rpcPools,
    // Legacy alias kept for older deployed contracts/UI. The first Xahau entry
    // is the primary; evernode-js-client receives the rest as fallbacks.
    rippleServer: rpcPools.xahau[0]?.url || clean(raw.rippleServer, 512),
    targetManagedNodes: target,
    signerQuorum: clampInt(raw.signerQuorum, defaultQuorum, 1, target),
    managedImage: clean(raw.managedImage, 512),
    maxLeaseAmountEvrPerMoment: clampNumber(raw.maxLeaseAmountEvrPerMoment, 0, 0, 1000000),
    lifeIncrMomentMinLimit: clampInt(raw.lifeIncrMomentMinLimit, 2, 1, 96),
    maxLifeMomentLimit: clampInt(raw.maxLifeMomentLimit, 0, 0, 100000),
    parallelGrow: !!raw.parallelGrow,
    preferredHosts: Array.isArray(raw.preferredHosts)
      ? raw.preferredHosts.map(x => clean(x, 128)).filter(Boolean).slice(0, 64)
      : clean(raw.preferredHosts, 8192).split(/[\s,]+/).map(x => clean(x, 128)).filter(Boolean).slice(0, 64),
    maturityLclThreshold: clampInt(raw.maturityLclThreshold, 2, 1, 1000),
    acknowledgeLclThreshold: clampInt(raw.acknowledgeLclThreshold, 2, 1, 1000),
    candidateReadyTimeoutMs: clampInt(raw.candidateReadyTimeoutMs, 4 * 60 * 1000, 30 * 1000, 30 * 60 * 1000),
    candidateAdmissionTimeoutMs: clampInt(admissionTimeoutInput, 20 * 60 * 1000, 20 * 60 * 1000, 60 * 60 * 1000),
    candidatePoolSize: clampInt(raw.candidatePoolSize, 4, 1, 8),
    candidateSpeculativeAcquireDelayMs: clampInt(raw.candidateSpeculativeAcquireDelayMs, 2 * 60 * 1000, 30 * 1000, 15 * 60 * 1000),
    candidateReadyStaleGraceMs: clampInt(raw.candidateReadyStaleGraceMs, 60 * 1000, 15 * 1000, 10 * 60 * 1000),
    readyProbeUnreachableTimeoutMs: clampInt(raw.readyProbeUnreachableTimeoutMs, 60 * 1000, 15 * 1000, 10 * 60 * 1000),
    evrTrustLimit: clean(raw.evrTrustLimit || '1000000000', 64),
    bootstrapPubkey: clean(raw.bootstrapPubkey, 256),
    bootstrapPublicHost: clean(raw.bootstrapPublicHost, 255),
    readyControllerPublicKey: cleanPublicKey(raw.readyControllerPublicKey) || null
  };
}
function settings() {
  const out = normalizeSettings(readJson(SETTINGS_FILE, {}));
  const controllerMeta = readJson(READY_CONTROLLER_META, null);
  const controllerKey = cleanPublicKey(controllerMeta && controllerMeta.publicKey);
  if (controllerKey) out.readyControllerPublicKey = controllerKey;
  return out;
}

function helperExists() { return fs.existsSync(SECRET_HELPER); }
function secretRead(file) {
  if (helperExists()) {
    try { return execFileSync(SECRET_HELPER, ['read', file], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return null; }
  }
  try { return fs.readFileSync(file, 'utf8').trim(); } catch { return null; }
}
function secretWrite(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (helperExists()) {
    execFileSync(SECRET_HELPER, ['write', file], { input: String(value), stdio: ['pipe', 'ignore', 'pipe'] });
    return;
  }
  fs.writeFileSync(file, String(value), { mode: 0o600 });
}
function secretRemove(file) {
  if (helperExists()) {
    try { execFileSync(SECRET_HELPER, ['remove', file], { stdio: 'ignore' }); } catch {}
  }
  try { fs.rmSync(file, { force: true }); } catch {}
}
function stateRoot() {
  // HotPocket's live state is authoritative even when the base application
  // executable is supplied by the Docker image and index.js is therefore not
  // present in state. Never fall back to seed merely because code files are
  // absent from the live mount.
  const candidates = [
    '/contract/contract_fs/mnt/rw/state',
    process.env.EVERSMARTNODE_CONTRACT_STATE_ROOT,
    '/contract/state',
    '/contract/contract_fs/seed/state'
  ].filter(Boolean);
  for (const c of candidates) {
    try {
      const p = path.resolve(c);
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
    } catch {}
  }
  return null;
}
function readHpCfg() {
  const candidates = ['/contract/cfg/hp.cfg', '/contract/hp.cfg'];
  for (const file of candidates) {
    try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  }
  return null;
}
let readyControllerPair = null;
let readyControllerPublicKey = null;
let candidateRelayPair = null;
let candidateRelayPublicKey = null;
let candidateRelayTransportBusy = false;
let candidateRelayLastAcceptedFingerprint = null;
let candidateRelayLastAttemptAt = 0;
let candidateRelayLastPurpose = null;
let candidateRelayLastAcceptedAt = 0;
const readyStatProbeIdentities = new Map(); // candidate pubkey -> { pair, publicKey }
let readyControllerTransportBusy = false;
let readyControllerTransportClient = null;
let readyControllerTransportEndpoint = null;
let readyControllerTransportBootstrap = null;
let readyControllerTransportLabel = null;
let readyStatBusy = false;
const readyStatClients = new Map();
// Cluster-level HotPocket user identity invariant: one user public key may back
// at most one live client socket at a time. Reusing a user keypair on a second
// connection can cause HotPocket to treat the two sessions as the same client.
const liveHpUserSockets = new Map();
// candidate -> { fingerprint, inputLedger, submittedAt }. A sent input is NOT
// treated as canonical READY until autocluster.state.json records the proof.
const readyStatPending = new Map();
const readyProbeLastLog = new Map();
// Node-local control-plane observations. These are DISPLAY/OPERATOR diagnostics only;
// they never enter HotPocket consensus state. They let the UI show what the
// candidate is actually doing even while the authenticated READY record is still
// being submitted/committed.
const readyLiveProbes = new Map();
let readyControllerAuthStatus = { ok:null, expected:null, local:null, observedAt:null, reason:'not-checked' };
const READY_LIVE_PROBE_MAX_AGE_MS = 30000;
const READY_PROBE_LOG_INTERVAL_MS = 10000;
// READY proof submission must never serialize the whole candidate scan. HotPocket
// input acceptance can legitimately take several 4-second rounds, so dispatch the
// proof and observe its status asynchronously while continuing to poll peers.
const READY_SUBMISSION_PENDING_MS = 30000;
const READY_STATUS_UNKNOWN_RETRY_MS = 8000;
let readySubmissionSeq = 0;
let readySubmitInFlight = null; // one Bootstrap-A user-input submission at a time; candidate stat scanning stays parallel
const SIGNED_CANDIDATE_RELAY_MODE = true;
const SIGNED_RELAY_FINAL_PROOF_DELAY_LCLS = 7;
const SIGNED_RELAY_FINAL_RETRY_LCLS = 16;
const NPL_READINESS_MODE = false; // legacy pre-UNL NPL bridge disabled; NPL does not carry non-UNL candidate reports.
const NPL_PREUNL_REPORT_MAX_LAG_LCLS = 4;
const nplMaturitySubmitted = new Map();
let membershipCommandPending = null; // { fingerprint, submittedAt, status, token, inputLedger }
let postRemovalFinalizeBusy = false;
let readyMeshLastProbeAt = 0;
const READY_MESH_PROBE_INTERVAL_MS = 10000;
// Must match cluster-controller.js CANDIDATE_READY_REQUIRED_HEARTBEATS. A
// candidate is called READY after two accepted canonical observations at
// strictly increasing LCLs, proving one actual forward ledger advance.
const READY_STABLE_REQUIRED_HEARTBEATS = 2;
const readyUnreachableSince = new Map();
const readyUnreachableSubmitted = new Map();
// Bad/weak candidates are the ones most likely to burn sockets/CPU. Keep healthy
// candidates responsive, but back off weak and unreachable endpoints so a cheap
// VPS cannot be DoS'd by our own readiness scanner.
const readyProbeNextAt = new Map();
const READY_PROBE_WEAK_BACKOFF_MS = 30 * 1000;
const READY_PROBE_ERROR_BACKOFF_MS = 60 * 1000;
const READY_LOCAL_HISTORY_WINDOW = 32;
const BOOTSTRAP_ADMISSION_MAX_LAG_LCLS = 24;
const UNL_CONVERGENCE_MAX_LAG_LCLS = 4;
const UNL_CONVERGENCE_OUTLIER_REMOVE_LCLS = 6;
const unlConvergenceOutlierSince = new Map(); // convKey -> { sinceAt, sinceLcl, lastLcl }

const unlConvergenceRemovalSubmitted = new Set();
// Root-local only. FINAL-proof candidate rotation must never mutate replicated
// contract state; otherwise the candidates are forced to chase a new state hash.
const atomicFinalProbeCooldownUntil = new Map();
let atomicMembershipTarget = null; // ephemeral UI/diagnostic target, never consensus state
const ATOMIC_FINAL_PROBE_COOLDOWN_MS = 8000;
// The 1->2 transition has zero fault tolerance at 60%: both validators must vote.
// A single getStatus() tuple is not enough because hpcore can advertise the
// consensus/network LCL while its local primary/raw shards are still catching up.
// Require sustained exact-tip + vote=synced evidence across distinct advancing
// observations before the first managed validator is allowed into the UNL.
const FIRST_ADD_SYNC_STREAK_REQUIRED = 5;
const firstAddSyncStreaks = new Map(); // pubkey -> { observations:[{lcl,hash,voteStatus,peerCount}] }
let firstAddSyncTarget = null;

function publicNodeStatusCode(node) {
  if (!node) return null;
  if (Number.isFinite(Number(node.statusCode))) return Number(node.statusCode);
  const raw = node.status && typeof node.status === 'object' ? (node.status.status ?? node.status.state) : node.status;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}
function publicNodeAcknowledged(node) {
  if (!node) return false;
  if (node.isUnl) return true;
  if (publicNodeStatusCode(node) >= 3) return true;
  return /^(acknowledged|added_to_unl|unl)$/i.test(String(node.statusName || ''));
}
function serverDurableQualification(auto, node, lcl) {
  const pubkey = cleanPublicKey(node && node.pubkey);
  if (!pubkey || !auto) return { ready:false, maturityAge:0, maturityRequired:8 };
  const rec = (Array.isArray(auto.candidateReadiness) ? auto.candidateReadiness : []).find(r => cleanPublicKey(r && r.pubkey) === pubkey) || null;
  const readyHeartbeats = Math.max(0, Number(rec && rec.readyHeartbeats) || 0);
  const syncHeartbeats = Math.max(0, Number(rec && rec.syncHeartbeats) || 0);
  const candidateLcl = Math.max(0, Number(rec && rec.candidateLcl) || 0);
  const candidateHash = clean(rec && rec.candidateHash || '', 256).toLowerCase();
  const history = Array.isArray(rec && rec.proofHistory) ? rec.proofHistory : [];
  const canonicalTupleRecorded = !!(candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash) && history.some(h =>
    Number(h && h.candidateLcl) === candidateLcl && clean(h && h.candidateHash || '',256).toLowerCase() === candidateHash));
  const transport = clean(rec && rec.transport || '', 48).toLowerCase();
  const canonicalTransport = /^(?:bootstrap-canonical-controller|client-stat|npl|signed-(?:canonical|hpfs)-relay)$/.test(transport);
  const statusObj = node && node.status && typeof node.status === 'object' ? node.status : {};
  const acknowledgedOnLcl = Math.max(0, Number(statusObj.onLcl || node && node.acknowledgedOnLcl) || 0);
  const maturityRequired = Math.max(8, Number(auto.maturityLclThreshold) || 0);
  const maturityAge = acknowledgedOnLcl && lcl ? Math.max(0, Number(lcl) - acknowledgedOnLcl) : 0;
  const signer = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(node && node.signerAddress || ''));
  return {
    ready: !!(publicNodeAcknowledged(node) && signer && acknowledgedOnLcl > 0 && maturityAge >= maturityRequired &&
      readyHeartbeats >= READY_STABLE_REQUIRED_HEARTBEATS && syncHeartbeats >= 1 && canonicalTransport && canonicalTupleRecorded),
    readyHeartbeats, syncHeartbeats, canonicalTransport, canonicalTupleRecorded, maturityAge, maturityRequired
  };
}
function atomicBootstrapAdmissionPlan(local, auto, committedUnl, bootstrapPubkey) {
  const none = { frozen:false, target:null, candidates:[], reason:'not-applicable' };
  if (!local || !auto || auto.phase !== 'growing' || !bootstrapPubkey || !Array.isArray(committedUnl) || !committedUnl.includes(bootstrapPubkey)) return none;
  const targetManaged = Math.max(1, Number(auto.targetManagedNodes) || 1);
  if (committedUnl.length !== 1) { firstAddSyncTarget = null; firstAddSyncStreaks.clear(); }
  if (committedUnl.length >= targetManaged + 1) return { ...none, reason:'bridge-target-reached' };
  const stab = auto.stabilization && typeof auto.stabilization === 'object' ? auto.stabilization : null;
  const nodes = Array.isArray(local.nodes) ? local.nodes : [];
  const stalled = new Set((Array.isArray(auto.candidateWatchdogs) ? auto.candidateWatchdogs : [])
    .filter(w => w && w.stalledAt && !w.kickedAt).map(w => cleanPublicKey(w.pubkey)).filter(Boolean));
  const managedUsable = nodes.filter(n => n && cleanPublicKey(n.pubkey) !== bootstrapPubkey && !stalled.has(cleanPublicKey(n.pubkey)));
  const history = readyLocalLedgerHistory();
  const head = history.length ? history[history.length - 1] : null;
  const lcl = Number(head && head.lcl) || Number(local.bootstrapObservedLcl) || 0;
  const qualified = managedUsable.filter(n => !n.isUnl && serverDurableQualification(auto, n, lcl).ready);
  // Before the first addition, match the contract's hard-freeze boundary: full
  // usable fleet and target-count durable qualification. After 1->2 commits, the
  // contract permanently stays in consensus-purity mode for the rest of growth.
  const frozen = committedUnl.length >= 2 || (managedUsable.length >= targetManaged && qualified.length >= targetManaged);
  if (!frozen) return { frozen:false, target:null, candidates:qualified, reason:`pre-freeze-${qualified.length}/${targetManaged}` };
  if (stab && stab.active) return { frozen:true, target:null, candidates:qualified, reason:'validator-stabilization-active' };
  const now = Date.now();
  // Once a singleton candidate starts proving sustained local readiness, keep
  // probing that same node instead of rotating targets every scan. Any failed
  // exact/synced sample clears this lock below and another candidate may try.
  if (committedUnl.length === 1 && firstAddSyncTarget) {
    const locked = qualified.find(n => cleanPublicKey(n && n.pubkey) === firstAddSyncTarget) || null;
    const until = Number(atomicFinalProbeCooldownUntil.get(firstAddSyncTarget) || 0);
    if (locked && (!until || until <= now)) {
      return { frozen:true, target:locked, candidates:qualified, reason:'first-add-sustained-sync-target-locked' };
    }
    firstAddSyncTarget = null;
  }
  const currentHeadLcl = Number(head && head.lcl) || 0;
  const currentHeadHash = clean(head && head.hash || '',256).toLowerCase();
  const requiredPeers = requiredAdmissionPeers(committedUnl.length);
  const ranked = qualified.filter(n => {
    const until = Number(atomicFinalProbeCooldownUntil.get(cleanPublicKey(n.pubkey)) || 0);
    return !until || until <= now;
  }).map(n => {
    const pubkey = cleanPublicKey(n.pubkey);
    const live = readyLiveProbes.get(pubkey) || null;
    const liveExact = !!(live && Date.now() - Number(live.observedAt || 0) <= READY_LIVE_PROBE_MAX_AGE_MS &&
      live.canonicalMatch && Number(live.candidateLag) === 0 && Number(live.candidateLcl) === currentHeadLcl &&
      clean(live.candidateHash || '',256).toLowerCase() === currentHeadHash && clean(live.voteStatus || '',32).toLowerCase() === 'synced' && live.contractExecutionEnabled !== false &&
      !live.weaklyConnected && Number(live.peers || 0) >= requiredPeers);
    return { node:n, pubkey, liveExact, observedAt:Number(live && live.observedAt) || 0 };
  }).sort((a,b) => Number(b.liveExact)-Number(a.liveExact) || b.observedAt-a.observedAt || a.pubkey.localeCompare(b.pubkey));
  return { frozen:true, target:ranked.length ? ranked[0].node : null, candidates:ranked.map(x=>x.node), reason:ranked.length?'candidate-selected':'all-qualified-candidates-cooling' };
}

function readyLocalLedgerHistoryFile() {
  const sr = stateRoot();
  return sr ? path.resolve(sr, '..', 'autocluster-local', 'recent-ledgers.json') : null;
}
function readyNplNodeStatusFile() {
  const sr = stateRoot();
  return sr ? path.resolve(sr, '..', 'autocluster-local', 'npl-node-status.json') : null;
}
function candidateAttestationFile() {
  const sr = stateRoot();
  return sr ? path.resolve(sr, '..', 'autocluster-local', 'candidate-attestation.json') : null;
}
function readyNplNodeStatusCache() {
  const file = readyNplNodeStatusFile();
  const raw = file ? readJson(file, null) : null;
  return {
    observations: raw && raw.observations && typeof raw.observations === 'object' ? raw.observations : {},
    maturities: raw && raw.maturities && typeof raw.maturities === 'object' ? raw.maturities : {}
  };
}
function readyLocalLedgerHistory() {
  const file = readyLocalLedgerHistoryFile();
  const raw = file ? readJson(file, null) : null;
  const rows = raw && Array.isArray(raw.recentLedgers) ? raw.recentLedgers : [];
  const byLcl = new Map();
  for (const row of rows) {
    const lcl = Number(row && row.lcl) || 0;
    const hash = clean(row && row.hash || '', 256).toLowerCase();
    if (lcl > 0 && /^[0-9a-f]{64}$/.test(hash)) byLcl.set(lcl, hash);
  }
  return [...byLcl.entries()].sort((a,b)=>a[0]-b[0]).slice(-READY_LOCAL_HISTORY_WINDOW).map(([lcl,hash])=>({lcl,hash}));
}
function readyLocalLedgerStatus(lcl, hash) {
  const seq = Number(lcl) || 0;
  const digest = clean(hash || '', 256).toLowerCase();
  if (!seq || !/^[0-9a-f]{64}$/.test(digest)) return { match:false, reason:'invalid-proof', expected:null };
  const row = readyLocalLedgerHistory().find(x => x.lcl === seq) || null;
  if (!row) return { match:false, reason:'canonical-lcl-missing', expected:null };
  if (row.hash !== digest) return { match:false, reason:'canonical-hash-mismatch', expected:row.hash };
  return { match:true, reason:null, expected:row.hash };
}
function readyLocalLedgerMatches(lcl, hash) { return readyLocalLedgerStatus(lcl, hash).match; }

function readyProbeLog(candidatePubkey, stage, detail = {}, signature = null, force = false) {
  const candidate = cleanPublicKey(candidatePubkey) || clean(candidatePubkey || 'bootstrap', 96) || 'bootstrap';
  const sig = signature == null ? String(stage || '') : String(signature);
  const key = `${candidate}|${stage || 'probe'}`;
  const previous = readyProbeLastLog.get(key);
  const now = Date.now();
  if (!force && previous && previous.signature === sig && now - previous.at < READY_PROBE_LOG_INTERVAL_MS) return;
  readyProbeLastLog.set(key, { at:now, signature:sig });
  const fields = Object.entries(detail || {}).map(([k,v]) => {
    if (Array.isArray(v)) return `${k}=[${v.join(',')}]`;
    if (v == null) return `${k}=null`;
    return `${k}=${String(v).replace(/\s+/g, ' ').slice(0, 700)}`;
  }).join(' ');
  console.log(`[READY-PROBE] ${stage || 'probe'} candidate=${candidate}${fields ? ` ${fields}` : ''}`);
}

function delay(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
async function withTimeout(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label || 'operation'} timed out after ${ms}ms`)), ms); })
    ]);
  } finally { if (timer) clearTimeout(timer); }
}
function normalizeHotPocketPrivateKey(value) {
  let raw = clean(value || '', 512).toLowerCase().replace(/\s+/g, '');
  if (raw.startsWith('ed')) raw = raw.slice(2);
  return /^[0-9a-f]{128}$/.test(raw) ? `ed${raw}` : null;
}
function hpKey(value) {
  if (typeof value === 'string') return cleanPublicKey(value);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return cleanPublicKey(Buffer.from(value).toString('hex'));
  if (value && Array.isArray(value.data)) return cleanPublicKey(Buffer.from(value.data).toString('hex'));
  return null;
}
function hpEndpoint(host, port) {
  host = clean(host || '', 255).toLowerCase(); port = validPort(port);
  if (!host || !port) return null;
  return `wss://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}`;
}
async function ensureReadyControllerIdentity() {
  if (readyControllerPair && readyControllerPublicKey) return { pair:readyControllerPair, publicKey:readyControllerPublicKey };
  const HotPocket = require('hotpocket-js-client');
  // alpha53.24: keep the READY controller identity on the Evernode instance
  // config mount beside hp.cfg. Migrate the legacy /var/lib key on an in-place
  // upgrade so the already-authorized controller public key does not rotate.
  if (!secretRead(READY_CONTROLLER_SECRET)) {
    const legacy = normalizeHotPocketPrivateKey(secretRead(READY_CONTROLLER_LEGACY_SECRET));
    if (legacy) {
      try { secretWrite(READY_CONTROLLER_SECRET, legacy); } catch {}
    }
  }
  let saved = normalizeHotPocketPrivateKey(secretRead(READY_CONTROLLER_SECRET));
  let pair = null;
  if (saved) {
    try { pair = await HotPocket.generateKeys(saved); } catch { pair = null; }
  }
  if (!pair) {
    pair = await HotPocket.generateKeys();
    const privateHex = `ed${Buffer.from(pair.privateKey).toString('hex')}`;
    secretWrite(READY_CONTROLLER_SECRET, privateHex);
  }
  const publicKey = hpKey(pair.publicKey);
  if (!publicKey) throw new Error('Could not derive AutoCluster READY controller HotPocket public key.');
  readyControllerPair = pair;
  readyControllerPublicKey = publicKey;
  writeJson(READY_CONTROLLER_META, { schema:1, publicKey, createdAt:Date.now() });
  return { pair, publicKey };
}
async function ensureCandidateRelayIdentity() {
  if (candidateRelayPair && candidateRelayPublicKey) return { pair:candidateRelayPair, publicKey:candidateRelayPublicKey };
  const HotPocket = require('hotpocket-js-client');
  let saved = normalizeHotPocketPrivateKey(secretRead(CANDIDATE_RELAY_SECRET));
  let pair = null;
  if (saved) { try { pair = await HotPocket.generateKeys(saved); } catch { pair = null; } }
  if (!pair) {
    pair = await HotPocket.generateKeys();
    secretWrite(CANDIDATE_RELAY_SECRET, `ed${Buffer.from(pair.privateKey).toString('hex')}`);
  }
  const publicKey = hpKey(pair.publicKey);
  if (!publicKey) throw new Error('Could not derive candidate sidecar HotPocket user identity.');
  candidateRelayPair = pair;
  candidateRelayPublicKey = publicKey;
  writeJson(CANDIDATE_RELAY_META, { schema:1, publicKey, purpose:'signed-candidate-local-relay', createdAt:Date.now() });
  return { pair, publicKey };
}
async function ensureReadyStatProbeIdentity(candidatePubkey) {
  const candidate = cleanPublicKey(candidatePubkey);
  if (!candidate) throw new Error('Candidate public key is required for isolated STAT identity.');
  const cached = readyStatProbeIdentities.get(candidate);
  if (cached && cached.pair && cached.publicKey) return cached;

  const HotPocket = require('hotpocket-js-client');
  fs.mkdirSync(READY_STAT_PROBE_SECRET_DIR, { recursive:true });
  fs.mkdirSync(READY_STAT_PROBE_META_DIR, { recursive:true });
  const secretFile = path.join(READY_STAT_PROBE_SECRET_DIR, `${candidate}.key`);
  const metaFile = path.join(READY_STAT_PROBE_META_DIR, `${candidate}.json`);

  let saved = normalizeHotPocketPrivateKey(secretRead(secretFile));
  let pair = null;
  if (saved) {
    try { pair = await HotPocket.generateKeys(saved); } catch { pair = null; }
  }
  if (!pair) {
    pair = await HotPocket.generateKeys();
    const privateHex = `ed${Buffer.from(pair.privateKey).toString('hex')}`;
    secretWrite(secretFile, privateHex);
  }

  const publicKey = hpKey(pair.publicKey);
  if (!publicKey) throw new Error(`Could not derive isolated STAT probe identity for ${candidate}.`);
  const controller = await ensureReadyControllerIdentity();
  if (publicKey === controller.publicKey) {
    secretRemove(secretFile);
    readyStatProbeIdentities.delete(candidate);
    return await ensureReadyStatProbeIdentity(candidate);
  }

  // Persistent pre-UNL STAT identity: unique per candidate. The global socket
  // registry additionally enforces one live socket per HotPocket user public key.
  // Post-join checks never reuse this pair; they allocate one-shot identities.
  for (const [otherCandidate, identity] of readyStatProbeIdentities.entries()) {
    if (otherCandidate !== candidate && identity && identity.publicKey === publicKey) {
      secretRemove(secretFile);
      readyStatProbeIdentities.delete(candidate);
      return await ensureReadyStatProbeIdentity(candidate);
    }
  }

  const out = { pair, publicKey };
  readyStatProbeIdentities.set(candidate, out);
  writeJson(metaFile, { schema:2, candidatePubkey:candidate, publicKey, purpose:'read-only-candidate-stat', createdAt:Date.now() });
  return out;
}
function hpPairPublicKey(pair) {
  return hpKey(pair && pair.publicKey);
}
async function createExclusiveHpClient(endpoints, pair, options, role = 'hotpocket-client') {
  const HotPocket = require('hotpocket-js-client');
  const userPublicKey = hpPairPublicKey(pair);
  if (!userPublicKey) throw new Error(`HOTPOCKET_USER_IDENTITY_INVALID:${role}`);
  const existing = liveHpUserSockets.get(userPublicKey);
  if (existing) {
    throw new Error(`HOTPOCKET_USER_IDENTITY_IN_USE:${userPublicKey}:${existing.role || 'unknown'}->${role}`);
  }
  // Reserve before create/connect so concurrent async paths cannot race and open
  // two sockets with the same HotPocket user identity.
  const reservation = { client:null, role, endpoints:Array.isArray(endpoints)?[...endpoints]:[], createdAt:Date.now() };
  liveHpUserSockets.set(userPublicKey, reservation);
  try {
    const client = await HotPocket.createClient(endpoints, pair, options);
    reservation.client = client;
    client.__autoclusterUserPublicKey = userPublicKey;
    client.__autoclusterSocketRole = role;
    return client;
  } catch (e) {
    if (liveHpUserSockets.get(userPublicKey) === reservation) liveHpUserSockets.delete(userPublicKey);
    throw e;
  }
}
async function createEphemeralHpSocketIdentity(role = 'ephemeral-stat') {
  const HotPocket = require('hotpocket-js-client');
  for (let attempt = 0; attempt < 8; attempt++) {
    const pair = await HotPocket.generateKeys();
    const publicKey = hpPairPublicKey(pair);
    if (publicKey && !liveHpUserSockets.has(publicKey)) return { pair, publicKey, role };
  }
  throw new Error(`Could not allocate unique ephemeral HotPocket user identity for ${role}.`);
}
async function closeHpClient(client) {
  if (!client) return;
  const userPublicKey = client.__autoclusterUserPublicKey || null;
  try {
    if (typeof client.close === 'function') await client.close();
  } catch {} finally {
    if (userPublicKey) {
      const existing = liveHpUserSockets.get(userPublicKey);
      if (existing && existing.client === client) liveHpUserSockets.delete(userPublicKey);
    }
  }
}
async function closeReadyStatClientForCandidate(candidatePubkey, reason = 'role-transition') {
  const candidate = cleanPublicKey(candidatePubkey);
  if (!candidate) return 0;
  let closed = 0;
  for (const [key, client] of [...readyStatClients.entries()]) {
    if (key === candidate || key.startsWith(`${candidate}|`)) {
      readyStatClients.delete(key);
      await closeHpClient(client);
      closed++;
    }
  }
  if (closed) readyProbeLog(candidate, 'SOCKET', { verdict:'CLOSED', reason, count:closed }, `socket-role-close|${reason}|${closed}`, true);
  return closed;
}
async function closeReadyStatClients() {
  const clients = [...readyStatClients.values()];
  readyStatClients.clear();
  await Promise.all(clients.map(closeHpClient));
  if (readyControllerTransportClient) await closeHpClient(readyControllerTransportClient);
  readyControllerTransportClient = null;
  readyControllerTransportEndpoint = null;
  readyControllerTransportBootstrap = null;
  readyControllerTransportBusy = false;
  readyControllerTransportLabel = null;
  readySubmitInFlight = null;
}
async function ensureBootstrapControllerTransportClient(pair, bootstrapPubkey, userPort, label = 'controller-input') {
  const endpoint = hpEndpoint('127.0.0.1', userPort);
  if (!endpoint || !bootstrapPubkey) throw new Error('Bootstrap A local HotPocket controller endpoint is unavailable.');
  const sameTarget = readyControllerTransportEndpoint === endpoint && readyControllerTransportBootstrap === bootstrapPubkey;
  if (sameTarget && readyControllerTransportClient && typeof readyControllerTransportClient.isConnected === 'function' && readyControllerTransportClient.isConnected()) {
    return readyControllerTransportClient;
  }
  if (readyControllerTransportClient) await closeHpClient(readyControllerTransportClient);
  readyControllerTransportClient = null;
  readyControllerTransportEndpoint = null;
  readyControllerTransportBootstrap = null;
  const HotPocket = require('hotpocket-js-client');
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    let client = null;
    try {
      client = await createExclusiveHpClient([endpoint], pair, { trustedServerKeys:[bootstrapPubkey] }, `bootstrap-controller:${label}`);
      const connected = await withTimeout(client.connect(), 8000, `Bootstrap A ${label} controller connect attempt ${attempt}/3`);
      if (!connected) throw new Error(`Could not connect ${label} client to Bootstrap A user.port.`);
      readyControllerTransportClient = client;
      readyControllerTransportEndpoint = endpoint;
      readyControllerTransportBootstrap = bootstrapPubkey;
      return client;
    } catch (e) {
      lastError = e;
      if (client) await closeHpClient(client);
      if (attempt < 3) await delay(300 * attempt);
    }
  }
  throw lastError || new Error(`Could not connect ${label} client to Bootstrap A user.port.`);
}
async function ensureTrustedHpClient(cacheKey, endpoint, trustedServerKey, pair) {
  const HotPocket = require('hotpocket-js-client');
  let client = readyStatClients.get(cacheKey) || null;
  if (client && typeof client.isConnected === 'function' && client.isConnected()) return client;
  if (client) { await closeHpClient(client); readyStatClients.delete(cacheKey); }
  client = await createExclusiveHpClient([endpoint], pair, { trustedServerKeys:[trustedServerKey] }, `persistent-stat:${cacheKey}`);
  try {
    const connected = await withTimeout(client.connect(), 5000, `HotPocket stat connect ${cacheKey}`);
    if (!connected) throw new Error(`Could not connect to ${cacheKey}.`);
    readyStatClients.set(cacheKey, client);
    return client;
  } catch (e) {
    await closeHpClient(client);
    readyStatClients.delete(cacheKey);
    throw e;
  }
}
async function dispatchBootstrapControllerInput(pair, bootstrapPubkey, userPort, payload, maxLedgerCount = 4, label = 'controller-input') {
  // READY/final-proof writes use one persistent Bootstrap-A controller websocket.
  // submitContractInput() writes synchronously into that websocket, but closing the
  // socket immediately afterwards can convert a successfully queued write into a
  // connection_error before HotPocket has consumed it. Keep the socket alive and
  // serialize only the actual write; submissionStatus is observed separately.
  if (readyControllerTransportBusy) {
    throw new Error(`HOTPOCKET_CONTROLLER_IDENTITY_BUSY:${readyControllerTransportLabel || 'unknown'}`);
  }
  readyControllerTransportBusy = true;
  readyControllerTransportLabel = label;
  try {
    const client = await ensureBootstrapControllerTransportClient(pair, bootstrapPubkey, userPort, label);
    const submitted = await client.submitContractInput(payload, undefined, maxLedgerCount, true);
    if (!submitted || !submitted.submissionStatus) throw new Error(`${label} returned no HotPocket submission status promise.`);
    return { status:'dispatched', submissionStatus:submitted.submissionStatus };
  } catch (e) {
    // A real write/connect failure invalidates the persistent transport. The next
    // proof gets a clean reconnect. Do not tear it down merely because a later
    // submissionStatus is slow or negative.
    if (readyControllerTransportClient) await closeHpClient(readyControllerTransportClient);
    readyControllerTransportClient = null;
    readyControllerTransportEndpoint = null;
    readyControllerTransportBootstrap = null;
    throw e;
  } finally {
    readyControllerTransportBusy = false;
    readyControllerTransportLabel = null;
  }
}

async function submitBootstrapControllerInput(pair, bootstrapPubkey, userPort, payload, maxLedgerCount = 4, statusTimeoutMs = 30000, label = 'controller-input') {
  // Strict/authoritative controller operations still wait for HotPocket's status,
  // but they share the same persistent identity/socket as READY. This avoids two
  // simultaneous connections with the controller identity while also avoiding the
  // close-immediately race that dropped READY writes in alpha.53.66.
  if (readyControllerTransportBusy) {
    throw new Error(`HOTPOCKET_CONTROLLER_IDENTITY_BUSY:${readyControllerTransportLabel || 'unknown'}`);
  }
  readyControllerTransportBusy = true;
  readyControllerTransportLabel = label;
  try {
    const client = await ensureBootstrapControllerTransportClient(pair, bootstrapPubkey, userPort, label);
    const submitted = await client.submitContractInput(payload, undefined, maxLedgerCount, true);
    if (!submitted || !submitted.submissionStatus) throw new Error(`${label} returned no HotPocket submission status promise.`);
    return await withTimeout(submitted.submissionStatus, statusTimeoutMs, `${label} HotPocket submission status`);
  } catch (e) {
    // If the socket itself died, isConnected() will force a reconnect next time.
    // A pure status timeout does not justify closing a transport that may still be
    // carrying other accepted inputs.
    if (readyControllerTransportClient && typeof readyControllerTransportClient.isConnected === 'function' && !readyControllerTransportClient.isConnected()) {
      await closeHpClient(readyControllerTransportClient);
      readyControllerTransportClient = null;
      readyControllerTransportEndpoint = null;
      readyControllerTransportBootstrap = null;
    }
    throw e;
  } finally {
    readyControllerTransportBusy = false;
    readyControllerTransportLabel = null;
  }
}

async function submitLocalCandidateAttestation(pair, localNodeKey, userPort, payload, maxLedgerCount = 4, statusTimeoutMs = 30000) {
  if (candidateRelayTransportBusy) throw new Error('CANDIDATE_RELAY_BUSY');
  const endpoint = hpEndpoint('127.0.0.1', userPort);
  if (!endpoint || !localNodeKey) throw new Error('Candidate local HotPocket user endpoint is unavailable.');
  const HotPocket = require('hotpocket-js-client');
  candidateRelayTransportBusy = true;
  let client = null;
  try {
    client = await createExclusiveHpClient([endpoint], pair, { trustedServerKeys:[localNodeKey] }, 'candidate-local-relay');
    const connected = await withTimeout(client.connect(), 8000, 'Candidate signed-relay localhost connect');
    if (!connected) throw new Error('Could not connect candidate signed-relay client to local HotPocket user.port.');
    const submitted = await client.submitContractInput(payload, undefined, maxLedgerCount, true);
    if (!submitted || !submitted.submissionStatus) throw new Error('Candidate signed relay returned no HotPocket submission status promise.');
    return await withTimeout(submitted.submissionStatus, statusTimeoutMs, 'Candidate signed-relay submission status');
  } finally {
    if (client) await closeHpClient(client);
    candidateRelayTransportBusy = false;
  }
}

async function relayLocalCandidateAttestation(auto, cfg, localNodeKey) {
  if (!SIGNED_CANDIDATE_RELAY_MODE || !auto || auto.phase !== 'growing' || !localNodeKey) return false;
  const bootstrapPubkey = cleanPublicKey(auto.bootstrapPubkey);
  if (!bootstrapPubkey || localNodeKey === bootstrapPubkey) return false;
  const file = candidateAttestationFile();
  const report = file ? readJson(file, null) : null;
  if (!report || report.type !== 'autocluster_candidate_attestation_v1') return false;
  const claimed = cleanPublicKey(report.pubkey);
  const lcl = Number(report.lcl) || 0;
  const hash = clean(report.lclHash || '', 256).toLowerCase();
  const signature = clean(report.signature || '', 1024);
  if (claimed !== localNodeKey || !lcl || !/^[0-9a-f]{64}$/.test(hash) || !signature) {
    readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'WAIT', reason:'invalid-or-mismatched-local-attestation', claimed:claimed || null, lcl:lcl || null }, `signed-relay-invalid|${claimed || ''}|${lcl}|${hash}`);
    return false;
  }
  // Managed-node public-consensus relay carries maturity plus the durable public
  // signer identity. During legacy-bridge repair this also lets already-UNL
  // managed validators publish signerAddress after phase returns to growing.
  // READY canonicality is validated by Bootstrap A's root-side controller against
  // Bootstrap A's node-local recent-ledger witness, then submitted through A's own
  // user.port. This keeps node-local witness reads completely outside replicated
  // contract execution and also removes recurring candidate-local READY inputs.
  const local = localClusterStatus();
  const localNode = Array.isArray(local && local.nodes) ? local.nodes.find(n => cleanPublicKey(n && n.pubkey) === localNodeKey) || null : null;
  const sharedMature = !!(localNode && (localNode.isUnl || Number(localNode.statusCode) >= 3));
  const maturityNeeded = report.maturityReady === true && !sharedMature;
  const attestedSigner = clean(report.signerAddress || '', 96);
  const sharedSigner = clean(localNode && localNode.signerAddress || '', 96);
  const signerNeeded = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(attestedSigner) && !sharedSigner;
  if (!maturityNeeded && !signerNeeded) {
    readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'QUIET', candidateLcl:lcl, sharedMature, signerReady:!!sharedSigner, reason:'maturity-and-signer-already-shared;ready-is-bootstrap-controller-validated' }, `signed-relay-quiet|${sharedMature}|${!!sharedSigner}`);
    return false;
  }
  const purpose = maturityNeeded && signerNeeded ? 'maturity+signer' : (maturityNeeded ? 'maturity' : 'signer');
  const fingerprint = `${claimed}|${lcl}|${hash}|${signature}`;
  if (candidateRelayLastAcceptedFingerprint === fingerprint || candidateRelayTransportBusy) return false;
  const now = Date.now();
  // Give an accepted milestone time to appear in synchronized shared state before
  // retrying the same semantic purpose with a newer LCL/signature. This avoids
  // duplicate consensus inputs during the observer's normal catch-up window.
  if (candidateRelayLastPurpose === purpose && candidateRelayLastAcceptedAt && now - candidateRelayLastAcceptedAt < 20000) return false;
  if (candidateRelayLastAttemptAt && now - candidateRelayLastAttemptAt < 2500) return false;
  candidateRelayLastAttemptAt = now;
  const userPort = validPort(cfg && cfg.user && cfg.user.port);
  if (!userPort) {
    readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'WAIT', reason:'candidate-local-user-port-unavailable', lcl }, `signed-relay-no-port|${lcl}`);
    return false;
  }
  const identity = await ensureCandidateRelayIdentity();
  readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'DISPATCHED', candidateLcl:lcl, purpose, signerAddress:attestedSigner || null, transport:'signed-node-attestation->localhost-user-input', outerUser:identity.publicKey.slice(0,18), reason:'managed-maturity-and-public-signer-relay;canonical-ready-is-bootstrap-controller-validated' }, `signed-relay-dispatched|${purpose}|${fingerprint}`, true);
  try {
    const st = await submitLocalCandidateAttestation(identity.pair, localNodeKey, userPort, JSON.stringify(report), 4, READY_SUBMISSION_PENDING_MS);
    if (st && st.status === 'accepted') {
      candidateRelayLastAcceptedFingerprint = fingerprint;
      candidateRelayLastPurpose = purpose;
      candidateRelayLastAcceptedAt = Date.now();
      readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'INPUT-ACCEPTED', candidateLcl:lcl, purpose, inputLedger:Number(st.ledgerSeqNo)||'unknown', transport:'localhost-user-input->public-consensus' }, `signed-relay-accepted|${purpose}|${fingerprint}`, true);
      return true;
    }
    readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'REJECTED', candidateLcl:lcl, status:st&&st.status||'unknown', reason:st&&st.reason||'input-not-accepted' }, `signed-relay-rejected|${fingerprint}`, true);
  } catch (e) {
    readyProbeLog(localNodeKey, 'SIGNED-RELAY', { verdict:'ERROR', candidateLcl:lcl, reason:e&&e.message?e.message:String(e) }, `signed-relay-error|${fingerprint}`, true);
  }
  return false;
}

function statCurrentUnl(stat) {
  return [...new Set((Array.isArray(stat && stat.currentUnl) ? stat.currentUnl : []).map(hpKey).filter(Boolean))].sort();
}

async function statManagedValidator(node, purpose = 'post-join-stat') {
  const pubkey = cleanPublicKey(node && node.pubkey);
  const endpoint = hpEndpoint(node && node.domain, node && node.userPort);
  if (!pubkey || !endpoint) return { ok:false, pubkey:pubkey || null, endpoint:endpoint || null, reason:'missing-managed-validator-endpoint' };
  let client = null;
  let socketIdentity = null;
  try {
    // Once a node is being inspected as a managed validator, its pre-UNL
    // persistent STAT socket must be gone. Post-join checks get a fresh user
    // identity for this one socket, then close it after the status read.
    await closeReadyStatClientForCandidate(pubkey, `${purpose}-post-join-boundary`);
    socketIdentity = await createEphemeralHpSocketIdentity(`${purpose}:${pubkey.slice(0,12)}`);
    client = await createExclusiveHpClient([endpoint], socketIdentity.pair, { trustedServerKeys:[pubkey] }, `${purpose}:${pubkey.slice(0,12)}`);
    const connected = await withTimeout(client.connect(), 5000, `Handover mesh connect ${pubkey}`);
    if (!connected) throw new Error('connect returned false');
    const stat = await withTimeout(client.getStatus(), 4000, `Handover mesh stat ${pubkey}`);
    if (!stat) throw new Error('empty stat response');
    return { ok:true, pubkey, endpoint, stat, socketUserPublicKey:socketIdentity && socketIdentity.publicKey || null };
  } catch (e) {
    return { ok:false, pubkey, endpoint, reason:e && e.message ? e.message : String(e) };
  } finally {
    await closeHpClient(client);
  }
}

function statLedgerHashHex(stat) {
  const raw = stat && stat.ledgerHash;
  if (Buffer.isBuffer(raw) || raw instanceof Uint8Array) return Buffer.from(raw).toString('hex').toLowerCase();
  return clean(raw || '', 256).toLowerCase();
}
async function probeCurrentUnlConvergence(local, committedUnl, bootstrapPubkey, newestPubkey = null) {
  const expected = [...new Set((committedUnl || []).map(cleanPublicKey).filter(Boolean))].sort();
  const result = { ok:false, expectedUnl:expected, rows:[], newestPubkey:cleanPublicKey(newestPubkey), clearNewestOutlier:false, commonLcl:null, commonHash:null, healthyPubkeys:[] };
  if (expected.length <= 1) { result.ok=true; return result; }
  if (!bootstrapPubkey) { result.reason='bootstrap-canonical-head-unavailable'; return result; }

  const nodes = (Array.isArray(local && local.nodes) ? local.nodes : [])
    .filter(n => n && n.isUnl && !n.isBootstrap && expected.includes(cleanPublicKey(n.pubkey)))
    .sort((a,b)=>String(a.pubkey||'').localeCompare(String(b.pubkey||'')));
  const remote = await Promise.all(nodes.map(async n => {
    const pubkey=cleanPublicKey(n.pubkey);
    try {
      const r=await statManagedValidator(n, 'unl-convergence');
      if(!r.ok) return {ok:false,pubkey,reason:r.reason||'stat-failed'};
      const stat=r.stat||{}, lcl=Number(stat.ledgerSeqNo)||0, hash=statLedgerHashHex(stat), currentUnl=statCurrentUnl(stat);
      const reasons=[];
      if(!lcl||!/^[0-9a-f]{64}$/.test(hash)) reasons.push('missing-ledger');
      if(JSON.stringify(currentUnl)!==JSON.stringify(expected)) reasons.push('unl-mismatch');
      if(stat.contractExecutionEnabled===false) reasons.push('execution-disabled');
      if(stat.weaklyConnected) reasons.push('weakly-connected');
      return {ok:reasons.length===0,pubkey,lcl,hash,currentUnl,contractExecutionEnabled:stat.contractExecutionEnabled!==false,weaklyConnected:!!stat.weaklyConnected,reason:reasons.join(';')||null};
    } catch(e) { return {ok:false,pubkey,reason:e&&e.message?e.message:String(e)}; }
  }));

  // Read Bootstrap A's history AFTER the parallel remote status calls. A can close
  // another ledger while those sockets are sampled; evaluating against the latest
  // local history avoids falsely calling a healthy validator "ahead" merely because
  // the bootstrap history snapshot was taken before the remote request completed.
  const history = readyLocalLedgerHistory();
  const head = history.length ? history[history.length - 1] : null;
  if (!head) { result.reason='bootstrap-canonical-head-unavailable'; result.rows=remote; return result; }
  const historyByLcl = new Map(history.map(r => [Number(r.lcl)||0, clean(r.hash||'',256).toLowerCase()]));
  result.rows = [{
    ok:true, converged:true, canonical:true, pubkey:bootstrapPubkey,
    lcl:Number(head.lcl)||0, hash:clean(head.hash||'',256).toLowerCase(), lag:0,
    currentUnl:[...expected], contractExecutionEnabled:true, weaklyConnected:false,
    source:'bootstrap-local-canonical'
  }, ...remote];

  const byKey=new Map(result.rows.map(r=>[r.pubkey,r]));
  const complete=expected.every(k=>byKey.has(k));
  if(!complete){result.reason='missing-unl-endpoint';return result;}
  const allRows=expected.map(k=>byKey.get(k));

  // Post-join stabilization is a SAME-CHAIN test, not a simultaneous-head test.
  // getStatus() calls happen at different wall-clock instants, so healthy validators
  // naturally report adjacent LCLs. A row is converged when its reported tuple is in
  // Bootstrap A's recent canonical history and it is only a few ledgers behind the
  // latest Bootstrap head. UNL/execution/weak-connectivity checks above remain strict.
  for (const row of allRows) {
    if (!row || row.pubkey === bootstrapPubkey) continue;
    const reasons = row.reason ? row.reason.split(';').filter(Boolean) : [];
    const expectedHash = historyByLcl.get(Number(row.lcl)||0) || null;
    row.canonical = !!(expectedHash && expectedHash === row.hash);
    row.lag = (Number(head.lcl)||0) - (Number(row.lcl)||0);
    if (!row.canonical) reasons.push(expectedHash ? 'canonical-hash-mismatch' : 'canonical-lcl-missing');
    if (row.lag < 0) reasons.push('ahead-of-bootstrap-history');
    if (row.lag > UNL_CONVERGENCE_MAX_LAG_LCLS) reasons.push(`canonical-lag-${row.lag}-gt-${UNL_CONVERGENCE_MAX_LAG_LCLS}`);
    row.reason = [...new Set(reasons)].join(';') || null;
    row.converged = !!(row.ok && row.canonical && row.lag >= 0 && row.lag <= UNL_CONVERGENCE_MAX_LAG_LCLS);
  }

  result.ok=allRows.every(r=>r&&r.converged);
  if(result.ok){
    const anchorLcl=Math.min(...allRows.map(r=>Number(r.lcl)||Number(head.lcl)||0));
    result.commonLcl=anchorLcl;
    result.commonHash=historyByLcl.get(anchorLcl)||clean(head.hash||'',256).toLowerCase();
    result.healthyPubkeys=[...expected];
    result.reason=`all-current-unl-on-bootstrap-canonical-history-within-${UNL_CONVERGENCE_MAX_LAG_LCLS}-ledgers`;
    return result;
  }

  // Automatic-removal safety uses the same canonical-history model as ordinary
  // post-join convergence, but still requires EVERY older validator to be healthy.
  // getStatus() samples are not simultaneous, so A=N and M1=N-1 is a healthy
  // signing quorum when both tuples are present in Bootstrap A's canonical history.
  // The newest member is removable only when it alone fails canonical convergence.
  const newest=result.newestPubkey;
  if(newest&&expected.includes(newest)){
    const older=allRows.filter(r=>r.pubkey!==newest);
    const nr=byKey.get(newest);
    if(older.length===expected.length-1&&older.every(r=>r&&r.converged)&&!(nr&&nr.converged)){
      const canonicalHeadLcl=Number(head.lcl)||0;
      const canonicalHeadHash=clean(head.hash||'',256).toLowerCase();
      const minHistoryLcl=Math.max(1,canonicalHeadLcl-UNL_CONVERGENCE_MAX_LAG_LCLS);
      result.clearNewestOutlier=true;
      result.commonLcl=canonicalHeadLcl;
      result.commonHash=canonicalHeadHash;
      result.canonicalHeadLcl=canonicalHeadLcl;
      result.canonicalHeadHash=canonicalHeadHash;
      result.healthyPubkeys=older.map(r=>r.pubkey).sort();
      result.healthyRows=older.map(r=>({
        pubkey:r.pubkey,lcl:Number(r.lcl)||0,hash:r.hash,lag:Number(r.lag),canonical:r.canonical===true,converged:r.converged===true
      })).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
      result.canonicalHistory=history
        .filter(r=>(Number(r.lcl)||0)>=minHistoryLcl&&(Number(r.lcl)||0)<=canonicalHeadLcl)
        .map(r=>({lcl:Number(r.lcl)||0,hash:clean(r.hash||'',256).toLowerCase()}));
      result.reason='newest-validator-is-sole-outlier-older-quorum-on-canonical-history';
    }
  }
  if (!result.reason) result.reason='current-unl-not-canonically-converged';
  return result;
}

async function verifyManagedPeerMesh(local, opts = {}) {
  const auto = local && local.auto;
  const cfg = readHpCfg() || {};
  const expectedUnl = [...new Set(hpUnl(cfg).map(cleanPublicKey).filter(Boolean))].sort();
  const target = Math.max(1, Number(auto && auto.targetManagedNodes) || 1);
  const allNodes = Array.isArray(local && local.nodes) ? local.nodes : [];
  const frozen = Array.isArray(auto && auto.handoverSignerPubkeys)
    ? [...new Set(auto.handoverSignerPubkeys.map(cleanPublicKey).filter(Boolean))].sort() : [];
  const frozenSet = new Set(frozen);
  const bootstrapPubkey = cleanPublicKey(auto && auto.bootstrapPubkey);
  const bridgeActive = !!(bootstrapPubkey && expectedUnl.includes(bootstrapPubkey) && expectedUnl.length > 1 && !['handover','autonomous'].includes(auto && auto.phase));
  const usingFrozenFinalSet = frozenSet.size === target;
  // During signer handover the frozen final signer set contains all target managed
  // validators and they are already committed in UNL beside Bootstrap A. Before
  // freezing, ordinary mesh diagnostics cover only the currently admitted managed set.
  const managed = allNodes
    .filter(n => n && !n.isBootstrap && cleanPublicKey(n.pubkey) && (usingFrozenFinalSet ? frozenSet.has(cleanPublicKey(n.pubkey)) : n.isUnl))
    .sort((a,b)=>String(a.pubkey||'').localeCompare(String(b.pubkey||'')));
  // Existing validators only need enough peer links to participate in the
  // HotPocket 60% consensus quorum. The validator itself contributes one vote,
  // so the peer requirement is ceil(0.60 * UNL) - 1 (bounded by UNL-1).
  // This is deliberately less strict than pre-admission candidate proofing.
  const consensusVotesRequired = Math.max(1, Math.ceil(expectedUnl.length * 0.60));
  const requiredPeers = Math.min(Math.max(0, expectedUnl.length - 1), Math.max(0, consensusVotesRequired - 1));
  const expectedUnlCount = bridgeActive && usingFrozenFinalSet ? target + 1 : (bridgeActive ? expectedUnl.length : target);
  const requiredManaged = usingFrozenFinalSet ? target : (bridgeActive ? Math.max(0, expectedUnl.length - 1) : target);
  const result = { ok:false, expectedUnl, target, bridgeActive, managedCount:managed.length, requiredManaged, requiredPeers, nodes:[] };
  if (!auto || !auto.bootstrapPubkey) { result.reason='autocluster-state-unavailable'; return result; }
  if (expectedUnl.length !== expectedUnlCount) { result.reason=`committed-unl-size-${expectedUnl.length}-expected-${expectedUnlCount}`; return result; }
  if (managed.length !== requiredManaged) { result.reason=`frozen-managed-size-${managed.length}-expected-${requiredManaged}`; return result; }
  const rows = await Promise.all(managed.map(async n => {
    return await statManagedValidator(n, 'full-unl-mesh');
  }));
  for (const row of rows) {
    if (!row.ok) { result.nodes.push(row); continue; }
    const stat = row.stat || {};
    const currentUnl = statCurrentUnl(stat);
    const voteStatus = clean(stat.voteStatus || '', 32).toLowerCase();
    const weak = !!stat.weaklyConnected;
    const exec = stat.contractExecutionEnabled !== false;
    const peers = Array.isArray(stat.peers) ? stat.peers.length : 0;
    const reasons = [];
    if (JSON.stringify(currentUnl) !== JSON.stringify(expectedUnl)) reasons.push('unl-mismatch');
    if (voteStatus !== 'synced') reasons.push(`vote=${voteStatus || 'missing'}`);
    if (weak) reasons.push('weakly-connected');
    if (!exec) reasons.push('contract-execution-disabled');
    if (peers < requiredPeers) reasons.push(`peer-mesh=${peers}/${requiredPeers}`);
    result.nodes.push({ ok:reasons.length===0, pubkey:row.pubkey, endpoint:row.endpoint, lcl:Number(stat.ledgerSeqNo)||0, voteStatus, weak, exec, peers, currentUnl, reasons });
  }
  result.ok = result.nodes.length === managed.length && result.nodes.every(x => x.ok);
  result.reason = result.ok ? 'quorum-managed-peer-mesh-ready' : 'managed-peer-mesh-not-ready';
  if (opts.log !== false) {
    for (const row of result.nodes) {
      readyProbeLog(row.pubkey || 'mesh', 'MESH', {
        verdict:row.ok ? 'READY' : 'WAIT', endpoint:row.endpoint || 'missing', lcl:row.lcl || 'unknown', vote:row.voteStatus || 'missing', weak:row.weak,
        peers:row.peers == null ? 'unknown' : `${row.peers}/${requiredPeers}`, unl:row.currentUnl || [], reason:row.ok ? 'quorum-peer-mesh-ready' : (row.reasons && row.reasons.length ? row.reasons.join(';') : row.reason || 'probe-failed')
      }, row.ok ? `ready|${row.lcl||0}|${row.peers||0}` : `wait|${(row.reasons||[]).join('|')}|${row.reason||''}|${row.peers||0}`);
    }
  }
  return result;
}
function liveReadyProbeSnapshot() {
  const now = Date.now();
  const rows = [];
  for (const [pubkey, rec] of readyLiveProbes.entries()) {
    if (!rec || now - Number(rec.observedAt || 0) > READY_LIVE_PROBE_MAX_AGE_MS * 4) continue;
    rows.push({
      pubkey,
      endpoint:rec.endpoint || null,
      observedAt:Number(rec.observedAt) || null,
      fresh:now - Number(rec.observedAt || 0) <= READY_LIVE_PROBE_MAX_AGE_MS,
      candidateLcl:Number(rec.candidateLcl) || 0,
      candidateHash:rec.candidateHash || null,
      candidateLag:rec.candidateLag == null ? null : Number(rec.candidateLag),
      canonicalMatch:!!rec.canonicalMatch,
      peers:rec.peers == null ? null : Number(rec.peers),
      weaklyConnected:!!rec.weaklyConnected,
      contractExecutionEnabled:rec.contractExecutionEnabled !== false,
      currentUnl:Array.isArray(rec.currentUnl) ? rec.currentUnl : [],
      voteStatus:rec.voteStatus || null,
      verdict:rec.verdict || 'unknown',
      reason:rec.reason || null
    });
  }
  return rows.sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
}


async function bridgeNplCandidateObservations(local, auto, cfg, bootstrapPubkey, identity, userPort, committedUnl) {
  const cache = readyNplNodeStatusCache();
  const history = readyLocalLedgerHistory();
  const head = history.length ? history[history.length - 1] : null;
  const bootstrapLcl = Number(head && head.lcl) || 0;
  const bootstrapHash = clean(head && head.hash || '',256).toLowerCase();
  const candidates = (Array.isArray(local && local.nodes) ? local.nodes : [])
    .filter(n => n && !n.isUnl && cleanPublicKey(n.pubkey) && cleanPublicKey(n.pubkey) !== bootstrapPubkey)
    .sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));

  const live = new Set(candidates.map(n => cleanPublicKey(n.pubkey)).filter(Boolean));
  for (const key of [...nplMaturitySubmitted.keys()]) if (!live.has(key.split('|')[0])) nplMaturitySubmitted.delete(key);

  // First commit authenticated NPL maturity observations. One input per poll keeps
  // the Bootstrap-A controller identity serialized without ever opening a socket
  // to the candidate itself.
  for (const node of candidates) {
    const pubkey = cleanPublicKey(node.pubkey);
    const mat = pubkey && cache.maturities[pubkey];
    if (!pubkey || !mat) continue;
    const fingerprint = `${pubkey}|${Number(mat.receivedAtLocalMs)||0}|${Number(mat.lcl)||0}|${clean(mat.lclHash||'',256)}`;
    if (nplMaturitySubmitted.get(pubkey) === fingerprint) continue;
    if (readyControllerTransportBusy) return true;
    const payload = JSON.stringify({
      type:'autocluster_npl_maturity_observation',
      candidatePubkey:pubkey,
      candidateLcl:Number(mat.lcl)||null,
      candidateHash:clean(mat.lclHash||'',256).toLowerCase()||null
    });
    readyProbeLog(pubkey, 'NPL-MATURED', {
      verdict:'DISPATCHED',
      candidateLcl:Number(mat.lcl)||'unknown',
      transport:'npl->bootstrap-local-consensus-input',
      reason:'authenticated-npl-sender-observation'
    }, `npl-matured|${fingerprint}`, true);
    try {
      const st = await submitBootstrapControllerInput(identity.pair, bootstrapPubkey, userPort, payload, 4, READY_SUBMISSION_PENDING_MS, `NPL-MATURED:${pubkey.slice(0,12)}`);
      if (st && st.status === 'accepted') {
        nplMaturitySubmitted.set(pubkey, fingerprint);
        readyProbeLog(pubkey, 'NPL-MATURED', { verdict:'INPUT-ACCEPTED', inputLedger:Number(st.ledgerSeqNo)||'unknown' }, `npl-matured-accepted|${fingerprint}`, true);
      } else {
        readyProbeLog(pubkey, 'NPL-MATURED', { verdict:'REJECTED', status:st&&st.status||'unknown', reason:st&&st.reason||'input-not-accepted' }, `npl-matured-rejected|${fingerprint}`, true);
      }
    } catch (e) {
      readyProbeLog(pubkey, 'NPL-MATURED', { verdict:'ERROR', reason:e&&e.message?e.message:String(e) }, `npl-matured-error|${fingerprint}`, true);
    }
    return true;
  }

  // Then translate the newest authenticated NPL status from each candidate into
  // the same deterministic READY observation the contract already understands.
  for (const node of candidates) {
    const pubkey = cleanPublicKey(node.pubkey);
    const obs = pubkey && cache.observations[pubkey];
    if (!pubkey || !obs) {
      readyLiveProbes.set(pubkey, { observedAt:Date.now(), verdict:'wait', reason:'no-authenticated-npl-status-yet', currentUnl:[] });
      continue;
    }
    const candidateLcl = Number(obs.lcl) || 0;
    const candidateHash = clean(obs.lclHash || '',256).toLowerCase();
    const candidateUnl = [...new Set((Array.isArray(obs.currentUnl)?obs.currentUnl:[]).map(cleanPublicKey).filter(Boolean))].sort();
    const canonical = candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash) ? readyLocalLedgerStatus(candidateLcl, candidateHash) : { match:false, reason:'invalid-candidate-ledger' };
    const candidateLag = bootstrapLcl && candidateLcl ? bootstrapLcl - candidateLcl : Number.POSITIVE_INFINITY;
    const unlMatches = JSON.stringify(candidateUnl) === JSON.stringify(committedUnl);
    const receivedAgeMs = Math.max(0, Date.now() - Number(obs.receivedAtLocalMs || 0));
    const nplFresh = receivedAgeMs <= READY_LIVE_PROBE_MAX_AGE_MS * 2;
    const ready = !!(canonical.match && Number.isFinite(candidateLag) && candidateLag >= 0 && candidateLag <= NPL_PREUNL_REPORT_MAX_LAG_LCLS && unlMatches && nplFresh);
    readyLiveProbes.set(pubkey, {
      endpoint:'npl',
      observedAt:Number(obs.receivedAtLocalMs)||Date.now(),
      candidateLcl,
      candidateHash,
      candidateLag:Number.isFinite(candidateLag)?candidateLag:null,
      canonicalMatch:!!canonical.match,
      peers:committedUnl.length,
      weaklyConnected:false,
      contractExecutionEnabled:true,
      currentUnl:candidateUnl,
      voteStatus:'npl',
      verdict:ready?'ready':'wait',
      reason:ready?'authenticated-npl-status-canonical':'npl-status-not-yet-qualified'
    });
    readyProbeLog(pubkey, 'NPL-STATUS', {
      verdict:ready?'READY':'WAIT',
      candidateLcl:candidateLcl||'missing',
      bootstrapLcl:bootstrapLcl||'missing',
      lag:Number.isFinite(candidateLag)?candidateLag:'unknown',
      hash:candidateHash?candidateHash.slice(0,16):'missing',
      canonical:!!canonical.match,
      currentUnl:candidateUnl,
      expectedUnl:committedUnl,
      ageMs:receivedAgeMs,
      reason:ready?`authenticated-npl-status-canonical-lag<=${NPL_PREUNL_REPORT_MAX_LAG_LCLS}`:(canonical.reason||(!unlMatches?'unl-mismatch':(!nplFresh?'npl-status-stale':`lag>${NPL_PREUNL_REPORT_MAX_LAG_LCLS}`)))
    }, `npl-status|${candidateLcl}|${candidateHash}|${candidateLag}|${unlMatches}|${nplFresh}`);

    if (!ready || readyControllerTransportBusy) continue;

    const fingerprint = `npl|${pubkey}|${candidateLcl}|${candidateHash}|${committedUnl.join(',')}`;
    const existing = readyStatPending.get(pubkey);
    const existingAge = existing ? Math.max(0, Date.now() - Number(existing.submittedAt || 0)) : Number.POSITIVE_INFINITY;
    if (existing && existing.fingerprint === fingerprint && existingAge < READY_SUBMISSION_PENDING_MS) continue;

    const payload = JSON.stringify({
      type:'autocluster_ready_observation',
      candidatePubkey:pubkey,
      candidateLcl,
      candidateHash,
      candidateLag,
      voteStatus:'npl',
      weaklyConnected:false,
      contractExecutionEnabled:true,
      currentUnl:candidateUnl,
      peers:Math.max(1, committedUnl.length),
      transport:'npl'
    });
    const token = ++readySubmissionSeq;
    const submittedAt = Date.now();
    readySubmitInFlight = { candidatePubkey:pubkey, fingerprint, submittedAt, token };
    readyStatPending.set(pubkey, { fingerprint, inputLedger:null, submittedAt, status:'dispatched', token });
    try {
      const st = await submitBootstrapControllerInput(identity.pair, bootstrapPubkey, userPort, payload, 4, READY_SUBMISSION_PENDING_MS, `NPL-READY:${pubkey.slice(0,12)}:${candidateLcl}`);
      const current = readyStatPending.get(pubkey);
      if (st && st.status === 'accepted') {
        if (current && current.token === token) {
          current.status = 'accepted';
          current.inputLedger = Number(st.ledgerSeqNo)||null;
          current.acceptedAt = Date.now();
          readyStatPending.set(pubkey, current);
        }
        readyProbeLog(pubkey, 'NPL-READY', { verdict:'INPUT-ACCEPTED', candidateLcl, inputLedger:Number(st.ledgerSeqNo)||'unknown', transport:'npl->bootstrap-local-consensus-input' }, `npl-ready-accepted|${fingerprint}`, true);
      } else {
        if (current && current.token === token) readyStatPending.delete(pubkey);
        readyProbeLog(pubkey, 'NPL-READY', { verdict:'REJECTED', candidateLcl, status:st&&st.status||'unknown', reason:st&&st.reason||'input-not-accepted' }, `npl-ready-rejected|${fingerprint}`, true);
      }
    } catch (e) {
      const current = readyStatPending.get(pubkey);
      if (current && current.token === token) readyStatPending.delete(pubkey);
      readyProbeLog(pubkey, 'NPL-READY', { verdict:'ERROR', candidateLcl, reason:e&&e.message?e.message:String(e) }, `npl-ready-error|${fingerprint}`, true);
    } finally {
      if (readySubmitInFlight && readySubmitInFlight.token === token) readySubmitInFlight = null;
    }
    return true;
  }
  return false;
}

async function probeReadyCandidates() {
  if (readyStatBusy) return;
  readyStatBusy = true;
  try {
    const local = localClusterStatus();
    const auto = local && local.auto;
    const cfg = readHpCfg() || {};
    const cfgNode = cfg.node && typeof cfg.node === 'object' ? cfg.node : {};
    const localNodeKey = cleanPublicKey(cfgNode.public_key || cfgNode.publicKey || cfg.public_key || cfg.publicKey);
    const bootstrapPubkey = cleanPublicKey(auto && auto.bootstrapPubkey);
    if (!auto || !bootstrapPubkey) {
      if (readyStatClients.size || readyControllerTransportClient) await closeReadyStatClients();
      return;
    }
    if (localNodeKey !== bootstrapPubkey) {
      // Pre-UNL nodes cannot rely on NPL delivery to current UNL. Instead the
      // contract signs its own local LCL/hash/maturity attestation with the
      // HotPocket node key, and this root sidecar submits that signed blob only
      // through localhost user.port. HotPocket's public consensus circulates the
      // input; the contract verifies the inner node signature before recording it.
      // There is no cross-node readiness WebSocket here.
      if (readyStatClients.size || readyControllerTransportClient) await closeReadyStatClients();
      if (SIGNED_CANDIDATE_RELAY_MODE) await relayLocalCandidateAttestation(auto, cfg, localNodeKey);
      return;
    }
    const committedUnl = [...new Set(hpUnl(cfg).map(cleanPublicKey).filter(Boolean))].sort();

    // After the REMOVE_UNL(A) config patch commits, A is no longer a validator.
    // Its root-side process may now perform the one remaining irreversible local
    // treasury action: DisableMaster. This can never run while A is still in UNL.
    if (['handover','autonomous'].includes(auto.phase) && committedUnl.length && !committedUnl.includes(bootstrapPubkey) && secretRead(SEED_SECRET)) {
      if (!postRemovalFinalizeBusy) {
        postRemovalFinalizeBusy = true;
        try {
          const final = await finalizeHandover();
          readyProbeLog('bootstrap', 'POST-REMOVE-HANDOVER', {
            verdict:final && final.pending ? 'PENDING' : 'COMPLETE',
            stage:final && final.stage || 'disable-master',
            masterSeedDeleted:!!(final && final.masterSeedDeleted),
            reason:final && final.message || 'Bootstrap A removed; post-consensus treasury finalization executed'
          }, `post-remove|${final && final.pending ? final.stage || 'pending' : 'complete'}`, true);
        } catch (e) {
          readyProbeLog('bootstrap', 'POST-REMOVE-HANDOVER', { verdict:'ERROR', reason:e && e.message ? e.message : String(e) }, `post-remove-error|${e && e.message ? e.message : String(e)}`, true);
        } finally { postRemovalFinalizeBusy = false; }
      }
      return;
    }

    const singletonBootstrap = committedUnl.length === 1 && committedUnl[0] === bootstrapPubkey;
    // The external cfg mount can lag the contract execution that submitted the
    // bootstrap membership patch. Once consensus state says the promotion batch was
    // submitted, those pubkeys have graduated from candidate READY testing even if
    // server.js still sees the previous singleton hp.cfg for a few seconds.
    const submittedPubkey = auto && auto.promotionBatch && auto.promotionBatch.active && Number(auto.promotionBatch.submittedAtLcl) > 0
      ? cleanPublicKey(auto.promotionBatch.submittedPubkey)
      : null;
    // A promotionBatch is a candidate POOL. Only the one pubkey whose ADD_UNL
    // command was actually submitted has graduated from READY probing. Keeping
    // the rest live prevents C/D/E readiness from aging while B's patch commits.
    const submittedBatch = submittedPubkey ? [submittedPubkey] : [];
    const pendingPromoted = new Set(submittedBatch);
    const pendingFullUnl = submittedBatch.length ? [...new Set([bootstrapPubkey, ...submittedBatch])].sort() : [];
    const bootstrapReadyPhases = ['growing','signing','ready-to-handover'];
    // Bootstrap A remains the external READY/mesh controller until it is actually
    // removed. After the full A+managed bridge is complete there are no required
    // candidates outside UNL; this loop is mesh diagnostics only while signer/
    // DisableMaster handover completes. Candidate-pool surplus is retired by the contract.
    if (!bootstrapReadyPhases.includes(auto.phase) || !committedUnl.includes(bootstrapPubkey)) {
      if (readyStatClients.size || readyControllerTransportClient) await closeReadyStatClients();
      return;
    }
    if (!NPL_READINESS_MODE && !singletonBootstrap && committedUnl.length > 1) {
      const now = Date.now();
      if (!readyMeshLastProbeAt || now - readyMeshLastProbeAt >= READY_MESH_PROBE_INTERVAL_MS) {
        readyMeshLastProbeAt = now;
        await verifyManagedPeerMesh(local, { log:true });
      }
    }
    const authorized = cleanPublicKey(auto.readyControllerPublicKey);
    const identity = await ensureReadyControllerIdentity();
    const controllerAuthorized = !!authorized && authorized === identity.publicKey;
    if (!controllerAuthorized) {
      readyControllerAuthStatus = { ok:false, expected:authorized || null, local:identity.publicKey || null, observedAt:Date.now(), reason:'controller-key-mismatch-or-missing' };
      readyProbeLog('bootstrap', 'CONTROLLER-AUTH', { verdict:'ERROR', expected:authorized || 'missing', local:identity.publicKey, reason:'controller-key-mismatch-or-missing;npl-bridge-observes-status-but-ready-input-submission-is-paused' }, `${authorized || 'missing'}|${identity.publicKey}`);
    } else {
      readyControllerAuthStatus = { ok:true, expected:authorized, local:identity.publicKey, observedAt:Date.now(), reason:'authorized' };
    }
    readyProbeLog('bootstrap', 'IDENTITY-ISOLATION', {
      verdict:'ACTIVE', controller:identity.publicKey.slice(0,18),
      policy:'bootstrap-a-local-consensus-input-only',
      reason:'candidate maturity is node-signed; canonical readiness is validated and submitted only by Bootstrap-A controller'
    }, `isolated-controller|${identity.publicKey}`);
    const userPort = validPort(cfg.user && cfg.user.port);
    if (!userPort) {
      readyProbeLog('bootstrap', 'SUBMIT-ENDPOINT', { verdict:'ERROR', reason:'bootstrap-user-port-unavailable' }, 'no-user-port');
      return;
    }
    if (SIGNED_CANDIDATE_RELAY_MODE && auto.phase === 'growing') {
      // Signed candidate inputs carry deterministic MATURED/ACKNOWLEDGED only.
      // Bootstrap A MUST still poll candidate HotPocket status here: A alone owns
      // the node-local canonical recent-ledger witness, so A validates the exact
      // candidate LCL/hash outside consensus and submits the deterministic READY
      // observation through its own authorized controller identity below.
      readyProbeLog('bootstrap', 'CANONICAL-AUTHORITY', {
        verdict:'ACTIVE',
        reason:'bootstrap-a-sidecar-validates-candidate-lcl-hash;contract-never-reads-node-local-witness-for-ready'
      }, 'bootstrap-controller-canonical-authority');
    }
    if (NPL_READINESS_MODE && auto.phase === 'growing') {
      if (readyStatClients.size) await closeReadyStatClients();
      await bridgeNplCandidateObservations(local, auto, cfg, bootstrapPubkey, identity, userPort, committedUnl);
      return;
    }
    // AutoCluster never writes contract.unl from its autonomous tick. The
    // replicated contract state publishes a membershipCommand intent; Bootstrap
    // A's root-side HotPocket USER submits that intent back into the contract as
    // a normal input. At A+B and beyond this exact input is consensused by every
    // current validator before the contract writes the patch.cfg change.
    const replicatedMembershipCommand = auto && auto.membershipCommand && auto.membershipCommand.active === true
      ? auto.membershipCommand : null;
    const atomicAdmissionPlan = !replicatedMembershipCommand
      ? atomicBootstrapAdmissionPlan(local, auto, committedUnl, bootstrapPubkey)
      : { frozen:true, target:null, candidates:[], reason:'replicated-membership-command' };
    let membershipCommand = replicatedMembershipCommand;
    let directAtomicCommand = false;
    const atomicPendingAge = membershipCommandPending && membershipCommandPending.directAtomic
      ? Math.max(0, Date.now() - Number(membershipCommandPending.submittedAt || 0)) : Number.POSITIVE_INFINITY;
    const atomicPendingActive = !!(!replicatedMembershipCommand && membershipCommandPending && membershipCommandPending.directAtomic && atomicPendingAge < READY_SUBMISSION_PENDING_MS);
    if (atomicPendingActive) {
      atomicMembershipTarget = { operation:'add', pubkey:membershipCommandPending.pubkey || null, selectedAt:Number(membershipCommandPending.submittedAt)||Date.now(), state:membershipCommandPending.status || 'dispatched', directAtomic:true, lcl:membershipCommandPending.inputLedger || null };
    } else if (!membershipCommand && atomicAdmissionPlan.frozen && atomicAdmissionPlan.target) {
      const targetKey = cleanPublicKey(atomicAdmissionPlan.target.pubkey);
      membershipCommand = {
        active:true, operation:'add', pubkey:targetKey, requestedAtLcl:null, submittedAtLcl:null,
        directAtomic:true, reason:'root-local-exact-tip-proof-before-consensus-add'
      };
      directAtomicCommand = true;
      atomicMembershipTarget = { operation:'add', pubkey:targetKey, selectedAt:Date.now(), state:'probing', directAtomic:true };
      readyProbeLog(targetKey, 'UNL-COMMAND', {
        verdict:'ATOMIC-TARGET', operation:'add',
        reason:'hard-freeze-active;sampling-final-proof-before-any-replicated-membership-state-change'
      }, `atomic-target|${targetKey}`, true);
    } else if (membershipCommand) {
      const targetKey = cleanPublicKey(membershipCommand.pubkey || membershipCommand.publicKey);
      atomicMembershipTarget = targetKey ? { operation:clean(membershipCommand.operation||'',32).toLowerCase(), pubkey:targetKey, selectedAt:Date.now(), state:'legacy-intent', directAtomic:false } : null;
    } else if (!atomicAdmissionPlan.frozen) {
      atomicMembershipTarget = null;
    }
    if (membershipCommand && !Number(membershipCommand.submittedAtLcl)) {
      const operation = clean(membershipCommand.operation || '', 32).toLowerCase();
      const pubkey = cleanPublicKey(membershipCommand.pubkey || membershipCommand.publicKey);
      if (!controllerAuthorized) {
        readyProbeLog(membershipCommand.pubkey || 'bootstrap', 'UNL-COMMAND', {
          verdict:'CONTROLLER-AUTH-WAIT', operation,
          expected:authorized || 'missing', local:identity.publicKey || 'missing',
          reason:'membership-input-paused-until-ready-controller-identity-matches-authorized-key'
        }, `membership-controller-auth-wait|${authorized || ''}|${identity.publicKey || ''}`, true);
      } else if (['add','remove-bootstrap','swap-bootstrap','demote-managed'].includes(operation) && pubkey) {
        // FINAL has priority over ordinary READY traffic. If a READY input from the
        // previous scan still owns the one-shot controller identity, do NOT sample
        // FINAL yet and let that proof age in a queue. Wait for that transport to
        // close; this intent suppresses all new READY submissions below. The next
        // scan samples STAT and dispatches ADD_UNL back-to-back.
        if ((operation === 'add' || operation === 'swap-bootstrap') && readyControllerTransportBusy) {
          readyProbeLog(pubkey, 'UNL-COMMAND', {
            verdict:'FINAL-PRIORITY-WAIT', operation,
            activeTransport:readyControllerTransportLabel || 'unknown',
            reason:'membership-intent-has-priority;waiting-for-existing-controller-transport-to-close-before-taking-fresh-final-stat'
          }, `final-priority-wait|${readyControllerTransportLabel || 'unknown'}`, true);
          return;
        }
        // FINAL LOCKSTEP PROOF for ADD_UNL. Do not reuse the readiness record that
        // armed the intent: by the time this input is submitted it can be several
        // ledgers old. Reuse the candidate's dedicated STAT identity/socket, sample
        // it NOW, and require the candidate to be on Bootstrap A's canonical recent-ledger
        // history within the configured lag tolerance with live consensus transport. This proof is carried
        // inside the authenticated membership input and rechecked by the contract.
        let finalProof = null;
        if (operation === 'add' || operation === 'swap-bootstrap') {
          // After every committed addition, do not add another validator until the
          // CURRENT UNL has actually converged. We probe all current validators in
          // parallel and require every reported tuple to belong to Bootstrap A's
          // canonical recent-ledger history within a small lag bound. Status calls
          // are not simultaneous, so adjacent canonical heads are healthy and must
          // not block the next candidate merely because their LCL numbers differ.
          const stab = auto && auto.stabilization && typeof auto.stabilization === 'object' ? auto.stabilization : null;
          const latestAdded = stab && Array.isArray(stab.addedPubkeys) && stab.addedPubkeys.length === 1 ? cleanPublicKey(stab.addedPubkeys[0]) : null;
          if (committedUnl.length > 1 && latestAdded && committedUnl.includes(latestAdded)) {
            const conv = await probeCurrentUnlConvergence(local, committedUnl, bootstrapPubkey, latestAdded);
            const convKey = `${committedUnl.join(',')}|${latestAdded}`;
            if (!conv.ok) {
              let outlierAgeLcls = 0;
              let outlierAgeMs = 0;
              if (conv.clearNewestOutlier && committedUnl.length >= 3) {
                const bootstrapRow = Array.isArray(conv.rows) ? conv.rows.find(r => r && r.pubkey === bootstrapPubkey) : null;
                const observedLcl = Number(bootstrapRow && bootstrapRow.lcl) || Number(conv.commonLcl) || 0;
                let tracker = unlConvergenceOutlierSince.get(convKey);
                if (!tracker || typeof tracker !== 'object' || !Number.isFinite(Number(tracker.sinceLcl))) {
                  tracker = { sinceAt:Date.now(), sinceLcl:observedLcl || 0, lastLcl:observedLcl || 0 };
                }
                if (observedLcl > Number(tracker.lastLcl || 0)) tracker.lastLcl = observedLcl;
                unlConvergenceOutlierSince.set(convKey, tracker);
                outlierAgeMs = Math.max(0, Date.now() - Number(tracker.sinceAt || Date.now()));
                outlierAgeLcls = observedLcl && Number(tracker.sinceLcl) ? Math.max(0, observedLcl - Number(tracker.sinceLcl)) : 0;
              }
              readyProbeLog(latestAdded, 'UNL-CONVERGENCE', {
                verdict:conv.clearNewestOutlier?'OUTLIER':'WAIT', newest:latestAdded,
                commonLcl:conv.commonLcl||'unknown', commonHash:conv.commonHash?conv.commonHash.slice(0,16):'unknown',
                outlierAgeLcls:conv.clearNewestOutlier?outlierAgeLcls:undefined, outlierNeedLcls:conv.clearNewestOutlier?UNL_CONVERGENCE_OUTLIER_REMOVE_LCLS:undefined,
                rows:JSON.stringify(conv.rows.map(r=>({pubkey:r.pubkey,lcl:r.lcl||0,hash:r.hash?r.hash.slice(0,12):null,lag:Number.isFinite(Number(r.lag))?Number(r.lag):null,canonical:!!r.canonical,ok:!!r.ok,converged:!!r.converged,reason:r.reason||null}))),
                reason:conv.reason||'current-unl-not-converged'
              }, `unl-convergence|${conv.reason||''}|${conv.commonLcl||0}|${latestAdded}|${outlierAgeLcls}`, true);
              if (conv.clearNewestOutlier && committedUnl.length >= 3) {
                if (outlierAgeLcls >= UNL_CONVERGENCE_OUTLIER_REMOVE_LCLS && !unlConvergenceRemovalSubmitted.has(convKey) && !readyControllerTransportBusy) {
                  const payload = JSON.stringify({
                    type:'autocluster_unl_command', operation:'remove-managed', pubkey:latestAdded,
                    convergenceProof:{ currentUnl:committedUnl, outlierPubkey:latestAdded, outlierMatchesCanonical:false,
                      healthyPubkeys:conv.healthyPubkeys, healthyRows:conv.healthyRows,
                      canonicalHeadLcl:conv.canonicalHeadLcl, canonicalHeadHash:conv.canonicalHeadHash,
                      canonicalHistory:conv.canonicalHistory }
                  });
                  readyProbeLog(latestAdded,'UNL-CONVERGENCE',{verdict:'AUTO-REMOVE-DISPATCH',ageLcls:outlierAgeLcls,ageMs:outlierAgeMs,reason:`newest-validator-remained-sole-outlier-for-${UNL_CONVERGENCE_OUTLIER_REMOVE_LCLS}-committed-ledgers-while-every-older-validator-remained-on-bootstrap-canonical-history-and-signing-quorum-held`},`auto-remove|${convKey}`,true);
                  try {
                    const st = await submitBootstrapControllerInput(identity.pair, bootstrapPubkey, userPort, payload, 4, READY_SUBMISSION_PENDING_MS, `REMOVE-MANAGED:${latestAdded.slice(0,12)}`);
                    if (st && st.status === 'accepted') unlConvergenceRemovalSubmitted.add(convKey);
                    else readyProbeLog(latestAdded,'UNL-CONVERGENCE',{verdict:'AUTO-REMOVE-REJECTED',status:st&&st.status||'unknown',reason:st&&st.reason||'input-not-accepted'},`auto-remove-reject|${convKey}`,true);
                  } catch(e) {
                    readyProbeLog(latestAdded,'UNL-CONVERGENCE',{verdict:'AUTO-REMOVE-ERROR',reason:e&&e.message?e.message:String(e)},`auto-remove-error|${convKey}`,true);
                  }
                }
              } else {
                unlConvergenceOutlierSince.delete(convKey);
              }
              return;
            }
            unlConvergenceOutlierSince.delete(convKey);
            unlConvergenceRemovalSubmitted.delete(convKey);
            readyProbeLog(latestAdded,'UNL-CONVERGENCE',{verdict:'READY',lcl:conv.commonLcl,hash:conv.commonHash&&conv.commonHash.slice(0,16),validators:committedUnl.length,reason:`all-current-unl-on-bootstrap-canonical-history-within-${UNL_CONVERGENCE_MAX_LAG_LCLS}-ledgers;next-add-may-proceed`},`unl-converged|${conv.commonLcl}|${conv.commonHash}`,true);
          }
          const candidateNode = (Array.isArray(local.nodes) ? local.nodes : []).find(n => n && cleanPublicKey(n.pubkey) === pubkey) || null;
          const candidateEndpoint = candidateNode && hpEndpoint(candidateNode.domain, candidateNode.userPort);
          if (!candidateNode || !candidateEndpoint) {
            readyProbeLog(pubkey, 'UNL-COMMAND', { verdict:'FINAL-PROOF-WAIT', operation, reason:'candidate-endpoint-unavailable' }, 'final-proof-no-endpoint', true);
            return;
          }
          try {
            const probeIdentity = await ensureReadyStatProbeIdentity(pubkey);
            const cacheKey = `${pubkey}|${candidateEndpoint}`; // exactly the same key as normal STAT polling: never open a second same-identity socket.
            const candidateClient = await ensureTrustedHpClient(cacheKey, candidateEndpoint, pubkey, probeIdentity.pair);
            const stat = await withTimeout(candidateClient.getStatus(), 4000, `HotPocket final membership stat ${pubkey}`);
            const candidateLcl = Number(stat && stat.ledgerSeqNo) || 0;
            const candidateHash = Buffer.isBuffer(stat && stat.ledgerHash) || (stat && stat.ledgerHash instanceof Uint8Array)
              ? Buffer.from(stat.ledgerHash).toString('hex').toLowerCase()
              : clean(stat && stat.ledgerHash || '',256).toLowerCase();
            const candidateUnl = statCurrentUnl(stat || {});
            const peerCount = Array.isArray(stat && stat.peers) ? stat.peers.length : 0;
            const weaklyConnected = !!(stat && stat.weaklyConnected);
            const contractExecutionEnabled = !!(stat && stat.contractExecutionEnabled !== false);
            const voteStatus = clean(stat && stat.voteStatus || '', 32).toLowerCase();
            const history = readyLocalLedgerHistory();
            const head = history.length ? history[history.length - 1] : null;
            const bootstrapLcl = Number(head && head.lcl) || 0;
            const bootstrapHash = clean(head && head.hash || '',256).toLowerCase();
            const canonical = candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash) ? readyLocalLedgerStatus(candidateLcl, candidateHash) : { match:false, reason:'invalid-candidate-ledger' };
            const candidateLag = bootstrapLcl && candidateLcl ? bootstrapLcl - candidateLcl : Number.POSITIVE_INFINITY;
            const requiredPeers = requiredAdmissionPeers(committedUnl.length);
            const exactCanonical = !!(canonical.match && candidateLag === 0 &&
              candidateLcl === bootstrapLcl && /^[0-9a-f]{64}$/.test(candidateHash) && candidateHash === bootstrapHash);
            const unlMatches = JSON.stringify(candidateUnl) === JSON.stringify(committedUnl);
            const voteSynced = voteStatus === 'synced';
            const firstAdd = operation === 'add' && committedUnl.length === 1;
            const finalReady = exactCanonical && unlMatches && voteSynced && contractExecutionEnabled && !weaklyConnected && peerCount >= requiredPeers;
            if (!finalReady) {
              if (firstAdd) {
                firstAddSyncStreaks.delete(pubkey);
                if (firstAddSyncTarget === pubkey) firstAddSyncTarget = null;
              }
              if (directAtomicCommand) {
                atomicFinalProbeCooldownUntil.set(pubkey, Date.now() + ATOMIC_FINAL_PROBE_COOLDOWN_MS);
                atomicMembershipTarget = null;
              }
              readyProbeLog(pubkey, 'UNL-COMMAND', {
                verdict:'FINAL-PROOF-WAIT', operation, endpoint:candidateEndpoint,
                candidateLcl:candidateLcl||'missing', bootstrapLcl:bootstrapLcl||'missing',
                lag:Number.isFinite(candidateLag)?candidateLag:'unknown',
                hash:candidateHash?candidateHash.slice(0,16):'missing',
                bootstrapHash:bootstrapHash?bootstrapHash.slice(0,16):'missing',
                canonical:!!canonical.match, vote:voteStatus || 'missing', unl:candidateUnl, expectedUnl:committedUnl,
                exec:contractExecutionEnabled, weak:weaklyConnected, peers:`${peerCount}/${requiredPeers}`,
                reason:firstAdd?'first-add-requires-exact-tip-and-vote-synced-before-sustained-streak':'membership-input-requires-exact-bootstrap-tip-vote-synced-unl-exec-peer-proof'
              }, `final-wait|${candidateLcl}|${bootstrapLcl}|${candidateLag}|${voteStatus}|${peerCount}|${canonical.reason||''}`, true);
              return;
            }
            let firstAddSyncStreak = null;
            if (firstAdd) {
              firstAddSyncTarget = pubkey;
              const prev = firstAddSyncStreaks.get(pubkey) || { observations:[] };
              let observations = Array.isArray(prev.observations) ? prev.observations.slice(-FIRST_ADD_SYNC_STREAK_REQUIRED) : [];
              const last = observations.length ? observations[observations.length - 1] : null;
              if (last && Number(last.lcl) === candidateLcl && clean(last.hash || '',256).toLowerCase() === candidateHash) {
                // Same closed ledger sampled twice: keep the streak but never count it twice.
              } else if (!last || candidateLcl > Number(last.lcl)) {
                observations.push({ lcl:candidateLcl, hash:candidateHash, voteStatus:'synced', peerCount });
              } else {
                // The reported LCL moved backwards or otherwise broke monotonic progress, so
                // the zero-fault-tolerance 1->2 proof must start over from this ledger.
                observations = [{ lcl:candidateLcl, hash:candidateHash, voteStatus:'synced', peerCount }];
              }
              observations = observations.slice(-FIRST_ADD_SYNC_STREAK_REQUIRED);
              firstAddSyncStreaks.set(pubkey, { observations });
              const streakCount = observations.length;
              if (streakCount < FIRST_ADD_SYNC_STREAK_REQUIRED) {
                if (directAtomicCommand) atomicMembershipTarget = { operation:'add', pubkey, selectedAt:Date.now(), state:`sync-streak-${streakCount}`, directAtomic:true, lcl:candidateLcl };
                readyProbeLog(pubkey, 'UNL-COMMAND', {
                  verdict:'FIRST-ADD-SYNC-STREAK', operation, endpoint:candidateEndpoint,
                  lcl:candidateLcl, hash:candidateHash.slice(0,16), vote:voteStatus, peers:`${peerCount}/${requiredPeers}`,
                  streak:`${streakCount}/${FIRST_ADD_SYNC_STREAK_REQUIRED}`,
                  reason:'1-to-2-has-zero-fault-tolerance;requiring-five-advancing-exact-tip-vote-synced-observations-before-dispatch'
                }, `first-add-streak|${pubkey}|${streakCount}|${candidateLcl}|${candidateHash}`, true);
                return;
              }
              firstAddSyncStreak = { required:FIRST_ADD_SYNC_STREAK_REQUIRED, observations };
            }
            finalProof = {
              candidateLcl, candidateHash, bootstrapLcl, bootstrapHash, candidateLag, canonicalMatched:true, voteStatus,
              peerCount, contractExecutionEnabled:true, weaklyConnected:false, currentUnl:candidateUnl,
              ...(firstAddSyncStreak ? { firstAddSyncStreak } : {})
            };
            if (directAtomicCommand) atomicMembershipTarget = { operation:'add', pubkey, selectedAt:Date.now(), state:'final-proof-ready', directAtomic:true, lcl:candidateLcl };
            readyProbeLog(pubkey, 'UNL-COMMAND', {
              verdict:'FINAL-PROOF-READY', operation, endpoint:candidateEndpoint,
              lcl:candidateLcl, hash:candidateHash.slice(0,16), lag:candidateLag, vote:voteStatus, peers:`${peerCount}/${requiredPeers}`,
              streak:firstAdd?`${FIRST_ADD_SYNC_STREAK_REQUIRED}/${FIRST_ADD_SYNC_STREAK_REQUIRED}`:undefined,
              reason:firstAdd?'candidate-sustained-exact-tip-and-vote-synced-for-five-advancing-observations;dispatching-first-add':'candidate-exact-bootstrap-tip-with-vote-synced-valid-unl-exec-peer-proof;dispatching-atomic-membership-input'
            }, `final-ready|${candidateLcl}|${candidateHash}|${voteStatus}|${peerCount}`, true);
          } catch (err) {
            if (operation === 'add' && committedUnl.length === 1) { firstAddSyncStreaks.delete(pubkey); if (firstAddSyncTarget === pubkey) firstAddSyncTarget = null; }
            if (directAtomicCommand) {
              atomicFinalProbeCooldownUntil.set(pubkey, Date.now() + ATOMIC_FINAL_PROBE_COOLDOWN_MS);
              atomicMembershipTarget = null;
            }
            readyProbeLog(pubkey, 'UNL-COMMAND', { verdict:'FINAL-PROOF-WAIT', operation, reason:err && err.message ? err.message : String(err) }, `final-proof-error|${err && err.message ? err.message : String(err)}`, true);
            return;
          }
        }
        const fingerprint = `${directAtomicCommand?'atomic':'intent'}|${operation}|${pubkey}|${Number(membershipCommand.requestedAtLcl)||0}|${finalProof&&finalProof.bootstrapLcl||0}|${finalProof&&finalProof.bootstrapHash||''}`;
        const pendingAge = membershipCommandPending ? Math.max(0, Date.now() - Number(membershipCommandPending.submittedAt || 0)) : Number.POSITIVE_INFINITY;
        const samePending = membershipCommandPending && membershipCommandPending.fingerprint === fingerprint && pendingAge < READY_SUBMISSION_PENDING_MS;
        if (!samePending) {
          if (readyControllerTransportBusy) {
            readyProbeLog(pubkey, 'UNL-COMMAND', {
              verdict:'SERIALIZED-WAIT', operation,
              activeTransport:readyControllerTransportLabel || 'unknown',
              reason:'one-hotpocket-controller-identity-connection-at-a-time'
            }, `membership-transport-wait|${readyControllerTransportLabel || 'unknown'}`);
          } else {
            membershipCommandPending = null;
            try {
              const payload = JSON.stringify({
                type:'autocluster_unl_command',
                operation,
                pubkey,
                requestedAtLcl:Number(membershipCommand.requestedAtLcl) || null,
                ...(directAtomicCommand ? { directAtomic:true } : {}),
                ...((operation === 'add' || operation === 'swap-bootstrap') ? { finalProof } : {})
              });
              const token = ++readySubmissionSeq;
              membershipCommandPending = { fingerprint, submittedAt:Date.now(), status:'dispatched', token, inputLedger:null, directAtomic:directAtomicCommand, pubkey };
              if (directAtomicCommand) atomicMembershipTarget = { operation:'add', pubkey, selectedAt:Date.now(), state:'dispatched', directAtomic:true, lcl:finalProof&&finalProof.candidateLcl||null };
              readyProbeLog(pubkey, 'UNL-COMMAND', {
                verdict:'DISPATCHED', operation,
                requestedAtLcl:membershipCommand.requestedAtLcl || 'atomic',
                transport:'one-shot-bootstrap-a-controller-session',
                reason:directAtomicCommand?'final-proof-and-membership-change-submitted-atomically-with-no-replicated-pre-intent':'membership-change-submitted-as-hotpocket-user-input'
              }, `membership-dispatched|${fingerprint}|${token}`, true);
              submitBootstrapControllerInput(identity.pair, bootstrapPubkey, userPort, payload, 4, READY_SUBMISSION_PENDING_MS, `UNL-COMMAND:${operation}:${pubkey.slice(0,12)}`)
                .then(inputStatus => {
                  const current = membershipCommandPending;
                  if (!current || current.token !== token || current.fingerprint !== fingerprint) return;
                  if (!inputStatus || inputStatus.status !== 'accepted') {
                    membershipCommandPending = null;
                    if (operation === 'add' && committedUnl.length === 1) { firstAddSyncStreaks.delete(pubkey); if (firstAddSyncTarget === pubkey) firstAddSyncTarget = null; }
                    if (directAtomicCommand) { atomicFinalProbeCooldownUntil.set(pubkey, Date.now() + ATOMIC_FINAL_PROBE_COOLDOWN_MS); atomicMembershipTarget = null; }
                    readyProbeLog(pubkey, 'UNL-COMMAND', {
                      verdict:'REJECTED', operation,
                      status:inputStatus && inputStatus.status || 'unknown',
                      reason:inputStatus && inputStatus.reason || 'hotpocket-input-not-accepted'
                    }, `membership-rejected|${fingerprint}|${inputStatus && inputStatus.reason || 'unknown'}`, true);
                    return;
                  }
                  current.status = 'accepted';
                  current.inputLedger = Number(inputStatus.ledgerSeqNo) || null;
                  current.acceptedAt = Date.now();
                  membershipCommandPending = current;
                  if (directAtomicCommand) atomicMembershipTarget = { operation:'add', pubkey, selectedAt:Date.now(), state:'input-accepted', directAtomic:true, lcl:current.inputLedger || null };
                  readyProbeLog(pubkey, 'UNL-COMMAND', {
                    verdict:'INPUT-ACCEPTED', operation,
                    inputLedger:current.inputLedger || 'unknown',
                    transport:'one-shot-closed',
                    reason:'waiting-for-contract-config-patch-and-committed-unl'
                  }, `membership-accepted|${fingerprint}|${current.inputLedger||0}`, true);
                })
                .catch(err => {
                  const current = membershipCommandPending;
                  if (current && current.token === token && current.fingerprint === fingerprint) membershipCommandPending = null;
                  if (operation === 'add' && committedUnl.length === 1) { firstAddSyncStreaks.delete(pubkey); if (firstAddSyncTarget === pubkey) firstAddSyncTarget = null; }
                  if (directAtomicCommand) { atomicFinalProbeCooldownUntil.set(pubkey, Date.now() + ATOMIC_FINAL_PROBE_COOLDOWN_MS); atomicMembershipTarget = null; }
                  readyProbeLog(pubkey, 'UNL-COMMAND', {
                    verdict:'ERROR', operation,
                    reason:err && err.message ? err.message : String(err),
                    transport:'one-shot-closed'
                  }, `membership-error|${fingerprint}`, true);
                });
            } catch (err) {
              membershipCommandPending = null;
              if (operation === 'add' && committedUnl.length === 1) { firstAddSyncStreaks.delete(pubkey); if (firstAddSyncTarget === pubkey) firstAddSyncTarget = null; }
              if (directAtomicCommand) { atomicFinalProbeCooldownUntil.set(pubkey, Date.now() + ATOMIC_FINAL_PROBE_COOLDOWN_MS); atomicMembershipTarget = null; }
              readyProbeLog(pubkey, 'UNL-COMMAND', {
                verdict:'ERROR', operation,
                reason:err && err.message ? err.message : String(err)
              }, `membership-dispatch-error|${fingerprint}`, true);
            }
          }
        }
      }
    } else if (!membershipCommand) {
      membershipCommandPending = null;
    }

    // Once the hard fleet freeze is active, ordinary READY/unreachable writes stay
    // suppressed even when no candidate is exact-tip on this particular scan.
    // FINAL proof selection/rotation is root-local and therefore cannot move /state.
    if (membershipCommand || atomicAdmissionPlan.frozen) {
      const quietKey = membershipCommand && membershipCommand.pubkey || 'bootstrap';
      readyProbeLog(quietKey, 'TRANSITION-QUIET', {
        verdict:'ACTIVE', operation:membershipCommand && membershipCommand.operation || 'add',
        requestedAtLcl:membershipCommand && membershipCommand.requestedAtLcl || (directAtomicCommand?'atomic':'none'),
        reason:directAtomicCommand?'atomic-final-proof-mode;no-replicated-pre-intent;readiness-writes-paused':(membershipCommand?'membership-intent-armed;readiness-and-unreachable-submissions-paused':`hard-freeze-active;${atomicAdmissionPlan.reason};waiting-for-an-exact-tip-candidate-without-mutating-state`)
      }, `quiet|${membershipCommand&&membershipCommand.operation||'atomic'}|${membershipCommand&&membershipCommand.pubkey||''}|${membershipCommand&&membershipCommand.requestedAtLcl||0}|${atomicAdmissionPlan.reason||''}`);
      return;
    }

    // READY probing remains active during bootstrap growth. The probe runs outside
    // replicated contract execution, authenticates to the candidate, and only
    // submits a deterministic attestation after the candidate's exact LCL/hash
    // matches Bootstrap A's node-local canonical recent-ledger witness. Native
    // ACKNOWLEDGED is lifecycle maturity, never a substitute for this sync proof.

    // READY consensus observations use ONLY the authorized controller identity on
    // Bootstrap A. Candidate STAT sockets use per-candidate read-only identities.
    // Do not keep the controller websocket resident: each consensus input gets one
    // short-lived Bootstrap-A-only session, then that session is closed after the
    // submission status resolves. This makes same-identity overlap impossible.

    // During the one-ledger/config-mount transition after a bootstrap membership patch
    // submission, never send selected managed validators back to candidate READY
    // testing after they have graduated into the pending bridge UNL.
    const expectedUnl = singletonBootstrap && pendingFullUnl.length > 1 ? pendingFullUnl : (singletonBootstrap ? [bootstrapPubkey] : committedUnl);
    const allManaged = (Array.isArray(local.nodes) ? local.nodes : []).filter(n => n && !n.isBootstrap && cleanPublicKey(n.pubkey));
    const candidates = allManaged.filter(n => !n.isUnl && !pendingPromoted.has(cleanPublicKey(n.pubkey)) && n.domain && validPort(n.userPort));
    const target = Math.max(1, Number(auto.targetManagedNodes) || 1);
    if (pendingPromoted.size) {
      readyProbeLog('bootstrap', 'PROMOTION', {
        verdict:'GRADUATED', promoted:pendingPromoted.size, expectedUnl,
        reason:'submitted-validator-batch-excluded-from-ready-testing;all-selected-managed-validators-graduated'
      }, `graduated|${[...pendingPromoted].join(',')}|${expectedUnl.join(',')}`);
    }
    const stalled = new Set((Array.isArray(auto.candidateWatchdogs) ? auto.candidateWatchdogs : [])
      .filter(w => w && w.stalledAt && !w.kickedAt)
      .map(w => cleanPublicKey(w.pubkey)).filter(Boolean));
    const usablePhysical = allManaged.filter(n => !n.isUnl && !pendingPromoted.has(cleanPublicKey(n.pubkey)) && !stalled.has(cleanPublicKey(n.pubkey)));
    const qualificationActive = allManaged.filter(n => !n.isUnl).length >= target && usablePhysical.length >= target;
    // READY probing is node-local/outside replicated contract execution and must
    // NEVER be paused merely because acquisition/replacement is active. The old
    // pause created a feedback loop: watchdogs quarantined candidates while the
    // only candidate capable of proving them READY was deliberately disabled,
    // causing endless replacement purchases. Keep polling all materialized peers;
    // the contract still decides when a proof is current enough to count.
    if (!qualificationActive) {
      readyProbeLog('bootstrap', 'SCAN', { verdict:'ACTIVE', candidates:candidates.length, managed:allManaged.length, usable:usablePhysical.length, target, reason:'acquisition-or-replacement-active-ready-probes-continue' }, `active|${allManaged.length}|${usablePhysical.length}|${target}`);
    }
    if (!candidates.length) readyProbeLog('bootstrap', 'SCAN', { verdict:'WAIT', candidates:0, reason:'no-materialized-non-unl-candidates-with-endpoint' }, 'no-candidates');
    const activeKeys = new Set();
    for (const node of candidates) {
      const candidatePubkey = cleanPublicKey(node.pubkey);
      const endpoint = hpEndpoint(node.domain, node.userPort);
      if (!candidatePubkey || !endpoint) continue;
      const cacheKey = `${candidatePubkey}|${endpoint}`; activeKeys.add(cacheKey);
      const nextProbeAt = Number(readyProbeNextAt.get(candidatePubkey) || 0);
      if (nextProbeAt > Date.now()) continue;
      try {
        const probeIdentity = await ensureReadyStatProbeIdentity(candidatePubkey);
        readyProbeLog(candidatePubkey, 'IDENTITY', {
          verdict:'ISOLATED', endpoint,
          controller:identity.publicKey.slice(0,18), statProbe:probeIdentity.publicKey.slice(0,18),
          separate:identity.publicKey !== probeIdentity.publicKey,
          reason:'candidate-has-dedicated-read-only-hotpocket-user-identity'
        }, `candidate-identity|${probeIdentity.publicKey}`);
        const client = await ensureTrustedHpClient(cacheKey, endpoint, candidatePubkey, probeIdentity.pair);
        const stat = await withTimeout(client.getStatus(), 4000, `HotPocket stat ${candidatePubkey}`);
        if (!stat) throw new Error('empty stat response');
        readyUnreachableSince.delete(candidatePubkey);
        readyUnreachableSubmitted.delete(candidatePubkey);
        readyProbeNextAt.delete(candidatePubkey);
        const candidateLcl = Number(stat.ledgerSeqNo) || 0;
        const candidateHash = Buffer.isBuffer(stat.ledgerHash) || stat.ledgerHash instanceof Uint8Array
          ? Buffer.from(stat.ledgerHash).toString('hex').toLowerCase()
          : clean(stat.ledgerHash || '', 256).toLowerCase();
        const voteStatus = clean(stat.voteStatus || '', 32).toLowerCase();
        const currentUnl = statCurrentUnl(stat);
        const weaklyConnected = !!stat.weaklyConnected;
        const contractExecutionEnabled = stat.contractExecutionEnabled !== false;
        // A node that already reports a multi-validator UNL containing itself has
        // graduated from candidate to validator.  This direct node evidence closes
        // the final cfg/state-mount race: even if server.js briefly sees stale
        // singleton control-plane files, a promoted validator can never be pushed
        // back into READY testing. A pre-UNL pool candidate can report the full UNL
        // without containing itself; it correctly remains in candidate qualification.
        if (currentUnl.length > 1 && currentUnl.includes(bootstrapPubkey) && currentUnl.includes(candidatePubkey)) {
          // Promotion changes the socket role. Close the candidate's persistent
          // pre-UNL STAT connection before any post-join health/convergence probe
          // is allowed to connect with a different user identity.
          await closeReadyStatClientForCandidate(candidatePubkey, 'promotion-graduated-pre-unl-stat-retired');
          readyProbeLog(candidatePubkey, 'PROMOTION', { verdict:'GRADUATED', endpoint, lcl:candidateLcl || 'missing', unl:currentUnl, reason:'candidate-reports-full-unl-containing-self;pre-unl-stat-socket-closed;ready-testing-stopped' }, `self-unl|${currentUnl.join(',')}`);
          readyStatPending.delete(candidatePubkey);
          continue;
        }
        const reasons = [];
        let canonicalMatch = false;
        let candidateLag = null;
        if (!candidateLcl) reasons.push('missing-lcl');
        if (!/^[0-9a-f]{64}$/.test(candidateHash)) reasons.push('invalid-ledger-hash');
        if (weaklyConnected) reasons.push('weakly-connected');
        if (!contractExecutionEnabled) reasons.push('contract-execution-disabled');
        // Pre-UNL voteStatus is diagnostic only. A follower can legitimately report
        // desync/wait while tracking the canonical chain because it is not yet a
        // voting member. FINAL admission retains the strict voteStatus=synced gate.
        if (JSON.stringify(currentUnl) !== JSON.stringify(expectedUnl)) reasons.push(`unl-mismatch expected=[${expectedUnl.join(',')}]`);
        // A reported network LCL/hash is useful canonical evidence, but it does
        // NOT prove the node's local primary/raw shard has finished catching up.
        // hpcore can advertise the consensus ledger while history sync is still in
        // progress. Ordinary durable READY remains lag-tolerant, but FINAL promotion
        // requires voteStatus=synced; the first 1->2 transition additionally requires
        // a sustained exact/synced streak across distinct advancing observations.
        if (candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash)) {
          const canonical = readyLocalLedgerStatus(candidateLcl, candidateHash);
          canonicalMatch = !!canonical.match;
          if (!canonical.match) reasons.push(canonical.reason || 'canonical-history-miss');
          const localHistory = readyLocalLedgerHistory();
          const bootstrapLcl = localHistory.length ? Number(localHistory[localHistory.length - 1].lcl) || 0 : 0;
          candidateLag = bootstrapLcl ? Math.max(0, bootstrapLcl - candidateLcl) : null;
        }
        readyLiveProbes.set(candidatePubkey, {
          endpoint, observedAt:Date.now(), candidateLcl, candidateHash,
          candidateLag, canonicalMatch, peers:Array.isArray(stat.peers) ? stat.peers.length : null,
          weaklyConnected, contractExecutionEnabled, currentUnl, voteStatus,
          verdict:reasons.length ? 'wait' : 'synced', reason:reasons.length ? reasons.join(';') : 'canonical-live-stat'
        });
        if (reasons.length) {
          // Weak/network-marginal nodes do not benefit from a 15s hammer loop.
          // They still get regular opportunities to recover and immediately return
          // to the normal cadence after the first clean STAT.
          if (weaklyConnected) readyProbeNextAt.set(candidatePubkey, Date.now() + READY_PROBE_WEAK_BACKOFF_MS);
          readyProbeLog(candidatePubkey, 'STAT', { verdict:'WAIT', endpoint, lcl:candidateLcl || 'missing', hash:candidateHash ? candidateHash.slice(0,16) : 'missing', vote:voteStatus || 'missing', weak:weaklyConnected, exec:contractExecutionEnabled, unl:currentUnl, peers:Array.isArray(stat.peers) ? stat.peers.length : 'unknown', reason:reasons.join(';') }, reasons.join('|'));
          continue;
        }
        const fingerprint = `${candidateLcl}|${candidateHash}`;
        const readiness = Array.isArray(auto.candidateReadiness) ? auto.candidateReadiness : [];
        const priorReady = readiness.find(r => r && cleanPublicKey(r.pubkey) === candidatePubkey) || null;
        const canonical = priorReady && Number(priorReady.candidateLcl) === candidateLcl && clean(priorReady.candidateHash || '',256).toLowerCase() === candidateHash ? priorReady : null;
        if (canonical) {
          readyStatPending.delete(candidatePubkey);
          const heartbeats = Math.max(0, Number(canonical.readyHeartbeats) || 0);
          const stableReady = heartbeats >= READY_STABLE_REQUIRED_HEARTBEATS;
          readyProbeLog(candidatePubkey, 'CANONICAL', {
            verdict:stableReady ? 'READY' : 'PROGRESS',
            endpoint,
            lcl:candidateLcl,
            hash:candidateHash.slice(0,16),
            observedAtLcl:Number(canonical.observedAtLcl) || 'unknown',
            vote:voteStatus,
            unl:currentUnl,
            heartbeats:`${heartbeats}/${READY_STABLE_REQUIRED_HEARTBEATS}`,
            advances:`${Math.max(0, heartbeats - 1)}/${READY_STABLE_REQUIRED_HEARTBEATS - 1}`,
            reason:stableReady ? 'stable-canonical-forward-progress-proven' : 'canonical-proof-accepted-awaiting-more-ledger-advances'
          }, `${stableReady ? 'ready' : 'progress'}|${fingerprint}|${heartbeats}|${Number(canonical.observedAtLcl)||0}`);
          continue;
        }
        // Replicated READY is milestone-based: two initial advancing proofs plus
        // one fresh proof near the end of the ACKNOWLEDGED stability window. Do
        // not submit a consensus input for every observed candidate ledger.
        const readyHeartbeatsNow = Math.max(0, Number(priorReady && priorReady.readyHeartbeats) || 0);
        const admissionSyncHeartbeatsNow = Math.max(0, Number(priorReady && priorReady.admissionSyncHeartbeats) || 0);
        const priorCandidateLcl = Number(priorReady && priorReady.candidateLcl) || 0;
        const finalReadyAtLcl = Number(priorReady && priorReady.finalReadyAtLcl) || 0;
        const warm = auto && auto.promotionPeerWarmup && typeof auto.promotionPeerWarmup === 'object' ? auto.promotionPeerWarmup : null;
        const warmSelected = !!(warm && cleanPublicKey(warm.pubkey) === candidatePubkey);
        const warmStartedAtLcl = Number(warm && warm.startedAtLcl) || 0;
        const warmDone = warmSelected && warmStartedAtLcl > 0 && candidateLcl - warmStartedAtLcl >= SIGNED_RELAY_FINAL_PROOF_DELAY_LCLS;
        const initialReadyNeeded = candidateLcl > priorCandidateLcl && readyHeartbeatsNow < READY_STABLE_REQUIRED_HEARTBEATS;
        const exactAdmissionSample = warmDone && voteStatus === 'synced' && candidateLag === 0;
        // Admission exactness is sampled out-of-band immediately before the
        // authenticated membership input. Never create a replicated READY write
        // merely to prove admission sync: that write changes /state and would
        // invalidate the proof it just recorded.
        const admissionSyncNeeded = false;
        const finalRetryDue = !finalReadyAtLcl || candidateLcl - finalReadyAtLcl >= SIGNED_RELAY_FINAL_RETRY_LCLS;
        // Final readiness is always candidate-local because bootstrap admission is
        // strictly one-at-a-time. Once this candidate has warmed as an old-UNL peer,
        // submit a fresh final proof for its next single-node membership release.
        const finalReadyNeeded = candidateLcl > priorCandidateLcl && readyHeartbeatsNow >= READY_STABLE_REQUIRED_HEARTBEATS && warmDone && finalRetryDue;
        if (!initialReadyNeeded && !finalReadyNeeded && !admissionSyncNeeded) {
          readyProbeLog(candidatePubkey, 'CANONICAL', {
            verdict:'QUIET', endpoint, lcl:candidateLcl, hash:candidateHash.slice(0,16),
            heartbeats:`${readyHeartbeatsNow}/${READY_STABLE_REQUIRED_HEARTBEATS}`,
            admissionSync:`${admissionSyncHeartbeatsNow}/2`, vote:voteStatus || 'missing', lag:candidateLag == null ? 'unknown' : candidateLag,
            warmSelected, warmDone, finalReadyAtLcl:finalReadyAtLcl || null,
            reason:warmDone && admissionSyncHeartbeatsNow < 2 ? 'waiting-for-hpcore-synced-exact-tip-admission-sample' : 'no-replicated-ready-milestone-due'
          }, `canonical-quiet|${readyHeartbeatsNow}|${admissionSyncHeartbeatsNow}|${voteStatus}|${candidateLag}|${warmSelected}|${warmDone}|${finalReadyAtLcl}`);
          continue;
        }
        const pending = readyStatPending.get(candidatePubkey) || null;
        const pendingAge = pending ? Math.max(0, Date.now() - Number(pending.submittedAt || 0)) : 0;
        // Keep at most one not-yet-accepted READY input in flight per candidate.
        // This preserves proof ordering without blocking the scanner itself.
        const pendingRetryWindowMs = pending && pending.status === 'status-unknown' ? READY_STATUS_UNKNOWN_RETRY_MS : READY_SUBMISSION_PENDING_MS;
        if (pending && pending.status !== 'accepted' && pendingAge < pendingRetryWindowMs) {
          readyProbeLog(candidatePubkey, 'CANONICAL', {
            verdict:'PENDING', endpoint, lcl:candidateLcl, hash:candidateHash.slice(0,16),
            pendingMs:pendingAge, pendingFingerprint:pending.fingerprint,
            reason:pending.status === 'status-unknown' ? 'previous-proof-status-unknown-awaiting-short-idempotent-retry' : 'previous-proof-dispatched-awaiting-replicated-ready-record'
          }, `pending-dispatch|${pending.fingerprint}|${pending.status || 'unknown'}`);
          continue;
        }
        if (pending && pending.fingerprint === fingerprint && pendingAge < READY_SUBMISSION_PENDING_MS) {
          readyProbeLog(candidatePubkey, 'CANONICAL', {
            verdict:'INPUT-ACCEPTED', endpoint, lcl:candidateLcl, hash:candidateHash.slice(0,16),
            inputLedger:pending.inputLedger || 'unknown', pendingMs:pendingAge,
            reason:'hotpocket-input-accepted-awaiting-contract-ready-record'
          }, `accepted|${fingerprint}|${pending.inputLedger||0}`);
          continue;
        }
        // An accepted older fingerprint must not block the candidate from proving
        // its next higher LCL. A stale unresolved dispatch is also retriable after
        // the bounded pending window.
        if (pending) readyStatPending.delete(candidatePubkey);
        readyProbeLog(candidatePubkey, 'STAT', { verdict:admissionSyncNeeded?'ADMISSION-EXACT-TIP':'STAT-QUALIFIED', endpoint, lcl:candidateLcl, hash:candidateHash.slice(0,16), vote:voteStatus || 'missing', weak:weaklyConnected, exec:contractExecutionEnabled, unl:currentUnl, peers:Array.isArray(stat.peers) ? stat.peers.length : 'unknown', lag:candidateLag == null ? 'unknown' : candidateLag, admissionSync:`${admissionSyncHeartbeatsNow}/2`, reason:admissionSyncNeeded?'hpcore-vote-synced;bootstrap-measured-lag-zero;submitting-admission-proof':'canonical-ledger-reported;ordinary-ready-qualified' }, `stat-qualified|${candidateLcl}|${candidateHash}|${voteStatus}|${candidateLag}|${admissionSyncNeeded}`);
        const payload = JSON.stringify({
          type:'autocluster_ready_observation',
          candidatePubkey,
          candidateLcl,
          candidateHash,
          voteStatus,
          weaklyConnected,
          contractExecutionEnabled,
          currentUnl,
          hpVersion:clean(stat.hpVersion || '',64) || null,
          peers:Array.isArray(stat.peers) ? stat.peers.length : null,
          candidateLag,
          transport:'bootstrap-canonical-controller'
        });
        if (!controllerAuthorized) {
          readyProbeLog(candidatePubkey, 'SUBMIT', {
            verdict:'CONTROLLER-AUTH-WAIT', endpoint, lcl:candidateLcl,
            expected:authorized || 'missing', local:identity.publicKey || 'missing',
            reason:'live-candidate-is-synced-but-authenticated-ready-record-cannot-be-submitted-until-controller-key-matches'
          }, `controller-auth-wait|${candidateLcl}|${candidateHash}|${authorized || ''}|${identity.publicKey || ''}`);
          continue;
        }
        // Serialize only the actual controller websocket write.  Do NOT serialize
        // candidates behind the submissionStatus promise: live runs proved that
        // HotPocket can commit a READY input even when that promise times out at
        // 30 seconds.  Per-candidate readyStatPending suppresses duplicate proofs;
        // replicated candidateReadiness remains the authority for success.
        if (readyControllerTransportBusy) {
          readyProbeLog(candidatePubkey, 'SUBMIT', {
            verdict:'SERIALIZED-WAIT', endpoint, lcl:candidateLcl,
            activeTransport:readyControllerTransportLabel || 'none',
            reason:'bootstrap-controller-dispatch-write-in-progress'
          }, `serialized-wait|${readyControllerTransportLabel || ''}|${candidatePubkey}`);
          continue;
        }

        try {
          const token = ++readySubmissionSeq;
          const submittedAt = Date.now();
          readySubmitInFlight = { candidatePubkey, fingerprint, submittedAt, token };
          readyStatPending.set(candidatePubkey, { fingerprint, inputLedger:null, submittedAt, status:'dispatching', token });
          readyProbeLog(candidatePubkey, 'SUBMIT', {
            verdict:'DISPATCHED', endpoint, lcl:candidateLcl,
            hash:candidateHash.slice(0,16), vote:voteStatus, unl:currentUnl,
            transport:'bootstrap-a-controller-fire-and-observe',
            reason:'controller-mutex-releases-after-input-bytes-are-dispatched;status-is-diagnostic-only'
          }, `dispatched|${fingerprint}|${token}`);

          dispatchBootstrapControllerInput(identity.pair, bootstrapPubkey, userPort, payload, 4, `READY:${candidatePubkey.slice(0,12)}:${candidateLcl}`)
            .then(dispatched => {
              if (readySubmitInFlight && readySubmitInFlight.token === token) readySubmitInFlight = null;
              const current = readyStatPending.get(candidatePubkey);
              if (!current || current.token !== token || current.fingerprint !== fingerprint) return;
              current.status = 'dispatched';
              current.dispatchedAt = Date.now();
              readyStatPending.set(candidatePubkey, current);
              readyProbeLog(candidatePubkey, 'SUBMIT', {
                verdict:'BYTES-DISPATCHED', endpoint, lcl:candidateLcl,
                hash:candidateHash.slice(0,16),
                reason:'controller-write-released;persistent-socket-kept-open-awaiting-replicated-ready-record',
                candidateSocket:'kept-open',
                bootstrapSubmitSocket:'persistent-controller-kept-open'
              }, `bytes-dispatched|${fingerprint}|${token}`, true);

              // Observe HotPocket's status in the background, but never let a late
              // timeout erase the pending proof.  The contract's replicated READY
              // record is authoritative; an unresolved status simply becomes
              // retryable after READY_SUBMISSION_PENDING_MS.
              withTimeout(Promise.resolve(dispatched.submissionStatus), READY_SUBMISSION_PENDING_MS, `READY:${candidatePubkey.slice(0,12)}:${candidateLcl} HotPocket submission status`)
                .then(inputStatus => {
                  const pendingNow = readyStatPending.get(candidatePubkey);
                  if (!pendingNow || pendingNow.token !== token || pendingNow.fingerprint !== fingerprint) return;
                  if (inputStatus && inputStatus.status === 'accepted') {
                    pendingNow.status = 'accepted';
                    pendingNow.inputLedger = Number(inputStatus.ledgerSeqNo) || null;
                    pendingNow.acceptedAt = Date.now();
                    readyStatPending.set(candidatePubkey, pendingNow);
                    readyProbeLog(candidatePubkey, 'SUBMIT', {
                      verdict:'INPUT-ACCEPTED', endpoint, lcl:candidateLcl,
                      hash:candidateHash.slice(0,16), inputLedger:pendingNow.inputLedger || 'unknown',
                      reason:'awaiting-contract-canonical-ready-record'
                    }, `input-accepted|${fingerprint}|${pendingNow.inputLedger||0}`, true);
                  } else {
                    pendingNow.status = 'status-unknown';
                    pendingNow.statusReason = inputStatus && inputStatus.reason || 'hotpocket-input-not-confirmed';
                    readyStatPending.set(candidatePubkey, pendingNow);
                    readyProbeLog(candidatePubkey, 'SUBMIT', {
                      verdict:'STATUS-UNKNOWN', endpoint, lcl:candidateLcl,
                      status:inputStatus && inputStatus.status || 'unknown',
                      reason:`${pendingNow.statusReason};replicated-ready-record-remains-authoritative-and-proof-will-retry-if-absent`
                    }, `status-unknown|${fingerprint}|${pendingNow.statusReason}`, true);
                  }
                })
                .catch(statusErr => {
                  const pendingNow = readyStatPending.get(candidatePubkey);
                  if (!pendingNow || pendingNow.token !== token || pendingNow.fingerprint !== fingerprint) return;
                  pendingNow.status = 'status-unknown';
                  pendingNow.statusReason = statusErr && statusErr.message ? statusErr.message : String(statusErr);
                  readyStatPending.set(candidatePubkey, pendingNow);
                  readyProbeLog(candidatePubkey, 'SUBMIT', {
                    verdict:'STATUS-TIMEOUT', endpoint, lcl:candidateLcl,
                    hash:candidateHash.slice(0,16), reason:`${pendingNow.statusReason};input-may-already-be-committed;do-not-block-other-candidates`
                  }, `status-timeout|${fingerprint}|${pendingNow.statusReason}`, true);
                });
            })
            .catch(submitErr => {
              if (readySubmitInFlight && readySubmitInFlight.token === token) readySubmitInFlight = null;
              const current = readyStatPending.get(candidatePubkey);
              if (current && current.token === token && current.fingerprint === fingerprint) readyStatPending.delete(candidatePubkey);
              const submitMessage = submitErr && submitErr.message ? submitErr.message : String(submitErr);
              readyProbeLog(candidatePubkey, 'SUBMIT', {
                verdict:'DISPATCH-ERROR', endpoint, lcl:candidateLcl,
                hash:candidateHash.slice(0,16), reason:submitMessage,
                candidateSocket:'kept-open', bootstrapSubmitSocket:'one-shot-closed'
              }, `dispatch-error|${submitMessage}`, true);
            });
        } catch (submitErr) {
          readyStatPending.delete(candidatePubkey);
          if (readySubmitInFlight && readySubmitInFlight.candidatePubkey === candidatePubkey && readySubmitInFlight.fingerprint === fingerprint) readySubmitInFlight = null;
          const submitMessage = submitErr && submitErr.message ? submitErr.message : String(submitErr);
          readyProbeLog(candidatePubkey, 'SUBMIT', {
            verdict:'DISPATCH-ERROR', endpoint, lcl:candidateLcl,
            hash:candidateHash.slice(0,16), reason:submitMessage,
            candidateSocket:'kept-open'
          }, `dispatch-error|${submitMessage}`);
        }
      } catch (e) {
        const stale = readyStatClients.get(cacheKey);
        if (stale) {
          await closeHpClient(stale);
          readyStatClients.delete(cacheKey);
          readyProbeLog(candidatePubkey, 'SOCKET', { verdict:'RESET', endpoint, reason:'connect-or-stat-failure-client-closed-before-retry' }, 'socket-reset');
        }
        const message = e && e.message ? e.message : String(e);
        readyProbeNextAt.set(candidatePubkey, Date.now() + READY_PROBE_ERROR_BACKOFF_MS);
        readyLiveProbes.set(candidatePubkey, {
          endpoint, observedAt:Date.now(), candidateLcl:0, candidateHash:null, candidateLag:null,
          canonicalMatch:false, peers:null, weaklyConnected:false, contractExecutionEnabled:false,
          currentUnl:[], voteStatus:null, verdict:'error', reason:message
        });
        const failedAt = readyUnreachableSince.get(candidatePubkey) || Date.now();
        if (!readyUnreachableSince.has(candidatePubkey)) readyUnreachableSince.set(candidatePubkey, failedAt);
        const unreachableForMs = Math.max(0, Date.now() - failedAt);
        const unreachableLimitMs = Math.max(15000, Number(auto.readyProbeUnreachableTimeoutMs) || 60000);
        readyProbeLog(candidatePubkey, 'CONNECT/STAT', { verdict:'ERROR', endpoint, unreachableForMs, unreachableLimitMs, reason:message }, `${message}|${Math.floor(unreachableForMs/10000)}`);
        if (unreachableForMs >= unreachableLimitMs && !readyUnreachableSubmitted.has(candidatePubkey)) {
          try {
            const payload = JSON.stringify({ type:'autocluster_ready_unreachable_observation', candidatePubkey, endpoint, unreachableForMs });
            if (readyControllerTransportBusy) {
              readyProbeLog(candidatePubkey, 'UNREACHABLE', {
                verdict:'SERIALIZED-WAIT', endpoint,
                activeTransport:readyControllerTransportLabel || 'unknown',
                reason:'one-hotpocket-controller-identity-connection-at-a-time'
              }, `unreachable-transport-wait|${readyControllerTransportLabel || 'unknown'}`);
              continue;
            }
            const inputStatus = await submitBootstrapControllerInput(
              identity.pair, bootstrapPubkey, userPort, payload, 2, 8000,
              `UNREACHABLE:${candidatePubkey.slice(0,12)}`
            );
            if (inputStatus && inputStatus.status === 'accepted') {
              readyUnreachableSubmitted.set(candidatePubkey, Date.now());
              readyProbeLog(candidatePubkey, 'UNREACHABLE', { verdict:'INPUT-ACCEPTED', endpoint, unreachableForMs, limitMs:unreachableLimitMs, reason:'continuous-bootstrap-a-wss-failure-submitted-for-reversible-quarantine' }, `unreachable-accepted|${candidatePubkey}` , true);
            } else {
              readyProbeLog(candidatePubkey, 'UNREACHABLE', { verdict:'REJECTED', endpoint, status:inputStatus && inputStatus.status || 'unknown', reason:inputStatus && inputStatus.reason || 'hotpocket-input-not-accepted' }, `unreachable-rejected|${candidatePubkey}` , true);
            }
          } catch (submitErr) {
            readyProbeLog(candidatePubkey, 'UNREACHABLE', { verdict:'SUBMIT-ERROR', endpoint, reason:submitErr && submitErr.message ? submitErr.message : String(submitErr) }, `unreachable-submit-error|${candidatePubkey}` , true);
          }
        }
      }
    }
    // No paired READY bundle is emitted. Each selected candidate obtains its own
    // fresh final READY proof immediately before its one-at-a-time admission.

    for (const [key, client] of [...readyStatClients.entries()]) {
      if (!activeKeys.has(key)) { await closeHpClient(client); readyStatClients.delete(key); }
    }
    const activeCandidatePubkeys = new Set(candidates.map(n => cleanPublicKey(n && n.pubkey)).filter(Boolean));
    for (const key of [...readyStatPending.keys()]) if (!activeCandidatePubkeys.has(key)) readyStatPending.delete(key);
    for (const key of [...readyUnreachableSince.keys()]) if (!activeCandidatePubkeys.has(key)) readyUnreachableSince.delete(key);
    for (const key of [...readyUnreachableSubmitted.keys()]) if (!activeCandidatePubkeys.has(key)) readyUnreachableSubmitted.delete(key);
  } catch (e) {
    const message = e && e.message ? e.message : String(e);
    readyProbeLog('bootstrap', 'POLL', { verdict:'ERROR', reason:message }, message);
  } finally { readyStatBusy = false; }
}

function hpUnl(cfg) {
  const raw = cfg && cfg.contract && Array.isArray(cfg.contract.unl) ? cfg.contract.unl : [];
  return raw.map(x => typeof x === 'string' ? x : (x && (x.publicKey || x.public_key || x.pubkey))).filter(Boolean);
}
function detectBootstrapPubkey(s) {
  if (s.bootstrapPubkey) return s.bootstrapPubkey;
  const unl = hpUnl(readHpCfg());
  if (unl.length === 1) return unl[0];
  const sr = stateRoot();
  const c = sr && readJson(path.join(sr, 'cluster.json'), null);
  if (c && Array.isArray(c.nodes) && c.nodes.length === 1 && c.nodes[0].pubkey) return c.nodes[0].pubkey;
  throw new Error(`Cannot safely determine bootstrap validator public key (UNL count=${unl.length}). Enter it explicitly in Cluster Settings.`);
}
function supervisor(action) {
  const conf = process.env.EVERSMARTNODE_SUPERVISOR_CONF || '/etc/eversmartnode/supervisord.conf';
  return execFileSync('/usr/bin/supervisorctl', ['-c', conf, action, 'hotpocket'], { encoding: 'utf8' }).trim();
}

async function withTenant(address, seed, fn) {
  const s = settings();
  const xahauServers = rpcPoolUrls(s, 'xahau');
  if (!xahauServers.length && s.rippleServer) xahauServers.push(s.rippleServer);
  // Connect sequentially and remember the winner node-locally. This means a
  // dead first endpoint is tried once, the next server is used immediately, and
  // subsequent API/UI calls start with that known-good server instead of
  // re-triggering evernode-js-client's primary reconnect warning every poll.
  const selected = await connectXahauRpcSequential(xahauServers, s.network, 'tenant');
  const xrplApi = selected.xrplApi;
  const client = new evernode.TenantClient(address, seed || null, { xrplApi });
  try {
    await client.connect();
    return await fn(client);
  } finally {
    try { await client.disconnect(); } catch {}
    try { await xrplApi.disconnect(); } catch {}
  }
}
function walletMeta() { return readJson(WALLET_META, null); }
function cachedWalletStatus(address) {
  const cached = readJson(WALLET_STATUS_CACHE, null);
  return cached && cached.address === address ? cached : null;
}
function cacheWalletStatus(status) {
  if (!status || !status.generated || !status.address || !status.exists || status.ledgerError) return;
  try { writeJson(WALLET_STATUS_CACHE, { ...status, cachedAt: Date.now() }); } catch {}
}
function requireWalletSeed() {
  const meta = walletMeta();
  if (!meta || !meta.address) throw new Error('No cluster wallet has been generated.');
  const seed = secretRead(SEED_SECRET);
  if (!seed) throw new Error('Cluster master seed is not available (it may already have been discarded after handover).');
  return { meta, seed };
}

function isMasterDisabledFromInfo(flags, info) {
  // AccountRoot lsfDisableMaster is 0x00100000 (1048576). Keep the
  // parsed-name checks too because evernode-js-client/xrpl helper naming has
  // changed across releases.
  const parsed = !!(flags && (
    flags.lsfDisableMaster || flags.DisableMaster || flags.disableMasterKey || flags.disableMaster
  ));
  const rawFlags = Number(info && info.Flags != null ? info.Flags : 0);
  return parsed || ((rawFlags & 0x00100000) !== 0);
}

async function ledgerWalletStatus() {
  let meta = walletMeta();
  if (!meta || !meta.address) {
    const local = localClusterStatus();
    if (local.auto && local.auto.clusterAddress) {
      meta = { address: local.auto.clusterAddress, createdAt: local.auto.createdAt || null, network: local.auto.network, derivedFromConsensus: true };
    }
  }
  if (!meta || !meta.address) return { generated: false, seedPresent: false };
  const base = { generated: true, address: meta.address, createdAt: meta.createdAt, seedPresent: !!secretRead(SEED_SECRET), derivedFromConsensus: !!meta.derivedFromConsensus };
  try {
    const status = await withTenant(meta.address, null, async tenant => {
      const info = await tenant.xrplAcc.getInfo();
      const flags = await tenant.xrplAcc.getFlags();
      const lines = await tenant.xrplAcc.getTrustLines(evernode.EvernodeConstants.EVR, tenant.config.evrIssuerAddress);
      let objects = [];
      try { objects = await tenant.xrplAcc.getAccountObjects({ type: 'signer_list' }); } catch {}
      const sl = objects.find(o => o && (o.LedgerEntryType === 'SignerList' || o.SignerEntries));
      let uriTokens = [];
      try { uriTokens = await tenant.xrplAcc.getURITokens(); } catch {}

      // Advisory XAH reserve display using the ledger's live FeeSettings.
      // Acquiring an Evernode lease transfers a URIToken to the tenant, which
      // consumes one additional owner reserve. This is intentionally an
      // estimate only: it MUST NOT gate trustline/signer/acquire submission; the real transaction result is authoritative.
      let feeSettings = null;
      try { feeSettings = await tenant.xrplApi.getLedgerEntry(XAHAU_FEE_SETTINGS_INDEX); } catch {}
      const feeNode = feeSettings && (feeSettings.node || (feeSettings.result && (feeSettings.result.node || feeSettings.result)) || feeSettings);
      const dropsNumber = v => {
        if (v == null) return null;
        if (typeof v === 'object' && v.value != null) v = v.value;
        const n = Number(v); return Number.isFinite(n) ? n : null;
      };
      const balanceDrops = dropsNumber(info && info.Balance);
      const ownerCount = Number.isFinite(Number(info && info.OwnerCount)) ? Number(info.OwnerCount) : null;
      const reserveBaseDrops = dropsNumber(feeNode && (feeNode.ReserveBaseDrops != null ? feeNode.ReserveBaseDrops : feeNode.ReserveBase));
      const reserveIncrementDrops = dropsNumber(feeNode && (feeNode.ReserveIncrementDrops != null ? feeNode.ReserveIncrementDrops : feeNode.ReserveIncrement));
      const reserveNowDrops = balanceDrops != null && ownerCount != null && reserveBaseDrops != null && reserveIncrementDrops != null
        ? reserveBaseDrops + (ownerCount * reserveIncrementDrops) : null;
      const reserveNextObjectDrops = reserveNowDrops != null ? reserveNowDrops + reserveIncrementDrops : null;
      const spendableDrops = balanceDrops != null && reserveNowDrops != null ? Math.max(0, balanceDrops - reserveNowDrops) : null;
      const fundingRequiredForNextObject = balanceDrops != null && reserveNextObjectDrops != null
        ? balanceDrops < (reserveNextObjectDrops + RESERVE_FEE_BUFFER_DROPS) : null;
      const suggestedTopUpDrops = balanceDrops != null && reserveNextObjectDrops != null
        ? Math.max(0, (reserveNextObjectDrops + RESERVE_FEE_BUFFER_DROPS) - balanceDrops) : null;

      // Bootstrap needs room for the temporary SignerList and the first lease
      // URIToken. If a SignerList already exists, only the lease object remains.
      const bootstrapExtraOwners = sl ? 1 : 2;
      const reserveBootstrapReadyDrops = reserveNowDrops != null && reserveIncrementDrops != null
        ? reserveNowDrops + (bootstrapExtraOwners * reserveIncrementDrops) : null;
      const bootstrapFundingRequired = balanceDrops != null && reserveBootstrapReadyDrops != null
        ? balanceDrops < (reserveBootstrapReadyDrops + RESERVE_FEE_BUFFER_DROPS) : null;
      const suggestedBootstrapTopUpDrops = balanceDrops != null && reserveBootstrapReadyDrops != null
        ? Math.max(0, (reserveBootstrapReadyDrops + RESERVE_FEE_BUFFER_DROPS) - balanceDrops) : null;
      const toXah = d => d == null ? null : String(d / 1_000_000);

      return {
        ...base,
        exists: true,
        xah: toXah(balanceDrops),
        xahDrops: balanceDrops == null ? null : String(balanceDrops),
        ownerCount,
        reserveBaseXah: toXah(reserveBaseDrops),
        reserveIncrementXah: toXah(reserveIncrementDrops),
        reserveRequiredXah: toXah(reserveNowDrops),
        reserveNextObjectXah: toXah(reserveNextObjectDrops),
        spendableXah: toXah(spendableDrops),
        fundingRequiredForNextObject,
        suggestedTopUpXah: toXah(suggestedTopUpDrops),
        reserveBootstrapReadyXah: toXah(reserveBootstrapReadyDrops),
        bootstrapExtraOwners,
        bootstrapFundingRequired,
        suggestedBootstrapTopUpXah: toXah(suggestedBootstrapTopUpDrops),
        fundingBufferXah: String(RESERVE_FEE_BUFFER_DROPS / 1_000_000),
        evrIssuer: tenant.config.evrIssuerAddress,
        evrTrustline: lines.length > 0,
        evrBalance: lines.length ? String(lines[0].balance) : '0',
        flags,
        masterDisabled: isMasterDisabledFromInfo(flags, info),
        rewardTracking: {
          initialized: info && info.RewardAccumulator != null && info.RewardLgrFirst != null && info.RewardLgrLast != null && info.RewardTime != null,
          accumulator: info && info.RewardAccumulator != null ? String(info.RewardAccumulator) : null,
          ledgerFirst: info && info.RewardLgrFirst != null ? Number(info.RewardLgrFirst) : null,
          ledgerLast: info && info.RewardLgrLast != null ? Number(info.RewardLgrLast) : null,
          rewardTime: info && info.RewardTime != null ? Number(info.RewardTime) : null
        },
        signerList: sl ? {
          quorum: sl.SignerQuorum,
          signers: (sl.SignerEntries || []).map(e => ({ account: e.SignerEntry.Account, weight: e.SignerEntry.SignerWeight }))
        } : null,
        uriTokenCount: uriTokens.length
      };
    });
    cacheWalletStatus(status);
    return status;
  } catch (e) {
    const ledgerError = e && e.message ? e.message : String(e);
    const cached = cachedWalletStatus(meta.address);
    if (cached) {
      return {
        ...cached,
        ...base,
        exists: cached.exists !== false,
        ledgerStale: true,
        ledgerError,
        lastSuccessfulLedgerStatusAt: cached.cachedAt || null
      };
    }
    return { ...base, exists: false, ledgerStale: true, ledgerError, lastSuccessfulLedgerStatusAt: null };
  }
}


function nplHandoverProposalFile(clusterAddress) {
  const root = stateRoot();
  const address = clean(clusterAddress || '', 128);
  if (!root || !address) return null;
  return path.join(path.dirname(root), `${address}.npl-handover.json`);
}

function expectedSignerNplRoundId(auto, expectedManaged, currentUnl) {
  const payload = {
    clusterAddress: clean(auto && auto.clusterAddress || '', 128),
    bootstrapPubkey: clean(auto && auto.bootstrapPubkey || '', 256).toLowerCase(),
    bootstrapRunCreatedAt: Number(auto && auto.createdAt) || 0,
    signerQuorum: Number(auto && auto.signerQuorum) || 0,
    managed: [...new Set((expectedManaged || []).map(x => String(x || '').toLowerCase()).filter(Boolean))].sort(),
    unl: [...new Set((currentUnl || []).map(x => String(x || '').toLowerCase()).filter(Boolean))].sort()
  };
  return `signer-v2:${crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex')}`;
}

function nplHandoverStatus(auto, publicNodes) {
  const base = { ready:false, signerCount:0, required:Math.max(1, Number(auto && auto.targetManagedNodes || 1)), mappings:[], roundId:null, observedAtLcl:null, error:null };
  if (!auto || !auto.clusterAddress || !['signing','ready-to-handover','handover'].includes(auto.phase)) return base;
  const file = nplHandoverProposalFile(auto.clusterAddress);
  const raw = file ? readJson(file, null) : null;
  if (!raw || typeof raw !== 'object') return base;
  try {
    if (String(raw.clusterAddress || '') !== String(auto.clusterAddress || '')) throw new Error('cluster address mismatch');
    if (String(raw.bootstrapPubkey || '').toLowerCase() !== String(auto.bootstrapPubkey || '').toLowerCase()) throw new Error('bootstrap pubkey mismatch');
    if (Number(raw.signerQuorum || 0) !== Number(auto.signerQuorum || 0)) throw new Error('signer quorum mismatch');
    const expectedManaged = (Array.isArray(publicNodes) ? publicNodes : [])
      .filter(n => n && !n.isBootstrap && n.isUnl && n.pubkey)
      .map(n => String(n.pubkey).toLowerCase()).sort().slice(0, base.required);
    if (expectedManaged.length !== base.required) throw new Error(`managed UNL incomplete ${expectedManaged.length}/${base.required}`);
    const currentUnl = (Array.isArray(publicNodes) ? publicNodes : []).filter(n => n && n.isUnl && n.pubkey).map(n => String(n.pubkey).toLowerCase()).sort();
    const proposalUnl = [...new Set((Array.isArray(raw.unlPubkeys) ? raw.unlPubkeys : []).map(x => String(x || '').toLowerCase()).filter(Boolean))].sort();
    if (proposalUnl.length && JSON.stringify(proposalUnl) !== JSON.stringify(currentUnl)) throw new Error('UNL snapshot changed since NPL signer round');
    const expectedRoundId = expectedSignerNplRoundId(auto, expectedManaged, currentUnl);
    if (String(raw.roundId || '') !== expectedRoundId) throw new Error('stale NPL signer proposal from a different handover round');
    const mappings = (Array.isArray(raw.mappings) ? raw.mappings : []).map(m => ({
      pubkey: String(m && (m.pubkey || m.publicKey) || '').trim().toLowerCase(),
      signerAddress: String(m && (m.signerAddress || m.account) || '').trim()
    })).filter(m => m.pubkey && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(m.signerAddress)).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
    if (mappings.length !== base.required) throw new Error(`NPL signer set incomplete ${mappings.length}/${base.required}`);
    if (new Set(mappings.map(m => m.pubkey)).size !== mappings.length) throw new Error('duplicate NPL validator pubkey');
    if (new Set(mappings.map(m => m.signerAddress)).size !== mappings.length) throw new Error('duplicate NPL signer address');
    if (JSON.stringify(mappings.map(m => m.pubkey)) !== JSON.stringify(expectedManaged)) throw new Error('NPL signer pubkeys do not match current managed UNL');
    return { ready:true, signerCount:mappings.length, required:base.required, mappings, roundId:clean(raw.roundId || '',320)||null, observedAtLcl:Number(raw.observedAtLcl)||null, error:null };
  } catch (e) {
    return { ...base, error:String(e && e.message || e) };
  }
}

function liveAutoClusterState(root) {
  if (!root) return null;
  return readJson(path.join(root, 'autocluster.state.json'), null) || readJson(path.join(root, 'autocluster.json'), null);
}

function displayAutoClusterState(root, liveAuto, cluster, acquires) {
  if (liveAuto && typeof liveAuto === 'object') {
    try {
      writeJson(AUTOCLUSTER_STATUS_CACHE, {
        schema: 1,
        cachedAt: Date.now(),
        stateRoot: root,
        bootstrapPubkey: clean(liveAuto.bootstrapPubkey || '', 256).toLowerCase() || null,
        clusterAddress: clean(liveAuto.clusterAddress || '', 128) || null,
        auto: liveAuto
      });
    } catch {}
    return { auto: liveAuto, source: 'live', stale: false, cachedAt: null };
  }

  // HotPocket can briefly swap/replace the mounted consensus-state generation
  // after a validator-set change. During that narrow window server.js may be
  // able to read cluster.json while autocluster.state.json is momentarily absent
  // or unreadable. This cache is DISPLAY ONLY: mutation/bootstrap endpoints use
  // localClusterStatus() without displayCache and therefore never trust it.
  const cached = readJson(AUTOCLUSTER_STATUS_CACHE, null);
  const age = cached ? Date.now() - Number(cached.cachedAt || 0) : Number.POSITIVE_INFINITY;
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const acquired = acquires && Array.isArray(acquires.acquiredNodes) ? acquires.acquiredNodes : [];
  const cachedBootstrap = clean(cached && cached.bootstrapPubkey || '', 256).toLowerCase();
  const clusterStillExists = nodes.length > 1 || acquired.length > 0 || (cachedBootstrap && nodes.some(n => String(n && n.pubkey || '').toLowerCase() === cachedBootstrap));
  const sameRoot = !!(cached && cached.stateRoot === root);
  const validAge = age >= 0 && age <= AUTOCLUSTER_STATUS_CACHE_MAX_AGE_MS;
  if (cached && cached.auto && sameRoot && validAge && clusterStillExists) {
    return { auto: cached.auto, source: 'cached-transition', stale: true, cachedAt: Number(cached.cachedAt || 0) || null };
  }
  return { auto: null, source: 'missing', stale: false, cachedAt: null };
}

function localClusterStatus(options = {}) {
  const root = stateRoot();
  if (!root) return { stateRoot: null };
  const cluster = readJson(path.join(root, 'cluster.json'), null);
  const ops = readJson(path.join(root, 'operations.json'), null);
  const acquires = readJson(path.join(root, 'acquires.json'), null);
  const liveAuto = liveAutoClusterState(root);
  const autoView = options && options.displayCache
    ? displayAutoClusterState(root, liveAuto, cluster, acquires)
    : { auto: liveAuto, source: liveAuto ? 'live' : 'missing', stale: false, cachedAt: null };
  const auto = autoView.auto;
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const pendingNodes = cluster && Array.isArray(cluster.pendingNodes) ? cluster.pendingNodes : [];
  const acquiredNodes = acquires && Array.isArray(acquires.acquiredNodes) ? acquires.acquiredNodes : [];
  const acquiredByRef = new Map(acquiredNodes.filter(Boolean).map(n => [n.refId, n]));
  const bootstrapPubkey = auto && auto.bootstrapPubkey;
  const validatorMeta = new Map(((auto && Array.isArray(auto.validators)) ? auto.validators : []).filter(v => v && v.publicKey).map(v => [v.publicKey, v]));
  const managed = nodes.filter(n => !bootstrapPubkey || n.pubkey !== bootstrapPubkey);
  const statusCode = n => {
    const raw = n && n.status;
    const v = raw && typeof raw === 'object' ? raw.status : raw;
    const x = Number(v);
    return Number.isFinite(x) ? x : null;
  };
  const statusName = n => {
    const code = statusCode(n);
    return ({0:'NONE',1:'CREATED',2:'CONFIGURED',3:'ACKNOWLEDGED',4:'ADDED_TO_UNL'})[code] || (n && n.isUnl ? 'ADDED_TO_UNL' : 'UNKNOWN');
  };
  const managedWaitingMaturity = managed.filter(n => !n.isUnl && statusCode(n) === 1).length;
  const managedAcknowledged = managed.filter(n => !n.isUnl && statusCode(n) === 3).length;
  const pendingEndpointNodes = pendingNodes.map(n => {
    const acquired = acquiredByRef.get(n && n.refId) || null;
    return {
      refId: n && n.refId || null, host: n && n.host || acquired && acquired.host || null,
      aliveCheckCount: Number(n && n.aliveCheckCount || 0), acquireSentOnLcl: Number(n && n.acquireSentOnLcl || 0) || null,
      acquired: !!acquired, domain: acquired && acquired.domain || null, userPort: acquired && acquired.userPort || null,
      peerPort: acquired && (acquired.peerPort || acquired.meshPort) || null,
      gpTcp1Port: acquired && (acquired.gpTcp1Port || acquired.gpTcpPort || acquired.gptcp1 || acquired.gp_tcp_port || acquired.gp_tcp1_port) || null,
      gpUdp1Port: acquired && (acquired.gpUdp1Port || acquired.gpUdpPort || acquired.gpudp1 || acquired.gp_udp_port || acquired.gp_udp1_port) || null,
      pubkey: acquired && acquired.pubkey || null
    };
  });
  const publicNodes = nodes.map(n => {
    const meta = validatorMeta.get(n.pubkey) || {};
    return {
      pubkey: n.pubkey, isBootstrap: !!bootstrapPubkey && n.pubkey === bootstrapPubkey,
      isUnl: !!n.isUnl, signerAddress: n.signerAddress || meta.signerAddress || null, host: n.host || meta.hostAddress || null,
      domain: n.domain || meta.domain || null, userPort: n.userPort || meta.userPort || null, peerPort: n.peerPort || n.meshPort || meta.peerPort || null,
      gpTcp1Port: n.gpTcp1Port || n.gpTcpPort || meta.gpTcp1Port || null,
      gpUdp1Port: n.gpUdp1Port || n.gpUdpPort || meta.gpUdp1Port || null,
      lifeMoments: n.lifeMoments || meta.lifeMoments || null, targetLifeMoments: n.targetLifeMoments || meta.targetLifeMoments || null,
      maxLifeMoments: n.maxLifeMoments || meta.maxLifeMoments || null, status: n.status || null,
      statusCode: statusCode(n), statusName: statusName(n)
    };
  });
  const finalInventory = auto && auto.phase === 'autonomous'
    ? publicNodes.filter(n => !n.isBootstrap && n.isUnl).slice().sort((a,b)=>String(a.pubkey||'').localeCompare(String(b.pubkey||'')))
    : [];
  const finalInventoryReady = !!(auto && auto.phase === 'autonomous' && Number(auto.finalInventoryAtLcl) > 0 && finalInventory.length >= Number(auto.targetManagedNodes || 0) && finalInventory.every(n => n && n.signerAddress));
  const nplHandover = nplHandoverStatus(auto, publicNodes);
  const bootstrapHistory = readyLocalLedgerHistory();
  const bootstrapObservedLcl = bootstrapHistory.length ? Number(bootstrapHistory[bootstrapHistory.length - 1].lcl) || 0 : 0;
  return {
    stateRoot: root,
    bootstrapObservedLcl,
    readyController: { ...readyControllerAuthStatus },
    candidateProbes: liveReadyProbeSnapshot(),
    atomicMembershipTarget: atomicMembershipTarget ? { ...atomicMembershipTarget } : null,
    auto,
    autoStateView: { source:autoView.source, stale:!!autoView.stale, cachedAt:autoView.cachedAt || null },
    summary: {
      phase: auto && auto.phase || 'not-started',
      clusterNodes: nodes.length,
      managedNodes: managed.length,
      managedUnl: managed.filter(n => n.isUnl).length,
      managedSigners: managed.filter(n => n.signerAddress).length,
      nplSignerIdentities: nplHandover.ready ? nplHandover.signerCount : 0,
      managedWaitingMaturity,
      managedAcknowledged,
      pendingNodes: pendingNodes.length,
      pendingEndpointWaits: pendingEndpointNodes.filter(n => n.acquired && n.domain && n.userPort).length,
      operations: ops && Array.isArray(ops.operations) ? ops.operations.length : 0,
      pendingAcquires: acquires && Array.isArray(acquires.pendingAcquires) ? acquires.pendingAcquires.length : 0
    },
    pendingNodes: pendingEndpointNodes,
    nodes: publicNodes,
    nplHandover,
    finalInventoryReady,
    finalInventory: finalInventoryReady ? finalInventory : []
  };
}

async function generateWallet() {
  const existingCluster = localClusterStatus();
  if (existingCluster.auto && existingCluster.auto.enabled) throw new Error('This instance is already participating in an AutoCluster. Wallet generation is disabled here.');
  if (walletMeta() && secretRead(SEED_SECRET)) throw new Error('A cluster wallet already exists. Finalize it before generating another.');
  const seed = kp.generateSeed({ algorithm: 'ecdsa-secp256k1' });
  const keypair = kp.deriveKeypair(seed);
  const address = kp.deriveAddress(keypair.publicKey);
  const meta = { schema: 1, address, createdAt: Date.now(), network: settings().network };
  secretWrite(SEED_SECRET, seed);
  writeJson(WALLET_META, meta);
  logEvent('wallet-generated', { address, network: meta.network });
  // Seed is returned only by this generation call so the operator can keep an
  // offline recovery copy during the bootstrap window if desired.
  return { address, seed, createdAt: meta.createdAt };
}

async function importWalletSeed(rawSeed, replaceExisting = false) {
  const existingCluster = localClusterStatus();
  if (existingCluster.auto && existingCluster.auto.enabled) throw new Error('This instance is already participating in an AutoCluster. Cluster-wallet import is disabled after bootstrap starts.');
  const seed = clean(rawSeed, 256);
  if (!seed) throw new Error('Enter a Xahau/XRPL family seed.');
  let keypair, address;
  try {
    keypair = kp.deriveKeypair(seed);
    address = kp.deriveAddress(keypair.publicKey);
  } catch {
    throw new Error('The supplied secret seed is not a valid Xahau/XRPL family seed.');
  }
  const existing = walletMeta();
  const existingSeed = secretRead(SEED_SECRET);
  if ((existing || existingSeed) && !replaceExisting) {
    const current = existing && existing.address ? ` (${existing.address})` : '';
    const err = new Error(`A cluster wallet already exists${current}. Confirm replacement if you intentionally want to use another seed.`);
    err.code = 'WALLET_EXISTS';
    err.httpStatus = 409;
    throw err;
  }
  const meta = { schema: 1, address, createdAt: Date.now(), network: settings().network, imported: true };
  secretWrite(SEED_SECRET, seed);
  writeJson(WALLET_META, meta);
  logEvent('wallet-imported', { address, network: meta.network, replaced: !!(existing || existingSeed) });
  return { address, createdAt: meta.createdAt, imported: true, replaced: !!(existing || existingSeed) };
}

async function createTrustline() {
  const { meta, seed } = requireWalletSeed();
  const known = cachedWalletStatus(meta.address) || {
    generated: true,
    address: meta.address,
    createdAt: meta.createdAt,
    seedPresent: true,
    exists: false,
    evrTrustline: false,
    evrBalance: '0'
  };
  try {
    return await withTenant(meta.address, seed, async tenant => {
      const issuer = tenant.config.evrIssuerAddress;
      const existing = await tenant.xrplAcc.getTrustLines(evernode.EvernodeConstants.EVR, issuer);
      if (existing.length) {
        const wallet = { ...known, exists:true, evrIssuer:issuer, evrTrustline:true, evrBalance:String(existing[0].balance ?? known.evrBalance ?? '0'), ledgerStale:false, ledgerError:null };
        cacheWalletStatus(wallet);
        return { alreadyPresent:true, issuer, wallet };
      }
      const res = await tenant.xrplAcc.setTrustLine(evernode.EvernodeConstants.EVR, issuer, settings().evrTrustLimit || '1000000000');
      const wallet = { ...known, exists:true, evrIssuer:issuer, evrTrustline:true, ledgerStale:false, ledgerError:null };
      cacheWalletStatus(wallet);
      logEvent('evr-trustline-created', { address: meta.address, issuer });
      return { alreadyPresent:false, issuer, result:res, wallet };
    });
  } catch (e) {
    const text = String(e && e.message ? e.message : e || '');
    if (looksLikeFundingError(e) || /(actNotFound|account[^\n]{0,40}(not found|does not exist|not activated))/i.test(text)) {
      const wallet = cachedWalletStatus(meta.address) || known;
      const stage = wallet.exists ? 'evr-trustline' : 'wallet-activation';
      const message = wallet.exists
        ? `Xahau rejected the EVR trustline because the treasury does not have enough spendable XAH/reserve: ${text}`
        : 'Cluster wallet is not activated on Xahau yet. Send XAH to the displayed address first.';
      throw new FundingRequiredError(message, wallet, stage);
    }
    throw e;
  }
}

async function bootstrapPreflight() {
  const s = settings();
  if (!s.managedImage) throw new Error('Managed Evernode image is required. Set it to the image that contains this AutoCluster build.');
  if (!(Number(s.maxLeaseAmountEvrPerMoment) > 0)) throw new Error('Set a hard maximum lease cost (EVR per moment) before starting bootstrap.');
  if (!ALLOW_UNSAFE_SMALL && s.targetManagedNodes < 3) throw new Error('Autonomous handover requires at least 3 managed validators; 5 is the self-healing default.');
  if (s.signerQuorum > s.targetManagedNodes) throw new Error('Signer quorum cannot exceed managed node target.');
  const { meta } = requireWalletSeed();
  const wstat = await ledgerWalletStatus();
  if (!wstat.exists) throw new FundingRequiredError('Cluster wallet is not funded/activated on Xahau yet. Send XAH to the displayed address first.', wstat, 'wallet-activation');
  if (!wstat.evrTrustline) throw new Error('EVR trustline is missing. Create the trustline before starting bootstrap.');
  if (!(Number(wstat.evrBalance) > 0)) throw new FundingRequiredError('Cluster wallet has no EVR. Send EVR to the displayed cluster address before starting bootstrap.', wstat, 'evr-funding');
  if (wstat.bootstrapFundingRequired === true) {
    logFundingEvent('funding-warning', 'bootstrap-reserve', wstat, `Bootstrap reserve estimate is short by approximately ${wstat.suggestedBootstrapTopUpXah || 'an unknown amount of'} XAH. This is advisory; the ledger transaction remains authoritative.`);
  }
  return { ok:true, address:meta.address, wallet:wstat, settings:s };
}

async function startBootstrap(expectedSignerAddress = null) {
  // Bootstrap state and A's private signer are created *inside a HotPocket
  // consensus execution*. The root control plane must never inject files into
  // contract_fs/mnt/rw/state. Its only bootstrap responsibility is the
  // master-signed Xahau SignerListSet after HotPocket has exposed A's signer.
  const { meta, seed } = requireWalletSeed();
  const wstat = await ledgerWalletStatus();
  if (!wstat.exists) throw new FundingRequiredError('Cluster wallet is not funded/activated on Xahau yet. Send XAH to the displayed address first.', wstat, 'wallet-activation');
  if (!wstat.evrTrustline) throw new Error('EVR trustline is missing. Create the trustline before starting bootstrap.');
  if (!(Number(wstat.evrBalance) > 0)) throw new FundingRequiredError('Cluster wallet has no EVR. Send EVR to the displayed cluster address before starting bootstrap.', wstat, 'evr-funding');
  const local = localClusterStatus();
  const auto = local.auto;
  if (!auto || !auto.enabled) throw new Error('HotPocket has not prepared AutoCluster bootstrap state yet.');
  if (auto.phase !== 'awaiting-bootstrap-signerlist' && auto.phase !== 'growing') throw new Error(`AutoCluster cannot authorize signer A from phase ${auto.phase || 'unknown'}.`);
  const signerAddress = clean(expectedSignerAddress || auto.bootstrapSignerAddress, 128);
  if (!signerAddress || signerAddress !== auto.bootstrapSignerAddress) throw new Error('Bootstrap signer address does not match the signer prepared by HotPocket.');
  if (auto.clusterAddress !== meta.address) throw new Error('AutoCluster treasury address does not match the locally generated cluster wallet.');

  try {
    await withTenant(meta.address, seed, async tenant => {
      await tenant.xrplAcc.setSignerList([{ account: signerAddress, weight: 1 }], { signerQuorum: 1 });
    });
  } catch (e) {
    if (looksLikeFundingError(e)) {
      throw new FundingRequiredError(`Xahau rejected the bootstrap SignerListSet because the treasury does not have enough spendable XAH/reserve: ${e && e.message ? e.message : String(e)}`, await ledgerWalletStatus(), 'bootstrap-signer');
    }
    throw e;
  }
  const after = await ledgerWalletStatus();
  const sl = after.signerList;
  if (!sl || Number(sl.quorum) !== 1 || !Array.isArray(sl.signers) || !sl.signers.some(x => x.account === signerAddress && Number(x.weight) === 1)) {
    throw new Error('SignerListSet was submitted but the expected bootstrap signer is not visible on the cluster wallet yet.');
  }
  logEvent('bootstrap-signer-authorized', { address: meta.address, bootstrapSignerAddress: signerAddress });
  return { ok:true, bootstrapSignerAddress: signerAddress, signerList: sl };
}

async function finalizeHandover() {
  const meta = walletMeta();
  if (!meta || !meta.address) throw new Error('No cluster wallet has been generated.');
  const seed = secretRead(SEED_SECRET);
  const local = localClusterStatus();
  const auto = local.auto;
  if (!auto || !['signing','ready-to-handover','handover','autonomous'].includes(auto.phase)) throw new Error(`Cluster is not ready for handover (phase=${auto && auto.phase || 'none'}).`);
  const handoverTarget = Math.max(1, Number(auto.targetManagedNodes || 1));
  const frozenPubkeys = Array.isArray(auto.handoverSignerPubkeys) ? [...new Set(auto.handoverSignerPubkeys.map(x => String(x || '').trim().toLowerCase()).filter(Boolean))].sort() : [];
  if (frozenPubkeys.length !== handoverTarget) {
    throw new Error(`Waiting for frozen final managed signer set (${frozenPubkeys.length}/${handoverTarget}). Bootstrap A remains in the temporary bridge.`);
  }
  const managedNodes = (local.nodes || []).filter(n => n && !n.isBootstrap && n.pubkey);
  const byPubkey = new Map(managedNodes.map(n => [String(n.pubkey || '').toLowerCase(), n]));
  const managed = frozenPubkeys.map(pk => byPubkey.get(pk)).filter(Boolean);
  if (managed.length !== handoverTarget) {
    throw new Error(`Frozen final managed set is incomplete in local cluster state (${managed.length}/${handoverTarget}).`);
  }
  if (managed.some(n => !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')))) {
    const missing = managed.filter(n => !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || ''))).map(n => n.pubkey);
    throw new Error(`Waiting for signed pre-UNL managed signer identities (${handoverTarget - missing.length}/${handoverTarget}); missing=[${missing.join(',')}].`);
  }
  const signerMappings = managed.map(n => ({ pubkey:String(n.pubkey || '').toLowerCase(), signerAddress:n.signerAddress }));
  if (signerMappings.length !== handoverTarget) throw new Error(`Final handover requires exactly ${handoverTarget} managed signer identities; found ${signerMappings.length}.`);
  if (new Set(signerMappings.map(m => m.signerAddress)).size !== signerMappings.length) throw new Error('Final handover signer identities must be unique.');
  const signerList = signerMappings.map(n => ({ account: n.signerAddress, weight: 1 }));
  if (auto.signerQuorum < 1 || auto.signerQuorum > signerList.length) throw new Error('Invalid final signer quorum.');

  // Never perform the irreversible signer-list + DisableMaster handover while the
  // managed validators are still poorly connected beside Bootstrap A. Require every
  // frozen final managed validator to report the full committed temporary bridge UNL,
  // synced/non-weak status, and the required live peer count.
  // The peer safety threshold intentionally
  // matches the configured signer/consensus quorum instead of demanding a full
  // all-to-all mesh.
  if (!['handover','autonomous'].includes(auto.phase)) {
    const mesh = await verifyManagedPeerMesh(local, { log:true });
    if (!mesh.ok) {
      const detail = mesh.nodes.map(n => `${String(n.pubkey||'unknown').slice(0,12)}:${n.ok ? 'ready' : ((n.reasons&&n.reasons.join(',')) || n.reason || 'not-ready')}`).join(' ');
      throw new Error(`Managed validator peer mesh is not ready for irreversible handover (${detail || mesh.reason}). Bootstrap A will remain in the UNL and retry safely.`);
    }
  }

  // Idempotent retry after a successful DisableMaster: the master seed is
  // intentionally gone, but the browser may still need to submit the final
  // consensus confirmation that authorizes Bootstrap A removal.
  if (!seed) {
    const already = await ledgerWalletStatus();
    // A browser retry can arrive after Bootstrap A has already retired and the
    // autonomous cluster has normalized the signer list from the original four
    // handover signers to all managed validators. Accept either validated shape
    // as long as DisableMaster is on-ledger and the signers are exactly managed
    // validator identities known by the current cluster state.
    const activeManagedSigners = (local.nodes || [])
      .filter(n => !n.isBootstrap && n.isUnl && n.signerAddress)
      .slice(0, Math.max(1, Number(auto.targetManagedNodes || 1)))
      .map(n => ({ account:n.signerAddress, weight:1 }));
    const validatedSignerState = signerListMatches(already, signerList, auto.signerQuorum) ||
      (activeManagedSigners.length >= auto.signerQuorum && signerListMatches(already, activeManagedSigners, auto.signerQuorum));
    if (already.masterDisabled && validatedSignerState && rewardTrackingInitialized(already)) {
      return { ok:true, pending:false, finalizedAlready:true, address:meta.address, masterSeedDeleted:true, signerQuorum:auto.signerQuorum, signers:(activeManagedSigners.length ? activeManagedSigners : signerList), signerMappings, message:'DisableMaster, reward tracking, and a managed-validator signer list are already validated. Submit the AutoCluster handover confirmation if Bootstrap A has not retired yet.' };
    }
    if (already.masterDisabled && validatedSignerState && !rewardTrackingInitialized(already)) {
      throw new Error('Cluster master seed is unavailable and DisableMaster is already validated, but Xahau reward tracking fields are missing. The new handover invariant cannot initialize ClaimReward with A after master-key deletion; do not remove Bootstrap A automatically.');
    }
    throw new Error('Cluster master seed is unavailable, but the validated ledger does not yet show reward tracking + a managed-validator signer list + DisableMaster state. Do not remove Bootstrap A.');
  }

  // Step 6 is intentionally resumable. SignerListSet changes authorization and
  // may return terQUEUED during ledger load. Never interpret that provisional
  // code as a failure, never submit ClaimReward/DisableMaster behind it, and never
  // erase the master seed until signer list, reward tracking, and DisableMaster are
  // all visibly validated on-ledger.
  let wallet = await ledgerWalletStatus();
  let pending = readHandoverPending();
  const desiredVisible = signerListMatches(wallet, signerList, auto.signerQuorum);

  if (!desiredVisible) {
    if (pending && pending.stage === 'final-signer-list' && Date.now() - Number(pending.submittedAt || 0) < HANDOVER_QUEUE_HOLD_MS) {
      return { ok:true, pending:true, stage:'final-signer-list', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Final SignerListSet is still awaiting Xahau validation (previous submission was queued/pending). No duplicate transaction was submitted.' };
    }
    try {
      await withTenant(meta.address, seed, async tenant => {
        await tenant.xrplAcc.setSignerList(signerList, { signerQuorum: auto.signerQuorum });
      });
    } catch (e) {
      if (looksLikeTerQueued(e)) {
        writeHandoverPending('final-signer-list', { signerQuorum:auto.signerQuorum, signers:signerList.map(s=>s.account), reason:String(e && e.message || e) });
        logEvent('handover-signerlist-queued', { address:meta.address, quorum:auto.signerQuorum });
        return { ok:true, pending:true, stage:'final-signer-list', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Xahau returned terQUEUED for the final SignerListSet. This is provisional; waiting for validation without resubmitting.' };
      }
      if (looksLikeFundingError(e)) throw new FundingRequiredError(`Xahau rejected the final SignerListSet because the treasury needs more spendable XAH/reserve: ${e && e.message ? e.message : String(e)}`, await ledgerWalletStatus(), 'final-signer-list');
      throw e;
    }
    wallet = await ledgerWalletStatus();
    if (!signerListMatches(wallet, signerList, auto.signerQuorum)) {
      writeHandoverPending('final-signer-list', { signerQuorum:auto.signerQuorum, signers:signerList.map(s=>s.account), reason:'submitted-not-yet-visible' });
      return { ok:true, pending:true, stage:'final-signer-list', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Final SignerListSet was submitted but is not validated/visible yet. Waiting without submitting DisableMaster.' };
    }
    clearHandoverPending();
    pending = null;
  } else if (pending && pending.stage === 'final-signer-list') {
    clearHandoverPending();
    pending = null;
  }

  // The final managed SignerListSet is now confirmed, while A's treasury master
  // key is still enabled. Make ClaimReward the FIRST transaction after that
  // authorization change so Balance Adjustment tracking is initialized before
  // DisableMaster. This transaction is intentionally master-signed by A; later
  // periodic claims can be performed through the managed signer list.
  if (!rewardTrackingInitialized(wallet)) {
    pending = readHandoverPending();
    if (pending && pending.stage === 'claim-reward-validated') {
      return { ok:true, pending:true, stage:'claim-reward', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Initial ClaimReward validated previously; waiting for RewardLgrFirst/RewardLgrLast/RewardTime/RewardAccumulator to become visible before DisableMaster.' };
    }
    if (pending && pending.stage === 'claim-reward' && Date.now() - Number(pending.submittedAt || 0) < HANDOVER_QUEUE_HOLD_MS) {
      return { ok:true, pending:true, stage:'claim-reward', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Initial master-signed ClaimReward is still awaiting Xahau validation/visibility. DisableMaster has not been submitted.' };
    }
    try {
      const claim = await withTenant(meta.address, seed, async tenant => {
        return await submitMasterSignedInitialClaimReward(tenant, meta.address);
      });
      const claimId = claim && claim.result && (claim.result.id || claim.result.hash) || null;
      logEvent('handover-initial-claimreward-validated', { address:meta.address, txId:claimId, issuer:XAHAU_GENESIS_REWARD_ISSUER });
      wallet = await ledgerWalletStatus();
      if (!rewardTrackingInitialized(wallet)) {
        writeHandoverPending('claim-reward-validated', { txId:claimId, reason:'tesSUCCESS-but-reward-fields-not-yet-visible' });
        return { ok:true, pending:true, stage:'claim-reward', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, txId:claimId, message:'Initial ClaimReward validated with the master key, but reward tracking fields are not visible yet. Waiting before DisableMaster; no duplicate ClaimReward will be submitted.' };
      }
      clearHandoverPending();
      pending = null;
    } catch (e) {
      if (looksLikeTerQueued(e)) {
        writeHandoverPending('claim-reward', { reason:String(e && e.message || e) });
        logEvent('handover-initial-claimreward-queued', { address:meta.address, issuer:XAHAU_GENESIS_REWARD_ISSUER });
        return { ok:true, pending:true, stage:'claim-reward', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Xahau returned terQUEUED for the initial master-signed ClaimReward. Waiting for reward tracking visibility; DisableMaster has NOT been submitted.' };
      }
      if (looksLikeFundingError(e)) throw new FundingRequiredError(`Xahau rejected the initial ClaimReward because the treasury needs more spendable XAH for the transaction fee: ${e && e.message ? e.message : String(e)}`, await ledgerWalletStatus(), 'claim-reward');
      throw e;
    }
  } else if (pending && (pending.stage === 'claim-reward' || pending.stage === 'claim-reward-validated')) {
    clearHandoverPending();
    pending = null;
  }

  // Reward tracking and the final managed signer list are now prepared, but
  // Bootstrap A MUST leave HotPocket consensus before the irreversible master-key
  // disable. All target managed validators are already in the temporary bridge, so
  // A's final consensus operation is simply REMOVE_UNL(A), submitted as an
  // authenticated HotPocket user input. Only after hp.cfg proves A is absent may
  // this root process touch DisableMaster.
  const committedUnl = [...new Set(hpUnl(readHpCfg() || {}).map(cleanPublicKey).filter(Boolean))].sort();
  const bootstrapPubkey = cleanPublicKey(auto.bootstrapPubkey);
  const bootstrapRemoved = !!(bootstrapPubkey && committedUnl.length && !committedUnl.includes(bootstrapPubkey));
  if (!bootstrapRemoved) {
    clearHandoverPending();
    return {
      ok:true,
      pending:false,
      stage:'ready-for-bootstrap-removal',
      readyForBootstrapRemoval:true, readyForBootstrapSwap:false,
      address:meta.address,
      masterDisabled:false,
      signerQuorum:auto.signerQuorum,
      signers:signerList,
      signerMappings,
      message:'Final managed signer list and reward tracking are validated. All managed validators are already in UNL. DisableMaster is intentionally blocked until HotPocket consensus removes Bootstrap A.'
    };
  }

  // Bootstrap A is no longer a validator. DisableMaster is now the final local
  // treasury action and can no longer affect HotPocket consensus membership.
  // Keep the normal queued/pending treatment for the irreversible Xahau change.
  if (!wallet.masterDisabled) {
    pending = readHandoverPending();
    if (pending && pending.stage === 'disable-master' && Date.now() - Number(pending.submittedAt || 0) < HANDOVER_QUEUE_HOLD_MS) {
      return { ok:true, pending:true, stage:'disable-master', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'DisableMaster is still awaiting Xahau validation. The master seed remains stored and no duplicate transaction was submitted.' };
    }
    try {
      await withTenant(meta.address, seed, async tenant => {
        await tenant.xrplAcc.setAccountFields({ Flags: { asfDisableMaster: true } });
      });
    } catch (e) {
      if (looksLikeTerQueued(e)) {
        writeHandoverPending('disable-master', { reason:String(e && e.message || e) });
        logEvent('handover-disablemaster-queued', { address:meta.address });
        return { ok:true, pending:true, stage:'disable-master', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'Xahau returned terQUEUED for DisableMaster. Waiting for validation; the master seed has NOT been deleted.' };
      }
      throw e;
    }
    wallet = await ledgerWalletStatus();
    if (!wallet.masterDisabled) {
      writeHandoverPending('disable-master', { reason:'submitted-not-yet-visible' });
      return { ok:true, pending:true, stage:'disable-master', address:meta.address, signers:signerList.map(s=>s.account), signerMappings, message:'DisableMaster was submitted but is not validated/visible yet. The master seed remains stored.' };
    }
  }

  clearHandoverPending();
  secretRemove(SEED_SECRET);
  logEvent('handover-finalized', { address: meta.address, quorum: auto.signerQuorum, signers: signerList.map(s => s.account) });
  return { ok: true, pending:false, address: meta.address, masterSeedDeleted: true, signerQuorum: auto.signerQuorum, signers: signerList, signerMappings };
}

async function recentEvents() {
  try {
    const lines = fs.readFileSync(EVENTS_FILE, 'utf8').trim().split('\n').filter(Boolean).slice(-50);
    return lines.map(x => { try { return JSON.parse(x); } catch { return { raw: x }; } }).reverse();
  } catch { return []; }
}

function clusterDiagnostics() {
  const files = [
    '/contract/log/contract/rw.stdout.log',
    '/contract/log/contract/rw.stderr.log',
    '/contract/log/hp.log',
    '/var/log/supervisor/hotpocket.out.log',
    '/var/log/supervisor/hotpocket.err.log',
    '/var/log/supervisor/eversmartnode.out.log',
    '/var/log/supervisor/eversmartnode.err.log'
  ];
  const interesting = [];
  const readiness = [];
  for (const file of files) {
    const t = tailFile(file, 48 * 1024);
    if (!t.available || !t.content) continue;
    for (const line of t.content.split(/\r?\n/)) {
      const v = line.trim();
      if (!v) continue;
      const rec = { source:path.basename(file), line:v.slice(0, 1600) };
      if (/(READY-PROBE|CLIENT-STAT READY|candidate stat probe|READY stat candidate|VALIDATOR_READY|canonical READY|VERIFIED CLIENT-STAT READY)/i.test(v)) {
        readiness.push(rec);
        continue;
      }
      if (/(AutoCluster|EverPocket|Growing the cluster|Acquiring a new node|pending acquire|lease|vacant host|Transaction failed|tec[A-Z_]+|ter[A-Z_]+|insuff|reserve|fee|error|failed|Bad MAC|decrypt|decryption|ciphertext|authentication tag)/i.test(v))
        interesting.push(rec);
    }
  }
  const lines = interesting.slice(-80);
  const readyLines = readiness.slice(-50);
  const joined = lines.map(x => x.line).join('\n');
  const fundingError = /(tecINSUFFICIENT_RESERVE|tecINSUF_RESERVE|tecNO_LINE_INSUF_RESERVE|tecINSUFF_FEE|terINSUF_FEE|tecUNFUNDED|insufficient[^\n]*(xah|reserve|fee|balance|fund)|not enough[^\n]*(xah|reserve|fee|balance|fund)|unfunded)/i.test(joined);
  const historicalBadMac = /(Bad MAC|MAC check[^\n]*fail|decrypt(?:ion)?[^\n]*fail|ciphertext[^\n]*(invalid|fail))/i.test(joined);
  // Log tails are historical and can retain a Bad MAC long after a later
  // acquisition has succeeded. Only an explicit current AutoCluster blocker is
  // allowed to promote that history into an active UI warning.
  const root = stateRoot();
  const auto = root ? (readJson(path.join(root, 'autocluster.state.json'), null) || readJson(path.join(root, 'autocluster.json'), null)) : null;
  const badMac = !!(auto && auto.blocker && auto.blocker.type === 'encryption');
  return { fundingError, badMac, historicalBadMac, lines, readyLines };
}

// ---------------------------------------------------------------------------
// Native HTTPS + static frontend serving; no secondary web-server layer.
// ---------------------------------------------------------------------------
const VERSION = '1.7.0-alpha.53.95-purity-fence-handover';
const TEMPLATE_ROOT = '/opt/eversmartnode/contract';
const TLS_CERT = process.env.EVERSMARTNODE_TLS_CERT || '/contract/cfg/tlscert.pem';
const TLS_KEY = process.env.EVERSMARTNODE_TLS_KEY || '/contract/cfg/tlskey.pem';
const STATIC_RESERVED_TOP_LEVEL = new Set([
  'index.js','sidedish.js','cluster-controller.js','contract.deploy.json','everadmin.package.json','admin-auth.json','.upload-sessions.json',
  'unl-metadata.json','unl-prune-state.json','removed-unls.json','custom-fields.json','runtime-package-state.json',
  'autocluster.state.json','autocluster.json','cluster.json','operations.json','acquires.json','contract-versions','.contract-version-uploads',
  '.runtime-package-uploads','runtime-upgrade-snapshots','.web-uploads','.public-uploads'
]);
const MIME = {
  '.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.mjs':'application/javascript; charset=utf-8',
  '.json':'application/json; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg',
  '.ico':'image/x-icon','.css':'text/css; charset=utf-8','.md':'text/markdown; charset=utf-8','.txt':'text/plain; charset=utf-8',
  '.pdf':'application/pdf','.wasm':'application/wasm'
};
function staticRelativePath(pathname) {
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return null; }
  if (decoded === '/') return 'index.html';
  if (decoded === '/evernode' || decoded === '/evernode/') return 'evernode.html';
  decoded = decoded.replace(/^\/+/, '');
  if (!decoded || decoded.includes('\\') || decoded.includes('\0')) return null;
  const normalized = path.posix.normalize(decoded);
  if (normalized === '..' || normalized.startsWith('../') || path.posix.isAbsolute(normalized)) return null;
  const parts = normalized.split('/');
  if (parts.some(p => !p || p === '.' || p === '..' || p.startsWith('.'))) return null;
  if (STATIC_RESERVED_TOP_LEVEL.has(parts[0])) return null;
  return normalized;
}
function candidateStaticRoots(rel) {
  // HotPocket's live contract state is the authoritative source for the web UI,
  // including index.html and evernode.html. The image copy is bootstrap/recovery
  // fallback only, used when a requested public file does not yet exist in state.
  const roots = [];
  const sr = stateRoot();
  if (sr) roots.push(sr);
  roots.push(TEMPLATE_ROOT);
  return [...new Set(roots)];
}
function resolveStatic(rel) {
  for (const root of candidateStaticRoots(rel)) {
    try {
      const base = path.resolve(root);
      const file = path.resolve(base, rel);
      if (file !== base && !file.startsWith(base + path.sep)) continue;
      const st = fs.lstatSync(file);
      if (!st.isFile() || st.isSymbolicLink() || st.size > 16 * 1024 * 1024) continue;
      return { file, st };
    } catch {}
  }
  return null;
}
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  const rel = staticRelativePath(pathname);
  if (!rel) return false;
  const found = resolveStatic(rel);
  if (!found) return false;
  const type = MIME[path.extname(rel).toLowerCase()] || 'application/octet-stream';
  const headers = {
    'Content-Type': type,
    'Content-Length': found.st.size,
    'Cache-Control': rel.endsWith('.html') || rel.endsWith('.json') || rel.endsWith('service-worker.js') ? 'no-store' : 'public, max-age=300',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer'
  };
  res.writeHead(200, headers);
  if (req.method === 'HEAD') return res.end();
  const stream = fs.createReadStream(found.file);
  stream.on('error', () => { if (!res.headersSent) res.writeHead(500); res.end(); });
  stream.pipe(res);
  return true;
}

// ---------------------------------------------------------------------------
// Native Node.js recovery/runtime implementation. This must work even when
// HotPocket consensus itself is unhealthy.
// ---------------------------------------------------------------------------
const RECOVERY_PROTOCOL = 'everadmin-recovery-v1';
const SIGNER_ENVELOPE_PREFIX = 'evadmin:v1:';
const SIGNER_OTP_WINDOW_STEPS = 5;
const TOTP_STEP_SECONDS = 30;
const MAX_RECOVERY_BODY = 131072;
const MAX_RECOVERY_PAYLOAD = 65536;
const MAX_LOG_BYTES = 196608;
const MAX_CLOCK_SKEW_MS = 120000;
const CHALLENGE_TTL_MS = 300000;
const RECOVERY_TOKEN_TTL_MS = 600000;
const CHALLENGES_FILE = path.join(DATA_DIR, 'recovery-challenges.json');
const NONCES_FILE = path.join(DATA_DIR, 'recovery-nonces.json');
const RECOVERY_BACKUP_DIR = path.join(DATA_DIR, 'recovery-backups');

function nowMs() { return Date.now(); }
function cleanPublicKey(value) {
  let key = String(value == null ? '' : value).trim().toLowerCase();
  if (/^ed[0-9a-f]{64}$/.test(key)) return key;
  if (/^[0-9a-f]{64}$/.test(key)) return `ed${key}`;
  return null;
}
function validGuid(value) {
  const id = String(value == null ? '' : value).trim().toLowerCase();
  return /^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id) ? id : null;
}
function validPeer(value) {
  const peer = String(value == null ? '' : value).trim();
  if (!peer || peer.length > 320 || /\s|[/?#]/.test(peer) || peer.includes('://')) return null;
  let host, port;
  if (peer.startsWith('[')) {
    const m = peer.match(/^\[([0-9a-fA-F:]+)\]:(\d{1,5})$/);
    if (!m) return null;
    host = m[1].toLowerCase(); port = Number(m[2]);
    if (!host.includes(':')) return null;
    return port >= 1 && port <= 65535 ? `[${host}]:${port}` : null;
  }
  const pos = peer.lastIndexOf(':');
  if (pos < 1 || peer.indexOf(':') !== pos) return null;
  host = peer.slice(0, pos).trim().toLowerCase(); port = Number(peer.slice(pos + 1));
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return null;
  return port >= 1 && port <= 65535 ? `${host}:${port}` : null;
}
function validPort(value) {
  const p = Number(value);
  return Number.isInteger(p) && p >= 1 && p <= 65535 ? p : null;
}
function tailFile(file, maxBytes = MAX_LOG_BYTES) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink()) return { available:false, path:file, content:'' };
    const read = Math.min(st.size, maxBytes);
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(read);
      if (read) fs.readSync(fd, buf, 0, read, st.size - read);
      return { available:true, path:file, size:st.size, truncated:st.size > read, content:buf.toString('utf8') };
    } finally { fs.closeSync(fd); }
  } catch { return { available:false, path:file, content:'' }; }
}
function runtimeStatus() {
  // user.port and mesh.port are node-local HotPocket configuration and are
  // available before the contract has produced unl-health.json. Prefer the
  // health snapshot when present, but always fall back to hp.cfg so the
  // browser can discover the websocket port on a fresh bootstrap instance.
  const cfg = readHpCfg() || {};
  const cfgUser = cfg.user && typeof cfg.user === 'object' ? cfg.user : {};
  const cfgMesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
  const cfgNode = cfg.node && typeof cfg.node === 'object' ? cfg.node : {};
  let localUserPort = validPort(cfgUser.port);
  let localMeshPort = validPort(cfgMesh.port);
  let localKey = cleanPublicKey(cfgNode.public_key || cfgNode.publicKey || cfg.public_key || cfg.publicKey);
  let updatedAt = null;
  let validators = [];
  let source = '/contract/cfg/hp.cfg';

  const sr = stateRoot();
  if (sr) {
    const healthFile = path.resolve(sr, '..', 'unl-health.json');
    const localRoot = path.resolve(sr, '..');
    if (healthFile.startsWith(localRoot + path.sep)) {
      const decoded = readJson(healthFile, null);
      if (decoded && typeof decoded === 'object') {
        source = '../unl-health.json + /contract/cfg/hp.cfg';
        const reporter = cleanPublicKey(decoded.reporterPublicKey);
        const localRuntime = decoded.localRuntime && typeof decoded.localRuntime === 'object' ? decoded.localRuntime : {};
        localKey = cleanPublicKey(localRuntime.nodePublicKey) || reporter || localKey;
        localUserPort = validPort(localRuntime.userPort) || localUserPort;
        localMeshPort = validPort(localRuntime.meshPort) || localMeshPort;
        updatedAt = Number(localRuntime.updatedAt || decoded.runtimeUpdatedAt) || null;
        const observations = decoded.observations && typeof decoded.observations === 'object' ? decoded.observations : {};
        validators = Object.entries(observations).map(([publicKey, observation]) => {
          const key = cleanPublicKey(publicKey); if (!key || !observation || typeof observation !== 'object') return null;
          const status = ['alive','silent','unknown'].includes(String(observation.status || '').toLowerCase()) ? String(observation.status).toLowerCase() : 'unknown';
          return { publicKey:key, status, userPort:validPort(observation.userPort), meshPort:validPort(observation.meshPort), observedAt:Number(observation.observedAt) || null };
        }).filter(Boolean).sort((a,b) => a.publicKey.localeCompare(b.publicKey));
        if (!localUserPort && localKey) {
          const mine = validators.find(v => v.publicKey === localKey && v.userPort);
          if (mine) { localUserPort = mine.userPort; if (!localMeshPort) localMeshPort = mine.meshPort; }
        }
      }
    }
  }
  return { ok:!!localUserPort, source, localNodePublicKey:localKey, localUserPort, localMeshPort, updatedAt, validators };
}
function hpConfigSummary() {
  const file = '/contract/cfg/hp.cfg';
  const cfg = readJson(file, null);
  if (!cfg) return { available:false, path:file };
  const contract = cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : {};
  const mesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
  const node = cfg.node && typeof cfg.node === 'object' ? cfg.node : cfg;
  const discovery = mesh.peer_discovery && typeof mesh.peer_discovery === 'object' ? mesh.peer_discovery : {};
  const user = cfg.user && typeof cfg.user === 'object' ? cfg.user : {};
  return {
    available:true, path:file, contractId:validGuid(contract.id),
    localNodePublicKey:cleanPublicKey(node.public_key || node.publicKey),
    userPort:validPort(user.port), meshPort:validPort(mesh.port),
    unl:(Array.isArray(contract.unl) ? contract.unl : []).map(cleanPublicKey).filter(Boolean),
    knownPeers:(Array.isArray(mesh.known_peers) ? mesh.known_peers : []).map(String),
    peerDiscoveryEnabled:discovery.enabled !== false
  };
}
function pathWriteDiagnostic(file) {
  const dir = fs.existsSync(file) && fs.statSync(file).isDirectory() ? file : path.dirname(file);
  let st = null; try { st = fs.statSync(fs.existsSync(file) ? file : dir); } catch {}
  let writable = false; try { fs.accessSync(fs.existsSync(file) ? file : dir, fs.constants.W_OK); writable = true; } catch {}
  return { path:file, exists:fs.existsSync(file), directory:dir, directoryExists:fs.existsSync(dir), writable, ownerUid:st ? st.uid : null, groupGid:st ? st.gid : null, mode:st ? (st.mode & 0o7777).toString(8).padStart(4,'0') : null };
}
function restartQueueDirs() { return ['/contract/contract_fs/seed/restart-hotpocket.queue','/contract/contract_fs/mnt/rw/restart-hotpocket.queue']; }
function restartRequestCandidates() {
  const out = ['/contract/contract_fs/seed/restart-hotpocket.request','/contract/contract_fs/mnt/rw/restart-hotpocket.request'];
  const sr = stateRoot(); if (sr) out.push(path.join(path.dirname(sr), 'restart-hotpocket.request'));
  return [...new Set(out)];
}
function restartAuditCandidates(kind) {
  const name = ({ request:'restart-hotpocket.last-request.json', consumed:'restart-hotpocket.last-consumed.json', result:'restart-hotpocket.last-result.json' })[kind];
  return ['/contract/contract_fs/seed','/contract/contract_fs/mnt/rw','/contract/contract_fs'].map(r => path.join(r, name));
}
function latestJson(paths) {
  let best = null, mt = -1;
  for (const file of paths) {
    try { const st = fs.lstatSync(file); if (!st.isFile() || st.isSymbolicLink()) continue; const v = readJson(file, null); if (v && st.mtimeMs >= mt) { best = { ...v, _path:file, _mtime:Math.floor(st.mtimeMs / 1000) }; mt = st.mtimeMs; } } catch {}
  }
  return best;
}
function nativeWatcherStatus() {
  return {
    schemaVersion:3, phase:'watching', protocolVersion:3,
    capabilities:['queued-requests','recover-hotpocket','native-nodejs'],
    source:'eversmartnode-server.js', pid:process.pid, updatedAt:nowMs(),
    queueDepth:restartRequests().length
  };
}
function recoveryLog(name) {
  const map = { hp:'/contract/log/hp.log', 'contract-stdout':'/contract/log/contract/rw.stdout.log', 'contract-stderr':'/contract/log/contract/rw.stderr.log' };
  const key = Object.prototype.hasOwnProperty.call(map, String(name || '').toLowerCase()) ? String(name).toLowerCase() : 'hp';
  return { name:key, ...tailFile(map[key]) };
}
function useNonceOnce(nonce, timestamp) {
  const all = readJson(NONCES_FILE, {}) || {};
  const cutoff = nowMs() - 10 * 60 * 1000;
  for (const [k,v] of Object.entries(all)) if (Number(v) < cutoff) delete all[k];
  if (Object.prototype.hasOwnProperty.call(all, nonce)) return false;
  all[nonce] = timestamp; writeJson(NONCES_FILE, all, 0o600); return true;
}
function mutateChallenges(fn) {
  const all = readJson(CHALLENGES_FILE, {}) || {};
  const cutoff = nowMs() - Math.max(CHALLENGE_TTL_MS, RECOVERY_TOKEN_TTL_MS) - 60000;
  for (const [id,rec] of Object.entries(all)) if (!rec || Number(rec.createdAt || 0) < cutoff) delete all[id];
  const result = fn(all); writeJson(CHALLENGES_FILE, all, 0o600); return result;
}
function getChallenge(id) { return mutateChallenges(all => all[id] && typeof all[id] === 'object' ? { ...all[id] } : null); }
function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanValue = String(value || '').toUpperCase().replace(/\s+/g,'').replace(/=+$/,'');
  if (!cleanValue || !/^[A-Z2-7]+$/.test(cleanValue)) return null;
  let bits = '';
  for (const ch of cleanValue) { const idx = alphabet.indexOf(ch); if (idx < 0) return null; bits += idx.toString(2).padStart(5,'0'); }
  const out = []; for (let i=0;i+8<=bits.length;i+=8) out.push(parseInt(bits.slice(i,i+8),2));
  return Buffer.from(out);
}
function otp24FromHmac(mac) {
  const mod = 10n ** 24n; let n = 0n;
  for (const b of mac) n = (n * 256n + BigInt(b)) % mod;
  return n.toString().padStart(24,'0');
}
function signerOtpCode(secret, timeMs) {
  const key = base32Decode(secret); if (!key) return null;
  const counter = BigInt(Math.floor(timeMs / (1000 * TOTP_STEP_SECONDS)));
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(counter);
  return otp24FromHmac(crypto.createHmac('sha256', key).update(buf).digest());
}
function signerOtpCandidates(secret, timeMs) {
  const out = new Set();
  for (let i=-SIGNER_OTP_WINDOW_STEPS;i<=SIGNER_OTP_WINDOW_STEPS;i++) { const c = signerOtpCode(secret, timeMs + i*TOTP_STEP_SECONDS*1000); if (c) out.add(c); }
  return [...out];
}
function parseSignerEnvelope(input) {
  const raw = String(input || '').trim();
  if (!raw.startsWith(SIGNER_ENVELOPE_PREFIX)) throw new Error('Invalid EV Signer envelope prefix.');
  let decoded; try { decoded = Buffer.from(raw.slice(SIGNER_ENVELOPE_PREFIX.length), 'base64url').toString('utf8'); } catch { throw new Error('Invalid EV Signer envelope encoding.'); }
  let e; try { e = JSON.parse(decoded); } catch { throw new Error('Invalid EV Signer envelope encoding.'); }
  if (!e || e.v !== 1 || e.type !== 'otp-encrypted-admin-private-key' || e.alg !== 'aes-256-gcm' || e.kdf !== 'pbkdf2-sha256') throw new Error('Unsupported EV Signer envelope.');
  for (const f of ['salt','iv','authTag','ciphertext','iterations']) if (!e[f]) throw new Error(`EV Signer envelope missing ${f}.`);
  return e;
}
function decryptSignerEnvelope(secret, input, timeMs) {
  const e = parseSignerEnvelope(input);
  const salt = Buffer.from(String(e.salt), 'base64'), iv = Buffer.from(String(e.iv), 'base64'), tag = Buffer.from(String(e.authTag), 'base64'), cipherText = Buffer.from(String(e.ciphertext), 'base64');
  const iterations = Number(e.iterations);
  if (salt.length < 8 || iv.length !== 12 || tag.length !== 16 || !cipherText.length || !Number.isInteger(iterations) || iterations < 100000 || iterations > 2000000) throw new Error('Invalid EV Signer envelope fields.');
  for (const code of signerOtpCandidates(secret, timeMs)) {
    try {
      const key = crypto.pbkdf2Sync(`otp-admin-envelope-v1:${code}`, salt, iterations, 32, 'sha256');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv); decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(cipherText), decipher.final()]).toString('utf8').trim();
      if (plain) return plain;
    } catch {}
  }
  throw new Error('Envelope did not match the current signer OTP window.');
}
function normalizePrivateAndPublic(value) {
  let raw = String(value || '').trim().toLowerCase();
  if (raw.startsWith('ed') && (raw.length === 66 || raw.length === 130)) raw = raw.slice(2);
  if (!/^[0-9a-f]+$/.test(raw) || ![64,128].includes(raw.length)) throw new Error('Signer private key must be a 64-hex seed or 128-hex HotPocket private key.');
  const seed = Buffer.from(raw.slice(0,64), 'hex');
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), seed]);
  const priv = crypto.createPrivateKey({ key:pkcs8, format:'der', type:'pkcs8' });
  const pubDer = crypto.createPublicKey(priv).export({ format:'der', type:'spki' });
  const pub = Buffer.from(pubDer).subarray(-32);
  if (raw.length === 128 && !crypto.timingSafeEqual(Buffer.from(raw.slice(64),'hex'), pub)) throw new Error('Signer private key seed/public-key half mismatch.');
  return { privateKey:`ed${Buffer.concat([seed,pub]).toString('hex')}`, publicKey:`ed${pub.toString('hex')}` };
}
function verifyHeadAdminSigner(state, envelope, timeMs) {
  const users = state && state.users && typeof state.users === 'object' ? state.users : {};
  let last = null;
  for (const [id,user] of Object.entries(users)) {
    if (!user || user.active === false || user.role !== 'head-admin' || user.method !== 'everstoring' || !user.publicKey || !user.totpSecret) continue;
    try {
      let plain = decryptSignerEnvelope(String(user.totpSecret), envelope, timeMs);
      if (plain.startsWith('{')) { try { const j = JSON.parse(plain); if (j && j.adminPrivateKey) plain = String(j.adminPrivateKey); } catch {} }
      const keys = normalizePrivateAndPublic(plain); const pub = cleanPublicKey(user.publicKey);
      if (pub && pub === keys.publicKey) return { userId:String(user.id || id), user, publicKey:keys.publicKey };
    } catch (e) { last = e; }
  }
  throw new Error(last ? last.message : 'EV Signer proof did not match an active OTP-enabled head admin.');
}
function currentHeadAdmin(state, userId) {
  const users = state && state.users && typeof state.users === 'object' ? state.users : {};
  const u = users[userId]; return u && u.active !== false && u.role === 'head-admin' ? u : null;
}
function authFromRecoveryToken(state, token, now) {
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  return mutateChallenges(all => {
    for (const rec of Object.values(all)) {
      if (!rec || rec.status !== 'authorized' || Number(rec.tokenExpiresAt || 0) <= now || !rec.tokenHash || rec.tokenHash !== hash) continue;
      const uid = String(rec.userId || ''); const u = currentHeadAdmin(state, uid);
      if (u) return { userId:uid, user:u, authMethod:'ev-signer', devicePublicKey:null };
    }
    return null;
  });
}
function ed25519Verify(publicKey, message, signatureHex) {
  const raw = Buffer.from(publicKey.slice(2), 'hex');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100','hex'), raw]);
  const key = crypto.createPublicKey({ key:spki, format:'der', type:'spki' });
  return crypto.verify(null, Buffer.from(message, 'utf8'), key, Buffer.from(signatureHex, 'hex'));
}
function recoveryAuthState() {
  const sr = stateRoot(); if (!sr) throw new Error('EverAdmin authentication state is unavailable.');
  const state = readJson(path.join(sr, 'admin-auth.json'), null);
  if (!state) throw new Error('EverAdmin authentication state is unavailable.');
  return state;
}
function backupHpConfig(cfgFile, cfg, reason) {
  fs.mkdirSync(RECOVERY_BACKUP_DIR, { recursive:true, mode:0o700 });
  const file = path.join(RECOVERY_BACKUP_DIR, `hp.cfg.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.json`);
  writeJson(file, { reason, backedUpAt:nowMs(), source:cfgFile, config:cfg }, 0o600);
  return file;
}
function atomicHpConfigWrite(file, cfg) {
  let mode = 0o600; try { mode = fs.statSync(file).mode & 0o777; } catch {}
  const tmp = `${file}.eversmartnode-${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n', { mode }); fs.renameSync(tmp, file);
}
function recoveryAudit(request, result) {
  const root = restartInboxRoots().find(r => fs.existsSync(r)) || DATA_DIR;
  const rec = { schemaVersion:3, requestId:request.requestId, requestedAt:request.requestedAt, completedAt:nowMs(), request, ...result };
  safeWriteAudit(path.join(root, 'restart-hotpocket.last-request.json'), { schemaVersion:3, writtenAt:request.requestedAt, requestId:request.requestId, request });
  safeWriteAudit(path.join(root, 'restart-hotpocket.last-consumed.json'), { ...rec, phase:'consumed' });
  safeWriteAudit(path.join(root, 'restart-hotpocket.last-result.json'), rec);
  safeWriteAudit(path.join(root, 'restart-hotpocket.status.json'), { ...rec, phase:result.ok ? 'completed' : 'failed', capabilities:['queued-requests','recover-hotpocket','native-nodejs'], protocolVersion:3 });
  return rec;
}
function executeRecovery(request) {
  const action = request.action;
  if (action === 'restart-hotpocket') {
    try { const output = supervisor('restart'); return recoveryAudit(request, { ok:true, output }); }
    catch (e) { recoveryAudit(request, { ok:false, error:e.message }); throw e; }
  }
  if (action !== 'recover-hotpocket') throw new Error('Unsupported recovery request action.');
  const file = '/contract/cfg/hp.cfg'; const cfg = readJson(file, null);
  if (!cfg) throw new Error('HotPocket config /contract/cfg/hp.cfg is unavailable.');
  cfg.contract = cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : {};
  cfg.mesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
  cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
  const backupPath = backupHpConfig(file, cfg, request.recovery && request.recovery.mode || 'recovery');
  if (request.recovery && request.recovery.mode === 'self-unl') {
    const local = cleanPublicKey((cfg.node && (cfg.node.public_key || cfg.node.publicKey)) || cfg.public_key || cfg.publicKey);
    if (!local) throw new Error('Local HotPocket validator public key is unavailable.');
    cfg.contract.unl = [local]; cfg.mesh.known_peers = []; cfg.mesh.peer_discovery.enabled = false; cfg.mesh.msg_forwarding = true;
    if (!Number.isInteger(Number(cfg.mesh.peer_discovery.interval)) || Number(cfg.mesh.peer_discovery.interval) < 1) cfg.mesh.peer_discovery.interval = 10000;
  } else if (request.recovery && request.recovery.mode === 'invite') {
    const contractId = validGuid(request.recovery.contractId), trusted = cleanPublicKey(request.recovery.trustedValidatorPublicKey), peer = validPeer(request.recovery.bootstrapPeer);
    if (!contractId || !trusted || !peer) throw new Error('Invalid invite recovery parameters.');
    cfg.contract.id = contractId; cfg.contract.unl = [trusted]; cfg.mesh.known_peers = [peer]; cfg.mesh.peer_discovery.enabled = false; cfg.mesh.msg_forwarding = true;
    if (!Number.isInteger(Number(cfg.mesh.peer_discovery.interval)) || Number(cfg.mesh.peer_discovery.interval) < 1) cfg.mesh.peer_discovery.interval = 10000;
  } else throw new Error('Unsupported recovery mode.');
  atomicHpConfigWrite(file, cfg);
  try { const output = supervisor('restart'); return recoveryAudit(request, { ok:true, output, backupPath }); }
  catch (e) { recoveryAudit(request, { ok:false, error:e.message, backupPath }); throw e; }
}
function recoveryStatusPayload(auth) {
  const watcher = nativeWatcherStatus();
  return {
    ok:true, headAdmin:true, userId:auth.userId, authMethod:auth.authMethod, devicePublicKey:auth.devicePublicKey,
    watcher, watcherReady:true, recoveryWatcherReady:true, queuedRequestsSupported:true,
    queueDirs:restartQueueDirs(),
    writerDiagnostics:{ nodeEffectiveUid:typeof process.geteuid === 'function' ? process.geteuid() : null, nodeEffectiveGid:typeof process.getegid === 'function' ? process.getegid() : null, queues:restartQueueDirs().map(pathWriteDiagnostic), mailboxes:restartRequestCandidates().map(pathWriteDiagnostic) },
    requestCandidates:restartRequestCandidates(),
    lastRequestWrite:latestJson(restartAuditCandidates('request')),
    lastConsumed:latestJson(restartAuditCandidates('consumed')),
    lastResult:latestJson(restartAuditCandidates('result')),
    hpConfig:hpConfigSummary()
  };
}
function recoveryHeaders(extra = {}) {
  return { 'Access-Control-Allow-Origin':'*', 'Access-Control-Allow-Methods':'GET, POST, OPTIONS', 'Access-Control-Allow-Headers':'Content-Type, Accept, X-Admin-Key-Envelope', 'Access-Control-Max-Age':'600', 'Referrer-Policy':'no-referrer', ...extra };
}
function sendJson(res, status, body, headers = {}) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Content-Length':data.length, 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff', ...headers }); res.end(data);
}
function sendActionError(res, error, cors = {}) {
  const status = Number(error && error.httpStatus) || 400;
  const body = { ok: false, error: error && error.message ? error.message : String(error) };
  if (error && error.code) body.code = error.code;
  if (error && error.stage) body.stage = error.stage;
  if (error && error.wallet) body.wallet = error.wallet;
  if (error && error.code === 'FUNDING_REQUIRED') {
    try { logFundingEvent('funding-required', error.stage || 'funding', error.wallet || {}, body.error); } catch {}
  }
  return sendJson(res, status, body, cors);
}
async function readJsonBody(req, max = 256 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0, done = false;
    req.on('data', c => { if (done) return; size += c.length; if (size > max) { done = true; reject(new Error('Request too large.')); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => { if (done) return; try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(new Error('Invalid JSON body.')); } });
    req.on('error', e => { if (!done) reject(e); });
  });
}
async function handleRecovery(req, res, url) {
  const cors = recoveryHeaders(req.headers['access-control-request-private-network'] === 'true' ? { 'Access-Control-Allow-Private-Network':'true' } : {});
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  const now = nowMs();
  if (req.method === 'GET') {
    const challenge = String(url.searchParams.get('challenge') || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(challenge)) return sendJson(res, 400, { ok:false, error:'Invalid recovery signer challenge.' }, cors);
    const rec = getChallenge(challenge);
    if (!rec || Number(rec.expiresAt || 0) <= now) return sendJson(res, 404, { ok:false, error:'Recovery signer challenge expired or was not found.' }, cors);
    return sendJson(res, 200, { ok:true, requestId:challenge, appName:'EverSmartNode', actionName:'Authorize head-admin recovery', description:'Approve a short-lived head-admin recovery session for this EverSmartNode. No HotPocket consensus is required.', expiresAt:rec.expiresAt }, cors);
  }
  if (req.method !== 'POST') return sendJson(res, 405, { ok:false, error:'GET or POST required.' }, cors);
  let body; try { body = await readJsonBody(req, MAX_RECOVERY_BODY); } catch (e) { return sendJson(res, 413, { ok:false, error:e.message }, cors); }
  let state; try { state = recoveryAuthState(); } catch (e) { return sendJson(res, 503, { ok:false, error:e.message }, cors); }
  const queryChallenge = String(url.searchParams.get('challenge') || '').trim().toLowerCase();
  const envelope = String(req.headers['x-admin-key-envelope'] || body.adminEnvelope || '').trim();
  if (queryChallenge && envelope) {
    if (!/^[0-9a-f]{64}$/.test(queryChallenge)) return sendJson(res, 400, { ok:false, error:'Invalid recovery signer challenge.' }, cors);
    const rec = getChallenge(queryChallenge);
    if (!rec || Number(rec.expiresAt || 0) <= now) return sendJson(res, 404, { ok:false, error:'Recovery signer challenge expired or was not found.' }, cors);
    if (rec.status === 'authorized') return sendJson(res, 200, { ok:true, authorized:true, message:'This recovery challenge is already authorized.' }, cors);
    try {
      const verified = verifyHeadAdminSigner(state, envelope, now), token = crypto.randomBytes(32).toString('hex');
      mutateChallenges(all => { const r = all[queryChallenge]; if (!r) throw new Error('Recovery challenge disappeared.'); Object.assign(r, { status:'authorized', authorizedAt:now, userId:verified.userId, signerPublicKey:verified.publicKey, token, tokenHash:crypto.createHash('sha256').update(token).digest('hex'), tokenExpiresAt:now + RECOVERY_TOKEN_TTL_MS }); });
      return sendJson(res, 200, { ok:true, authorized:true, userId:verified.userId, message:'Head-admin recovery approved. Return to EverSmartNode.' }, cors);
    } catch (e) { return sendJson(res, 403, { ok:false, error:e.message }, cors); }
  }
  const action = String(body.action || '').trim().toLowerCase();
  if (action === 'create-signer-challenge') {
    const pollHash = String(body.pollHash || '').trim().toLowerCase(); if (!/^[0-9a-f]{64}$/.test(pollHash)) return sendJson(res, 400, { ok:false, error:'Invalid signer recovery poll proof.' }, cors);
    const challenge = crypto.randomBytes(32).toString('hex'), expiresAt = now + CHALLENGE_TTL_MS;
    mutateChallenges(all => { all[challenge] = { createdAt:now, expiresAt, pollHash, status:'pending' }; });
    const host = /^[a-zA-Z0-9.\-:\[\]]+$/.test(String(req.headers.host || '')) ? req.headers.host : null;
    const signUrl = host ? `https://${host}/api/recovery?challenge=${challenge}` : null;
    return sendJson(res, 200, { ok:true, challenge, signUrl, expiresAt }, cors);
  }
  if (action === 'signer-status') {
    const challenge = String(body.challenge || '').trim().toLowerCase(), pollSecret = String(body.pollSecret || '').trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(challenge) || !/^[0-9a-f]{64}$/.test(pollSecret)) return sendJson(res, 400, { ok:false, error:'Invalid signer recovery status request.' }, cors);
    const rec = getChallenge(challenge); if (!rec || Number(rec.expiresAt || 0) <= now) return sendJson(res, 404, { ok:false, error:'Recovery signer challenge expired or was not found.' }, cors);
    const proof = crypto.createHash('sha256').update(pollSecret).digest('hex'); if (proof !== rec.pollHash) return sendJson(res, 403, { ok:false, error:'Invalid recovery poll proof.' }, cors);
    if (rec.status !== 'authorized') return sendJson(res, 200, { ok:true, authorized:false, expiresAt:rec.expiresAt }, cors);
    if (Number(rec.tokenExpiresAt || 0) <= now || !rec.token) return sendJson(res, 410, { ok:false, error:'Recovery authorization token expired. Create a new signer challenge.' }, cors);
    return sendJson(res, 200, { ok:true, authorized:true, userId:rec.userId || null, signerPublicKey:rec.signerPublicKey || null, recoveryToken:rec.token, tokenExpiresAt:rec.tokenExpiresAt }, cors);
  }
  if (!['status','log','restart','recover-self','recover-invite','repair-watcher','cluster-status','cluster-settings','cluster-wallet-generate','cluster-wallet-import','cluster-wallet-trustline','cluster-bootstrap-preflight','cluster-bootstrap-start','cluster-handover-finalize'].includes(action)) return sendJson(res, 400, { ok:false, error:'Unsupported recovery action.' }, cors);
  const payloadJson = String(body.payloadJson || '{}');
  if (Buffer.byteLength(payloadJson) > MAX_RECOVERY_PAYLOAD) return sendJson(res, 413, { ok:false, error:'Recovery payload is too large.' }, cors);
  let payload; try { payload = JSON.parse(payloadJson); if (!payload || Array.isArray(payload) || typeof payload !== 'object') throw new Error(); } catch { return sendJson(res, 400, { ok:false, error:'Recovery payload must be a JSON object.' }, cors); }
  let auth = authFromRecoveryToken(state, String(body.recoveryToken || '').trim().toLowerCase(), now);
  if (!auth) {
    const devicePublicKey = cleanPublicKey(body.devicePublicKey), timestamp = Number(body.timestamp), nonce = String(body.nonce || '').trim().toLowerCase(), signatureHex = String(body.signature || '').trim().toLowerCase();
    if (!devicePublicKey || !/^[0-9a-f]{32,128}$/.test(nonce) || !/^[0-9a-f]{128}$/.test(signatureHex)) return sendJson(res, 403, { ok:false, error:'No valid recovery proof. Use an authorized browser/device key or approve recovery with EV Signer.' }, cors);
    if (!Number.isFinite(timestamp) || timestamp <= 0 || Math.abs(now - timestamp) > MAX_CLOCK_SKEW_MS) return sendJson(res, 401, { ok:false, error:'Recovery request timestamp is outside the allowed window.' }, cors);
    const devices = state.authorizedDevices && typeof state.authorizedDevices === 'object' ? state.authorizedDevices : {}, device = devices[devicePublicKey];
    if (!device || Number(device.expiresAt || 0) <= now) return sendJson(res, 403, { ok:false, error:'This browser is not currently authorized for recovery. Import its old device private key or authorize recovery with EV Signer.' }, cors);
    const userId = String(device.userId || ''), user = currentHeadAdmin(state, userId); if (!user) return sendJson(res, 403, { ok:false, error:'Recovery is restricted to head admins.' }, cors);
    const payloadHash = crypto.createHash('sha256').update(payloadJson).digest('hex'), message = `${RECOVERY_PROTOCOL}|${action}|${devicePublicKey}|${timestamp}|${nonce}|${payloadHash}`;
    let verified = false; try { verified = ed25519Verify(devicePublicKey, message, signatureHex); } catch {}
    if (!verified) return sendJson(res, 403, { ok:false, error:'Invalid recovery signature.' }, cors);
    if (!useNonceOnce(nonce, timestamp)) return sendJson(res, 409, { ok:false, error:'Recovery request nonce was already used or could not be recorded.' }, cors);
    auth = { userId, user, authMethod:'device-key', devicePublicKey };
  }
  if (action === 'cluster-status') {
    const [wallet, events] = await Promise.all([ledgerWalletStatus(), recentEvents()]);
    return sendJson(res, 200, { ok:true, version:VERSION, auth:{ userId:auth.userId, role:'head-admin', method:auth.authMethod }, settings:settings(), wallet, cluster:localClusterStatus({ displayCache:true }), runtime:runtimeStatus(), diagnostics:clusterDiagnostics(), events }, cors);
  }
  if (action === 'cluster-settings') {
    const currentCluster = localClusterStatus();
    if (currentCluster.auto && currentCluster.auto.enabled) return sendJson(res, 409, { ok:false, error:'Cluster settings are consensus state after bootstrap starts. Bootstrap parameters are locked once started.' }, cors);
    const controller = await ensureReadyControllerIdentity();
    const next = normalizeSettings({ ...payload, readyControllerPublicKey:controller.publicKey }); writeJson(SETTINGS_FILE,next);
    logEvent('settings-updated',{requestedBy:auth.userId,targetManagedNodes:next.targetManagedNodes,signerQuorum:next.signerQuorum,network:next.network,managedImage:next.managedImage,candidateReadyTimeoutMs:next.candidateReadyTimeoutMs,candidateAdmissionTimeoutMs:next.candidateAdmissionTimeoutMs,candidatePoolSize:next.candidatePoolSize,candidateSpeculativeAcquireDelayMs:next.candidateSpeculativeAcquireDelayMs,candidateReadyStaleGraceMs:next.candidateReadyStaleGraceMs,readyProbeUnreachableTimeoutMs:next.readyProbeUnreachableTimeoutMs,xahauRpcCount:next.rpcPools?.xahau?.length||0});
    return sendJson(res,200,{ok:true,settings:next},cors);
  }
  if (action === 'cluster-wallet-generate') {
    try { return sendJson(res,200,{ok:true,...await generateWallet()},cors); } catch (e) { return sendJson(res,400,{ok:false,error:e.message},cors); }
  }
  if (action === 'cluster-wallet-import') {
    try { return sendJson(res,200,{ok:true,...await importWalletSeed(payload.seed, !!payload.replaceExisting)},cors); } catch (e) { return sendActionError(res,e,cors); }
  }
  if (action === 'cluster-wallet-trustline') {
    try { return sendJson(res,200,{ok:true,...await createTrustline()},cors); } catch (e) { return sendActionError(res,e,cors); }
  }
  if (action === 'cluster-bootstrap-preflight') {
    try { return sendJson(res,200,{ok:true,...await bootstrapPreflight()},cors); } catch (e) { return sendActionError(res,e,cors); }
  }
  if (action === 'cluster-bootstrap-start') {
    try { return sendJson(res,200,{ok:true,...await startBootstrap(payload.bootstrapSignerAddress || null)},cors); } catch (e) { return sendActionError(res,e,cors); }
  }
  if (action === 'cluster-handover-finalize') {
    try { return sendJson(res,200,{ok:true,...await finalizeHandover()},cors); } catch (e) { return sendJson(res,400,{ok:false,error:e.message},cors); }
  }
  if (action === 'status') return sendJson(res, 200, recoveryStatusPayload(auth), cors);
  if (action === 'log') {
    const log = recoveryLog(payload.log || 'hp');
    return sendJson(res, 200, { ok:true, headAdmin:true, authMethod:auth.authMethod, log, fallbackStdout:log.name === 'hp' && !log.available ? tailFile('/var/log/supervisor/hotpocket.out.log') : null, fallbackStderr:log.name === 'hp' && !log.available ? tailFile('/var/log/supervisor/hotpocket.err.log') : null }, cors);
  }
  if (action === 'repair-watcher') return sendJson(res, 200, { ok:true, message:'Native EverSmartNode Node.js recovery listener is running.', watcher:nativeWatcherStatus() }, cors);
  const base = { schemaVersion:3, requestedAt:now, requestedBy:auth.userId, devicePublicKey:auth.devicePublicKey, requestId:crypto.randomBytes(16).toString('hex'), source:'eversmartnode-server.js', recoveryAuthMethod:auth.authMethod };
  try {
    if (action === 'restart') {
      const request = { ...base, action:'restart-hotpocket', reason:'head-admin recovery restart' }; const result = executeRecovery(request);
      return sendJson(res, 202, { ok:true, queued:false, action:'restart-hotpocket', requestPath:null, queueMode:'native-nodejs', writeReceipt:{ requestId:request.requestId, writtenAt:request.requestedAt }, consumed:true, watcher:nativeWatcherStatus(), result, message:'HotPocket restart was executed by the native Node.js control plane.' }, cors);
    }
    if (action === 'recover-self') {
      const request = { ...base, action:'recover-hotpocket', recovery:{ mode:'self-unl' }, reason:'head-admin sole-UNL recovery' }; const result = executeRecovery(request);
      return sendJson(res, 202, { ok:true, queued:false, action:'recover-hotpocket', mode:'self-unl', queueMode:'native-nodejs', consumed:true, result, message:'Sole-UNL recovery was applied locally and HotPocket restarted.' }, cors);
    }
    const contractId = validGuid(payload.contractId), validatorPublicKey = cleanPublicKey(payload.validatorPublicKey || payload.trustedValidatorPublicKey), bootstrapPeer = validPeer(payload.bootstrapPeer);
    if (!contractId || !validatorPublicKey || !bootstrapPeer) return sendJson(res, 400, { ok:false, error:'Invite recovery requires a valid contractId, validatorPublicKey and bootstrapPeer.' }, cors);
    const request = { ...base, action:'recover-hotpocket', recovery:{ mode:'invite', contractId, trustedValidatorPublicKey:validatorPublicKey, bootstrapPeer }, reason:'head-admin invite recovery' }; const result = executeRecovery(request);
    return sendJson(res, 202, { ok:true, queued:false, action:'recover-hotpocket', mode:'invite', queueMode:'native-nodejs', consumed:true, result, message:'Invite recovery was applied locally and HotPocket restarted.' }, cors);
  } catch (e) { return sendJson(res, 503, { ok:false, error:e.message }, cors); }
}

// Restart requests are node-local, explicit operator actions only. Never let a stale
// mailbox entry restart HotPocket during normal AutoCluster operation. Requests must
// have been created after this control-plane process started and must still be fresh.
const RESTART_WATCH_STARTED_AT = Date.now();
const RESTART_REQUEST_MAX_AGE_MS = 2 * 60 * 1000;
let restartWatchBusy = false;
function restartInboxRoots() {
  const roots = new Set(['/contract/contract_fs/mnt/rw', '/contract/contract_fs/seed']);
  const sr = stateRoot(); if (sr) roots.add(path.dirname(sr)); return [...roots];
}
function safeWriteAudit(file, value) { try { writeJson(file, value, 0o600); } catch (e) { logEvent('restart-audit-error', { file, error:e.message }); } }
function restartRequests() {
  const out = [];
  for (const root of restartInboxRoots()) {
    const direct = path.join(root, 'restart-hotpocket.request');
    try { const st = fs.lstatSync(direct); if (st.isFile() && !st.isSymbolicLink()) out.push({ file:direct, root, queue:false, mtime:st.mtimeMs }); } catch {}
    const q = path.join(root, 'restart-hotpocket.queue'); let names = []; try { names = fs.readdirSync(q); } catch { continue; }
    for (const name of names) { if (!/^[0-9a-f]{32}\.json$/i.test(name)) continue; const file = path.join(q,name); try { const st = fs.lstatSync(file); if (st.isFile() && !st.isSymbolicLink()) out.push({ file, root, queue:true, mtime:st.mtimeMs }); } catch {} }
  }
  return out.sort((a,b) => a.mtime - b.mtime);
}
function consumeRestartRequest() {
  if (restartWatchBusy) return; const item = restartRequests()[0]; if (!item) return; restartWatchBusy = true;
  try {
    const req = JSON.parse(fs.readFileSync(item.file,'utf8')); fs.rmSync(item.file,{force:true});
    if (!req || !['restart-hotpocket','recover-hotpocket'].includes(req.action)) throw new Error('Unsupported restart request action.');
    const requestedAt = Number(req.requestedAt);
    const now = nowMs();
    if (!Number.isFinite(requestedAt)) throw new Error('Restart request is missing a valid requestedAt timestamp.');
    if (requestedAt < RESTART_WATCH_STARTED_AT) throw new Error(`Stale restart request predates this control-plane process (${requestedAt} < ${RESTART_WATCH_STARTED_AT}).`);
    if (requestedAt > now + 30000) throw new Error('Restart request timestamp is unreasonably in the future.');
    if (now - requestedAt > RESTART_REQUEST_MAX_AGE_MS) throw new Error(`Restart request expired after ${RESTART_REQUEST_MAX_AGE_MS}ms.`);

    // A contract-side restart request is valid only for the exact hpcore process
    // that created it. This closes the remaining race where an old contract
    // process can leave a fresh-looking mailbox request that is consumed after
    // Supervisor has already started a replacement HotPocket process.
    const expectedPid = Number(req.expectedHpcorePid);
    const runningPid = Number(supervisor('pid'));
    if (!Number.isInteger(expectedPid) || expectedPid <= 0) throw new Error('Restart request is missing the expected HotPocket PID.');
    if (!Number.isInteger(runningPid) || runningPid <= 0) throw new Error('Current HotPocket PID is unavailable; refusing restart request.');
    if (expectedPid !== runningPid) throw new Error(`Stale restart request targets hpcore PID ${expectedPid}, but current HotPocket PID is ${runningPid}.`);

    logEvent('restart-request-accepted',{file:item.file,action:req.action,requestedAt,ageMs:Math.max(0,now-requestedAt),expectedHpcorePid:expectedPid,currentHpcorePid:runningPid});
    executeRecovery({ ...req, requestId:clean(req.requestId || path.basename(item.file,'.json'),128) || crypto.randomBytes(16).toString('hex'), requestedAt, source:req.source || (item.queue?'contract-queue':'contract-request') });
  } catch (e) { try { fs.rmSync(item.file,{force:true}); } catch {} logEvent('restart-request-rejected',{file:item.file,error:e.message}); }
  finally { restartWatchBusy = false; }
}

async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
    if (url.pathname === '/api/recovery') return await handleRecovery(req, res, url);
    if (req.method === 'GET' && url.pathname === '/api/runtime') {
      try { const status = runtimeStatus(); return sendJson(res, status.ok ? 200 : 503, status); } catch (e) { return sendJson(res, 503, { ok:false, source:'../unl-health.json', error:e.message }); }
    }
    if (url.pathname === '/api/health') return sendJson(res, 200, { ok:true, version:VERSION });
    if (url.pathname.startsWith('/api/')) {
      // Cluster-changing operations intentionally do not have a second
      // EverSmartNode password/token. They are exposed only through
      // /api/recovery where the existing EverAdmin head-admin device/signer
      // proof is verified.
      return sendJson(res,404,{error:'Not found.'});
    }
    if (serveStatic(req,res,url.pathname)) return;
    return sendJson(res,404,{error:'Not found.'});
  } catch (e) {
    const msg = e && e.message ? e.message : String(e); logEvent('server-error',{method:req.method,url:req.url,error:msg});
    if (!res.headersSent) return sendJson(res,400,{error:msg}); res.end();
  }
}

consumeRestartRequest();
setInterval(consumeRestartRequest, 750).unref();
probeReadyCandidates().catch(() => {});
setInterval(() => { probeReadyCandidates().catch(() => {}); }, (SIGNED_CANDIDATE_RELAY_MODE || NPL_READINESS_MODE) ? 4000 : 15000).unref();

const tlsOptions = { cert:fs.readFileSync(TLS_CERT), key:fs.readFileSync(TLS_KEY), minVersion:'TLSv1.2' };
const webServer = https.createServer(tlsOptions, handler);

webServer.listen(PORT, HOST, () => {
  const cfg = readHpCfg() || {};
  const hpPort = validPort(cfg.user && cfg.user.port);
  console.log(`EverSmartNode ${VERSION} listening on https://${HOST}:${PORT}`);
  console.log(`HotPocket WSS is direct: wss://<host>:${hpPort || '<user.port>'}`);
  console.log('Node.js serves the EverSmartNode web/API only; HotPocket remains on its own user.port.');
});
