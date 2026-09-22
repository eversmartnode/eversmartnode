// EverAdmin Control Plane rebuild. Modified 2026-08-30 from the supplied V6 HotPocket package; distributed with COPYING (GPL v2).
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const zlib = require('zlib');
const autoCluster = require('./cluster-controller');

const APP_VERSION = '1.7.0-alpha.53.95-purity-fence-handover';
const APP_NAME = 'EverAdmin Control Plane';
const STATE_ROOT = process.cwd();
const IMAGE_BASE_ROOT = '/opt/eversmartnode/contract';
const AUTH_FILE = path.resolve(STATE_ROOT, 'admin-auth.json');
const UPLOAD_SESSIONS_FILE = path.resolve(STATE_ROOT, '.upload-sessions.json');
const UNL_METADATA_FILE = path.resolve(STATE_ROOT, 'unl-metadata.json');
const UNL_PRUNE_FILE = path.resolve(STATE_ROOT, 'unl-prune-state.json');
const REMOVED_UNLS_FILE = path.resolve(STATE_ROOT, 'removed-unls.json');
const CUSTOM_FIELDS_FILE = path.resolve(STATE_ROOT, 'custom-fields.json');
const LOCAL_CUSTOM_FILE = path.resolve(STATE_ROOT, '..', 'custom.json');
const LOCAL_HEALTH_FILE = path.resolve(STATE_ROOT, '..', 'unl-health.json');
const LOCAL_CLUSTER_JOIN_FILE = path.resolve(STATE_ROOT, '..', 'cluster-join.json');
const LOCAL_CLUSTER_RESTART_STATUS_FILE = path.resolve(STATE_ROOT, '..', 'cluster-restart.json');
const LOCAL_HOTPOCKET_RESTART_REQUEST_FILE = path.resolve(STATE_ROOT, '..', 'restart-hotpocket.request');
const LOCAL_HOTPOCKET_RESTART_WATCHER_STATUS_FILE = path.resolve(STATE_ROOT, '..', 'restart-hotpocket.status.json');
const CONTRACT_VERSIONS_ROOT = path.resolve(STATE_ROOT, 'contract-versions');
const CONTRACT_UPLOADS_ROOT = path.resolve(STATE_ROOT, '.contract-version-uploads');
const CONTRACT_LIBRARY_ROOTS = Object.freeze({ contracts:path.resolve(STATE_ROOT,'contracts'), betacontracts:path.resolve(STATE_ROOT,'betacontracts') });
const CONTRACT_VERSIONS_INDEX_FILE = path.resolve(CONTRACT_VERSIONS_ROOT, 'versions.json');
const ACTIVE_VERSION_FILE = path.resolve(CONTRACT_VERSIONS_ROOT, 'active-version.json');
const PREVIOUS_VERSION_FILE = path.resolve(CONTRACT_VERSIONS_ROOT, 'previous-active-version.json');
const WEB_UPLOADS_ROOT = path.resolve(STATE_ROOT, '.web-uploads');
const RUNTIME_PACKAGE_UPLOADS_ROOT = path.resolve(STATE_ROOT, '.runtime-package-uploads');
const RUNTIME_UPGRADE_SNAPSHOTS_ROOT = path.resolve(STATE_ROOT, 'runtime-upgrade-snapshots');
const RUNTIME_PACKAGE_STATE_FILE = path.resolve(STATE_ROOT, 'runtime-package-state.json');
const RUNTIME_PACKAGE_MANIFEST = 'everadmin.package.json';
const HP_CFG_CANDIDATES = [...new Set([
  process.env.EVERADMIN_HP_CFG_PATH ? path.resolve(process.env.EVERADMIN_HP_CFG_PATH) : null,
  path.resolve('/contract/cfg/hp.cfg'),
  // Current Evernode/Sashimono execution layout: /contract/contract_fs/mnt/{rw|ro}/state.
  path.resolve(STATE_ROOT, '../../../../cfg/hp.cfg'),
  // Older/direct seed layout: /contract/contract_fs/seed/state.
  path.resolve(STATE_ROOT, '../../../cfg/hp.cfg')
].filter(Boolean))];

const ROLE_HEAD_ADMIN = 'head-admin';
const ROLE_ADMIN = 'admin';
const VALID_ROLES = new Set([ROLE_HEAD_ADMIN, ROLE_ADMIN]);
const PASSWORD_KEY_BYTES = 32;
const DEFAULT_AUTH_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_AUTH_TTL_SECONDS = 365 * 24 * 60 * 60;
const PASSWORD_KDF_ITERATIONS = 310000;
const TOTP_DIGITS = 6;
const TOTP_STEP_SECONDS = 30;
const EVERSTORING_OTP_DIGITS = 24;
const EVERSTORING_OTP_WINDOW_STEPS = 5;
const EVERSTORING_ENVELOPE_ITERATIONS = 300000;
const EVERSTORING_ENVELOPE_PREFIX = 'evadmin:v1:';
const HEALTH_NPL_TYPE = 'everadmin-unl-health:v1';
const CLUSTER_JOIN_SCHEMA = 2;
const MAX_PUBLIC_FILE_BYTES = 8 * 1024 * 1024;
const MAX_CONTRACT_FILE_BYTES = 25 * 1024 * 1024;
const MAX_CONTRACT_TOTAL_BYTES = 80 * 1024 * 1024;
const MAX_CONTRACT_LIBRARY_ZIP_BYTES = 100 * 1024 * 1024;
const MAX_CODE_EDITOR_BYTES = 2 * 1024 * 1024;
const MAX_RUNTIME_PACKAGE_BYTES = 100 * 1024 * 1024;
const MAX_RUNTIME_PACKAGE_FILES = 128;
const MAX_RUNTIME_PACKAGE_UNCOMPRESSED_BYTES = 120 * 1024 * 1024;
const EDITABLE_TEXT_EXTENSIONS = new Set(['.js','.mjs','.cjs','.html','.htm','.css','.json','.txt','.md','.svg','.xml','.webmanifest']);

const ADMIN_ALLOWED_ACTIONS = new Set([
  'get-diagnostics',
  'list-custom-fields',
  'get-local-custom',
  'set-custom-value',
  'append-custom-value',
  'remove-custom-item',
  'clear-custom-value',
  'auth-status',
  'load-dashboard',
  'logout-device',
  'change-password',
  'set-user-2fa'
]);

let runtime = null;

function nowMs(ctx) {
  const raw = Number(ctx && ctx.timestamp);
  if (Number.isFinite(raw) && raw > 0) return raw < 100000000000 ? Math.floor(raw * 1000) : Math.floor(raw);
  return Date.now();
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}

function writeJson(file, value) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function safeString(value, max = 4096) {
  return String(value === undefined || value === null ? '' : value).trim().slice(0, max);
}

function unique(values) {
  return [...new Set((values || []).map(v => String(v || '').trim()).filter(Boolean))];
}


function normalizeContractId(value) {
  const id = safeString(value, 128).toLowerCase();
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id)) throw new Error('Contract ID must be a HotPocket GUID.');
  return id;
}

function normalizePeerAddress(value) {
  const raw = safeString(value, 320);
  if (!raw || /[\s/?#]/.test(raw) || raw.includes('://')) throw new Error('Bootstrap peer must be host:meshPort with no URL scheme.');
  let host = '', portText = '';
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 2 || raw[end + 1] !== ':') throw new Error('IPv6 peers must use [address]:port.');
    host = raw.slice(1, end);
    portText = raw.slice(end + 2);
    if (net.isIP(host) !== 6) throw new Error('Invalid IPv6 bootstrap peer.');
    host = `[${host.toLowerCase()}]`;
  } else {
    const split = raw.lastIndexOf(':');
    if (split <= 0 || raw.indexOf(':') !== split) throw new Error('Bootstrap peer must be domain-or-IP:meshPort. Use brackets for IPv6.');
    host = raw.slice(0, split).trim().toLowerCase();
    portText = raw.slice(split + 1).trim();
    if (!host || (!net.isIP(host) && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(host))) throw new Error('Invalid bootstrap peer hostname or IP.');
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Bootstrap mesh port must be 1-65535.');
  return `${host}:${port}`;
}

function resolveWritableHpConfig() {
  const errors = [];
  for (const candidate of HP_CFG_CANDIDATES) {
    try {
      if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) continue;
      const cfg = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      return { path: candidate, cfg };
    } catch (err) { errors.push(`${candidate}: ${safeString(err && err.message, 160)}`); }
  }
  throw new Error(`Could not load local hp.cfg${errors.length ? ` (${errors.join('; ')})` : ''}.`);
}

function atomicWriteText(file, content) {
  const stat = fs.existsSync(file) ? fs.statSync(file) : null;
  const tmp = `${file}.everadmin-${process.pid}-${randomHex(5)}.tmp`;
  fs.writeFileSync(tmp, content, { mode: stat ? stat.mode : 0o600 });
  if (stat) fs.chmodSync(tmp, stat.mode);
  fs.renameSync(tmp, file);
}

function atomicWriteJson(file, value) {
  atomicWriteText(file, `${JSON.stringify(value, null, 2)}\n`);
}

function readProcInfo(pid) {
  try {
    const cmd = fs.readFileSync(`/proc/${pid}/cmdline`).toString('utf8').replace(/\0/g, ' ').trim();
    const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const ppidMatch = status.match(/^PPid:\s+(\d+)/m);
    const uidMatch = status.match(/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);
    let exe = '';
    try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch {}
    return {
      pid,
      cmd,
      exe,
      ppid: ppidMatch ? Number(ppidMatch[1]) : 0,
      uid: uidMatch ? Number(uidMatch[1]) : null,
      euid: uidMatch ? Number(uidMatch[2]) : null
    };
  } catch { return null; }
}

function findHotPocketAncestor() {
  let pid = Number(process.ppid);
  for (let depth = 0; pid > 1 && depth < 8; depth++) {
    const info = readProcInfo(pid);
    if (!info) break;
    if (/(hotpocket|hpcore|hpserver)/i.test(`${info.exe} ${info.cmd}`)) return info;
    pid = info.ppid;
  }
  return null;
}

function resolveHpcoreExecutable(hp) {
  const candidates = unique([
    hp && hp.exe,
    '/usr/local/bin/hotpocket/hpcore',
    '/usr/local/bin/hpcore',
    '/usr/bin/hpcore'
  ]);
  for (const candidate of candidates) {
    try {
      if (candidate && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK);
        return candidate;
      }
    } catch {}
  }
  return null;
}

// Ask the privileged node-local HotPocket restart watcher to restart hpcore.
// The contract intentionally stays unprivileged. It only writes a fixed request file into
// the node-local seed/RW directory (../ from state). A root-owned sibling watcher, managed
// by Supervisor, consumes this file and performs the hard-coded `supervisorctl restart hotpocket`.
function scheduleHotPocketRestart(_delaySeconds = 0, targetContractId = null, options = {}) {
  const hp = findHotPocketAncestor();
  const trackJoin = options.trackJoin !== false;
  const target = targetContractId ? normalizeContractId(targetContractId) : null;
  const requestedAt = Date.now();
  const contractUid = typeof process.getuid === 'function' ? process.getuid() : null;
  const contractEuid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  const requestPath = LOCAL_HOTPOCKET_RESTART_REQUEST_FILE;
  const base = {
    schemaVersion:5,
    strategy:'seed-restart-request',
    requestedAt,
    requestPath:'../restart-hotpocket.request',
    watcher:'eversmartnode-hotpocket-watcher',
    oldPid:hp?.pid || null,
    oldCommand:safeString(hp?.cmd || '',500) || null,
    contractUid,
    contractEuid,
    targetContractId:target,
    restartAssurance:'root-supervisor-watcher',
    command:'eversmartnode-supervisorctl restart-hotpocket'
  };

  try {
    ensureDir(path.dirname(requestPath));
    const request = {
      schemaVersion:1,
      action:'restart-hotpocket',
      requestedAt,
      targetContractId:target,
      expectedHpcorePid:hp?.pid || null
    };
    atomicWriteJson(requestPath, request);
    atomicWriteJson(LOCAL_CLUSTER_RESTART_STATUS_FILE, { ...base, phase:'restart-request-written' });

    if (trackJoin) {
      const record = readClusterJoinRecord();
      if (record) writeClusterJoinRecord({
        ...record,
        phase:'restart-requested',
        error:null,
        restart:{
          ...(record.restart||{}),
          scheduled:true,
          attempted:true,
          accepted:true,
          strategy:'seed-restart-request',
          requestPath:'../restart-hotpocket.request',
          watcher:'eversmartnode-hotpocket-watcher',
          pid:hp?.pid || null,
          command:'eversmartnode-supervisorctl restart-hotpocket',
          requestedAt,
          restartAssurance:'root-supervisor-watcher'
        }
      });
    }

    return {
      scheduled:true,
      attempted:true,
      accepted:true,
      strategy:'seed-restart-request',
      requestPath:'../restart-hotpocket.request',
      watcher:'eversmartnode-hotpocket-watcher',
      pid:hp?.pid || null,
      command:'eversmartnode-supervisorctl restart-hotpocket',
      statusPath:'../cluster-restart.json',
      restartAssurance:'root-supervisor-watcher'
    };
  } catch (err) {
    const message = safeString(`Could not write HotPocket restart request: ${err && err.message ? err.message : err}`,2500);
    atomicWriteJson(LOCAL_CLUSTER_RESTART_STATUS_FILE, { ...base, phase:'restart-request-failed', failedAt:Date.now(), error:message });
    if (trackJoin) {
      const record = readClusterJoinRecord();
      if (record) writeClusterJoinRecord({
        ...record,
        phase:'restart-required',
        error:message,
        restart:{ ...(record.restart||{}), scheduled:false, attempted:true, accepted:false, strategy:'seed-restart-request', requestPath:'../restart-hotpocket.request', error:message }
      });
    }
    return { scheduled:false, attempted:true, accepted:false, strategy:'seed-restart-request', requestPath:'../restart-hotpocket.request', reason:message, error:message, restartAssurance:'root-supervisor-watcher' };
  }
}

function readClusterJoinRecord() {
  const value = readJson(LOCAL_CLUSTER_JOIN_FILE, null);
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function writeClusterJoinRecord(value) {
  ensureDir(path.dirname(LOCAL_CLUSTER_JOIN_FILE));
  fs.writeFileSync(LOCAL_CLUSTER_JOIN_FILE, `${JSON.stringify(value, null, 2)}\n`);
}

function restoreJoinBootstrap(record) {
  if (!record || !record.rollback) throw new Error('No rollback snapshot exists.');
  const hp = resolveWritableHpConfig();
  const cfg = hp.cfg;
  cfg.contract = cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : {};
  cfg.mesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
  cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
  cfg.contract.id = normalizeContractId(record.rollback.contractId);
  cfg.contract.unl = Array.isArray(record.rollback.unl) ? record.rollback.unl.map(normalizePublicKey) : [];
  cfg.mesh.known_peers = Array.isArray(record.rollback.knownPeers) ? record.rollback.knownPeers.map(normalizePeerAddress) : [];
  cfg.mesh.peer_discovery.enabled = false;
  if (Number.isInteger(Number(record.rollback.peerDiscoveryInterval)) && Number(record.rollback.peerDiscoveryInterval) > 0) cfg.mesh.peer_discovery.interval = Number(record.rollback.peerDiscoveryInterval);
  atomicWriteJson(hp.path, cfg);
  return hp.path;
}

async function probeTcpPeer(peer, timeoutMs = 3000) {
  const normalized = normalizePeerAddress(peer);
  let host, port;
  if (normalized.startsWith('[')) {
    const end = normalized.indexOf(']'); host = normalized.slice(1, end); port = Number(normalized.slice(end + 2));
  } else {
    const split = normalized.lastIndexOf(':'); host = normalized.slice(0, split); port = Number(normalized.slice(split + 1));
  }
  return await new Promise(resolve => {
    const started = Date.now();
    const socket = net.createConnection({ host, port });
    let settled = false;
    const done = (ok, error = null) => { if (settled) return; settled = true; try { socket.destroy(); } catch {} resolve({ peer: normalized, reachable: ok, latencyMs: Date.now() - started, error }); };
    socket.setTimeout(Math.max(500, Math.min(10000, Number(timeoutMs) || 3000)));
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false, 'timeout'));
    socket.once('error', err => done(false, safeString(err && err.message, 180)));
  });
}

function readNodeRuntimeConfig() {
  const errors = [];
  let parsedFallback = null;

  for (const candidate of HP_CFG_CANDIDATES) {
    try {
      if (!fs.existsSync(candidate)) {
        errors.push(`${candidate}: not found`);
        continue;
      }
      if (!fs.statSync(candidate).isFile()) {
        errors.push(`${candidate}: not a file`);
        continue;
      }

      const cfg = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      const userPort = Number(cfg && cfg.user && cfg.user.port);
      const meshPort = Number(cfg && cfg.mesh && cfg.mesh.port);
      const result = {
        detected: true,
        configPath: candidate,
        cwd: STATE_ROOT,
        hpVersion: safeString(cfg && (cfg.hp_version || cfg.version), 64) || null,
        userPort: Number.isInteger(userPort) && userPort > 0 && userPort <= 65535 ? userPort : null,
        meshPort: Number.isInteger(meshPort) && meshPort > 0 && meshPort <= 65535 ? meshPort : null,
        nodeRole: safeString(cfg && cfg.node && cfg.node.role, 32) || null
      };

      // Prefer the first readable config that contains a valid user.port.
      if (result.userPort) return result;
      parsedFallback ||= result;
      errors.push(`${candidate}: user.port missing or invalid`);
    } catch (err) {
      errors.push(`${candidate}: ${safeString(err && err.message, 160)}`);
      // Do not stop here. Another layout candidate may be the real hp.cfg.
    }
  }

  if (parsedFallback) {
    return { ...parsedFallback, errors: errors.slice(0, 8) };
  }

  const envPort = Number(process.env.EVERADMIN_USER_PORT || process.env.EVERADMIN_HP_USER_PORT || 0);
  if (Number.isInteger(envPort) && envPort > 0 && envPort <= 65535) {
    return {
      detected: true,
      configPath: 'environment',
      cwd: STATE_ROOT,
      hpVersion: null,
      userPort: envPort,
      meshPort: null,
      nodeRole: null,
      errors: errors.slice(0, 8)
    };
  }

  return {
    detected: false,
    configPath: null,
    cwd: STATE_ROOT,
    userPort: null,
    meshPort: null,
    hpVersion: null,
    nodeRole: null,
    errors: errors.slice(0, 8)
  };
}

function assertEditableTextFile(file, rel) {
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) throw new Error('Code file not found.');
  const size = fs.statSync(file).size;
  if (size > MAX_CODE_EDITOR_BYTES) throw new Error(`File is too large for the in-browser editor (${size} bytes). Upload it as a file instead.`);
  const ext = path.extname(rel).toLowerCase();
  if (!EDITABLE_TEXT_EXTENSIONS.has(ext)) throw new Error('This file type is not available in the text editor. Upload it as a binary asset instead.');
  const buf = fs.readFileSync(file);
  if (buf.includes(0)) throw new Error('Binary files cannot be opened in the text editor.');
  return { content: buf.toString('utf8'), size, sha256: sha256Hex(buf) };
}

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

function randomHex(bytes = 16) {
  return crypto.randomBytes(bytes).toString('hex');
}

function normalizeEdHex(value, kind = 'public key') {
  let hex = String(value || '').trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error(`Invalid ${kind}.`);
  if (kind === 'public key') {
    if (hex.startsWith('ed') && hex.length >= 64 && hex.length <= 66) hex = hex.slice(2).padStart(64, '0');
    else if (hex.length >= 62 && hex.length <= 64) hex = hex.padStart(64, '0');
    else throw new Error('Invalid public key length. Expected ed + 64 hex chars.');
  } else if (kind === 'private key') {
    if (hex.startsWith('ed') && (hex.length === 66 || hex.length === 130)) hex = hex.slice(2);
    if (hex.length === 64) {
      const seed = Buffer.from(hex, 'hex');
      const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
      const keyObj = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: 'der', type: 'pkcs8' });
      const spki = crypto.createPublicKey(keyObj).export({ format: 'der', type: 'spki' });
      hex += spki.subarray(spki.length - 32).toString('hex');
    } else if (hex.length !== 128) {
      throw new Error('Invalid private key length. Use a 64-hex Ed25519 seed or a 128-hex HotPocket private key (ed prefix optional).');
    }
  }
  return `ed${hex}`;
}

function normalizePublicKey(value) {
  const key = normalizeEdHex(value, 'public key');
  if (!/^ed[0-9a-f]{64}$/.test(key)) throw new Error('Invalid public key.');
  return key;
}

function normalizePrivateKey(value) {
  const key = normalizeEdHex(value, 'private key');
  if (!/^ed[0-9a-f]{128}$/.test(key)) throw new Error('Invalid private key.');
  return key;
}

function normalizePublicKeyMaybe(value) {
  if (!value) return null;
  try {
    if (typeof value === 'string') return normalizePublicKey(value);
    if (Buffer.isBuffer(value) || value instanceof Uint8Array || Array.isArray(value)) return normalizePublicKey(Buffer.from(value).toString('hex'));
    if (value && value.data && Array.isArray(value.data)) return normalizePublicKey(Buffer.from(value.data).toString('hex'));
    if (typeof value === 'object') return normalizePublicKey(value.publicKey || value.public_key || value.pubkey || value.key || value.id || '');
  } catch { return null; }
  return null;
}

function getUserPublicKey(user) {
  const key = normalizePublicKeyMaybe(user && (user.publicKey || user.pubkey || user.key || user.id));
  if (!key) throw new Error('Could not read connected HotPocket user public key.');
  return key;
}

function normalizeRole(role) {
  const clean = safeString(role, 32).toLowerCase();
  if (!VALID_ROLES.has(clean)) throw new Error('Role must be head-admin or admin.');
  return clean;
}

function normalizeUsername(value) {
  const username = safeString(value, 64).toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(username)) throw new Error('Username must be 2-64 chars using letters, numbers, dot, underscore or hyphen.');
  return username;
}

function normalizeTtlSeconds(value) {
  const n = Number(value || DEFAULT_AUTH_TTL_SECONDS);
  if (!Number.isInteger(n) || n < 60 || n > MAX_AUTH_TTL_SECONDS) throw new Error('ttlSeconds must be between 60 seconds and 365 days.');
  return n;
}

function normalizePasswordCredential(input = {}) {
  const salt = safeString(input.passwordSalt || input.salt, 256);
  const key = safeString(input.passwordKey || input.key, 256).toLowerCase();
  if (!/^[a-zA-Z0-9+/=_-]{16,256}$/.test(salt)) throw new Error('Invalid password salt.');
  if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('Invalid password-derived key. Expected 32-byte hex.');
  return { salt, key, iterations: PASSWORD_KDF_ITERATIONS, hash: 'SHA-256' };
}

function normalizeBase32Secret(secret, min = 16) {
  const clean = safeString(secret, 256).replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  if (!new RegExp(`^[A-Z2-7]{${min},}$`).test(clean)) throw new Error('Invalid base32 secret.');
  return clean;
}

function base32ToBuffer(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = normalizeBase32Secret(base32);
  let bits = '';
  for (const ch of clean) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totpCode(secret, timeMs, digits = TOTP_DIGITS, stepSeconds = TOTP_STEP_SECONDS, algorithm = 'sha1') {
  const counter = Math.floor(Number(timeMs) / 1000 / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algorithm, base32ToBuffer(secret)).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % (10 ** digits);
  return String(code).padStart(digits, '0');
}

function verifyTotp(secret, code, timestampMs, windowSteps = 1) {
  const clean = safeString(code, 32);
  if (!new RegExp(`^[0-9]{${TOTP_DIGITS}}$`).test(clean)) return false;
  for (let i = -windowSteps; i <= windowSteps; i++) {
    if (totpCode(secret, Number(timestampMs) + i * TOTP_STEP_SECONDS * 1000) === clean) return true;
  }
  return false;
}


function defaultAuthState() {
  return { schemaVersion: 2, bootstrapComplete: false, users: {}, authorizedDevices: {}, usedNonces: {} };
}

function loadAuthState() {
  const state = readJson(AUTH_FILE, defaultAuthState());
  state.schemaVersion = 2;
  state.bootstrapComplete = !!state.bootstrapComplete;
  state.users = state.users && typeof state.users === 'object' ? state.users : {};
  state.authorizedDevices = state.authorizedDevices && typeof state.authorizedDevices === 'object' ? state.authorizedDevices : {};
  state.usedNonces = state.usedNonces && typeof state.usedNonces === 'object' ? state.usedNonces : {};
  return state;
}

function saveAuthState(state) { writeJson(AUTH_FILE, state); }

function countActiveHeadAdmins(state) {
  return Object.values(state.users || {}).filter(u => u && u.active !== false && u.role === ROLE_HEAD_ADMIN).length;
}

function normalizeUserRecord(id, record = {}) {
  return {
    id,
    method: record.method === 'everstoring' ? 'everstoring' : 'password',
    username: record.username || null,
    publicKey: record.publicKey || null,
    role: normalizeRole(record.role || ROLE_ADMIN),
    active: record.active !== false,
    password: record.password || null,
    totpSecret: record.totpSecret || null,
    createdAt: record.createdAt || null,
    createdBy: record.createdBy || null,
    updatedAt: record.updatedAt || null,
    updatedBy: record.updatedBy || null
  };
}

function publicUserRecord(record) {
  return {
    id: record.id,
    method: record.method,
    username: record.username || null,
    publicKey: record.publicKey || null,
    role: record.role,
    active: record.active !== false,
    passwordEnabled: !!(record.password && record.password.key),
    everstoringEnabled: !!record.publicKey,
    twoFactorEnabled: !!record.totpSecret,
    createdAt: record.createdAt || null,
    createdBy: record.createdBy || null,
    updatedAt: record.updatedAt || null,
    updatedBy: record.updatedBy || null
  };
}

function getUserRecord(state, userId) {
  const raw = state.users && state.users[userId];
  if (!raw) return null;
  try { return normalizeUserRecord(userId, raw); } catch { return null; }
}

function findPasswordUser(state, username) {
  const normalized = normalizeUsername(username);
  for (const [id] of Object.entries(state.users || {})) {
    const user = getUserRecord(state, id);
    if (user && user.active !== false && user.username === normalized && user.password && user.password.key) return user;
  }
  return null;
}

function ensurePasswordUsernameAvailable(state, username, exceptUserId = null) {
  const normalized = normalizeUsername(username);
  const existing = findPasswordUser(state, normalized);
  if (existing && existing.id !== exceptUserId) throw new Error('That password username is already in use.');
  return normalized;
}

function findEverstoringUserByPublicKey(state, publicKey) {
  const key = normalizePublicKey(publicKey);
  return getUserRecord(state, `ev:${key}`);
}

function getHeadAdminEverstoringPublicKey(state) {
  for (const [id, raw] of Object.entries(state.users || {})) {
    const user = getUserRecord(state, id);
    if (user && user.active !== false && user.method === 'everstoring' && user.role === ROLE_HEAD_ADMIN && user.publicKey) return user.publicKey;
  }
  return null;
}

function cleanupAuthState(state, timestampMs) {
  let changed = false;
  for (const [key, auth] of Object.entries(state.authorizedDevices || {})) {
    const user = auth && getUserRecord(state, auth.userId);
    if (!auth || !user || user.active === false || Number(auth.expiresAt || 0) <= timestampMs) {
      delete state.authorizedDevices[key];
      changed = true;
      continue;
    }
    if (auth.role !== user.role) { auth.role = user.role; changed = true; }
  }
  const cutoff = timestampMs - (7 * 24 * 60 * 60 * 1000);
  for (const [nonce, rec] of Object.entries(state.usedNonces || {})) {
    if (Number(rec && rec.usedAt || 0) < cutoff) { delete state.usedNonces[nonce]; changed = true; }
  }
  return changed;
}

function getDeviceAuth(state, publicKey, timestampMs) {
  const key = normalizePublicKey(publicKey);
  const auth = state.authorizedDevices[key];
  if (!auth || Number(auth.expiresAt || 0) <= timestampMs) return null;
  const user = getUserRecord(state, auth.userId);
  if (!user || user.active === false) return null;
  return { ...auth, role: user.role, user };
}

function revokeUserSessions(state, userId) {
  for (const [key, auth] of Object.entries(state.authorizedDevices || {})) {
    if (auth && auth.userId === userId) delete state.authorizedDevices[key];
  }
}

function passwordProofMessage(username, devicePublicKey, nonce, ttlSeconds) {
  return `everadmin-password-login-v1|${normalizeUsername(username)}|${normalizePublicKey(devicePublicKey)}|${nonce}|${ttlSeconds}`;
}

function verifyPasswordProof(user, message = {}) {
  if (!user.password || !user.password.key) throw new Error('Password login is not configured for this user.');
  const nonce = safeString(message.nonce, 128);
  if (!/^[a-fA-F0-9]{32,128}$/.test(nonce)) throw new Error('Invalid login nonce.');
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const expected = crypto.createHmac('sha256', Buffer.from(user.password.key, 'hex'))
    .update(passwordProofMessage(user.username, devicePublicKey, nonce, ttlSeconds), 'utf8')
    .digest('hex');
  const supplied = safeString(message.proof, 128).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(supplied)) return false;
  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(supplied, 'hex'));
}

function derivePublicKeyFromHotPocketPrivateKey(privateKey) {
  const clean = normalizePrivateKey(privateKey).slice(2);
  const raw = Buffer.from(clean, 'hex');
  if (raw.length !== 64) throw new Error('Invalid HotPocket private key.');
  const seed = raw.subarray(0, 32);
  const embeddedPublic = raw.subarray(32, 64);
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const keyObj = crypto.createPrivateKey({ key: Buffer.concat([pkcs8Prefix, seed]), format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(keyObj).export({ format: 'der', type: 'spki' });
  const derived = spki.subarray(spki.length - 32);
  if (!derived.equals(embeddedPublic)) throw new Error('Private key seed/public key mismatch.');
  return normalizePublicKey(derived.toString('hex'));
}

async function sendOutput(user, payload) {
  if (!runtime || !runtime.bson) throw new Error('BSON runtime is unavailable.');
  await user.send(runtime.bson.serialize(payload));
}

async function authStatus(user, message, ctx) {
  const state = loadAuthState();
  const timestampMs = nowMs(ctx);
  const changed = cleanupAuthState(state, timestampMs);
  const devicePublicKey = getUserPublicKey(user);
  const auth = getDeviceAuth(state, devicePublicKey, timestampMs);
  if (!ctx.readonly && changed) saveAuthState(state);
  const activeUsers = Object.entries(state.users || {}).map(([id]) => getUserRecord(state, id)).filter(u => u && u.active !== false);
  const methods = [];
  if (activeUsers.some(u => u.password && u.password.key)) methods.push('password');
  if (activeUsers.some(u => u.publicKey)) methods.push('everstoring');
  await sendOutput(user, {
    type: 'auth-status', actionId: message.actionId || null,
    appName: APP_NAME, appVersion: APP_VERSION,
    bootstrapComplete: state.bootstrapComplete,
    configuredMethods: methods,
    devicePublicKey,
    authorized: !!auth,
    role: auth ? auth.role : null,
    userId: auth ? auth.userId : null,
    username: auth && auth.user ? auth.user.username : null,
    authMethod: auth && auth.user ? (auth.method || auth.user.method) : null,
    expiresAt: auth ? auth.expiresAt : null,
    canManageUsers: !!auth && auth.role === ROLE_HEAD_ADMIN,
    headAdminPublicKey: getHeadAdminEverstoringPublicKey(state),
    now: timestampMs
  });
}

async function bootstrapHeadAdmin(user, message, ctx) {
  if (ctx.readonly) throw new Error('Bootstrap requires consensus input.');
  const state = loadAuthState();
  if (state.bootstrapComplete) throw new Error('Head admin is already bootstrapped.');
  const timestampMs = nowMs(ctx);
  const method = safeString(message.method, 32).toLowerCase();
  let record;
  let id;
  if (method === 'password') {
    const username = normalizeUsername(message.username || 'admin');
    id = `pwd:${username}`;
    record = {
      id, method: 'password', username, publicKey: null,
      role: ROLE_HEAD_ADMIN, active: true,
      password: normalizePasswordCredential(message),
      totpSecret: message.totpSecret ? normalizeBase32Secret(message.totpSecret) : null,
      createdAt: timestampMs, createdBy: id, updatedAt: timestampMs, updatedBy: id
    };
  } else if (method === 'everstoring') {
    const publicKey = normalizePublicKey(message.publicKey || message.headAdminPublicKey);
    id = `ev:${publicKey}`;
    const passwordRequested = !!(message.passwordKey || message.passwordSalt || message.username);
    const username = passwordRequested ? normalizeUsername(message.username || 'admin') : null;
    record = {
      id, method: 'everstoring', username, publicKey,
      role: ROLE_HEAD_ADMIN, active: true,
      password: passwordRequested ? normalizePasswordCredential(message) : null,
      totpSecret: message.totpSecret ? normalizeBase32Secret(message.totpSecret) : null,
      createdAt: timestampMs, createdBy: id, updatedAt: timestampMs, updatedBy: id
    };
  } else throw new Error('Bootstrap method must be password or everstoring.');
  state.bootstrapComplete = true;
  state.users = { [id]: record };
  state.authorizedDevices = {};
  state.usedNonces = {};
  saveAuthState(state);
  await sendOutput(user, { type: 'bootstrap-success', actionId: message.actionId || null, method, user: publicUserRecord(record), message: 'Head admin created. Sign in with the selected method.' });
}

async function passwordLoginInfo(user, message, ctx) {
  const state = loadAuthState();
  let account = null;
  try { account = findPasswordUser(state, message.username); } catch {}
  const passwordTotpSecret = account && account.method === 'password' ? account.totpSecret : null;
  await sendOutput(user, {
    type: 'password-login-info', actionId: message.actionId || null,
    found: !!account && account.active !== false && !!account.password,
    username: account && account.active !== false ? account.username : normalizeUsername(message.username),
    salt: account && account.active !== false && account.password ? account.password.salt : null,
    iterations: account && account.active !== false && account.password ? account.password.iterations : PASSWORD_KDF_ITERATIONS,
    twoFactorEnabled: !!passwordTotpSecret
  });
}

async function passwordLogin(user, message, ctx) {
  if (ctx.readonly) throw new Error('Password login requires consensus input.');
  const state = loadAuthState();
  if (!state.bootstrapComplete) throw new Error('Head admin is not bootstrapped.');
  const timestampMs = nowMs(ctx);
  cleanupAuthState(state, timestampMs);
  const account = findPasswordUser(state, message.username);
  if (!account || account.active === false) throw new Error('Invalid username or password.');
  const nonce = safeString(message.nonce, 128);
  if (!/^[a-fA-F0-9]{32,128}$/.test(nonce) || state.usedNonces[nonce]) throw new Error('Invalid or already-used login nonce.');
  if (!verifyPasswordProof(account, message)) throw new Error('Invalid username or password.');
  const passwordTotpSecret = account.method === 'password' ? account.totpSecret : null;
  if (passwordTotpSecret && !verifyTotp(passwordTotpSecret, message.totpCode, timestampMs)) throw new Error('Invalid 2FA code.');
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);
  const submitter = getUserPublicKey(user);
  const expiresAt = timestampMs + ttlSeconds * 1000;
  state.authorizedDevices[devicePublicKey] = { userId: account.id, role: account.role, approvedBy: account.id, submittedBy: submitter, method: 'password', approvedAt: timestampMs, expiresAt, nonce };
  state.usedNonces[nonce] = { usedAt: timestampMs, devicePublicKey, userId: account.id };
  saveAuthState(state);
  await sendOutput(user, { type: 'auth-success', actionId: message.actionId || null, devicePublicKey, userId: account.id, username: account.username, role: account.role, authMethod: 'password', expiresAt });
}

function everstoringProofMessage(signerPublicKey, devicePublicKey, nonce, ttlSeconds) {
  return `everadmin-everstoring-login-v1|${normalizePublicKey(signerPublicKey)}|${normalizePublicKey(devicePublicKey)}|${nonce}|${ttlSeconds}`;
}

function verifyEd25519Signature(publicKey, text, signatureHex) {
  const key = normalizePublicKey(publicKey);
  const raw = Buffer.from(key.slice(2), 'hex');
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const keyObject = crypto.createPublicKey({ key: Buffer.concat([spkiPrefix, raw]), format: 'der', type: 'spki' });
  const sig = safeString(signatureHex, 256).toLowerCase();
  if (!/^[0-9a-f]{128}$/.test(sig)) return false;
  return crypto.verify(null, Buffer.from(text, 'utf8'), keyObject, Buffer.from(sig, 'hex'));
}

function everstoringOtpCode(secret, timeMs) {
  const counter = Math.floor(Number(timeMs) / 1000 / TOTP_STEP_SECONDS);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha256', base32ToBuffer(secret)).update(counterBuffer).digest();
  let value = 0n;
  for (const byte of hmac) value = (value << 8n) + BigInt(byte);
  const modulo = 10n ** BigInt(EVERSTORING_OTP_DIGITS);
  return String(value % modulo).padStart(EVERSTORING_OTP_DIGITS, '0');
}

function everstoringOtpCandidates(secret, timestampMs) {
  const values = [];
  for (let i = -EVERSTORING_OTP_WINDOW_STEPS; i <= EVERSTORING_OTP_WINDOW_STEPS; i++) {
    values.push(everstoringOtpCode(secret, Number(timestampMs) + i * TOTP_STEP_SECONDS * 1000));
  }
  return [...new Set(values)];
}

function deriveEverstoringEnvelopeKey(otpCode, salt, iterations = EVERSTORING_ENVELOPE_ITERATIONS) {
  const code = safeString(otpCode, 64).trim();
  if (!new RegExp(`^[0-9]{${EVERSTORING_OTP_DIGITS}}$`).test(code)) throw new Error(`OTP code must be ${EVERSTORING_OTP_DIGITS} digits.`);
  const cleanIterations = Number(iterations);
  if (!Number.isInteger(cleanIterations) || cleanIterations < 100000 || cleanIterations > 2000000) throw new Error('Invalid envelope KDF iterations.');
  return crypto.pbkdf2Sync(`otp-admin-envelope-v1:${code}`, salt, cleanIterations, 32, 'sha256');
}

function parseEverstoringEnvelope(input) {
  const raw = safeString(input, 200000).trim();
  if (!raw.startsWith(EVERSTORING_ENVELOPE_PREFIX)) throw new Error(`Invalid envelope prefix. Expected ${EVERSTORING_ENVELOPE_PREFIX}`);
  const encoded = raw.slice(EVERSTORING_ENVELOPE_PREFIX.length).trim();
  if (!encoded) throw new Error('Envelope payload is empty.');
  let envelope;
  try { envelope = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')); }
  catch { throw new Error('Invalid EV Signer envelope payload.'); }
  if (!envelope || envelope.v !== 1) throw new Error('Unsupported envelope version. Expected v=1.');
  if (envelope.type !== 'otp-encrypted-admin-private-key') throw new Error('Unsupported envelope type.');
  if (envelope.alg !== 'aes-256-gcm') throw new Error('Unsupported envelope algorithm.');
  if (envelope.kdf !== 'pbkdf2-sha256') throw new Error('Unsupported envelope KDF.');
  for (const field of ['salt','iv','authTag','ciphertext','iterations']) if (!envelope[field]) throw new Error(`Envelope missing field: ${field}.`);
  return envelope;
}

function decryptEverstoringEnvelope(secret, envelopeInput, timestampMs) {
  const envelope = parseEverstoringEnvelope(envelopeInput);
  const salt = Buffer.from(envelope.salt, 'base64');
  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  if (salt.length < 8 || iv.length !== 12 || authTag.length !== 16 || !ciphertext.length) throw new Error('Invalid envelope binary fields.');
  for (const code of everstoringOtpCandidates(secret, timestampMs)) {
    try {
      const key = deriveEverstoringEnvelopeKey(code, salt, Number(envelope.iterations));
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(authTag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8').trim();
    } catch {}
  }
  throw new Error('Envelope did not match the current signer OTP window.');
}

function parseEverstoringEnvelopePayload(plaintext) {
  const raw = safeString(plaintext, 10000).trim();
  if (!raw) throw new Error('Signer envelope plaintext is empty.');
  if (!raw.startsWith('{')) return { type: 'everstoring-admin-login-v1', adminPrivateKey: raw };
  let payload;
  try { payload = JSON.parse(raw); } catch { throw new Error('Invalid signer envelope plaintext.'); }
  if (payload.type !== 'everstoring-admin-login-v1') throw new Error('Unsupported signer envelope payload type.');
  return payload;
}

function verifyEverstoringOtpEnvelope(account, message, timestampMs) {
  if (!account.totpSecret) throw new Error('Signer OTP is not configured.');
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const nonce = safeString(message.nonce, 128).trim();
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);
  const payload = parseEverstoringEnvelopePayload(decryptEverstoringEnvelope(account.totpSecret, message.adminEnvelope, timestampMs));
  if (payload.devicePublicKey && normalizePublicKey(payload.devicePublicKey) !== devicePublicKey) throw new Error('Envelope is bound to a different device public key.');
  if (payload.nonce && safeString(payload.nonce, 128).trim() !== nonce) throw new Error('Envelope nonce does not match request nonce.');
  if (payload.ttlSeconds !== undefined && normalizeTtlSeconds(payload.ttlSeconds) !== ttlSeconds) throw new Error('Envelope auth expiry does not match requested ttlSeconds.');
  const privateKey = normalizePrivateKey(payload.adminPrivateKey);
  const derivedPublicKey = derivePublicKeyFromHotPocketPrivateKey(privateKey);
  if (derivedPublicKey !== account.publicKey) throw new Error('OTP matched, but the envelope private key does not match this signer.');
  return true;
}

function findEverstoringSignerFromEnvelope(state, message, timestampMs) {
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const nonce = safeString(message.nonce, 128).trim();
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);
  const envelopeInput = safeString(message.adminEnvelope, 200000).trim();
  if (!envelopeInput) throw new Error('Missing adminEnvelope.');

  const candidates = Object.keys(state.users || {})
    .map(id => getUserRecord(state, id))
    .filter(account => account && account.active !== false && account.method === 'everstoring' && account.totpSecret && account.publicKey);

  if (!candidates.length) throw new Error('No active OTP-enabled EV Signer users are configured.');

  for (const account of candidates) {
    try {
      const payload = parseEverstoringEnvelopePayload(decryptEverstoringEnvelope(account.totpSecret, envelopeInput, timestampMs));
      if (payload.devicePublicKey && normalizePublicKey(payload.devicePublicKey) !== devicePublicKey) throw new Error('Envelope is bound to a different device public key.');
      if (payload.nonce && safeString(payload.nonce, 128).trim() !== nonce) throw new Error('Envelope nonce does not match request nonce.');
      if (payload.ttlSeconds !== undefined && normalizeTtlSeconds(payload.ttlSeconds) !== ttlSeconds) throw new Error('Envelope auth expiry does not match requested ttlSeconds.');
      const privateKey = normalizePrivateKey(payload.adminPrivateKey);
      const derivedPublicKey = derivePublicKeyFromHotPocketPrivateKey(privateKey);
      if (derivedPublicKey !== account.publicKey) throw new Error('OTP matched one signer, but the private key matched another signer.');
      return { account, payload, signerPublicKey: derivedPublicKey };
    } catch {
      // Match Sound Alive / EV Signer behavior: try each active OTP-enabled signer.
    }
  }

  throw new Error('Envelope did not match any active signer OTP/private-key pair.');
}

async function authorizeDevice(user, message, ctx) {
  if (ctx.readonly) throw new Error('Read-only mode does not allow authorization changes.');
  const state = loadAuthState();
  if (!state.bootstrapComplete) throw new Error('Head admin is not bootstrapped.');

  const timestampMs = nowMs(ctx);
  cleanupAuthState(state, timestampMs);
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const nonce = safeString(message.nonce, 128).trim();
  if (!/^[a-fA-F0-9]{32,128}$/.test(nonce)) throw new Error('Invalid nonce.');
  if (state.usedNonces[nonce]) throw new Error('Login nonce has already been used.');
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);

  const signer = findEverstoringSignerFromEnvelope(state, message, timestampMs);
  const account = signer.account;
  const submitter = getUserPublicKey(user);
  const expiresAt = timestampMs + ttlSeconds * 1000;

  state.authorizedDevices[devicePublicKey] = {
    userId: account.id,
    role: account.role,
    approvedBy: signer.signerPublicKey,
    submittedBy: submitter,
    method: 'everstoring',
    approvedAt: timestampMs,
    expiresAt,
    nonce
  };
  state.usedNonces[nonce] = {
    usedAt: timestampMs,
    devicePublicKey,
    userId: account.id,
    submittedBy: submitter,
    approvedBy: signer.signerPublicKey
  };
  saveAuthState(state);

  await sendOutput(user, {
    type: 'auth-success',
    actionId: message.actionId || null,
    devicePublicKey,
    userId: account.id,
    signerPublicKey: signer.signerPublicKey,
    approvedBy: signer.signerPublicKey,
    role: account.role,
    authMethod: 'everstoring',
    ttlSeconds,
    expiresAt,
    message: `Browser/device authorized as ${account.role}.`
  });
}

async function everstoringLoginInfo(user, message, ctx) {
  const state = loadAuthState();
  let account = null;
  try { account = findEverstoringUserByPublicKey(state, message.signerPublicKey || message.publicKey); } catch {}
  await sendOutput(user, {
    type: 'everstoring-login-info', actionId: message.actionId || null,
    found: !!account && account.active !== false,
    signerPublicKey: account && account.active !== false ? account.publicKey : null,
    twoFactorEnabled: !!(account && account.active !== false && account.totpSecret),
    loginMode: account && account.active !== false && account.totpSecret ? 'otp-envelope' : 'signature',
    envelopePrefix: EVERSTORING_ENVELOPE_PREFIX,
    otpDigits: account && account.active !== false && account.totpSecret ? EVERSTORING_OTP_DIGITS : null
  });
}

async function everstoringLogin(user, message, ctx) {
  if (ctx.readonly) throw new Error('EV Signer login requires consensus input.');
  const state = loadAuthState();
  if (!state.bootstrapComplete) throw new Error('Head admin is not bootstrapped.');
  const timestampMs = nowMs(ctx);
  cleanupAuthState(state, timestampMs);
  const signerPublicKey = normalizePublicKey(message.signerPublicKey || message.publicKey);
  const account = findEverstoringUserByPublicKey(state, signerPublicKey);
  if (!account || account.active === false) throw new Error('Unknown or inactive signer.');
  const devicePublicKey = normalizePublicKey(message.devicePublicKey);
  const nonce = safeString(message.nonce, 128);
  if (!/^[a-fA-F0-9]{32,128}$/.test(nonce) || state.usedNonces[nonce]) throw new Error('Invalid or already-used login nonce.');
  const ttlSeconds = normalizeTtlSeconds(message.ttlSeconds);
  if (account.totpSecret) {
    verifyEverstoringOtpEnvelope(account, message, timestampMs);
  } else {
    const proofText = everstoringProofMessage(signerPublicKey, devicePublicKey, nonce, ttlSeconds);
    if (!verifyEd25519Signature(signerPublicKey, proofText, message.signature)) throw new Error('Invalid EV Signer signature.');
  }
  const submitter = getUserPublicKey(user);
  const expiresAt = timestampMs + ttlSeconds * 1000;
  state.authorizedDevices[devicePublicKey] = { userId: account.id, role: account.role, approvedBy: signerPublicKey, submittedBy: submitter, method: 'everstoring', approvedAt: timestampMs, expiresAt, nonce };
  state.usedNonces[nonce] = { usedAt: timestampMs, devicePublicKey, userId: account.id };
  saveAuthState(state);
  await sendOutput(user, { type: 'auth-success', actionId: message.actionId || null, devicePublicKey, userId: account.id, signerPublicKey, role: account.role, authMethod: 'everstoring', expiresAt });
}

function ephemeralDelegationMessage(devicePublicKey, sessionPublicKey, action, actionId) {
  return `everadmin-ephemeral-session-v1|${normalizePublicKey(devicePublicKey)}|${normalizePublicKey(sessionPublicKey)}|${safeString(action,128)}|${safeString(actionId,160)}`;
}

function delegatedDeviceAuth(state, userPublicKey, message, timestampMs) {
  try {
    const d = message && message.deviceDelegation;
    if (!d || d.protocol !== 'everadmin-ephemeral-session-v1') return null;
    const sessionPublicKey = normalizePublicKey(d.sessionPublicKey);
    const actualUser = normalizePublicKey(userPublicKey);
    if (sessionPublicKey !== actualUser) return null;
    const action = safeString(message.type, 128), actionId = safeString(message.actionId, 160);
    if (!action || !actionId || safeString(d.action,128) !== action || safeString(d.actionId,160) !== actionId) return null;
    const devicePublicKey = normalizePublicKey(d.devicePublicKey);
    const auth = getDeviceAuth(state, devicePublicKey, timestampMs);
    if (!auth) return null;
    const signed = ephemeralDelegationMessage(devicePublicKey, sessionPublicKey, action, actionId);
    if (!verifyEd25519Signature(devicePublicKey, signed, d.signature)) return null;
    return { auth, devicePublicKey, sessionPublicKey };
  } catch { return null; }
}

async function requireRole(user, message, ctx, roles = [ROLE_HEAD_ADMIN, ROLE_ADMIN]) {
  const state = loadAuthState();
  if (!state.bootstrapComplete) { await sendOutput(user, { type: 'error', action: message.type, actionId: message.actionId || null, error: 'Head admin is not bootstrapped.' }); return null; }
  const timestampMs = nowMs(ctx);
  const changed = cleanupAuthState(state, timestampMs);
  const publicKey = getUserPublicKey(user);
  let auth = getDeviceAuth(state, publicKey, timestampMs);
  let delegatedFrom = null;
  if (!auth) {
    const delegated = delegatedDeviceAuth(state, publicKey, message, timestampMs);
    if (delegated) { auth = delegated.auth; delegatedFrom = delegated.devicePublicKey; }
  }
  if (!ctx.readonly && changed) saveAuthState(state);
  if (!auth) { await sendOutput(user, { type: 'error', action: message.type, actionId: message.actionId || null, error: 'Unauthorized or session expired.' }); return null; }
  if (!roles.includes(auth.role)) { await sendOutput(user, { type: 'error', action: message.type, actionId: message.actionId || null, error: 'Permission denied.' }); return null; }
  if (auth.role === ROLE_ADMIN && !ADMIN_ALLOWED_ACTIONS.has(message.type)) { await sendOutput(user, { type: 'error', action: message.type, actionId: message.actionId || null, error: 'This action requires head-admin.' }); return null; }
  return { state, auth, publicKey, delegatedFrom, timestampMs, user: auth.user };
}

async function logoutDevice(user, message, ctx) {
  if (ctx.readonly) throw new Error('Logout requires consensus input.');
  const authz = await requireRole(user, message, ctx);
  if (!authz) return;
  delete authz.state.authorizedDevices[authz.publicKey];
  saveAuthState(authz.state);
  await sendOutput(user, { type: 'logout-success', actionId: message.actionId || null });
}

async function listUsers(user, message, ctx) {
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const users = Object.entries(authz.state.users || {}).map(([id, r]) => publicUserRecord(normalizeUserRecord(id, r))).sort((a,b) => String(a.id).localeCompare(String(b.id)));
  await sendOutput(user, { type: 'users', actionId: message.actionId || null, users, activeHeadAdmins: countActiveHeadAdmins(authz.state) });
}

async function addUser(user, message, ctx) {
  if (ctx.readonly) throw new Error('User changes require consensus input.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const method = safeString(message.method, 32).toLowerCase();
  const role = normalizeRole(message.role || ROLE_ADMIN);
  let id, record;
  if (method === 'password') {
    const username = ensurePasswordUsernameAvailable(authz.state, message.username);
    id = `pwd:${username}`;
    if (authz.state.users[id]) throw new Error('User already exists.');
    record = { id, method, username, publicKey: null, role, active: true, password: normalizePasswordCredential(message), totpSecret: message.totpSecret ? normalizeBase32Secret(message.totpSecret) : null };
  } else if (method === 'everstoring') {
    const publicKey = normalizePublicKey(message.publicKey);
    id = `ev:${publicKey}`;
    if (authz.state.users[id]) throw new Error('User already exists.');
    const passwordRequested = !!(message.passwordKey || message.passwordSalt || message.username);
    const username = passwordRequested ? ensurePasswordUsernameAvailable(authz.state, message.username) : null;
    record = { id, method, username, publicKey, role, active: true, password: passwordRequested ? normalizePasswordCredential(message) : null, totpSecret: message.totpSecret ? normalizeBase32Secret(message.totpSecret) : null };
  } else throw new Error('User method must be password or everstoring.');
  record.createdAt = authz.timestampMs; record.createdBy = authz.auth.userId; record.updatedAt = authz.timestampMs; record.updatedBy = authz.auth.userId;
  authz.state.users[id] = record;
  saveAuthState(authz.state);
  await sendOutput(user, { type: 'user-added', actionId: message.actionId || null, user: publicUserRecord(record) });
}

async function setUserRole(user, message, ctx) {
  if (ctx.readonly) throw new Error('User changes require consensus input.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const id = safeString(message.userId, 256);
  const record = getUserRecord(authz.state, id); if (!record) throw new Error('User not found.');
  const nextRole = normalizeRole(message.role);
  if (record.role === ROLE_HEAD_ADMIN && nextRole !== ROLE_HEAD_ADMIN && countActiveHeadAdmins(authz.state) <= 1) throw new Error('Cannot demote the last active head-admin.');
  record.role = nextRole; record.updatedAt = authz.timestampMs; record.updatedBy = authz.auth.userId;
  authz.state.users[id] = record; revokeUserSessions(authz.state, id); saveAuthState(authz.state);
  await sendOutput(user, { type: 'user-role-set', actionId: message.actionId || null, user: publicUserRecord(record), sessionsRevoked: true });
}

async function removeUser(user, message, ctx) {
  if (ctx.readonly) throw new Error('User changes require consensus input.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const id = safeString(message.userId, 256);
  const record = getUserRecord(authz.state, id); if (!record) throw new Error('User not found.');
  if (record.role === ROLE_HEAD_ADMIN && record.active !== false && countActiveHeadAdmins(authz.state) <= 1) throw new Error('Cannot remove the last active head-admin.');
  record.active = false; record.updatedAt = authz.timestampMs; record.updatedBy = authz.auth.userId;
  authz.state.users[id] = record; revokeUserSessions(authz.state, id); saveAuthState(authz.state);
  await sendOutput(user, { type: 'user-removed', actionId: message.actionId || null, user: publicUserRecord(record) });
}

async function changePassword(user, message, ctx) {
  if (ctx.readonly) throw new Error('Password changes require consensus input.');
  const authz = await requireRole(user, message, ctx); if (!authz) return;
  const id = safeString(message.userId || authz.auth.userId, 256);
  if (authz.auth.role !== ROLE_HEAD_ADMIN && id !== authz.auth.userId) throw new Error('Admins can only change their own password.');
  const record = getUserRecord(authz.state, id); if (!record) throw new Error('User not found.');
  const username = ensurePasswordUsernameAvailable(authz.state, message.username || record.username || '', id);
  record.username = username;
  record.password = normalizePasswordCredential(message);
  record.updatedAt = authz.timestampMs; record.updatedBy = authz.auth.userId;
  authz.state.users[id] = record; revokeUserSessions(authz.state, id); saveAuthState(authz.state);
  await sendOutput(user, { type: 'password-changed', actionId: message.actionId || null, userId: id, username, passwordEnabled: true, sessionsRevoked: true });
}

async function setUserTwoFactor(user, message, ctx) {
  if (ctx.readonly) throw new Error('2FA changes require consensus input.');
  const authz = await requireRole(user, message, ctx); if (!authz) return;
  const id = safeString(message.userId || authz.auth.userId, 256);
  if (authz.auth.role !== ROLE_HEAD_ADMIN && id !== authz.auth.userId) throw new Error('Admins can only change their own 2FA.');
  const record = getUserRecord(authz.state, id); if (!record) throw new Error('User not found.');
  const enabled = message.enabled !== false;
  record.totpSecret = enabled ? normalizeBase32Secret(message.totpSecret) : null;
  record.updatedAt = authz.timestampMs; record.updatedBy = authz.auth.userId;
  authz.state.users[id] = record; revokeUserSessions(authz.state, id); saveAuthState(authz.state);
  await sendOutput(user, { type: 'user-2fa-set', actionId: message.actionId || null, userId: id, enabled, sessionsRevoked: true });
}

function getContractConfigSection(cfg = {}) { return cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : cfg; }
function getOrCreate(parent, key) { if (!parent[key] || typeof parent[key] !== 'object' || Array.isArray(parent[key])) parent[key] = {}; return parent[key]; }
function getConfigUnl(cfg = {}) { return unique(getContractConfigSection(cfg).unl || []).map(normalizePublicKey).sort(); }
function getLocalNodePublicKey(ctx, cfg = {}) { const nodeCfg = cfg.node && typeof cfg.node === 'object' ? cfg.node : cfg; return normalizePublicKeyMaybe(ctx.publicKey) || normalizePublicKeyMaybe(ctx.public_key) || normalizePublicKeyMaybe(nodeCfg.public_key) || normalizePublicKeyMaybe(nodeCfg.publicKey) || null; }
function normalizeVisibility(value) { const mode = safeString(value, 16).toLowerCase(); if (!['public','private'].includes(mode)) throw new Error('Mode must be public or private.'); return mode; }
function readVisibility(cfg = {}) { const c = getContractConfigSection(cfg); const consensus = c.consensus || {}; const npl = c.npl || {}; return { consensus: normalizeVisibility(consensus.mode || 'public'), npl: normalizeVisibility(npl.mode || consensus.mode || 'public') }; }
function readRoundtime(cfg = {}) { const c = getContractConfigSection(cfg); const n = Number(c.consensus && c.consensus.roundtime); return Number.isInteger(n) ? n : null; }
function readThreshold(cfg = {}) { const c = getContractConfigSection(cfg); const totalNodes = getConfigUnl(cfg).length; const threshold = Number(c.consensus && c.consensus.threshold); const percent = Number.isInteger(threshold) && threshold >= 1 && threshold <= 100 ? threshold : 80; return { threshold: percent, totalNodes, requiredVotes: totalNodes ? Math.max(1, Math.ceil(totalNodes * percent / 100)) : 0 }; }
function thresholdForVotes(requiredVotes, totalNodes) { const r = Number(requiredVotes), t = Number(totalNodes); if (!Number.isInteger(r) || !Number.isInteger(t) || t < 1 || r < 1 || r > t) throw new Error('Invalid requiredVotes/totalNodes.'); return Math.max(1, Math.min(100, Math.floor(r * 100 / t))); }

function normalizeDomain(value) {
  let domain = safeString(value, 512).replace(/^https?:\/\//i, '').split('/')[0].trim();
  domain = domain.replace(/:(gptcp1|\d+)$/i, '');
  if (domain && (/\s/.test(domain) || domain.includes('/'))) throw new Error('Invalid domain.');
  return domain;
}
function loadUnlMetadata() { const d = readJson(UNL_METADATA_FILE, {}); return d && typeof d === 'object' && !Array.isArray(d) ? d : {}; }
function saveUnlMetadata(d) { writeJson(UNL_METADATA_FILE, d); }
function loadRemovedUnls() { const d = readJson(REMOVED_UNLS_FILE, []); return Array.isArray(d) ? d : []; }
function saveRemovedUnls(d) { writeJson(REMOVED_UNLS_FILE, d); }
function updateUnlMeta(publicKey, message, authz) { const key = normalizePublicKey(publicKey); const all = loadUnlMetadata(); const old = all[key] || {}; const domain = normalizeDomain(message.domain || old.domain || ''); all[key] = { publicKey:key, domain, url: domain ? `https://${domain}:gptcp1` : '', updatedAt:authz.timestampMs, updatedBy:authz.auth.userId }; saveUnlMetadata(all); return all[key]; }

function defaultPruneState() {
  return {
    settings: {
      enabled: false, healthAutoEnabled: true, healthEveryLedgers: 10, healthTimeoutMs: 2500,
      minDeadMinutes: 15, minInstancesAgreeing: 1, maxDisagreePercent: 50, maxPurgePerRun: 2,
      autoReaddEnabled: false, readdEveryLedgers: 60, readdMaxPerRun: 2
    },
    nodes: {}, lastHealthLedger: 0, lastPruneLedger: 0, lastReaddLedger: 0, lastHealthAt: null, lastPruneAt: null, lastReaddAt: null
  };
}
function loadPruneState() { const s = readJson(UNL_PRUNE_FILE, defaultPruneState()); s.settings = { ...defaultPruneState().settings, ...(s.settings || {}) }; s.settings.healthAutoEnabled = false; s.nodes = s.nodes && typeof s.nodes === 'object' ? s.nodes : {}; return s; }
function savePruneState(s) { writeJson(UNL_PRUNE_FILE, s); }
function ledgerNo(ctx) { const n = Number(ctx && ctx.lclSeqNo); return Number.isInteger(n) && n > 0 ? n : 0; }
function boundInt(v, fallback, min, max) { const n = Number(v); return Number.isInteger(n) && n >= min && n <= max ? n : fallback; }
function pruneStatus(state, cfg, timestampMs) {
  const unl = getConfigUnl(cfg); const threshold = readThreshold(cfg); const settings = state.settings;
  const nodes = unl.map(publicKey => { const r = state.nodes[publicKey] || {}; const silentForMs = r.deadSince ? Math.max(0, timestampMs - Number(r.deadSince)) : 0; return { publicKey, status:r.status || 'unknown', lastAliveAt:r.lastAliveAt || null, deadSince:r.deadSince || null, lastReportAt:r.lastReportAt || null, silentForMs, eligibleForPurge:r.status === 'silent' && silentForMs >= settings.minDeadMinutes * 60000 }; });
  return { settings, totalNodes:unl.length, threshold:threshold.threshold, requiredVotes:threshold.requiredVotes, liveNodes:nodes.filter(n=>n.status==='alive').length, silentNodes:nodes.filter(n=>n.status==='silent').length, eligibleNodes:nodes.filter(n=>n.eligibleForPurge).length, nodes, removedUnls:loadRemovedUnls(), lastHealthAt:state.lastHealthAt || null, lastPruneAt:state.lastPruneAt || null, lastReaddAt:state.lastReaddAt || null };
}
function nplToString(msg) { if (Buffer.isBuffer(msg)) return msg.toString('utf8'); if (msg instanceof Uint8Array) return Buffer.from(msg).toString('utf8'); return String(msg || ''); }
function nplSender(node) { return normalizePublicKeyMaybe(node && (node.publicKey || node.public_key || node)); }

function validRuntimePort(value){const n=Number(value);return Number.isInteger(n)&&n>0&&n<=65535?n:null;}
function publicRuntimeRecord(runtimeInfo={}){return{userPort:validRuntimePort(runtimeInfo.userPort),meshPort:validRuntimePort(runtimeInfo.meshPort),hpVersion:safeString(runtimeInfo.hpVersion,64)||null,updatedAt:Date.now()};}

async function refreshLocalHealthRuntime(ctx) {
  if (ctx.readonly) return readLocalHealth();
  let cfg={}; try{cfg=await ctx.getConfig();}catch{}
  const local=getLocalNodePublicKey(ctx,cfg);
  const runtimeInfo=readNodeRuntimeConfig();
  const runtimeRecord=publicRuntimeRecord(runtimeInfo);
  const ts=nowMs(ctx);
  const snapshot=readLocalHealth()||{};
  snapshot.schemaVersion=2;
  snapshot.reporterPublicKey=local||normalizePublicKeyMaybe(snapshot.reporterPublicKey)||null;
  snapshot.ledgerNo=ledgerNo(ctx)||Number(snapshot.ledgerNo)||0;
  snapshot.ledgerHash=safeString(ctx.lclHash||snapshot.ledgerHash||'',256);
  snapshot.observedAt=Number(snapshot.observedAt)||ts;
  snapshot.runtimeUpdatedAt=ts;
  snapshot.localRuntime={nodePublicKey:local||null,...runtimeRecord,updatedAt:ts};
  snapshot.observations=snapshot.observations&&typeof snapshot.observations==='object'&&!Array.isArray(snapshot.observations)?snapshot.observations:{};
  if(local){const old=snapshot.observations[local]||{};snapshot.observations[local]={...old,status:'alive',observedAt:ts,userPort:runtimeRecord.userPort,meshPort:runtimeRecord.meshPort};}
  writeLocalCustomHealth(snapshot);
  return snapshot;
}

async function probeLocalHealth(ctx) {
  if (ctx.readonly || !ctx.unl || typeof ctx.unl.send !== 'function' || typeof ctx.unl.onMessage !== 'function') return null;
  const cfg = await ctx.getConfig(); const unl = getConfigUnl(cfg); if (!unl.length) return null;
  const settings = loadPruneState().settings; const timeout = boundInt(settings.healthTimeoutMs, 2500, 500, 15000);
  const expected = new Set(unl); const alive = new Set(); const runtimes = {};
  const local = getLocalNodePublicKey(ctx, cfg);
  const localRuntime = publicRuntimeRecord(readNodeRuntimeConfig());
  if (local && expected.has(local)) { alive.add(local); runtimes[local]=localRuntime; }
  const roundId = `health:${ledgerNo(ctx)}:${safeString(ctx.lclHash || '', 128) || 'nohash'}`;
  let done = false, resolveWait; let timer;
  const finish = () => { if (done) return; done = true; if (timer) clearTimeout(timer); if (resolveWait) resolveWait(); };
  ctx.unl.onMessage((node, msg) => { try { const sender = nplSender(node); if (!sender || !expected.has(sender)) return; const p = JSON.parse(nplToString(msg)); if (p.type !== HEALTH_NPL_TYPE || p.roundId !== roundId || normalizePublicKey(p.publicKey) !== sender) return; alive.add(sender); runtimes[sender]={userPort:validRuntimePort(p.userPort),meshPort:validRuntimePort(p.meshPort),hpVersion:null,updatedAt:nowMs(ctx)}; if (alive.size >= expected.size) finish(); } catch {} });
  const wait = new Promise(resolve => { resolveWait = resolve; timer = setTimeout(finish, timeout); });
  if (local && expected.has(local)) await ctx.unl.send(JSON.stringify({ type:HEALTH_NPL_TYPE, roundId, publicKey:local, userPort:localRuntime.userPort, meshPort:localRuntime.meshPort }));
  if (alive.size >= expected.size) finish();
  await wait;
  const ts = nowMs(ctx); const observations = {};
  for (const key of unl) { const r=runtimes[key]||{}; observations[key] = { status: alive.has(key) ? 'alive' : 'silent', observedAt: ts, userPort:validRuntimePort(r.userPort), meshPort:validRuntimePort(r.meshPort) }; }
  const snapshot = { schemaVersion:2, reporterPublicKey:local, ledgerNo:ledgerNo(ctx), ledgerHash:safeString(ctx.lclHash || '',256), observedAt:ts, runtimeUpdatedAt:ts, localRuntime:{nodePublicKey:local||null,...localRuntime,updatedAt:ts}, observations };
  writeLocalCustomHealth(snapshot);
  return snapshot;
}
function writeLocalCustomHealth(snapshot){try{ensureDir(path.dirname(LOCAL_HEALTH_FILE));fs.writeFileSync(LOCAL_HEALTH_FILE,JSON.stringify(snapshot,null,2));return true;}catch(err){console.log(`Local unl-health.json write failed: ${err.message}`);return false;}}
function readLocalHealth(){const d=readJson(LOCAL_HEALTH_FILE,null);return d&&typeof d==='object'&&!Array.isArray(d)?d:null;}
function runtimeFromLocalHealth(){const snapshot=readLocalHealth();const local=snapshot&&snapshot.localRuntime&&typeof snapshot.localRuntime==='object'?snapshot.localRuntime:null;const userPort=validRuntimePort(local&&local.userPort);if(userPort)return{detected:true,source:'../unl-health.json',configPath:null,cwd:STATE_ROOT,hpVersion:safeString(local.hpVersion,64)||null,userPort,meshPort:validRuntimePort(local.meshPort),nodeRole:null,nodePublicKey:normalizePublicKeyMaybe(local.nodePublicKey)||normalizePublicKeyMaybe(snapshot.reporterPublicKey)||null,updatedAt:Number(local.updatedAt)||Number(snapshot.runtimeUpdatedAt)||null};const fallback=readNodeRuntimeConfig();return{...fallback,source:'hp.cfg-fallback'};}

function calculateManagedThreshold(cfg, state) {
  const total = getConfigUnl(cfg).length; if (!total) return null;
  const minAgree = Math.max(1, Math.min(total, boundInt(state.settings.minInstancesAgreeing, 1, 1, 100000)));
  const maxDisagree = Math.max(0, Math.min(99, Number(state.settings.maxDisagreePercent || 50)));
  const percentageVotes = Math.max(1, Math.ceil(total * (100 - maxDisagree) / 100));
  const requiredVotes = Math.max(minAgree, percentageVotes);
  return { requiredVotes, totalNodes:total, threshold:thresholdForVotes(requiredVotes, total) };
}
function applyManagedThreshold(cfg, state) { if (!state.settings.enabled) return null; const info = calculateManagedThreshold(cfg,state); if (!info) return null; const c = getContractConfigSection(cfg); getOrCreate(c,'consensus').threshold = info.threshold; return info; }

async function evaluatePrune(ctx, actor='automatic', trigger='manual') {
  const cfg = await ctx.getConfig(); const c = getContractConfigSection(cfg); const unl = getConfigUnl(cfg); const state = loadPruneState(); const ts = nowMs(ctx);
  if (!state.settings.enabled) return { changed:false, reason:'disabled', status:pruneStatus(state,cfg,ts) };
  const eligible = unl.filter(k => { const r=state.nodes[k]||{}; return r.status==='silent' && r.deadSince && ts-Number(r.deadSince) >= Number(state.settings.minDeadMinutes)*60000; });
  const max = boundInt(state.settings.maxPurgePerRun,2,1,100); const remove = eligible.slice(0,max);
  const minAgree = boundInt(state.settings.minInstancesAgreeing,1,1,100000);
  while (remove.length && unl.length - remove.length < minAgree) remove.pop();
  if (!remove.length) { state.lastPruneAt=ts; state.lastPruneLedger=ledgerNo(ctx); savePruneState(state); return {changed:false,reason:'nothing-safe-to-remove',status:pruneStatus(state,cfg,ts)}; }
  c.unl = unl.filter(k => !remove.includes(k));
  const meta = loadUnlMetadata(); const removed = loadRemovedUnls();
  for (const key of remove) { const m=meta[key]||{}; removed.unshift({ publicKey:key, domain:m.domain||'', url:m.url||'', removedAt:ts, removedBy:actor, reason:`silent:${trigger}` }); }
  saveRemovedUnls(removed.slice(0,10000)); state.lastPruneAt=ts; state.lastPruneLedger=ledgerNo(ctx); applyManagedThreshold(cfg,state); await ctx.updateConfig(cfg); savePruneState(state);
  return {changed:true,removed:remove,status:pruneStatus(state,cfg,ts)};
}

async function evaluateReadd(ctx, actor='automatic', trigger='manual') {
  const cfg = await ctx.getConfig(); const c=getContractConfigSection(cfg); const current=getConfigUnl(cfg); const state=loadPruneState(); const removed=loadRemovedUnls(); const ts=nowMs(ctx);
  const candidates = removed.filter(r => r && r.healthStatus === 'alive').slice(0,boundInt(state.settings.readdMaxPerRun,2,1,100));
  if (!candidates.length) { state.lastReaddAt=ts; state.lastReaddLedger=ledgerNo(ctx); savePruneState(state); return {changed:false,reason:'no-alive-removed-nodes'}; }
  const add = candidates.map(r=>normalizePublicKey(r.publicKey)).filter(k=>!current.includes(k)); c.unl = unique([...current,...add]).map(normalizePublicKey).sort();
  saveRemovedUnls(removed.filter(r=>!add.includes(normalizePublicKeyMaybe(r.publicKey)))); state.lastReaddAt=ts; state.lastReaddLedger=ledgerNo(ctx); applyManagedThreshold(cfg,state); await ctx.updateConfig(cfg); savePruneState(state); return {changed:add.length>0,added:add};
}

async function getClusterJoinStatus(user, message, ctx) {
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  let cfg = {}; try { cfg = await ctx.getConfig(); } catch {}
  const localKey = getLocalNodePublicKey(ctx, cfg);
  const currentContractId = safeString(ctx.contractId || '', 128).toLowerCase() || null;
  const record = readClusterJoinRecord();
  const restartRuntime = readJson(LOCAL_CLUSTER_RESTART_STATUS_FILE, null);
  const hpRuntime = runtimeFromLocalHealth();
  let hpContractId = null;
  try { hpContractId = normalizeContractId(resolveWritableHpConfig().cfg?.contract?.id); } catch {}
  const rollbackAvailable = !!(record && record.rollbackVerified === true && record.rollback && typeof record.rollback === 'object');
  await sendOutput(user, {
    type: 'cluster-join-status', actionId: message.actionId || null,
    localNodePublicKey: localKey,
    currentContractId,
    localNodeInUnl: !!(localKey && getConfigUnl(cfg).includes(localKey)),
    hpConfigPath: hpRuntime.configPath || readNodeRuntimeConfig().configPath || null,
    hpContractId,
    migrationPrepared: !!(currentContractId && hpContractId && currentContractId !== hpContractId),
    rollbackAvailable,
    rollbackWarning: record && !rollbackAvailable && record.rollback ? (record.rollbackUnsafeReason || 'Rollback snapshot is not verified by this EverAdmin version and is disabled for safety.') : null,
    record,
    restartRuntime,
    restartRequestPending: fs.existsSync(LOCAL_HOTPOCKET_RESTART_REQUEST_FILE),
    restartRequestPath: '../restart-hotpocket.request',
    restartWatcherStatus: readJson(LOCAL_HOTPOCKET_RESTART_WATCHER_STATUS_FILE, null),
    restartWatcherStatusPath: '../restart-hotpocket.status.json'
  });
}

async function probeClusterTarget(user, message, ctx) {
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const peer = normalizePeerAddress(message.bootstrapPeer || message.peer);
  const targetContractId = normalizeContractId(message.targetContractId || message.contractId);
  const trustedValidatorPublicKey = normalizePublicKey(message.trustedValidatorPublicKey || message.publicKey);
  const probe = await probeTcpPeer(peer, message.timeoutMs || 3000);
  await sendOutput(user, {
    type: 'cluster-target-probe', actionId: message.actionId || null,
    targetContractId, trustedValidatorPublicKey, ...probe,
    note: 'TCP reachability only. Contract identity is verified after HotPocket restarts and synchronizes.'
  });
}

async function applyClusterJoinOnThisNode(ctx, authz, request) {
  const currentId = normalizeContractId(ctx.contractId);
  const hp = resolveWritableHpConfig();
  const cfg = hp.cfg;
  cfg.contract = cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : {};
  cfg.mesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
  cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
  const hpCurrentId = normalizeContractId(cfg.contract.id || currentId);
  const existing = readClusterJoinRecord();

  // A previous attempt may already have written the target bootstrap while the old
  // hpcore is still executing. Never re-snapshot that prepared target as the source.
  if (hpCurrentId === request.targetContractId && currentId !== request.targetContractId) {
    const rollbackVerified = existing?.rollbackVerified === true;
    const restart = scheduleHotPocketRestart(4, request.targetContractId);
    writeClusterJoinRecord({
      ...(existing || {}),
      schemaVersion: CLUSTER_JOIN_SCHEMA,
      phase: restart.scheduled ? 'restart-scheduled' : 'restart-required',
      requestedAt: Number(existing?.requestedAt) || authz.timestampMs,
      requestedBy: existing?.requestedBy || authz.auth.userId,
      sourceNodePublicKey: existing?.sourceNodePublicKey || request.localNodePublicKey,
      sourceContractId: existing?.sourceContractId && existing.sourceContractId !== request.targetContractId
        ? existing.sourceContractId
        : currentId,
      target: existing?.target || {
        contractId: request.targetContractId,
        trustedValidatorPublicKey: request.trustedValidatorPublicKey,
        bootstrapPeer: request.bootstrapPeer
      },
      hpConfigPath: hp.path,
      rollback: existing?.rollback || null,
      rollbackVerified,
      rollbackUnsafeReason: rollbackVerified ? null : 'Migration was already prepared before a verified rollback snapshot existed. Restore is disabled for safety.',
      preparedAt: Number(existing?.preparedAt) || authz.timestampMs,
      retryAt: authz.timestampMs,
      retryBy: authz.auth.userId,
      restart,
      error: restart.scheduled ? null : restart.reason
    });
    return;
  }

  // If disk and the currently executing contract disagree for any other reason,
  // restarting is the safe operation. Do not destroy evidence by starting a new join.
  if (hpCurrentId !== currentId) {
    throw new Error(`hp.cfg contract.id (${hpCurrentId}) differs from the running contract (${currentId}). Use Restart HotPocket or repair/restore the pending migration before changing clusters again.`);
  }

  const existingSourceMatches = !!(
    existing &&
    existing.rollbackVerified === true &&
    normalizePublicKeyMaybe(existing.sourceNodePublicKey) === request.localNodePublicKey &&
    safeString(existing.sourceContractId || '',128).toLowerCase() === currentId &&
    existing.rollback && typeof existing.rollback === 'object'
  );
  const previous = existingSourceMatches ? existing.rollback : {
    contractId: hpCurrentId,
    unl: Array.isArray(cfg.contract.unl) ? [...cfg.contract.unl] : [],
    knownPeers: Array.isArray(cfg.mesh.known_peers) ? [...cfg.mesh.known_peers] : [],
    peerDiscoveryEnabled: cfg.mesh.peer_discovery.enabled !== false,
    peerDiscoveryInterval: Number(cfg.mesh.peer_discovery.interval) || null
  };
  const baseRecord = {
    schemaVersion: CLUSTER_JOIN_SCHEMA,
    phase: 'preparing',
    requestedAt: existingSourceMatches ? Number(existing.requestedAt) || authz.timestampMs : authz.timestampMs,
    requestedBy: existingSourceMatches ? existing.requestedBy || authz.auth.userId : authz.auth.userId,
    lastRequestedAt: authz.timestampMs,
    lastRequestedBy: authz.auth.userId,
    sourceNodePublicKey: request.localNodePublicKey,
    sourceContractId: currentId,
    target: {
      contractId: request.targetContractId,
      trustedValidatorPublicKey: request.trustedValidatorPublicKey,
      bootstrapPeer: request.bootstrapPeer
    },
    hpConfigPath: hp.path,
    rollback: previous,
    rollbackVerified: true,
    rollbackUnsafeReason: null,
    error: null
  };
  writeClusterJoinRecord(baseRecord);

  let hpWritten = false;
  try {
    cfg.contract.id = request.targetContractId;
    cfg.contract.unl = [request.trustedValidatorPublicKey];
    cfg.mesh.known_peers = [request.bootstrapPeer];
    cfg.mesh.peer_discovery.enabled = false;
    if (!Number.isInteger(Number(cfg.mesh.peer_discovery.interval)) || Number(cfg.mesh.peer_discovery.interval) < 1) cfg.mesh.peer_discovery.interval = 10000;
    cfg.mesh.msg_forwarding = true;
    atomicWriteJson(hp.path, cfg);
    hpWritten = true;
    // Deterministic peer mode owns connectivity. Persist the bootstrap peer in hp.cfg
    // for first contact; after state sync AutoCluster installs the full current-UNL
    // mesh with peerChangeset before the node can mature.
    const restart = scheduleHotPocketRestart(4, request.targetContractId);
    writeClusterJoinRecord({ ...baseRecord, phase: restart.scheduled ? 'restart-scheduled' : 'restart-required', preparedAt: authz.timestampMs, restart, error: restart.scheduled ? null : restart.reason });
  } catch (err) {
    try {
      if (hpWritten) {
        const restore = resolveWritableHpConfig();
        const rcfg = restore.cfg;
        rcfg.contract = rcfg.contract && typeof rcfg.contract === 'object' ? rcfg.contract : {};
        rcfg.mesh = rcfg.mesh && typeof rcfg.mesh === 'object' ? rcfg.mesh : {};
        rcfg.mesh.peer_discovery = rcfg.mesh.peer_discovery && typeof rcfg.mesh.peer_discovery === 'object' ? rcfg.mesh.peer_discovery : {};
        rcfg.contract.id = previous.contractId;
        rcfg.contract.unl = previous.unl;
        rcfg.mesh.known_peers = previous.knownPeers;
        rcfg.mesh.peer_discovery.enabled = false;
        if (previous.peerDiscoveryInterval) rcfg.mesh.peer_discovery.interval = previous.peerDiscoveryInterval;
        atomicWriteJson(restore.path, rcfg);
      }
    } catch (rollbackErr) { console.log(`Cluster join immediate rollback failed: ${rollbackErr.message}`); }
    writeClusterJoinRecord({ ...baseRecord, phase: 'error', error: safeString(err && err.message, 500) });
  }
}

async function connectToCluster(user, message, ctx) {
  if (ctx.readonly) throw new Error('Cluster switching requires consensus input so the authenticated request can target exactly one validator.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const request = {
    localNodePublicKey: normalizePublicKey(message.localNodePublicKey || message.targetNodePublicKey),
    targetContractId: normalizeContractId(message.targetContractId),
    trustedValidatorPublicKey: normalizePublicKey(message.trustedValidatorPublicKey),
    bootstrapPeer: normalizePeerAddress(message.bootstrapPeer)
  };
  if (request.localNodePublicKey === request.trustedValidatorPublicKey) throw new Error('The trusted target validator key cannot be this node’s own key.');
  const currentCfg = await ctx.getConfig();
  const currentUnl = getConfigUnl(currentCfg);
  if (currentUnl.includes(request.localNodePublicKey) && currentUnl.length > 1) throw new Error('Drain this validator from the current cluster UNL before switching its node-local bootstrap.');
  const localKey = normalizePublicKeyMaybe(ctx.publicKey);
  if (localKey === request.localNodePublicKey) {
    try { await applyClusterJoinOnThisNode(ctx, authz, request); }
    catch (err) {
      const existing = readClusterJoinRecord();
      writeClusterJoinRecord({
        ...(existing || {}),
        schemaVersion:CLUSTER_JOIN_SCHEMA,
        phase:'error',
        requestedAt:Number(existing?.requestedAt)||authz.timestampMs,
        requestedBy:existing?.requestedBy||authz.auth.userId,
        lastRequestedAt:authz.timestampMs,
        lastRequestedBy:authz.auth.userId,
        sourceNodePublicKey:existing?.sourceNodePublicKey||request.localNodePublicKey,
        sourceContractId:existing?.sourceContractId||safeString(ctx.contractId||'',128).toLowerCase()||null,
        target:existing?.target||{contractId:request.targetContractId,trustedValidatorPublicKey:request.trustedValidatorPublicKey,bootstrapPeer:request.bootstrapPeer},
        error:safeString(err && err.message,500)
      });
    }
  }
  await sendOutput(user, {
    type: 'cluster-join-scheduled', actionId: message.actionId || null,
    localNodePublicKey: request.localNodePublicKey,
    targetContractId: request.targetContractId,
    trustedValidatorPublicKey: request.trustedValidatorPublicKey,
    bootstrapPeer: request.bootstrapPeer,
    message: 'Node-local cluster switch requested. Only the selected validator applies the bootstrap change.'
  });
}

async function restartHotPocket(user, message, ctx) {
  if (ctx.readonly) throw new Error('HotPocket restart requires consensus input so the authenticated request can target exactly one validator.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const targetNode = normalizePublicKey(message.localNodePublicKey || message.targetNodePublicKey);
  const localKey = normalizePublicKeyMaybe(ctx.publicKey);
  let localRestart = null;
  if (localKey === targetNode) {
    let hpContractId = null;
    try { hpContractId = normalizeContractId(resolveWritableHpConfig().cfg?.contract?.id); } catch {}
    const record = readClusterJoinRecord();
    const trackJoin = !!(record && record.target && typeof record.target === 'object');
    localRestart = scheduleHotPocketRestart(3, hpContractId || record?.target?.contractId || ctx.contractId || null, { trackJoin });
    if (record) {
      writeClusterJoinRecord({
        ...record,
        manualRestartRequestedAt: authz.timestampMs,
        manualRestartRequestedBy: authz.auth.userId,
        restart: localRestart,
        phase: localRestart.scheduled ? 'restart-scheduled' : 'restart-required',
        error: localRestart.scheduled ? null : localRestart.reason
      });
    }
  }
  await sendOutput(user, {
    type:'hotpocket-restart-requested', actionId:message.actionId||null,
    localNodePublicKey:targetNode,
    restart:localRestart,
    message:"EverAdmin wrote a node-local seed restart request. The root Supervisor watcher will restart the selected validator HotPocket program."
  });
}

async function restorePreviousCluster(user, message, ctx) {
  if (ctx.readonly) throw new Error('Cluster rollback requires consensus input.');
  const authz = await requireRole(user, message, ctx, [ROLE_HEAD_ADMIN]); if (!authz) return;
  const targetNode = normalizePublicKey(message.localNodePublicKey || message.targetNodePublicKey);
  const localKey = normalizePublicKeyMaybe(ctx.publicKey);
  if (localKey === targetNode) {
    const record = readClusterJoinRecord();
    try {
      if (!record || record.rollbackVerified !== true) throw new Error(record?.rollbackUnsafeReason || 'Previous cluster rollback is unavailable because this snapshot was not verified.');
      const hpPath = restoreJoinBootstrap(record);
      const restart = scheduleHotPocketRestart(4, record?.rollback?.contractId || null);
      writeClusterJoinRecord({ ...(record || {}), phase:restart.scheduled?'rollback-restart-scheduled':'rollback-restart-required', rollbackRequestedAt:authz.timestampMs, rollbackRequestedBy:authz.auth.userId, hpConfigPath:hpPath, restart, error:restart.scheduled?null:restart.reason });
    } catch (err) {
      writeClusterJoinRecord({ ...(record || {}), phase:'rollback-error', rollbackRequestedAt:authz.timestampMs, error:safeString(err && err.message,500) });
    }
  }
  await sendOutput(user, { type:'cluster-join-rollback-scheduled', actionId:message.actionId||null, localNodePublicKey:targetNode, message:'Previous node-local bootstrap settings were requested for restoration on the selected validator.' });
}

async function listUnls(user, message, ctx) {
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]); if(!authz)return;
  const cfg=await ctx.getConfig(); const meta=loadUnlMetadata(); const state=loadPruneState(); const status=pruneStatus(state,cfg,authz.timestampMs);
  const unls=getConfigUnl(cfg).map((publicKey,index)=>({ index, publicKey, ...(meta[publicKey]||{}), ...(state.nodes[publicKey]||{}) }));
  await sendOutput(user,{type:'unls',actionId:message.actionId||null,unls,removedUnls:loadRemovedUnls(),visibilityMode:readVisibility(cfg),consensusThreshold:readThreshold(cfg),consensusRoundtime:readRoundtime(cfg),prune:status});
}
async function addUnl(user,message,ctx){ if(ctx.readonly)throw new Error('UNL changes require consensus input.'); const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const key=normalizePublicKey(message.publicKey);const cfg=await ctx.getConfig();const c=getContractConfigSection(cfg);const unl=getConfigUnl(cfg);if(!unl.includes(key))c.unl=unique([...unl,key]).map(normalizePublicKey).sort();const m=updateUnlMeta(key,message,a);saveRemovedUnls(loadRemovedUnls().filter(r=>normalizePublicKeyMaybe(r.publicKey)!==key));const s=loadPruneState();applyManagedThreshold(cfg,s);await ctx.updateConfig(cfg);await sendOutput(user,{type:'unl-added',actionId:message.actionId||null,publicKey:key,metadata:m,consensusThreshold:readThreshold(cfg)});}
async function removeUnl(user,message,ctx){ if(ctx.readonly)throw new Error('UNL changes require consensus input.'); const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const key=normalizePublicKey(message.publicKey);const cfg=await ctx.getConfig();const c=getContractConfigSection(cfg);const unl=getConfigUnl(cfg);if(!unl.includes(key))throw new Error('Public key is not in UNL.');if(unl.length<=1)throw new Error('Cannot remove the final UNL node.');c.unl=unl.filter(k=>k!==key);const meta=loadUnlMetadata()[key]||{};const removed=loadRemovedUnls();removed.unshift({publicKey:key,domain:meta.domain||'',url:meta.url||'',removedAt:a.timestampMs,removedBy:a.auth.userId,reason:'manual'});saveRemovedUnls(removed);const s=loadPruneState();applyManagedThreshold(cfg,s);await ctx.updateConfig(cfg);await sendOutput(user,{type:'unl-removed',actionId:message.actionId||null,publicKey:key,consensusThreshold:readThreshold(cfg)});}
async function setVisibility(user,message,ctx){ if(ctx.readonly)throw new Error('Config changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const mode=normalizeVisibility(message.mode);const cfg=await ctx.getConfig();const c=getContractConfigSection(cfg);getOrCreate(c,'consensus').mode=mode;getOrCreate(c,'npl').mode=mode;await ctx.updateConfig(cfg);await sendOutput(user,{type:'cluster-visibility-mode-set',actionId:message.actionId||null,mode,visibilityMode:readVisibility(cfg)});}
async function setThreshold(user,message,ctx){ if(ctx.readonly)throw new Error('Config changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const s=loadPruneState();if(s.settings.enabled)throw new Error('Manual threshold is locked while auto purge is enabled.');const cfg=await ctx.getConfig();const total=getConfigUnl(cfg).length;let threshold=Number(message.threshold);if(message.requiredVotes!==undefined)threshold=thresholdForVotes(Number(message.requiredVotes),total);if(!Number.isInteger(threshold)||threshold<1||threshold>100)throw new Error('Threshold must be 1-100.');getOrCreate(getContractConfigSection(cfg),'consensus').threshold=threshold;await ctx.updateConfig(cfg);await sendOutput(user,{type:'consensus-threshold-set',actionId:message.actionId||null,consensusThreshold:readThreshold(cfg)});}
async function setRoundtime(user,message,ctx){ if(ctx.readonly)throw new Error('Config changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const n=Number(message.roundtimeMs||message.roundtime);if(!Number.isInteger(n)||n<1||n>3600000)throw new Error('Roundtime must be 1-3600000 ms.');const cfg=await ctx.getConfig();getOrCreate(getContractConfigSection(cfg),'consensus').roundtime=n;await ctx.updateConfig(cfg);await sendOutput(user,{type:'consensus-roundtime-set',actionId:message.actionId||null,roundtime:n});}
async function getPruneSettings(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const cfg=await ctx.getConfig();const s=loadPruneState();await sendOutput(user,{type:'unl-prune-settings',actionId:message.actionId||null,...pruneStatus(s,cfg,a.timestampMs)});}
async function setPruneSettings(user,message,ctx){if(ctx.readonly)throw new Error('Prune settings require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const s=loadPruneState();const i=message.settings||message;s.settings={...s.settings,enabled:i.enabled===undefined?s.settings.enabled:!!i.enabled,healthAutoEnabled:false,healthEveryLedgers:boundInt(i.healthEveryLedgers,s.settings.healthEveryLedgers,1,100000),healthTimeoutMs:boundInt(i.healthTimeoutMs,s.settings.healthTimeoutMs,500,15000),minDeadMinutes:boundInt(i.minDeadMinutes,s.settings.minDeadMinutes,1,100000),minInstancesAgreeing:boundInt(i.minInstancesAgreeing,s.settings.minInstancesAgreeing,1,100000),maxDisagreePercent:boundInt(i.maxDisagreePercent,s.settings.maxDisagreePercent,0,99),maxPurgePerRun:boundInt(i.maxPurgePerRun,s.settings.maxPurgePerRun,1,100),autoReaddEnabled:i.autoReaddEnabled===undefined?s.settings.autoReaddEnabled:!!i.autoReaddEnabled,readdEveryLedgers:boundInt(i.readdEveryLedgers,s.settings.readdEveryLedgers,1,100000),readdMaxPerRun:boundInt(i.readdMaxPerRun,s.settings.readdMaxPerRun,1,100)};const cfg=await ctx.getConfig();applyManagedThreshold(cfg,s);await ctx.updateConfig(cfg);savePruneState(s);await sendOutput(user,{type:'unl-prune-settings-set',actionId:message.actionId||null,...pruneStatus(s,cfg,a.timestampMs)});}
async function manualHealth(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;await probeLocalHealth(ctx);await sendOutput(user,{type:'unl-health-probed',actionId:message.actionId||null,message:'NPL probe completed locally on each executing validator. Results stay outside consensus in ../unl-health.json.'});}
async function getLocalHealth(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const cfg=await ctx.getConfig();await sendOutput(user,{type:'local-unl-health',actionId:message.actionId||null,nodePublicKey:getLocalNodePublicKey(ctx,cfg),path:'../unl-health.json',snapshot:readLocalHealth()});}
async function reportUnlHealth(user,message,ctx){if(ctx.readonly)throw new Error('Health reports require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const key=normalizePublicKey(message.publicKey);const status=safeString(message.status,16).toLowerCase();if(!['alive','silent','unknown'].includes(status))throw new Error('Status must be alive, silent or unknown.');const cfg=await ctx.getConfig();if(!getConfigUnl(cfg).includes(key))throw new Error('Public key is not in the current UNL.');const state=loadPruneState();const old=state.nodes[key]||{};if(status==='alive')state.nodes[key]={...old,status,lastAliveAt:a.timestampMs,deadSince:null,lastReportAt:a.timestampMs,reportedBy:a.auth.userId};else if(status==='silent')state.nodes[key]={...old,status,deadSince:old.deadSince||a.timestampMs,lastReportAt:a.timestampMs,reportedBy:a.auth.userId};else state.nodes[key]={...old,status,lastReportAt:a.timestampMs,reportedBy:a.auth.userId};savePruneState(state);await sendOutput(user,{type:'unl-health-reported',actionId:message.actionId||null,publicKey:key,status});}
async function manualPrune(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const result=await evaluatePrune(ctx,a.auth.userId,'manual');await sendOutput(user,{type:'unl-prune-result',actionId:message.actionId||null,...result});}
async function reportRemovedHealth(user,message,ctx){if(ctx.readonly)throw new Error('Health reports require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const key=normalizePublicKey(message.publicKey);const status=safeString(message.status,16).toLowerCase();if(!['alive','silent','unknown'].includes(status))throw new Error('Status must be alive, silent or unknown.');const list=loadRemovedUnls();const r=list.find(x=>normalizePublicKeyMaybe(x.publicKey)===key);if(!r)throw new Error('Removed UNL not found.');r.healthStatus=status;r.healthReportedAt=a.timestampMs;r.healthReportedBy=a.auth.userId;saveRemovedUnls(list);await sendOutput(user,{type:'removed-unl-health-set',actionId:message.actionId||null,publicKey:key,status});}
async function readdRemoved(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const result=await evaluateReadd(ctx,a.auth.userId,'manual');await sendOutput(user,{type:'unl-readd-result',actionId:message.actionId||null,...result});}
async function deleteRemoved(user,message,ctx){if(ctx.readonly)throw new Error('Changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const key=normalizePublicKey(message.publicKey);saveRemovedUnls(loadRemovedUnls().filter(r=>normalizePublicKeyMaybe(r.publicKey)!==key));await sendOutput(user,{type:'removed-unl-deleted',actionId:message.actionId||null,publicKey:key});}

function loadCustomFields() { const d=readJson(CUSTOM_FIELDS_FILE,{fields:[]}); d.fields=Array.isArray(d.fields)?d.fields:[]; return d; }
function saveCustomFields(d) { writeJson(CUSTOM_FIELDS_FILE,d); }
function normalizeFieldId(value) { const id=safeString(value,64).toLowerCase(); if(!/^[a-z][a-z0-9_-]{0,63}$/.test(id))throw new Error('Field id must start with a letter and use letters, numbers, underscore or hyphen.'); return id; }
function normalizeFieldType(value) { const t=safeString(value,16).toLowerCase(); if(!['string','number','boolean','json','secret'].includes(t))throw new Error('Field type must be string, number, boolean, json or secret.'); return t; }
function normalizeFieldMode(value) { const m=safeString(value||'single',16).toLowerCase(); if(!['single','repeater'].includes(m))throw new Error('Field mode must be single or repeater.'); return m; }
function fieldMode(field){return normalizeFieldMode(field&&field.mode||'single');}
function normalizeCustomValue(field,value){ if(field.type==='number'){const n=Number(value);if(!Number.isFinite(n))throw new Error('Value must be a number.');return n;} if(field.type==='boolean'){if(typeof value==='boolean')return value;const s=String(value).toLowerCase();if(s==='true'||s==='1')return true;if(s==='false'||s==='0')return false;throw new Error('Value must be true or false.');} if(field.type==='json'){if(typeof value==='object'&&value!==null)return value;try{return JSON.parse(String(value));}catch{throw new Error('Value must be valid JSON.');}} return String(value===undefined||value===null?'':value); }
function normalizeCustomTarget(message){const scope=safeString(message.targetScope||message.scope||'node',16).toLowerCase();if(scope==='all')return{scope:'all',targetPublicKey:null};if(scope!=='node'&&scope!=='selected')throw new Error('Target scope must be node or all.');return{scope:'node',targetPublicKey:normalizePublicKey(message.targetPublicKey)};}
function customTargetApplies(target,local){return target.scope==='all'||target.targetPublicKey===local;}
function customTargetOutput(target){return target.scope==='all'?{targetScope:'all',targetPublicKey:null}:{targetScope:'node',targetPublicKey:target.targetPublicKey};}
function canonicalCustomValue(value){if(Array.isArray(value))return`[${value.map(canonicalCustomValue).join(',')}]`;if(value&&typeof value==='object'){return`{${Object.keys(value).sort().map(k=>`${JSON.stringify(k)}:${canonicalCustomValue(value[k])}`).join(',')}}`;}return JSON.stringify(value);}
function readLocalCustom(){const d=readJson(LOCAL_CUSTOM_FILE,{});return d&&typeof d==='object'&&!Array.isArray(d)?d:{};}
function writeLocalCustomQuiet(data){try{ensureDir(path.dirname(LOCAL_CUSTOM_FILE));fs.writeFileSync(LOCAL_CUSTOM_FILE,JSON.stringify(data,null,2));return true;}catch(err){console.log(`Local custom.json write failed: ${err.message}`);return false;}}
async function listCustomFields(user,message,ctx){const a=await requireRole(user,message,ctx);if(!a)return;const d=loadCustomFields();d.fields=d.fields.map(f=>({...f,mode:fieldMode(f)}));await sendOutput(user,{type:'custom-fields',actionId:message.actionId||null,...d});}
async function addCustomField(user,message,ctx){if(ctx.readonly)throw new Error('Field changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const d=loadCustomFields();const id=normalizeFieldId(message.id||message.fieldId);if(d.fields.some(f=>f.id===id))throw new Error('Custom field already exists.');const f={id,label:safeString(message.label||id,128),type:normalizeFieldType(message.fieldType||message.dataType||'string'),mode:normalizeFieldMode(message.fieldMode||(message.repeatable?'repeater':'single')),description:safeString(message.description,512),required:!!message.required,sensitive:!!message.sensitive,createdAt:a.timestampMs,createdBy:a.auth.userId};d.fields.push(f);d.fields.sort((x,y)=>x.id.localeCompare(y.id));saveCustomFields(d);await sendOutput(user,{type:'custom-field-added',actionId:message.actionId||null,field:f});}
async function updateCustomField(user,message,ctx){if(ctx.readonly)throw new Error('Field changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const d=loadCustomFields();const id=normalizeFieldId(message.id||message.fieldId);const f=d.fields.find(x=>x.id===id);if(!f)throw new Error('Custom field not found.');if(message.label!==undefined)f.label=safeString(message.label,128);if(message.description!==undefined)f.description=safeString(message.description,512);if(message.fieldType!==undefined||message.dataType!==undefined)f.type=normalizeFieldType(message.fieldType||message.dataType);if(message.fieldMode!==undefined||message.repeatable!==undefined)f.mode=normalizeFieldMode(message.fieldMode||(message.repeatable?'repeater':'single'));if(message.required!==undefined)f.required=!!message.required;if(message.sensitive!==undefined)f.sensitive=!!message.sensitive;f.updatedAt=a.timestampMs;f.updatedBy=a.auth.userId;saveCustomFields(d);await sendOutput(user,{type:'custom-field-updated',actionId:message.actionId||null,field:{...f,mode:fieldMode(f)}});}
async function removeCustomField(user,message,ctx){if(ctx.readonly)throw new Error('Field changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const d=loadCustomFields();const id=normalizeFieldId(message.id||message.fieldId);const before=d.fields.length;d.fields=d.fields.filter(f=>f.id!==id);if(d.fields.length===before)throw new Error('Custom field not found.');saveCustomFields(d);await sendOutput(user,{type:'custom-field-removed',actionId:message.actionId||null,fieldId:id});}
async function setCustomValue(user,message,ctx){if(ctx.readonly)throw new Error('Custom writes require consensus input.');const a=await requireRole(user,message,ctx);if(!a)return;const fieldId=normalizeFieldId(message.fieldId);const field=loadCustomFields().fields.find(f=>f.id===fieldId);if(!field)throw new Error('Unknown custom field.');if(fieldMode(field)==='repeater')throw new Error('Repeater fields use append-custom-value so existing items are preserved.');const target=normalizeCustomTarget(message);const value=normalizeCustomValue(field,message.value);const cfg=await ctx.getConfig();const local=getLocalNodePublicKey(ctx,cfg);if(customTargetApplies(target,local)){const data=readLocalCustom();data[fieldId]=value;writeLocalCustomQuiet(data);}await sendOutput(user,{type:'custom-value-dispatched',actionId:message.actionId||null,...customTargetOutput(target),fieldId,storage:{path:'../custom.json',scope:'node-local-seed',consensusState:false},message:target.scope==='all'?'Value dispatched to ../custom.json on all currently executing validators.':'Value dispatched to ../custom.json on the selected validator.'});}
async function appendCustomValue(user,message,ctx){if(ctx.readonly)throw new Error('Custom writes require consensus input.');const a=await requireRole(user,message,ctx);if(!a)return;const fieldId=normalizeFieldId(message.fieldId);const field=loadCustomFields().fields.find(f=>f.id===fieldId);if(!field)throw new Error('Unknown custom field.');if(fieldMode(field)!=='repeater')throw new Error('This field is not a repeater. Use set-custom-value for regular fields.');const target=normalizeCustomTarget(message);const value=normalizeCustomValue(field,message.value);const cfg=await ctx.getConfig();const local=getLocalNodePublicKey(ctx,cfg);if(customTargetApplies(target,local)){const data=readLocalCustom();let list=data[fieldId];if(!Array.isArray(list))list=list===undefined?[]:[list];list.push(value);data[fieldId]=list;writeLocalCustomQuiet(data);}await sendOutput(user,{type:'custom-value-appended',actionId:message.actionId||null,...customTargetOutput(target),fieldId,storage:{path:'../custom.json',scope:'node-local-seed',consensusState:false},message:target.scope==='all'?'Item appended on all currently executing validators.':'Item appended on the selected validator.'});}
async function removeCustomItem(user,message,ctx){if(ctx.readonly)throw new Error('Custom writes require consensus input.');const a=await requireRole(user,message,ctx);if(!a)return;const fieldId=normalizeFieldId(message.fieldId);const field=loadCustomFields().fields.find(f=>f.id===fieldId);if(!field)throw new Error('Unknown custom field.');if(fieldMode(field)!=='repeater')throw new Error('This field is not a repeater.');const target=normalizeCustomTarget(message);const value=normalizeCustomValue(field,message.value);const cfg=await ctx.getConfig();const local=getLocalNodePublicKey(ctx,cfg);if(customTargetApplies(target,local)){const data=readLocalCustom();const list=Array.isArray(data[fieldId])?data[fieldId]:[];const wanted=canonicalCustomValue(value);const idx=list.findIndex(v=>canonicalCustomValue(v)===wanted);if(idx>=0)list.splice(idx,1);data[fieldId]=list;writeLocalCustomQuiet(data);}await sendOutput(user,{type:'custom-item-removed',actionId:message.actionId||null,...customTargetOutput(target),fieldId,storage:{path:'../custom.json',scope:'node-local-seed',consensusState:false},message:'Removed one matching repeater item where present.'});}
async function clearCustomValue(user,message,ctx){if(ctx.readonly)throw new Error('Custom writes require consensus input.');const a=await requireRole(user,message,ctx);if(!a)return;const fieldId=normalizeFieldId(message.fieldId);const target=normalizeCustomTarget(message);const cfg=await ctx.getConfig();const local=getLocalNodePublicKey(ctx,cfg);if(customTargetApplies(target,local)){const data=readLocalCustom();delete data[fieldId];writeLocalCustomQuiet(data);}await sendOutput(user,{type:'custom-value-cleared',actionId:message.actionId||null,...customTargetOutput(target),fieldId,storage:{path:'../custom.json',scope:'node-local-seed',consensusState:false}});}
async function getLocalCustom(user,message,ctx){const a=await requireRole(user,message,ctx);if(!a)return;const cfg=await ctx.getConfig();const fields=loadCustomFields().fields;const data=readLocalCustom();const reveal=message.revealSensitive===true;const safe={};for(const f of fields){if(Object.prototype.hasOwnProperty.call(data,f.id))safe[f.id]=(f.sensitive&&!reveal)?'••••••••':data[f.id];}for(const [k,v] of Object.entries(data)){if(!fields.some(f=>f.id===k))safe[k]=v;}await sendOutput(user,{type:'local-custom',actionId:message.actionId||null,nodePublicKey:getLocalNodePublicKey(ctx,cfg),path:'../custom.json',storageScope:'node-local-seed',consensusState:false,values:safe});}

const WEB_RESERVED_TOP_LEVEL = new Set([
  'index.js','sidedish.js','cluster-controller.js','blake3_js_bg.wasm','contract.deploy.json','everadmin.package.json','admin-auth.json','.upload-sessions.json',
  'unl-metadata.json','unl-prune-state.json','removed-unls.json','custom-fields.json','runtime-package-state.json',
  'autocluster.state.json','autocluster.json','cluster.json','operations.json','acquires.json',
  'contract-versions','.contract-version-uploads','.runtime-package-uploads','runtime-upgrade-snapshots','.web-uploads','.public-uploads'
]);
function normalizeWebPath(value){
  let rel=safeString(value,512).replace(/\\/g,'/').replace(/^\/+/, '');
  // Transitional convenience for a cached pre-1.5.1 admin page: public/foo becomes foo.
  if(rel.startsWith('public/'))rel=rel.slice(7);
  if(!rel||rel.endsWith('/')||rel.includes('\0'))throw new Error('Invalid frontend state path.');
  const parts=rel.split('/');
  if(parts.some(part=>!part||part==='.'||part==='..'))throw new Error('Frontend state path cannot contain . or .. segments.');
  if(WEB_RESERVED_TOP_LEVEL.has(parts[0])||parts[0].startsWith('.'))throw new Error(`Frontend path is reserved by EverAdmin: ${parts[0]}`);
  return rel;
}
function normalizeLegacyPublicPath(value){
  const rel=safeString(value,512).replace(/\\/g,'/').replace(/^\/+/, '');
  if(!rel||!rel.startsWith('public/')||rel.includes('\0'))throw new Error('Invalid legacy public asset path.');
  const parts=rel.split('/');
  if(parts.some(part=>!part||part==='.'||part==='..'))throw new Error('Unsafe legacy public asset path.');
  return rel;
}
function resolveWebTarget(value){
  const rel=normalizeWebPath(value),target=path.resolve(STATE_ROOT,rel);
  if(!target.startsWith(STATE_ROOT+path.sep))throw new Error('Frontend path escaped state root.');
  return {rel,target};
}
function resolveManagedAssetPath(value,role){
  if(role==='web')return resolveWebTarget(value).target;
  if(role==='public'){
    const rel=normalizeLegacyPublicPath(value),target=path.resolve(STATE_ROOT,rel);
    if(!target.startsWith(STATE_ROOT+path.sep))throw new Error('Legacy public path escaped state root.');
    return target;
  }
  throw new Error(`Unsupported managed frontend role: ${role}`);
}
function walkWebAssets(dir=STATE_ROOT,prefix=''){
  if(!fs.existsSync(dir))return[];
  let out=[];
  for(const name of fs.readdirSync(dir).sort()){
    if(!prefix&&(WEB_RESERVED_TOP_LEVEL.has(name)||name.startsWith('.')))continue;
    const f=path.join(dir,name),rel=prefix?`${prefix}/${name}`:name,l=fs.lstatSync(f);
    if(l.isSymbolicLink())continue;
    if(l.isDirectory())out=out.concat(walkWebAssets(f,rel));
    else if(l.isFile()&&l.size<=MAX_PUBLIC_FILE_BYTES){try{normalizeWebPath(rel);out.push({path:rel,size:l.size,sha256:sha256Hex(fs.readFileSync(f))});}catch{}}
  }
  return out;
}
function safeUploadId(value){const id=safeString(value||randomHex(16),128);if(!/^[a-zA-Z0-9._-]{8,128}$/.test(id))throw new Error('Invalid upload id.');return id;}
function loadUploadSessions(){return readJson(UPLOAD_SESSIONS_FILE,{});} function saveUploadSessions(s){writeJson(UPLOAD_SESSIONS_FILE,s);}
async function uploadPublicAsset(user,message,ctx){if(ctx.readonly)throw new Error('Uploads require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const {rel,target}=resolveWebTarget(message.path||message.filename);const uploadId=safeUploadId(message.uploadId);const chunkNo=Number(message.chunkNo),totalChunks=Number(message.totalChunks);if(!Number.isInteger(chunkNo)||!Number.isInteger(totalChunks)||chunkNo<1||totalChunks<1||chunkNo>totalChunks)throw new Error('Invalid chunk numbers.');const hex=String(message.chunk||'');if(!/^[0-9a-fA-F]*$/.test(hex))throw new Error('Chunk must be hex.');const sessions=loadUploadSessions();const key=`web:${uploadId}`;ensureDir(WEB_UPLOADS_ROOT);ensureDir(path.dirname(target));const staged=path.resolve(WEB_UPLOADS_ROOT,`${uploadId}.part`);if(!staged.startsWith(WEB_UPLOADS_ROOT+path.sep))throw new Error('Invalid frontend upload staging path.');if(chunkNo===1){fs.rmSync(staged,{force:true});sessions[key]={rel,totalChunks,nextChunk:1,staged:path.basename(staged)};}const sess=sessions[key];if(!sess||sess.rel!==rel||sess.totalChunks!==totalChunks||sess.nextChunk!==chunkNo)throw new Error('Upload session mismatch.');fs.appendFileSync(staged,Buffer.from(hex,'hex'));if(fs.statSync(staged).size>MAX_PUBLIC_FILE_BYTES){fs.rmSync(staged,{force:true});delete sessions[key];saveUploadSessions(sessions);throw new Error('Frontend asset too large.');}if(chunkNo===totalChunks){const size=fs.statSync(staged).size,hash=sha256Hex(fs.readFileSync(staged));fs.renameSync(staged,target);delete sessions[key];saveUploadSessions(sessions);await sendOutput(user,{type:'public-asset-uploaded',actionId:message.actionId||null,path:rel,size,sha256:hash,atomic:true,storage:{root:'.',scope:'consensus-state',consensusState:true,layout:'flat-state-root'}});}else{sess.nextChunk++;saveUploadSessions(sessions);await sendOutput(user,{type:'upload-ack',actionId:message.actionId||null,uploadId,chunkNo,totalChunks,staged:true});}}
async function listPublicAssets(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const assets=walkWebAssets();await sendOutput(user,{type:'public-assets',actionId:message.actionId||null,storage:{root:'.',scope:'consensus-state',consensusState:true,layout:'flat-state-root'},assets});}

async function nodeRuntimeInfo(user,message,ctx){
  if(!ctx.readonly) throw new Error('Node runtime info is node-local and is available only through a read request.');
  const local = runtimeFromLocalHealth();
  await sendOutput(user,{type:'node-runtime-info',actionId:message.actionId||null,...local,nodePublicKey:local.nodePublicKey||normalizePublicKeyMaybe(ctx.publicKey)||normalizePublicKeyMaybe(ctx.public_key)||null});
}

function resolveReadableCodeFile(message){
  const kind=safeString(message.kind||'frontend',24).toLowerCase();
  if(kind==='frontend'){
    const {rel,target:file}=resolveWebTarget(message.path||'evernode.html');
    return {kind,source:'state',rel,file,protected:false,consensusState:true};
  }
  if(kind!=='contract')throw new Error('Code kind must be frontend or contract.');
  const source=safeString(message.source||'active',32).toLowerCase();
  const rel=normalizeVersionRel(message.path||message.filename||'sidedish.js');
  if(source==='base'){
    if(!['sidedish.js','index.js'].includes(rel))throw new Error('Built-in source exposes sidedish.js and protected index.js only.');
    const stateFile=path.resolve(STATE_ROOT,rel),imageFile=path.resolve(IMAGE_BASE_ROOT,rel);return {kind,source,rel,file:fs.existsSync(stateFile)?stateFile:imageFile,protected:rel==='index.js',consensusState:fs.existsSync(stateFile)};
  }
  const versions=loadVersions();
  let versionId=null;
  if(source==='active') versionId=versions.activeVersion;
  else if(source==='version') versionId=normalizeVersionId(message.versionId);
  else throw new Error('Contract source must be base, active or version.');
  if(!versionId)throw new Error('There is no active staged contract version. Load the built-in base instead.');
  if(!versions.versions[versionId])throw new Error('Contract version not found.');
  const root=versionRoot(versionId),file=targetIn(root,rel);
  return {kind,source,versionId,rel,file,protected:false,consensusState:true};
}

async function readCodeFile(user,message,ctx){
  const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;
  const target=resolveReadableCodeFile(message);
  const text=assertEditableTextFile(target.file,target.rel);
  await sendOutput(user,{type:'code-file',actionId:message.actionId||null,kind:target.kind,source:target.source,versionId:target.versionId||null,path:target.rel,protected:target.protected,consensusState:true,stateRootLabel:'HotPocket state (contract working directory)',...text});
}

function copyContractDraftTree(src,dst,prefix=''){
  ensureDir(dst);
  for(const name of fs.readdirSync(src)){
    const rel=prefix?`${prefix}/${name}`:name;
    if(rel==='manifest.json')continue;
    const s=path.join(src,name),d=path.join(dst,name),l=fs.lstatSync(s);
    if(l.isSymbolicLink())throw new Error('Symlinks are not allowed in contract versions.');
    if(l.isDirectory())copyContractDraftTree(s,d,rel);
    else if(l.isFile())fs.copyFileSync(s,d);
  }
}

async function prepareContractDraft(user,message,ctx){
  if(ctx.readonly)throw new Error('Preparing a contract draft requires consensus input.');
  const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;
  const bundleId=safeUploadId(message.versionUploadId),root=versionUploadRoot(bundleId);
  fs.rmSync(root,{recursive:true,force:true});ensureDir(root);
  const source=safeString(message.source||'active',32).toLowerCase();
  const versions=loadVersions();
  let copiedFrom=null;
  if(source==='active'){
    if(versions.activeVersion){copiedFrom=versions.activeVersion;copyContractDraftTree(versionRoot(copiedFrom),root);}
    else {copiedFrom='base';fs.copyFileSync(fs.existsSync(path.resolve(STATE_ROOT,'sidedish.js'))?path.resolve(STATE_ROOT,'sidedish.js'):path.resolve(IMAGE_BASE_ROOT,'sidedish.js'),path.join(root,'sidedish.js'));}
  }else if(source==='base'){
    copiedFrom='base';fs.copyFileSync(fs.existsSync(path.resolve(STATE_ROOT,'sidedish.js'))?path.resolve(STATE_ROOT,'sidedish.js'):path.resolve(IMAGE_BASE_ROOT,'sidedish.js'),path.join(root,'sidedish.js'));
  }else if(source==='version'){
    copiedFrom=normalizeVersionId(message.versionId);if(!versions.versions[copiedFrom])throw new Error('Source contract version not found.');copyContractDraftTree(versionRoot(copiedFrom),root);
  }else if(source==='empty'){copiedFrom='empty';}
  else throw new Error('Draft source must be active, base, version or empty.');
  const files=walkFiles(root);
  await sendOutput(user,{type:'contract-draft-prepared',actionId:message.actionId||null,versionUploadId:bundleId,copiedFrom,files,storage:{root:'.contract-version-uploads',scope:'consensus-state',consensusState:true}});
}

function normalizeContractLibraryKind(value){const kind=safeString(value||'contracts',32).toLowerCase();if(!Object.prototype.hasOwnProperty.call(CONTRACT_LIBRARY_ROOTS,kind))throw new Error('Contract library must be contracts or betacontracts.');return kind;}
function normalizeContractLibraryName(value){const name=safeString(value,180).trim();if(!name||name.includes('/')||name.includes('\\')||name.includes('\0')||name.startsWith('.')||!name.toLowerCase().endsWith('.zip'))throw new Error('Contract library filename must be a simple .zip filename.');return name;}
function contractLibraryPath(kindValue,nameValue){const kind=normalizeContractLibraryKind(kindValue),name=normalizeContractLibraryName(nameValue),root=CONTRACT_LIBRARY_ROOTS[kind],target=path.resolve(root,name);if(!target.startsWith(root+path.sep))throw new Error('Contract library path escaped its folder.');return {kind,name,root,target};}
function contractLibraryFiles(){const out=[];for(const kind of ['contracts','betacontracts']){const root=CONTRACT_LIBRARY_ROOTS[kind];if(!fs.existsSync(root))continue;let names=[];try{names=fs.readdirSync(root).sort();}catch{continue;}for(const name of names){if(!name.toLowerCase().endsWith('.zip'))continue;let target;try{target=contractLibraryPath(kind,name).target;}catch{continue;}let st;try{st=fs.statSync(target);}catch{continue;}if(!st.isFile())continue;out.push({kind,name,path:`${kind}/${name}`,size:st.size,sha256:sha256Hex(fs.readFileSync(target)),modifiedAt:Math.floor(st.mtimeMs)});}}return out;}
function contractZipEntriesForDraft(buffer,entryFile='sidedish.js'){
  if(!Buffer.isBuffer(buffer)||buffer.length<1)throw new Error('Contract ZIP is empty.');
  if(buffer.length>MAX_CONTRACT_LIBRARY_ZIP_BYTES)throw new Error('Contract ZIP exceeds the maximum package size.');
  const parsed=parseZipEntries(buffer),wanted=normalizeVersionRel(entryFile||'sidedish.js');
  const usable=[...parsed.values()].filter(e=>!e.path.startsWith('__MACOSX/')&&!e.path.endsWith('/.DS_Store')&&e.path!=='.DS_Store');
  if(!usable.length)throw new Error('Contract ZIP contains no usable files.');
  let prefix='';
  if(!usable.some(e=>e.path===wanted)){
    const tops=new Set(usable.map(e=>e.path.split('/')[0]));
    if(tops.size===1){const only=[...tops][0];if(usable.some(e=>e.path===`${only}/${wanted}`))prefix=`${only}/`;}
  }
  const files=[];let total=0;
  for(const e of usable){if(prefix&&!e.path.startsWith(prefix))continue;const rel=normalizeVersionRel(prefix?e.path.slice(prefix.length):e.path);if(!rel)continue;if(e.data.length>MAX_CONTRACT_FILE_BYTES)throw new Error(`Contract ZIP file is too large: ${rel}`);total+=e.data.length;if(total>MAX_CONTRACT_TOTAL_BYTES)throw new Error('Contract ZIP expands beyond the allowed contract bundle size.');files.push({rel,data:e.data});}
  if(!files.some(f=>f.rel===wanted))throw new Error(`Contract ZIP is missing entry file ${wanted}. Put it at the ZIP root (or inside one top-level folder).`);
  return {files,entryFile:wanted,totalBytes:total,strippedPrefix:prefix||null};
}
function extractContractZipToDraft(buffer,bundleId,entryFile){const root=versionUploadRoot(bundleId);fs.rmSync(root,{recursive:true,force:true});ensureDir(root);try{const inspected=contractZipEntriesForDraft(buffer,entryFile);for(const f of inspected.files){const target=targetIn(root,f.rel);ensureDir(path.dirname(target));fs.writeFileSync(target,f.data);}return inspected;}catch(err){fs.rmSync(root,{recursive:true,force:true});throw err;}}
async function listContractLibrary(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;await sendOutput(user,{type:'contract-library',actionId:message.actionId||null,folders:['contracts','betacontracts'],files:contractLibraryFiles()});}
async function uploadContractLibraryZip(user,message,ctx){if(ctx.readonly)throw new Error('ZIP library uploads require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const {kind,name,target}=contractLibraryPath(message.kind,message.filename||message.name),uploadId=safeUploadId(message.uploadId),chunkNo=Number(message.chunkNo),totalChunks=Number(message.totalChunks);if(!Number.isInteger(chunkNo)||!Number.isInteger(totalChunks)||chunkNo<1||totalChunks<1||chunkNo>totalChunks)throw new Error('Invalid chunk numbers.');const hex=String(message.chunk||'');if(!/^[0-9a-fA-F]*$/.test(hex))throw new Error('Chunk must be hex.');ensureDir(WEB_UPLOADS_ROOT);ensureDir(path.dirname(target));const staged=path.resolve(WEB_UPLOADS_ROOT,`zip-library-${uploadId}.part`);if(!staged.startsWith(WEB_UPLOADS_ROOT+path.sep))throw new Error('Invalid ZIP library staging path.');const sessions=loadUploadSessions(),key=`zip-library:${uploadId}`;if(chunkNo===1){fs.rmSync(staged,{force:true});sessions[key]={kind,name,totalChunks,nextChunk:1};}const sess=sessions[key];if(!sess||sess.kind!==kind||sess.name!==name||sess.totalChunks!==totalChunks||sess.nextChunk!==chunkNo)throw new Error('ZIP library upload session mismatch.');fs.appendFileSync(staged,Buffer.from(hex,'hex'));if(fs.statSync(staged).size>MAX_CONTRACT_LIBRARY_ZIP_BYTES){fs.rmSync(staged,{force:true});delete sessions[key];saveUploadSessions(sessions);throw new Error('ZIP exceeds the maximum library package size.');}if(chunkNo===totalChunks){const data=fs.readFileSync(staged);fs.renameSync(staged,target);delete sessions[key];saveUploadSessions(sessions);await sendOutput(user,{type:'contract-library-uploaded',actionId:message.actionId||null,kind,name,path:`${kind}/${name}`,size:data.length,sha256:sha256Hex(data),validation:'deferred-until-use'});}else{sess.nextChunk++;saveUploadSessions(sessions);await sendOutput(user,{type:'upload-ack',actionId:message.actionId||null,uploadId,chunkNo,totalChunks});}}
async function deleteContractLibraryZip(user,message,ctx){if(ctx.readonly)throw new Error('Contract library changes require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const {kind,name,target}=contractLibraryPath(message.kind,message.name||message.filename);if(!fs.existsSync(target))throw new Error('Contract ZIP was not found.');fs.rmSync(target,{force:true});await sendOutput(user,{type:'contract-library-deleted',actionId:message.actionId||null,kind,name});}
async function stageContractLibraryZip(user,message,ctx){if(ctx.readonly)throw new Error('Staging a contract ZIP requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const {kind,name,target}=contractLibraryPath(message.kind,message.name||message.filename);if(!fs.existsSync(target)||!fs.statSync(target).isFile())throw new Error('Contract ZIP was not found in the library.');const bundleId=safeUploadId(message.versionUploadId||randomHex(16)),entryFile=message.entryFile||'sidedish.js';extractContractZipToDraft(fs.readFileSync(target),bundleId,entryFile);const label=safeString(message.label||path.basename(name,'.zip'),48);await finalizeContractVersion(user,{...message,versionUploadId:bundleId,label,entryFile},ctx);}
async function prepareLibraryRuntimePackage(user,message,ctx){if(ctx.readonly)throw new Error('Loading a library ZIP into the runtime upgrader requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const {kind,name,target}=contractLibraryPath(message.kind,message.name||message.filename);if(!fs.existsSync(target)||!fs.statSync(target).isFile())throw new Error('ZIP was not found in the library.');const packageUploadId=safeUploadId(message.packageUploadId);ensureDir(RUNTIME_PACKAGE_UPLOADS_ROOT);const dst=runtimePackagePath(packageUploadId);fs.rmSync(dst,{force:true});fs.copyFileSync(target,dst);try{await sendOutput(user,{...inspectRuntimePackageInternal(packageUploadId),actionId:message.actionId||null,library:{kind,name,path:`${kind}/${name}`}});}catch(err){fs.rmSync(dst,{force:true});throw err;}}
function normalizeVersionRel(value){const rel=safeString(value||'sidedish.js',512).replace(/\\/g,'/').replace(/^\/+/, '');if(!rel||rel.includes('..')||rel.startsWith('.'))throw new Error('Invalid version file path.');return rel;}
function normalizeVersionId(value){const id=safeString(value,160);if(!/^[a-zA-Z0-9._-]{3,160}$/.test(id)||id.includes('..'))throw new Error('Invalid version id.');return id;}
function versionRoot(id){const r=path.resolve(CONTRACT_VERSIONS_ROOT,normalizeVersionId(id));if(!r.startsWith(CONTRACT_VERSIONS_ROOT+path.sep))throw new Error('Invalid version path.');return r;}
function versionUploadRoot(id){const r=path.resolve(CONTRACT_UPLOADS_ROOT,safeUploadId(id));if(!r.startsWith(CONTRACT_UPLOADS_ROOT+path.sep))throw new Error('Invalid upload path.');return r;}
function targetIn(root,rel){const t=path.resolve(root,normalizeVersionRel(rel));if(!t.startsWith(path.resolve(root)+path.sep))throw new Error('Version path escaped root.');return t;}
function walkFiles(dir,prefix=''){if(!fs.existsSync(dir))return[];let out=[];for(const name of fs.readdirSync(dir).sort()){const f=path.join(dir,name),rel=prefix?`${prefix}/${name}`:name,l=fs.lstatSync(f);if(l.isSymbolicLink())throw new Error('Symlinks are not allowed.');if(l.isDirectory())out=out.concat(walkFiles(f,rel));else if(l.isFile()){if(l.size>MAX_CONTRACT_FILE_BYTES)throw new Error(`File too large: ${rel}`);out.push({path:rel,size:l.size,sha256:sha256Hex(fs.readFileSync(f))});}}return out;}
function bundleHash(files){const h=crypto.createHash('sha256');for(const f of files){h.update(f.path);h.update('\0');h.update(String(f.size));h.update('\0');h.update(f.sha256);h.update('\n');}return h.digest('hex');}
function copyTree(src,dst){ensureDir(dst);for(const name of fs.readdirSync(src)){const s=path.join(src,name),d=path.join(dst,name),l=fs.lstatSync(s);if(l.isSymbolicLink())throw new Error('Symlinks are not allowed.');if(l.isDirectory())copyTree(s,d);else if(l.isFile())fs.copyFileSync(s,d);}}
function loadVersions(){const d=readJson(CONTRACT_VERSIONS_INDEX_FILE,{activeVersion:null,previousActiveVersion:null,versions:{}});d.versions=d.versions&&typeof d.versions==='object'?d.versions:{};return d;} function saveVersions(d){ensureDir(CONTRACT_VERSIONS_ROOT);writeJson(CONTRACT_VERSIONS_INDEX_FILE,d);}
async function uploadContractVersionFile(user,message,ctx){if(ctx.readonly)throw new Error('Uploads require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const bundleId=safeUploadId(message.versionUploadId);const fileId=safeUploadId(message.uploadId);const rel=normalizeVersionRel(message.filename||message.path);const root=versionUploadRoot(bundleId),target=targetIn(root,rel);const chunkNo=Number(message.chunkNo),totalChunks=Number(message.totalChunks);if(!Number.isInteger(chunkNo)||!Number.isInteger(totalChunks)||chunkNo<1||totalChunks<1||chunkNo>totalChunks)throw new Error('Invalid chunk numbers.');const hex=String(message.chunk||'');if(!/^[0-9a-fA-F]*$/.test(hex))throw new Error('Chunk must be hex.');const sessions=loadUploadSessions();const key=`version:${bundleId}:${fileId}`;ensureDir(path.dirname(target));if(chunkNo===1){if(fs.existsSync(target))fs.rmSync(target,{force:true});sessions[key]={rel,totalChunks,nextChunk:1};}const s=sessions[key];if(!s||s.rel!==rel||s.totalChunks!==totalChunks||s.nextChunk!==chunkNo)throw new Error('Version upload session mismatch.');fs.appendFileSync(target,Buffer.from(hex,'hex'));if(fs.statSync(target).size>MAX_CONTRACT_FILE_BYTES){fs.rmSync(target,{force:true});delete sessions[key];saveUploadSessions(sessions);throw new Error('Contract file too large.');}if(chunkNo===totalChunks){delete sessions[key];saveUploadSessions(sessions);await sendOutput(user,{type:'contract-version-file-uploaded',actionId:message.actionId||null,versionUploadId:bundleId,filename:rel,size:fs.statSync(target).size});}else{s.nextChunk++;saveUploadSessions(sessions);await sendOutput(user,{type:'upload-ack',actionId:message.actionId||null,versionUploadId:bundleId,filename:rel,chunkNo,totalChunks});}}
async function finalizeContractVersion(user,message,ctx){if(ctx.readonly)throw new Error('Finalization requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const bundleId=safeUploadId(message.versionUploadId),root=versionUploadRoot(bundleId),entry=normalizeVersionRel(message.entryFile||'sidedish.js');if(!fs.existsSync(root))throw new Error('Version upload not found.');const entryPath=targetIn(root,entry);if(!fs.existsSync(entryPath)||fs.statSync(entryPath).size<1)throw new Error('Entry file is missing/empty.');if(path.extname(entryPath)==='.js'){try{new Function('exports','require','module','__filename','__dirname',fs.readFileSync(entryPath,'utf8'));}catch(err){throw new Error(`JavaScript syntax check failed: ${err.message}`);}}const files=walkFiles(root);const total=files.reduce((n,f)=>n+f.size,0);if(total>MAX_CONTRACT_TOTAL_BYTES)throw new Error('Contract bundle is too large.');const hash=bundleHash(files);const label=safeString(message.label||'contract',48).replace(/[^a-zA-Z0-9._-]+/g,'-').replace(/^-+|-+$/g,'')||'contract';const stamp=new Date(a.timestampMs).toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'z');const id=normalizeVersionId(`${stamp}-${label}-${hash.slice(0,12)}`);const dst=versionRoot(id);if(fs.existsSync(dst))throw new Error('Version already exists.');copyTree(root,dst);fs.rmSync(root,{recursive:true,force:true});const manifest={versionId:id,label,entryFile:entry,bundleHash:hash,status:'staged',createdAt:a.timestampMs,createdBy:a.auth.userId,activatedAt:null,activatedBy:null,fileCount:files.length,totalBytes:total,files};writeJson(path.join(dst,'manifest.json'),manifest);const index=loadVersions();index.versions[id]=manifest;saveVersions(index);await sendOutput(user,{type:'contract-version-finalized',actionId:message.actionId||null,version:manifest});}
async function listContractVersions(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const index=loadVersions();await sendOutput(user,{type:'contract-versions',actionId:message.actionId||null,activeVersion:index.activeVersion,previousActiveVersion:index.previousActiveVersion,versions:Object.values(index.versions).sort((x,y)=>Number(y.createdAt||0)-Number(x.createdAt||0)),loaderMode:true,baseAppVersion:APP_VERSION});}
async function activateContractVersion(user,message,ctx){if(ctx.readonly)throw new Error('Activation requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const id=normalizeVersionId(message.versionId),index=loadVersions(),v=index.versions[id];if(!v)throw new Error('Version not found.');const expected=safeString(message.expectedHash||message.bundleHash,128).toLowerCase();if(expected&&expected!==String(v.bundleHash).toLowerCase())throw new Error('Expected hash does not match.');const entry=targetIn(versionRoot(id),v.entryFile||'sidedish.js');if(!fs.existsSync(entry))throw new Error('Version entry file is missing.');if(index.activeVersion&&index.activeVersion!==id)index.previousActiveVersion=index.activeVersion;index.activeVersion=id;for(const [vid,rec] of Object.entries(index.versions)){if(rec)rec.status=vid===id?'active':(rec.status==='active'?'inactive':rec.status);}v.activatedAt=a.timestampMs;v.activatedBy=a.auth.userId;saveVersions(index);writeJson(ACTIVE_VERSION_FILE,{versionId:id,entryFile:v.entryFile||'sidedish.js',bundleHash:v.bundleHash,activatedAt:a.timestampMs,activatedBy:a.auth.userId});if(index.previousActiveVersion)writeJson(PREVIOUS_VERSION_FILE,{versionId:index.previousActiveVersion});await sendOutput(user,{type:'contract-version-activated',actionId:message.actionId||null,activeVersion:id,previousActiveVersion:index.previousActiveVersion,loaderMode:true,message:'Version activated behind stable loader. It will be loaded on the next invocation.'});}
async function rollbackContractVersion(user,message,ctx){if(ctx.readonly)throw new Error('Rollback requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const index=loadVersions();const id=normalizeVersionId(message.versionId||index.previousActiveVersion);if(!index.versions[id])throw new Error('Rollback version not found.');const old=index.activeVersion;index.activeVersion=id;index.previousActiveVersion=old&&old!==id?old:index.previousActiveVersion;for(const [vid,rec] of Object.entries(index.versions)){if(rec)rec.status=vid===id?'active':(rec.status==='active'?'inactive':rec.status);}saveVersions(index);const v=index.versions[id];writeJson(ACTIVE_VERSION_FILE,{versionId:id,entryFile:v.entryFile||'sidedish.js',bundleHash:v.bundleHash,activatedAt:a.timestampMs,activatedBy:a.auth.userId,rollback:true});await sendOutput(user,{type:'contract-version-rolled-back',actionId:message.actionId||null,activeVersion:id,previousActiveVersion:index.previousActiveVersion});}
async function deactivateContractVersion(user,message,ctx){if(ctx.readonly)throw new Error('Deactivation requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const index=loadVersions();if(index.activeVersion)index.previousActiveVersion=index.activeVersion;index.activeVersion=null;saveVersions(index);if(fs.existsSync(ACTIVE_VERSION_FILE))fs.rmSync(ACTIVE_VERSION_FILE,{force:true});await sendOutput(user,{type:'contract-version-deactivated',actionId:message.actionId||null,baseAppVersion:APP_VERSION});}
async function deleteContractVersion(user,message,ctx){if(ctx.readonly)throw new Error('Deletion requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const id=normalizeVersionId(message.versionId),index=loadVersions();if(id===index.activeVersion||id===index.previousActiveVersion)throw new Error('Cannot delete active or rollback version.');if(!index.versions[id])throw new Error('Version not found.');fs.rmSync(versionRoot(id),{recursive:true,force:true});delete index.versions[id];saveVersions(index);await sendOutput(user,{type:'contract-version-deleted',actionId:message.actionId||null,versionId:id});}



// -----------------------------------------------------------------------------
// Runtime ZIP upgrades
// -----------------------------------------------------------------------------
function normalizePackagePath(value){
  const rel=safeString(value,512);
  if(!rel||rel.includes('\\')||rel.includes('\0')||rel.startsWith('/')||rel.endsWith('/'))throw new Error('Invalid package file path.');
  const parts=rel.split('/');
  if(parts.some(part=>!part||part==='.'||part==='..'))throw new Error(`Unsafe package path: ${rel}`);
  if(rel.includes(':'))throw new Error(`Unsafe package path: ${rel}`);
  return rel;
}
function runtimePackagePath(id){
  const r=path.resolve(RUNTIME_PACKAGE_UPLOADS_ROOT,`${safeUploadId(id)}.zip`);
  if(!r.startsWith(RUNTIME_PACKAGE_UPLOADS_ROOT+path.sep))throw new Error('Invalid runtime package path.');
  return r;
}
function runtimeSnapshotRoot(id){
  const r=path.resolve(RUNTIME_UPGRADE_SNAPSHOTS_ROOT,normalizeVersionId(id));
  if(!r.startsWith(RUNTIME_UPGRADE_SNAPSHOTS_ROOT+path.sep))throw new Error('Invalid runtime snapshot path.');
  return r;
}
function crc32(buf){
  let crc=0xffffffff;
  for(let i=0;i<buf.length;i++){
    crc^=buf[i];
    for(let bit=0;bit<8;bit++) crc=(crc>>>1)^((crc&1)?0xedb88320:0);
  }
  return (crc^0xffffffff)>>>0;
}
function parseZipEntries(buffer){
  if(!Buffer.isBuffer(buffer)||buffer.length<22)throw new Error('ZIP is empty or truncated.');
  if(buffer.length>MAX_RUNTIME_PACKAGE_BYTES)throw new Error('Runtime ZIP exceeds the maximum package size.');
  const min=Math.max(0,buffer.length-65557);let eocd=-1;
  for(let i=buffer.length-22;i>=min;i--){if(buffer.readUInt32LE(i)===0x06054b50){eocd=i;break;}}
  if(eocd<0)throw new Error('ZIP end-of-central-directory record was not found.');
  const diskNo=buffer.readUInt16LE(eocd+4),cdDisk=buffer.readUInt16LE(eocd+6),diskEntries=buffer.readUInt16LE(eocd+8),entryCount=buffer.readUInt16LE(eocd+10);
  const cdSize=buffer.readUInt32LE(eocd+12),cdOffset=buffer.readUInt32LE(eocd+16);
  if(diskNo!==0||cdDisk!==0||diskEntries!==entryCount)throw new Error('Multi-disk ZIP packages are not supported.');
  if(entryCount===0||entryCount>MAX_RUNTIME_PACKAGE_FILES)throw new Error('Runtime ZIP has an invalid number of files.');
  if(cdOffset===0xffffffff||cdSize===0xffffffff||entryCount===0xffff)throw new Error('ZIP64 runtime packages are not supported.');
  if(cdOffset+cdSize>eocd||cdOffset<0)throw new Error('ZIP central directory is invalid.');
  const entries=new Map();let pos=cdOffset,totalUncompressed=0;
  for(let n=0;n<entryCount;n++){
    if(pos+46>buffer.length||buffer.readUInt32LE(pos)!==0x02014b50)throw new Error('ZIP central directory entry is invalid.');
    const madeBy=buffer.readUInt16LE(pos+4),flags=buffer.readUInt16LE(pos+8),method=buffer.readUInt16LE(pos+10),expectedCrc=buffer.readUInt32LE(pos+16)>>>0;
    const compressedSize=buffer.readUInt32LE(pos+20),uncompressedSize=buffer.readUInt32LE(pos+24),nameLen=buffer.readUInt16LE(pos+28),extraLen=buffer.readUInt16LE(pos+30),commentLen=buffer.readUInt16LE(pos+32),externalAttrs=buffer.readUInt32LE(pos+38),localOffset=buffer.readUInt32LE(pos+42);
    if(compressedSize===0xffffffff||uncompressedSize===0xffffffff||localOffset===0xffffffff)throw new Error('ZIP64 entries are not supported.');
    if(flags&1)throw new Error('Encrypted ZIP entries are not supported.');
    if(![0,8].includes(method))throw new Error(`Unsupported ZIP compression method ${method}.`);
    const nameStart=pos+46,nameEnd=nameStart+nameLen;
    if(nameEnd+extraLen+commentLen>buffer.length)throw new Error('ZIP filename record is truncated.');
    const rawName=buffer.subarray(nameStart,nameEnd).toString('utf8');
    pos=nameEnd+extraLen+commentLen;
    if(rawName.endsWith('/'))continue;
    const rel=normalizePackagePath(rawName);
    if(entries.has(rel))throw new Error(`Duplicate ZIP path: ${rel}`);
    const host=(madeBy>>>8)&0xff,mode=(externalAttrs>>>16)&0xffff;
    if(host===3&&(mode&0xf000)===0xa000)throw new Error(`Symlinks are not allowed in runtime packages: ${rel}`);
    if(localOffset+30>buffer.length||buffer.readUInt32LE(localOffset)!==0x04034b50)throw new Error(`ZIP local header is invalid for ${rel}.`);
    const localNameLen=buffer.readUInt16LE(localOffset+26),localExtraLen=buffer.readUInt16LE(localOffset+28),dataStart=localOffset+30+localNameLen+localExtraLen,dataEnd=dataStart+compressedSize;
    if(dataEnd>buffer.length)throw new Error(`ZIP payload is truncated for ${rel}.`);
    const compressed=buffer.subarray(dataStart,dataEnd);
    let data;
    try{data=method===0?Buffer.from(compressed):zlib.inflateRawSync(compressed,{maxOutputLength:MAX_RUNTIME_PACKAGE_UNCOMPRESSED_BYTES});}
    catch(err){throw new Error(`Could not decompress ${rel}: ${err.message}`);}
    if(data.length!==uncompressedSize)throw new Error(`Uncompressed size mismatch for ${rel}.`);
    if(crc32(data)!==expectedCrc)throw new Error(`CRC-32 mismatch for ${rel}.`);
    totalUncompressed+=data.length;
    if(totalUncompressed>MAX_RUNTIME_PACKAGE_UNCOMPRESSED_BYTES)throw new Error('Runtime ZIP expands beyond the allowed total size.');
    entries.set(rel,{path:rel,data,size:data.length,compressedSize,sha256:sha256Hex(data),method});
  }
  return entries;
}
function parseSemver(value){const m=/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(safeString(value,64).replace(/^v/i,''));return m?m.slice(1,4).map(Number):null;}
function compareSemver(a,b){const x=parseSemver(a),y=parseSemver(b);if(!x||!y)return 0;for(let i=0;i<3;i++){if(x[i]!==y[i])return x[i]<y[i]?-1:1;}return 0;}
function loadRuntimePackageState(){const d=readJson(RUNTIME_PACKAGE_STATE_FILE,null);return d&&typeof d==='object'&&!Array.isArray(d)?d:null;}
function validateRuntimeManifest(entries){
  const manifestEntry=entries.get(RUNTIME_PACKAGE_MANIFEST);if(!manifestEntry)throw new Error(`Runtime ZIP is missing ${RUNTIME_PACKAGE_MANIFEST}.`);
  let manifest;try{manifest=JSON.parse(manifestEntry.data.toString('utf8'));}catch{throw new Error('Runtime package manifest is not valid JSON.');}
  if(!manifest||typeof manifest!=='object'||Array.isArray(manifest))throw new Error('Runtime package manifest must be an object.');
  if(Number(manifest.schema)!==1)throw new Error('Unsupported runtime package manifest schema.');
  if(safeString(manifest.product,80)!=='everadmin-control-plane')throw new Error('This ZIP is not an EverAdmin Control Plane runtime package.');
  const version=safeString(manifest.version,64).replace(/^v/i,'');if(!parseSemver(version))throw new Error('Runtime package version must be semantic version X.Y.Z.');
  const minimum=safeString(manifest.minimumUpgradeFrom||'1.4.0',64).replace(/^v/i,'');if(minimum&&!parseSemver(minimum))throw new Error('minimumUpgradeFrom is invalid.');
  if(minimum&&compareSemver(APP_VERSION,minimum)<0)throw new Error(`This package requires EverAdmin ${minimum} or newer; current runtime is ${APP_VERSION}.`);
  const declared=Array.isArray(manifest.files)?manifest.files:[];if(!declared.length||declared.length>MAX_RUNTIME_PACKAGE_FILES)throw new Error('Runtime package manifest has an invalid files list.');
  const layout=safeString(manifest.layout||'',64);
  const flatWebHints=new Set();
  if(layout==='flat-state-root'&&Array.isArray(manifest.webFiles)){
    for(const value of manifest.webFiles){const rel=normalizePackagePath(value);normalizeWebPath(rel);flatWebHints.add(rel);}
  }
  const allowedRoles=new Set(['contract','web','public','protected','metadata']);const seen=new Set(),files=[];
  for(const item of declared){
    if(!item||typeof item!=='object')throw new Error('Runtime package manifest contains an invalid file record.');
    const rel=normalizePackagePath(item.path),declaredRole=safeString(item.role,24).toLowerCase(),expected=safeString(item.sha256,64).toLowerCase();
    if(seen.has(rel))throw new Error(`Manifest declares ${rel} more than once.`);seen.add(rel);
    if(!allowedRoles.has(declaredRole))throw new Error(`Invalid role for ${rel}.`);
    const role=(layout==='flat-state-root'&&declaredRole==='metadata'&&flatWebHints.has(rel))?'web':declaredRole;
    if(!/^[0-9a-f]{64}$/.test(expected))throw new Error(`Invalid SHA-256 for ${rel}.`);
    const entry=entries.get(rel);if(!entry)throw new Error(`Manifest-declared file is missing from ZIP: ${rel}`);
    if(entry.sha256!==expected)throw new Error(`SHA-256 mismatch for ${rel}.`);
    if(role==='web')normalizeWebPath(rel);
    if(role==='public')normalizeLegacyPublicPath(rel);
    if(role==='contract'){
      const vr=normalizeVersionRel(rel);if(vr==='index.js')throw new Error('index.js cannot be a contract-managed upgrade file.');
    }
    if(role==='protected'&&rel!=='index.js')throw new Error(`Only index.js may use the protected role (${rel}).`);
    files.push({path:rel,role,declaredRole,sha256:expected,size:entry.size});
  }
  for(const rel of entries.keys())if(rel!==RUNTIME_PACKAGE_MANIFEST&&!seen.has(rel))throw new Error(`ZIP contains an undeclared file: ${rel}`);
  const entryFile=normalizeVersionRel(manifest.entryFile||'sidedish.js');
  if(!files.some(f=>f.role==='contract'&&f.path===entryFile))throw new Error(`Contract entry file ${entryFile} is not declared as a contract file.`);
  return {schema:1,product:'everadmin-control-plane',version,minimumUpgradeFrom:minimum,entryFile,layout,webFiles:[...flatWebHints],files};
}
function currentManagedFile(pathValue,role){
  const rel=normalizePackagePath(pathValue);let file;
  if(role==='contract'){
    const versions=loadVersions();
    if(versions.activeVersion)file=targetIn(versionRoot(versions.activeVersion),normalizeVersionRel(rel));
    else file=path.resolve(STATE_ROOT,normalizeVersionRel(rel));
  }else if(role==='web')file=resolveManagedAssetPath(rel,'web');
  else if(role==='public')file=resolveManagedAssetPath(rel,'public');
  else file=path.resolve(STATE_ROOT,rel);
  if(!file.startsWith(STATE_ROOT+path.sep)&&file!==STATE_ROOT)throw new Error('Managed file escaped state root.');
  if(!fs.existsSync(file)||!fs.statSync(file).isFile())return null;
  const data=fs.readFileSync(file);return {size:data.length,sha256:sha256Hex(data),file};
}
function inspectRuntimePackageInternal(packageUploadId){
  const zipPath=runtimePackagePath(packageUploadId);if(!fs.existsSync(zipPath))throw new Error('Uploaded runtime package was not found.');
  const zip=fs.readFileSync(zipPath),packageSha256=sha256Hex(zip),entries=parseZipEntries(zip),manifest=validateRuntimeManifest(entries),previous=loadRuntimePackageState();
  const diffs=manifest.files.map(f=>{const current=currentManagedFile(f.path,f.role),apply=f.role==='contract'||f.role==='web'||f.role==='public';return {...f,apply,status:current?(current.sha256===f.sha256?'same':'modified'):'added',currentSha256:current?current.sha256:null,currentSize:current?current.size:null};});
  const newManaged=new Map(manifest.files.filter(f=>f.role==='contract'||f.role==='web'||f.role==='public').map(f=>[f.path,f.role]));const removed=[];
  if(previous&&Array.isArray(previous.managedFiles))for(const old of previous.managedFiles){const rel=normalizePackagePath(old.path),role=safeString(old.role,24);if((role==='contract'||role==='web'||role==='public')&&!newManaged.has(rel)){const current=currentManagedFile(rel,role);removed.push({path:rel,role,status:'removed',apply:true,currentSha256:current?current.sha256:null,currentSize:current?current.size:null});}}
  // Flat-layout migration: remove only legacy public/ copies of files explicitly owned by this package.
  if(manifest.layout==='flat-state-root'){for(const rel of manifest.webFiles||[]){const legacy=`public/${rel}`;if(!removed.some(r=>r.path===legacy)){const current=currentManagedFile(legacy,'public');if(current)removed.push({path:legacy,role:'public',status:'removed',apply:true,migration:'flat-state-root',currentSha256:current.sha256,currentSize:current.size});}}}
  const appliedChanges=diffs.filter(d=>d.apply&&d.status!=='same').length+removed.length;
  return {type:'runtime-package-inspection',packageUploadId:safeUploadId(packageUploadId),packageSha256,packageBytes:zip.length,currentVersion:APP_VERSION,targetVersion:manifest.version,minimumUpgradeFrom:manifest.minimumUpgradeFrom,manifest,diffs,removed,appliedChanges,protectedFiles:diffs.filter(d=>d.role==='protected'),metadataFiles:diffs.filter(d=>d.role==='metadata'),previousPackageState:previous};
}
async function uploadRuntimePackage(user,message,ctx){
  if(ctx.readonly)throw new Error('Runtime package uploads require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;
  const id=safeUploadId(message.packageUploadId||message.uploadId),chunkNo=Number(message.chunkNo),totalChunks=Number(message.totalChunks);if(!Number.isInteger(chunkNo)||!Number.isInteger(totalChunks)||chunkNo<1||totalChunks<1||chunkNo>totalChunks)throw new Error('Invalid chunk numbers.');
  const hex=String(message.chunk||'');if(!/^[0-9a-fA-F]*$/.test(hex))throw new Error('Chunk must be hex.');ensureDir(RUNTIME_PACKAGE_UPLOADS_ROOT);const target=runtimePackagePath(id),sessions=loadUploadSessions(),key=`runtime-package:${id}`;
  if(chunkNo===1){fs.rmSync(target,{force:true});sessions[key]={totalChunks,nextChunk:1};}
  const sess=sessions[key];if(!sess||sess.totalChunks!==totalChunks||sess.nextChunk!==chunkNo)throw new Error('Runtime package upload session mismatch.');fs.appendFileSync(target,Buffer.from(hex,'hex'));
  if(fs.statSync(target).size>MAX_RUNTIME_PACKAGE_BYTES){fs.rmSync(target,{force:true});delete sessions[key];saveUploadSessions(sessions);throw new Error('Runtime ZIP exceeds the maximum package size.');}
  if(chunkNo===totalChunks){delete sessions[key];saveUploadSessions(sessions);await sendOutput(user,{type:'runtime-package-uploaded',actionId:message.actionId||null,packageUploadId:id,size:fs.statSync(target).size,sha256:sha256Hex(fs.readFileSync(target))});}
  else{sess.nextChunk++;saveUploadSessions(sessions);await sendOutput(user,{type:'upload-ack',actionId:message.actionId||null,packageUploadId:id,chunkNo,totalChunks});}
}
async function inspectRuntimePackage(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;await sendOutput(user,{...inspectRuntimePackageInternal(message.packageUploadId),actionId:message.actionId||null});}
function createRuntimeVersionFromPackage(inspection,entries,a){
  const contractFiles=inspection.manifest.files.filter(f=>f.role==='contract');const removedContract=inspection.removed.filter(f=>f.role==='contract');
  const contractChanged=inspection.diffs.some(f=>f.role==='contract'&&f.status!=='same')||removedContract.length>0;if(!contractChanged)return null;
  const bundleId=safeUploadId(`pkg-${crypto.randomBytes(12).toString('hex')}`),root=versionUploadRoot(bundleId);fs.rmSync(root,{recursive:true,force:true});ensureDir(root);
  const versions=loadVersions();if(versions.activeVersion)copyContractDraftTree(versionRoot(versions.activeVersion),root);else fs.copyFileSync(fs.existsSync(path.resolve(STATE_ROOT,'sidedish.js'))?path.resolve(STATE_ROOT,'sidedish.js'):path.resolve(IMAGE_BASE_ROOT,'sidedish.js'),path.join(root,'sidedish.js'));
  for(const f of contractFiles){const target=targetIn(root,f.path);ensureDir(path.dirname(target));fs.writeFileSync(target,entries.get(f.path).data);}
  for(const f of removedContract){const target=targetIn(root,f.path);fs.rmSync(target,{force:true});}
  const entry=inspection.manifest.entryFile,entryPath=targetIn(root,entry);if(!fs.existsSync(entryPath)||fs.statSync(entryPath).size<1)throw new Error('Runtime package contract entry file is missing/empty after staging.');
  if(path.extname(entryPath)==='.js'){try{new Function('exports','require','module','__filename','__dirname',fs.readFileSync(entryPath,'utf8'));}catch(err){throw new Error(`Runtime package JavaScript syntax check failed: ${err.message}`);}}
  const files=walkFiles(root),total=files.reduce((n,f)=>n+f.size,0);if(total>MAX_CONTRACT_TOTAL_BYTES)throw new Error('Runtime package contract bundle is too large.');const hash=bundleHash(files);
  const stamp=new Date(a.timestampMs).toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'z'),id=normalizeVersionId(`${stamp}-runtime-v${inspection.targetVersion}-${hash.slice(0,12)}`),dst=versionRoot(id);if(fs.existsSync(dst))throw new Error('Runtime package version already exists.');
  copyTree(root,dst);fs.rmSync(root,{recursive:true,force:true});const manifest={versionId:id,label:`runtime-v${inspection.targetVersion}`,entryFile:entry,bundleHash:hash,status:'staged',createdAt:a.timestampMs,createdBy:a.auth.userId,activatedAt:null,activatedBy:null,fileCount:files.length,totalBytes:total,files};writeJson(path.join(dst,'manifest.json'),manifest);const index=loadVersions();index.versions[id]=manifest;saveVersions(index);return manifest;
}
function activateRuntimeVersion(version,a){if(!version)return;const index=loadVersions(),id=version.versionId;if(index.activeVersion&&index.activeVersion!==id)index.previousActiveVersion=index.activeVersion;index.activeVersion=id;for(const [vid,rec] of Object.entries(index.versions)){if(rec)rec.status=vid===id?'active':(rec.status==='active'?'inactive':rec.status);}const v=index.versions[id];v.activatedAt=a.timestampMs;v.activatedBy=a.auth.userId;saveVersions(index);writeJson(ACTIVE_VERSION_FILE,{versionId:id,entryFile:v.entryFile||'sidedish.js',bundleHash:v.bundleHash,activatedAt:a.timestampMs,activatedBy:a.auth.userId,runtimePackage:true});if(index.previousActiveVersion)writeJson(PREVIOUS_VERSION_FILE,{versionId:index.previousActiveVersion});}
function restoreSnapshotPublic(snapshotRoot,meta){
  const records=[...(meta.webFiles||[]),...(meta.publicFiles||[]).map(rec=>({...rec,role:rec.role||'public'}))];
  for(const rec of records){const role=rec.role||'web',target=resolveManagedAssetPath(rec.path,role);if(rec.existed){const src=path.resolve(snapshotRoot,'files',role,rec.path);const legacySrc=path.resolve(snapshotRoot,'files',rec.path);const actual=fs.existsSync(src)?src:legacySrc;ensureDir(path.dirname(target));fs.copyFileSync(actual,target);}else fs.rmSync(target,{force:true});}
}
async function applyRuntimePackage(user,message,ctx){
  if(ctx.readonly)throw new Error('Runtime upgrades require consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const inspection=inspectRuntimePackageInternal(message.packageUploadId),expected=safeString(message.expectedPackageSha256,64).toLowerCase();if(expected&&expected!==inspection.packageSha256)throw new Error('Runtime package changed after inspection. Inspect it again.');
  if(inspection.appliedChanges<1)throw new Error('This runtime package has no managed changes to apply.');const entries=parseZipEntries(fs.readFileSync(runtimePackagePath(message.packageUploadId)));
  const versionsBefore=loadVersions(),previousPackageState=loadRuntimePackageState();const stamp=new Date(a.timestampMs).toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'z'),snapshotId=normalizeVersionId(`${stamp}-v${inspection.targetVersion}-${inspection.packageSha256.slice(0,12)}`),snap=runtimeSnapshotRoot(snapshotId);ensureDir(path.join(snap,'files'));
  const webTargets=[...inspection.diffs.filter(f=>(f.role==='web'||f.role==='public')&&f.status!=='same'),...inspection.removed.filter(f=>f.role==='web'||f.role==='public')];const webFiles=[];
  for(const f of webTargets){const target=resolveManagedAssetPath(f.path,f.role),existed=fs.existsSync(target)&&fs.statSync(target).isFile();webFiles.push({path:f.path,role:f.role,existed,sha256:existed?sha256Hex(fs.readFileSync(target)):null});if(existed){const dst=path.resolve(snap,'files',f.role,f.path);ensureDir(path.dirname(dst));fs.copyFileSync(target,dst);}}
  const snapMeta={schema:1,snapshotId,createdAt:a.timestampMs,createdBy:a.auth.userId,fromVersion:previousPackageState&&previousPackageState.version?previousPackageState.version:APP_VERSION,toVersion:inspection.targetVersion,packageSha256:inspection.packageSha256,previousActiveVersion:versionsBefore.activeVersion||null,previousPreviousActiveVersion:versionsBefore.previousActiveVersion||null,previousPackageState,webFiles};writeJson(path.join(snap,'snapshot.json'),snapMeta);
  let newVersion=null;
  try{
    newVersion=createRuntimeVersionFromPackage(inspection,entries,a);
    for(const f of inspection.manifest.files.filter(f=>f.role==='web'||f.role==='public')){if(inspection.diffs.find(d=>d.path===f.path)?.status==='same')continue;const target=resolveManagedAssetPath(f.path,f.role),tmp=`${target}.upgrade-${snapshotId}.tmp`;ensureDir(path.dirname(target));fs.writeFileSync(tmp,entries.get(f.path).data);fs.renameSync(tmp,target);}
    for(const f of inspection.removed.filter(f=>f.role==='web'||f.role==='public'))fs.rmSync(resolveManagedAssetPath(f.path,f.role),{force:true});
    activateRuntimeVersion(newVersion,a);
    const managedFiles=inspection.manifest.files.filter(f=>f.role==='contract'||f.role==='web'||f.role==='public').map(f=>({path:f.path,role:f.role,sha256:f.sha256}));writeJson(RUNTIME_PACKAGE_STATE_FILE,{schema:1,product:'everadmin-control-plane',version:inspection.targetVersion,packageSha256:inspection.packageSha256,appliedAt:a.timestampMs,appliedBy:a.auth.userId,activeVersion:newVersion?newVersion.versionId:versionsBefore.activeVersion||null,latestSnapshotId:snapshotId,managedFiles});
    fs.rmSync(runtimePackagePath(message.packageUploadId),{force:true});
  }catch(err){try{restoreSnapshotPublic(snap,snapMeta);}catch{}if(newVersion){const idx=loadVersions();if(idx.versions[newVersion.versionId]&&idx.activeVersion!==newVersion.versionId){fs.rmSync(versionRoot(newVersion.versionId),{recursive:true,force:true});delete idx.versions[newVersion.versionId];saveVersions(idx);}}throw err;}
  await sendOutput(user,{type:'runtime-package-applied',actionId:message.actionId||null,fromVersion:snapMeta.fromVersion,toVersion:inspection.targetVersion,packageSha256:inspection.packageSha256,snapshotId,activeVersion:newVersion?newVersion.versionId:loadVersions().activeVersion,changed:inspection.diffs.filter(d=>d.apply&&d.status!=='same').map(d=>({path:d.path,status:d.status,role:d.role})),removed:inspection.removed});
}
async function rollbackRuntimePackage(user,message,ctx){
  if(ctx.readonly)throw new Error('Runtime rollback requires consensus input.');const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;const state=loadRuntimePackageState(),snapshotId=normalizeVersionId(message.snapshotId||(state&&state.latestSnapshotId)||'');const snap=runtimeSnapshotRoot(snapshotId),meta=readJson(path.join(snap,'snapshot.json'),null);if(!meta)throw new Error('Runtime upgrade snapshot was not found.');restoreSnapshotPublic(snap,meta);
  const index=loadVersions(),current=index.activeVersion,previous=meta.previousActiveVersion||null;if(previous&&index.versions[previous]){index.activeVersion=previous;index.previousActiveVersion=current&&current!==previous?current:(meta.previousPreviousActiveVersion||null);for(const [vid,rec] of Object.entries(index.versions)){if(rec)rec.status=vid===previous?'active':(rec.status==='active'?'inactive':rec.status);}saveVersions(index);const v=index.versions[previous];writeJson(ACTIVE_VERSION_FILE,{versionId:previous,entryFile:v.entryFile||'sidedish.js',bundleHash:v.bundleHash,activatedAt:a.timestampMs,activatedBy:a.auth.userId,runtimeRollback:true});}
  else{index.activeVersion=null;index.previousActiveVersion=current||meta.previousPreviousActiveVersion||null;for(const rec of Object.values(index.versions))if(rec&&rec.status==='active')rec.status='inactive';saveVersions(index);fs.rmSync(ACTIVE_VERSION_FILE,{force:true});}
  if(meta.previousPackageState)writeJson(RUNTIME_PACKAGE_STATE_FILE,meta.previousPackageState);else fs.rmSync(RUNTIME_PACKAGE_STATE_FILE,{force:true});
  await sendOutput(user,{type:'runtime-package-rolled-back',actionId:message.actionId||null,snapshotId,restoredVersion:meta.fromVersion,activeVersion:loadVersions().activeVersion});
}
async function getRuntimeUpgradeStatus(user,message,ctx){const a=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!a)return;await sendOutput(user,{type:'runtime-upgrade-status',actionId:message.actionId||null,currentRuntimeVersion:APP_VERSION,packageState:loadRuntimePackageState()});}

async function getDiagnostics(user,message,ctx){const a=await requireRole(user,message,ctx);if(!a)return;let cfg={};try{cfg=await ctx.getConfig();}catch{}const local=getLocalNodePublicKey(ctx,cfg);const nodeRuntime=ctx.readonly?runtimeFromLocalHealth():{detected:false,userPort:null,source:'consensus-execution'};let customStat=null,customError=null;try{customStat=fs.existsSync(LOCAL_CUSTOM_FILE)?fs.statSync(LOCAL_CUSTOM_FILE):null;}catch(err){customError=err.message;}const auth=loadAuthState(),versions=loadVersions(),prune=loadPruneState();const pubFiles=['index.html','evernode.html'].map(n=>{const f=path.join(STATE_ROOT,n);return fs.existsSync(f)?{name:n,size:fs.statSync(f).size,sha256:sha256Hex(fs.readFileSync(f))}:{name:n,missing:true};});await sendOutput(user,{type:'diagnostics',actionId:message.actionId||null,app:{name:APP_NAME,version:APP_VERSION,loaderMode:true},node:{publicKey:local,contractId:safeString(ctx.contractId||'',128)||null,readonly:!!ctx.readonly,ledgerNo:ledgerNo(ctx),ledgerHash:safeString(ctx.lclHash||'',256),timestamp:nowMs(ctx),runtime:nodeRuntime,clusterJoin:readClusterJoinRecord()},config:{unl:getConfigUnl(cfg),visibility:readVisibility(cfg),consensusThreshold:readThreshold(cfg),roundtime:readRoundtime(cfg)},auth:{bootstrapComplete:auth.bootstrapComplete,activeUsers:Object.values(auth.users||{}).filter(u=>u&&u.active!==false).length,activeHeadAdmins:countActiveHeadAdmins(auth),authorizedDevices:Object.keys(auth.authorizedDevices||{}).length},custom:{path:'../custom.json',absolutePath:LOCAL_CUSTOM_FILE,storageScope:'node-local-seed',consensusState:false,exists:!!customStat,size:customStat?customStat.size:0,error:customError,fieldCount:loadCustomFields().fields.length},localHealth:{path:'../unl-health.json',snapshot:readLocalHealth()},prune:pruneStatus(prune,cfg,nowMs(ctx)),versions:{activeVersion:versions.activeVersion,previousActiveVersion:versions.previousActiveVersion,count:Object.keys(versions.versions||{}).length},publicFiles:pubFiles,autoclusterAcquisition:autoCluster.publicStatus().acquisitionDiagnostics});}

async function loadDashboard(user,message,ctx){
  const state=loadAuthState();
  const ts=nowMs(ctx);
  const device=getUserPublicKey(user);
  const auth=getDeviceAuth(state,device,ts);
  if(!auth){await sendOutput(user,{type:'dashboard-state',actionId:message.actionId||null,authorized:false});return;}
  let cfg={};try{cfg=await ctx.getConfig();}catch{}
  const localNodePublicKey=getLocalNodePublicKey(ctx,cfg);
  const base={
    type:'dashboard-state',actionId:message.actionId||null,authorized:true,
    auth:{role:auth.role,userId:auth.userId,username:auth.user.username||null,method:auth.method||auth.user.method,primaryMethod:auth.user.method,passwordEnabled:!!(auth.user.password&&auth.user.password.key),everstoringEnabled:!!auth.user.publicKey,expiresAt:auth.expiresAt},
    customFields:loadCustomFields().fields.map(f=>({...f,mode:fieldMode(f)})),
    localNodePublicKey,
    ledgerNo:ledgerNo(ctx),
    contractId:safeString(ctx.contractId||'',128)||null,
    localNodeInUnl:!!(localNodePublicKey&&getConfigUnl(cfg).includes(localNodePublicKey)),
    unls:getConfigUnl(cfg).map(k=>({publicKey:k,...(loadUnlMetadata()[k]||{})})),
    unlSummary:{count:getConfigUnl(cfg).length,visibility:readVisibility(cfg),threshold:readThreshold(cfg),roundtime:readRoundtime(cfg)},
    autocluster:autoCluster.publicStatus()
  };
  if(auth.role===ROLE_HEAD_ADMIN){
    base.users=Object.entries(state.users||{}).map(([id,r])=>publicUserRecord(normalizeUserRecord(id,r)));
    base.unls=getConfigUnl(cfg).map(k=>({publicKey:k,...(loadUnlMetadata()[k]||{}),...(loadPruneState().nodes[k]||{})}));
    base.removedUnls=loadRemovedUnls();
    base.prune=pruneStatus(loadPruneState(),cfg,ts);
    base.versions={activeVersion:loadVersions().activeVersion,previousActiveVersion:loadVersions().previousActiveVersion,versions:Object.values(loadVersions().versions||{})};
    base.clusterJoin=readClusterJoinRecord();
  }
  await sendOutput(user,base);
}



async function autoClusterPrepareBootstrap(user,message,ctx){
  if(ctx.readonly)throw new Error('Preparing AutoCluster bootstrap requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.prepareBootstrap(ctx,message.config||message.settings||{});
  await sendOutput(user,{type:'autocluster-bootstrap-prepared',actionId:message.actionId||null,bootstrapSignerAddress:result.bootstrapSignerAddress,state:result.state,message:'Bootstrap signer prepared in HotPocket private storage. Authorize it on the cluster treasury next.'});
}
async function autoClusterActivateBootstrap(user,message,ctx){
  if(ctx.readonly)throw new Error('Activating AutoCluster requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.activateBootstrap(ctx);
  await sendOutput(user,{type:'autocluster-bootstrap-activated',actionId:message.actionId||null,state:result.state,message:'AutoCluster growth is active.'});
}
async function autoClusterSetBootstrapEndpoint(user,message,ctx){
  if(ctx.readonly)throw new Error('Publishing the Bootstrap A endpoint requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.setBootstrapEndpoint(message.endpoint||message.bootstrapEndpoint||message);
  await sendOutput(user,{type:'autocluster-bootstrap-endpoint-set',actionId:message.actionId||null,...result,message:'Bootstrap A peer/user endpoint published for managed-node maturity callbacks.'});
}

async function autoClusterConfirmMasterHandover(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Preparing final handover requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.confirmMasterHandover(ctx,message||{});
  if(autoRun)autoRun.deferTickOnce=true; // commit handover preparation first; request the fixed-size A->final-managed swap on the next clean ledger.
  await sendOutput(user,{type:'autocluster-handover-confirmed',actionId:message.actionId||null,...result,message:'Handover preparation committed. Bootstrap A will request one atomic fixed-size swap with the pre-acquired final managed validator; DisableMaster remains blocked until that swap commits.'});
}

async function autoClusterAddHosts(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Adding AutoCluster hosts requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.addHosts(message.hosts||message.addresses||[],ledgerNo(ctx),autoRun&&autoRun.state?autoRun.state:null);
  await sendOutput(user,{type:'autocluster-hosts-updated',actionId:message.actionId||null,...result,message:`Added ${result.added.length} host(s); reset ${result.reset.length} host(s).`});
}
async function autoClusterRemoveHost(user,message,ctx){
  if(ctx.readonly)throw new Error('Removing an AutoCluster host requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.removeHost(message.address);
  await sendOutput(user,{type:'autocluster-hosts-updated',actionId:message.actionId||null,...result});
}
async function autoClusterRetryHosts(user,message,ctx){
  if(ctx.readonly)throw new Error('Retrying AutoCluster hosts requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.retryFailedHosts();
  await sendOutput(user,{type:'autocluster-hosts-updated',actionId:message.actionId||null,...result});
}
async function autoClusterRetryFunding(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Rechecking AutoCluster funding requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  if(!autoRun)throw new Error('AutoCluster runtime is unavailable in this ledger; refresh status and try the funding recheck again.');
  const result=autoCluster.retryFundingWait(autoRun);
  await sendOutput(user,{type:'autocluster-funding-recheck',actionId:message.actionId||null,...result,message:result.reset?`Rechecking funding for ${result.reset} paused host(s).`:'No funding-wait host is currently paused.'});
}
async function autoClusterSkipPending(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Skipping an AutoCluster pending acquisition requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  if(!autoRun)throw new Error('AutoCluster runtime is unavailable in this ledger; retry after the cluster status refreshes.');
  // A skip releases the sequential acquisition queue. If the ordinary
  // AutoCluster tick runs later in this *same* contract execution it can
  // immediately start the next Evernode/Xahau acquisition, keeping the ledger
  // invocation open long enough that the browser never receives this result.
  // Always end this ledger after answering the operator; the next normal
  // ledger will continue growth. This applies to forceRequired too so the
  // legacy forceRequired responses are still supported for API compatibility,
  // while the bundled UI sends force=true in a single deliberate Skip click.
  const result=autoCluster.skipPendingAttempt(autoRun,message.address,!!message.force);
  autoRun.deferTickOnce=true;
  await sendOutput(user,{type:'autocluster-pending-skip-result',actionId:message.actionId||null,...result});
}
async function autoClusterDropCandidate(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Dropping an AutoCluster candidate requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  if(!autoRun)throw new Error('AutoCluster runtime is unavailable in this ledger; refresh and try again.');
  const pubkey=safeString(message.pubkey||message.publicKey||'',256);
  if(!pubkey)throw new Error('Candidate public key is required.');
  const result=await autoCluster.dropCandidateInstance(autoRun,pubkey,'operator-drop');
  // Never acquire a replacement in the same execution that submitted TERMINATE_LEASE.
  autoRun.deferTickOnce=true;
  await sendOutput(user,{type:'autocluster-candidate-drop-result',actionId:message.actionId||null,...result,message:`Dropped pre-UNL candidate ${pubkey.slice(0,16)}…. Lease termination was submitted and the next queued host can start on the next ledger.`});
}

async function autoClusterSetMaxCost(user,message,ctx){
  if(ctx.readonly)throw new Error('Changing the AutoCluster lease cap requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.setMaxLeaseAmount(message.maxLeaseAmountEvrPerMoment);
  await sendOutput(user,{type:'autocluster-max-cost-updated',actionId:message.actionId||null,...result});
}
async function autoClusterForceBootstrapPromotion(user,message,ctx,autoRun){
  if(ctx.readonly)throw new Error('Forcing bootstrap promotion requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  if(!autoRun)throw new Error('AutoCluster runtime is unavailable in this ledger; retry after the cluster status refreshes.');
  // Force only pins the exact candidate. Membership still follows the same
  // lockstep user-input admission path and cannot bypass READY/SYNC/peer/final
  // exact-head safety checks.
  const result=await autoCluster.armBootstrapMeshOverride(autoRun,message.pubkey||message.publicKey||null);
  autoRun.deferTickOnce=true;
  const forceMessage=result.pending
    ? `FORCE ADD armed for ${result.forcedPubkey}. The validator will only be admitted through the lockstep HotPocket user-input path after CURRENT READY + runtime SYNC + live peer + final recent-canonical-ledger proof are all satisfied. No second click is required.`
    : `FORCE ADD did not arm a second candidate because ${result.forcedPubkey || 'a validator'} already has a membership change in flight.`;
  await sendOutput(user,{type:'autocluster-bootstrap-force-result',actionId:message.actionId||null,armed:!!result.armed,pending:!!result.pending,executed:!!result.executed,alreadyArmed:!!result.alreadyArmed,bypassAll:!!result.bypassAll,forcedPubkey:result.forcedPubkey||null,blockers:Array.isArray(result.blockers)?result.blockers:[],currentReady:result.currentReady===true,syncReady:result.syncReady===true,acknowledged:result.acknowledged===true,peers:result.peers==null?null:Number(result.peers),membershipCommand:result.membershipCommand||null,fromUnlSize:result.fromUnlSize||null,toUnlSize:result.toUnlSize||null,threshold:result.threshold||null,message:forceMessage});
}

async function autoClusterSetEverPocketSettings(user,message,ctx){
  if(ctx.readonly)throw new Error('Changing EverPocket settings requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.setRuntimeSettings(message.settings||message);
  await sendOutput(user,{type:'autocluster-settings-updated',actionId:message.actionId||null,...result,message:'EverPocket / AutoCluster settings updated.'});
}

async function autoClusterSetRpcPools(user,message,ctx){
  if(ctx.readonly)throw new Error('Changing chain RPC pools requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.setRpcPools(message.rpcPools||message.pools||{});
  await sendOutput(user,{type:'autocluster-rpc-pools-updated',actionId:message.actionId||null,...result,message:'Chain RPC/node pools saved in HotPocket consensus state.'});
}
async function autoClusterRetryRpc(user,message,ctx){
  if(ctx.readonly)throw new Error('Retrying the Xahau RPC pool requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.retryRpcPool();
  await sendOutput(user,{type:'autocluster-rpc-retry',actionId:message.actionId||null,...result});
}

async function autoClusterAddValidator(user,message,ctx){
  if(ctx.readonly)throw new Error('Adding a validator through EverPocket requires consensus input.');
  const authz=await requireRole(user,message,ctx,[ROLE_HEAD_ADMIN]);if(!authz)return;
  const result=autoCluster.addValidatorViaEverPocket(message.host||message.hostAddress||message.address,ledgerNo(ctx));
  await sendOutput(user,{type:'autocluster-validator-requested',actionId:message.actionId||null,...result,message:`EverPocket validator acquisition queued on ${result.host}; managed target is now ${result.targetManagedNodes}.`});
}

async function route(user,message,ctx,autoRun=null){
  const type=safeString(message&&message.type,128);
  if(type==='ping'){await sendOutput(user,{type:'pong',actionId:message.actionId||null,appVersion:APP_VERSION});return;}
  if(type==='node-runtime-info'){await nodeRuntimeInfo(user,message,ctx);return;}
  if(type==='cluster-join-status'){await getClusterJoinStatus(user,message,ctx);return;}
  if(type==='probe-cluster-target'){await probeClusterTarget(user,message,ctx);return;}
  if(type==='auth-status'){await authStatus(user,message,ctx);return;}
  if(type==='bootstrap-head-admin'){await bootstrapHeadAdmin(user,message,ctx);return;}
  if(type==='password-login-info'){await passwordLoginInfo(user,message,ctx);return;}
  if(type==='password-login'){await passwordLogin(user,message,ctx);return;}
  if(type==='everstoring-login-info'){await everstoringLoginInfo(user,message,ctx);return;}
  if(type==='authorize-device'){await authorizeDevice(user,message,ctx);return;}
  if(type==='everstoring-login'){await everstoringLogin(user,message,ctx);return;}
  if(type==='load-dashboard'){await loadDashboard(user,message,ctx);return;}
  const handlers={
    'logout-device':logoutDevice,'list-users':listUsers,'add-user':addUser,'set-user-role':setUserRole,'remove-user':removeUser,'change-password':changePassword,'set-user-2fa':setUserTwoFactor,
    'list-unls':listUnls,'add-unl':addUnl,'remove-unl':removeUnl,'connect-to-cluster':connectToCluster,'restart-hotpocket':restartHotPocket,'restore-previous-cluster':restorePreviousCluster,'set-cluster-visibility-mode':setVisibility,'set-consensus-threshold':setThreshold,'set-consensus-roundtime':setRoundtime,
    'get-unl-prune-settings':getPruneSettings,'set-unl-prune-settings':setPruneSettings,'refresh-unl-health':manualHealth,'get-local-unl-health':getLocalHealth,'report-unl-health':reportUnlHealth,'prune-silent-unls':manualPrune,'submit-removed-unl-health':reportRemovedHealth,'readd-removed-unls':readdRemoved,'delete-removed-unl':deleteRemoved,
    'list-custom-fields':listCustomFields,'add-custom-field':addCustomField,'update-custom-field':updateCustomField,'remove-custom-field':removeCustomField,'set-custom-value':setCustomValue,'append-custom-value':appendCustomValue,'remove-custom-item':removeCustomItem,'clear-custom-value':clearCustomValue,'get-local-custom':getLocalCustom,
    'upload-public-asset':uploadPublicAsset,'list-public-assets':listPublicAssets,'read-code-file':readCodeFile,
    'upload-runtime-package':uploadRuntimePackage,'inspect-runtime-package':inspectRuntimePackage,'apply-runtime-package':applyRuntimePackage,'rollback-runtime-package':rollbackRuntimePackage,'get-runtime-upgrade-status':getRuntimeUpgradeStatus,
    'prepare-contract-draft':prepareContractDraft,'upload-contract-version-file':uploadContractVersionFile,'finalize-contract-version':finalizeContractVersion,'list-contract-versions':listContractVersions,'activate-contract-version':activateContractVersion,'rollback-contract-version':rollbackContractVersion,'deactivate-contract-version':deactivateContractVersion,'delete-contract-version':deleteContractVersion,
    'list-contract-library':listContractLibrary,'upload-contract-library-zip':uploadContractLibraryZip,'delete-contract-library-zip':deleteContractLibraryZip,'stage-contract-library-zip':stageContractLibraryZip,'prepare-library-runtime-package':prepareLibraryRuntimePackage,
    'autocluster-bootstrap-prepare':autoClusterPrepareBootstrap,'autocluster-bootstrap-activate':autoClusterActivateBootstrap,'autocluster-bootstrap-endpoint-set':autoClusterSetBootstrapEndpoint,'autocluster-handover-confirm':autoClusterConfirmMasterHandover,'autocluster-add-hosts':autoClusterAddHosts,'autocluster-remove-host':autoClusterRemoveHost,'autocluster-retry-hosts':autoClusterRetryHosts,'autocluster-retry-funding':autoClusterRetryFunding,'autocluster-skip-pending':autoClusterSkipPending,'autocluster-drop-candidate':autoClusterDropCandidate,
    'get-diagnostics':getDiagnostics,
    'autocluster-hosts-add':autoClusterAddHosts,'autocluster-host-remove':autoClusterRemoveHost,'autocluster-hosts-retry':autoClusterRetryHosts,'autocluster-max-cost-set':autoClusterSetMaxCost,'autocluster-force-bootstrap-promotion':autoClusterForceBootstrapPromotion,'autocluster-settings-set':autoClusterSetEverPocketSettings,'autocluster-rpc-pools-set':autoClusterSetRpcPools,'autocluster-rpc-retry':autoClusterRetryRpc,'autocluster-add-validator':autoClusterAddValidator
  };
  const fn=handlers[type];if(!fn){await sendOutput(user,{type:'error',action:type,actionId:message.actionId||null,error:`Unknown message type: ${type}`});return;}await fn(user,message,ctx,autoRun);
}

async function processInputs(ctx,autoRun=null){let count=0;for(const user of ctx.users.list()){for(const input of user.inputs){count++;let message;const raw=await ctx.users.read(input);try{if(autoRun&&await autoCluster.feedUserMessage(autoRun,user,raw))continue;message=runtime.bson.deserialize(raw);await route(user,message,ctx,autoRun);}catch(err){try{await sendOutput(user,{type:'error',action:message&&message.type||null,actionId:message&&message.actionId||null,error:err&&err.message?err.message:String(err)});}catch{console.log(`Output error: ${err&&err.message?err.message:err}`);}}}}return count;}

async function maintenance(ctx){if(ctx.readonly)return;const ln=ledgerNo(ctx);if(!ln)return;const state=loadPruneState();if(state.settings.enabled&&ln%Math.max(1,boundInt(state.settings.healthEveryLedgers,10,1,100000))===0&&state.lastPruneLedger!==ln){try{await evaluatePrune(ctx,'automatic','scheduled-report-evaluation');}catch(err){console.log(`UNL prune tick failed: ${err.message}`);}}const latest=loadPruneState();if(latest.settings.autoReaddEnabled&&ln%boundInt(latest.settings.readdEveryLedgers,60,1,100000)===0&&latest.lastReaddLedger!==ln){try{await evaluateReadd(ctx,'automatic','scheduled');}catch(err){console.log(`UNL readd tick failed: ${err.message}`);}}}

async function contract(ctx, injectedRuntime) {
  runtime = injectedRuntime || runtime;
  const autoConfigured = autoCluster.isConfigured();

  // Consensus-critical PRE-FLIGHT fence. This must run before local health
  // refresh, user/admin input processing, EverPocket initialization, or any
  // Xahau/Evernode work. The first execution after a committed UNL patch is
  // deliberately sterile so every newly-trusted validator produces the same
  // state before the next signer-matched consensus round.
  if (!ctx.readonly && autoConfigured) {
    try {
      if (await autoCluster.validatorStabilizationPreflight(ctx)) return;
    } catch (err) {
      const detail = err && err.stack ? err.stack : (err && err.message ? err.message : err);
      console.log(`AutoCluster PRE-FLIGHT failed closed: ${detail}`);
      return;
    }
  }

  // HotPocket read requests execute against a read-only filesystem snapshot.
  // Never create directories, initialize EverPocket contexts, persist cluster
  // state, or run maintenance from a readonly invocation.
  if (!ctx.readonly) {
    // Do not materialize optional consensus-state directories on every ledger.
    // Their feature-specific writers create them lazily when needed. Runtime
    // health is node-local (../unl-health.json), so refreshing it every second
    // ledger is plenty for diagnostics/READY while halving repeated hp.cfg + disk
    // work on marginal hosts. The last snapshot remains valid between refreshes.
    const localHealthLcl = ledgerNo(ctx);
    if (!localHealthLcl || localHealthLcl % 2 === 0) {
      try { await refreshLocalHealthRuntime(ctx); } catch (err) { console.log(`Local runtime health refresh failed: ${err.message}`); }
    }
  }

  let autoRun = null;
  if (!ctx.readonly && autoConfigured) {
    try { autoRun = await autoCluster.begin(ctx); }
    catch (err) {
      const detail = err && err.stack ? err.stack : (err && err.message ? err.message : err);
      console.log(`AutoCluster init failed: ${detail}`);
      try { autoCluster.recordRuntimeError('init', err, ledgerNo(ctx)); } catch {}
    }
  }

  try {
    const inputCount = await processInputs(ctx, autoRun);
    if (autoRun && !autoRun.deferTickOnce) {
      try { await autoCluster.tick(autoRun); }
      catch (err) {
        const detail = err && err.stack ? err.stack : (err && err.message ? err.message : err);
        console.log(`AutoCluster tick failed: ${detail}`);
        try { autoCluster.recordRuntimeError('tick', err, ledgerNo(ctx)); } catch {}
      }
    } else if (!ctx.readonly && inputCount === 0 && !autoConfigured) {
      // The legacy scheduler runs only before AutoCluster exists. During the
      // bootstrap signer-list handshake AutoCluster is configured but paused.
      await maintenance(ctx);
    }
  } finally {
    if (autoRun) {
      try { await autoCluster.end(autoRun); }
      catch (err) {
        const detail = err && err.stack ? err.stack : (err && err.message ? err.message : err);
        console.log(`AutoCluster deinit failed: ${detail}`);
      }
    }
  }
}

module.exports = { contract, APP_VERSION, APP_NAME };
