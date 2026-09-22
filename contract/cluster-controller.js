'use strict';

// EverSmartNode autonomous cluster controller.
// This module runs *inside* the HotPocket contract. The root-side bootstrap API
// only creates/funds the treasury and performs the two master-key bootstrap
// transactions. All ongoing cluster lifecycle work remains in consensus here.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');

const STATE_FILE = path.resolve(process.cwd(), 'autocluster.state.json');
const LEGACY_STATE_FILE = path.resolve(process.cwd(), 'autocluster.json');
// Node-local AutoCluster runtime data lives one level above HotPocket consensus
// state. Anything written here may differ per node without changing the contract
// state hash. During singleton bootstrap the rolling canonical ledger witness is
// intentionally local to Bootstrap A; the outside READY controller verifies against
// this file before submitting a deterministic attestation into consensus.
const LOCAL_AUTOCLUSTER_ROOT = path.resolve(process.cwd(), '..', 'autocluster-local');
const LOCAL_RECENT_LEDGERS_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'recent-ledgers.json');
const LOCAL_SYNC_QUIESCENCE_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'sync-quiescence.json');
const LOCAL_NPL_NODE_STATUS_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'npl-node-status.json');
const LOCAL_CANDIDATE_ATTESTATION_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'candidate-attestation.json');
// Node-local sticky Xahau endpoint selection. The configured pool/order remains
// consensus state, but the last endpoint that actually connected is local runtime
// state so one dead priority-1 RPC does not get retried (and logged) every ledger.
const LOCAL_XAHAU_RPC_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'xahau-rpc.json');
const LOCAL_NATIVE_ACQUIRE_TRACE_FILE = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'native-acquire-trace.json');
const LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR = path.resolve(LOCAL_AUTOCLUSTER_ROOT, 'singleton-acquire-shadow');
const LOCAL_SINGLETON_ACQUIRE_SHADOW_META_FILE = path.resolve(LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR, 'meta.json');
// Pre-UNL admission uses two independent prerequisites: native EverPocket
// MATURED/ACKNOWLEDGED proves the candidate completed its configured maturity
// lifecycle, while canonical VALIDATOR_READY proves current HotPocket sync.
// Neither signal is sufficient alone. A materialized node gets this long to
// keep proving canonical sync on Bootstrap's ledger.
const DEFAULT_CANDIDATE_READY_TIMEOUT_MS = 4 * 60 * 1000;
// Absolute pre-UNL candidate lifetime. A materialized leased instance must reach
// committed UNL admission within this window or AutoCluster terminates the lease,
// drops its candidate bookkeeping, releases the serial slot and moves to the next host.
// This clock never resets on READY/SYNC/peer heartbeats.
const DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS = 20 * 60 * 1000;
const MIN_CANDIDATE_ADMISSION_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_CANDIDATE_ADMISSION_TIMEOUT_MS = 60 * 60 * 1000;
// Bootstrap keeps a bounded pool of pre-UNL candidates warming in parallel.
// Acquisition handoff is transaction-serialized only: once the previous Xahau
// acquisition transaction reaches ledger finality, native Evernode provisioning may
// continue asynchronously while the next lease purchase starts. A missing transient
// EverPocket pending row is never treated as proof that an acquisition failed.
// The legacy speculative-delay setting remains in state for upgrade compatibility only.
const DEFAULT_CANDIDATE_SPECULATIVE_ACQUIRE_DELAY_MS = 2 * 60 * 1000;
const DEFAULT_CANDIDATE_POOL_SIZE = 4;
const MAX_CANDIDATE_POOL_SIZE = 8;
// Recovery purchases may temporarily exceed targetManagedNodes, but only one-for-one
// against already-known unusable/uncertain paid leases and only inside the existing
// candidate-pool risk envelope. This prevents a provisioning/readiness-stalled lease
// from deadlocking replacement acquisition while still bounding worst-case temporary
// wallet exposure. With the default candidatePoolSize=4, target=5 can temporarily
// own at most 9 managed leases, and only if four distinct leases are already quarantined.
// A candidate that was canonically READY but stops refreshing that proof gets a
// shorter grace window before quarantine. This prevents one once-good/frozen
// lease from holding the bootstrap sync barrier forever.
const DEFAULT_CANDIDATE_READY_STALE_GRACE_MS = 60 * 1000;
const DEFAULT_READY_PROBE_UNREACHABLE_TIMEOUT_MS = 60 * 1000;
// Hard wall-clock/LCL cap while the native Evernode host response is still
// missing. Once AcquireSuccess is processed, endpoint reachability is no longer
// evaluated inside replicated contract execution.
const PENDING_ACQUISITION_TIMEOUT_MS = 3 * 60 * 1000;
const PENDING_ACQUISITION_TIMEOUT_LCL = 45;
// Acquisition retries are driven only by REAL acquireNode() failures. A ledger
// timer never changes an in-flight attempt back to queued. Give a host three
// consecutive transient transport/sequence failures before rotating it behind
// untouched hosts; after rotation it cools down and gets another three-call burst.
const ACQUIRE_TRANSIENT_BURST_ATTEMPTS = 3;
const ACQUIRE_TRANSIENT_ROTATE_COOLDOWN_LCL = 12;
const ACQUIRE_OPERATION_QUEUE_RETRY_LCL = 2;
// Candidate-pool capacity remains bounded even though already-acknowledged leases may
// provision in parallel. Native acquire responses serialize purchases only for a bounded
// window: after PENDING_ACQUISITION_TIMEOUT_* the unresolved host moves to a durable
// late-response watch (provisioning-stalled), its message key/refId are preserved, and
// the next queued host may be purchased. A late AcquireSuccess is recovered normally.
const BOOTSTRAP_MAX_CONCURRENT_PENDING = MAX_CANDIDATE_POOL_SIZE;
// Xahau acquisition requirements are carried in an encrypted/base64 XRPL memo.
// EverPocket itself keeps bootstrap UNL to one pubkey specifically to stay below
// the current 1 KiB serialized Memos ceiling. We project that full serialized
// array and retain only 8 bytes of safety headroom; peer seeds are the optional
// payload trimmed when necessary.
const XRPL_ACQUIRE_MEMO_MAX_BYTES = 1024;
// Keep a few bytes below the serialized-array ceiling for codec/version wiggle
// room while still allowing a quorum-useful seed set whenever it fits.
const XRPL_ACQUIRE_MEMO_TARGET_BYTES = XRPL_ACQUIRE_MEMO_MAX_BYTES - 8;
// EverPocket 0.1.6 normally performs user-port liveness inside ClusterContext.
// That observation is validator-local and must not be allowed to mutate replicated
// state, so alpha.37.43 keeps it as a deterministic success hook.
// External endpoint reachability is deliberately NOT a replicated-state gate.
// Native AcquireSuccess + canonical VALIDATOR_READY define provisioning/readiness.
// A UNL membership change alters the consensus quorum immediately. Do not let
// AutoCluster submit another irreversible Xahau/Evernode operation until the
// new validator set has demonstrated several successfully COMMITTED ledgers.
// Because this counter lives in HotPocket contract state, a failed/mismatched
// consensus round does not commit its increment.
const VALIDATOR_STABILIZATION_CLEAN_LEDGERS = 5;
// The reference evernode-client-cluster-manager deliberately leaves a MATURED
// candidate non-UNL for eight existing-UNL ledgers before promotion. Keep that
// as a hard floor even when the UI's legacy maturity setting is lower.
const REFERENCE_MATURITY_STABILITY_LCLS = 8;
const BOOTSTRAP_MEMBERSHIP_COMMAND_MAX_AGE_LCLS = 2;
// A frozen bootstrap ADD intent must never let one temporarily lagging candidate
// head-of-line block other durably-qualified candidates. If Bootstrap A cannot
// obtain an exact-tip FINAL proof within this bounded window, rotate that target
// behind its peers and try another candidate.
const LOCKSTEP_FINAL_INTENT_WAIT_LCLS = 4;
const LOCKSTEP_FINAL_CANDIDATE_COOLDOWN_LCLS = 8;
// A FINAL proof is sampled immediately before ADD_UNL dispatch, but the normal
// HotPocket user-input path can take a couple of committed ledgers before the
// contract executes it. Keep the proof cryptographically exact (same canonical
// candidate canonical LCL/hash within lag<=24 at sampling) while allowing bounded transport latency.
// The exact-tip membership proof is sampled immediately before dispatch. During
// the hard consensus-purity freeze, ordinary ledger closure may advance while the
// authenticated user input is transported/committed even though consensus state,
// old UNL membership, and lifecycle state remain unchanged. Preserve that exact
// sampled tuple for a bounded four-ledger transport window; anything older is
// rejected and re-sampled before the candidate crosses the UNL edge.
const LOCKSTEP_FINAL_PROOF_MAX_AGE_LCLS = 4;
// The first 1->2 transition has zero fault tolerance at 60% (2/2 votes).
// Keep its dispatch proof tighter than later additions and require a sustained
// exact-tip + vote=synced streak supplied by Bootstrap A's isolated controller.
const FIRST_ADD_FINAL_PROOF_MAX_AGE_LCLS = 2;
const FIRST_ADD_SYNC_STREAK_REQUIRED = 5;
// Automatic newest-validator rollback accepts older validators sampled at adjacent
// heads only when every tuple is proven inside Bootstrap A's recent canonical history.
const RECOVERY_CANONICAL_MAX_LAG_LCLS = 4;
// A healthy follower does not need to be on A's exact head to join the UNL.
// Accept up to twenty-four ledgers of follower lag, but only when Bootstrap A's controller
// proves the candidate LCL/hash is on A's own canonical recent-ledger history.
const BOOTSTRAP_ADMISSION_MAX_LAG_LCLS = 24;
// Once a candidate has actually reached the bounded-lag FINAL boundary, do not let
// the absolute candidate lifetime kill it while a safe deterministic admission
// retry is in progress. If current READY/SYNC/mesh falls away, this finite grace
// expires and the ordinary hard timeout becomes active again.
const LOCKSTEP_FINAL_ADMISSION_RETRY_GRACE_LCLS = 30;
// Once ACK + canonical READY + runtime SYNC + required peer transport are all
// simultaneously satisfied, the candidate has finished qualification.  Give that
// semantic milestone a separate bounded finalization window so the original
// materialization lifetime cannot kill a good validator while Bootstrap A is
// dispatching the last canonical proof / ADD_UNL command.  The deadline is fixed
// on first qualification and is never extended by later heartbeats.
const CANDIDATE_FINALIZATION_GRACE_MS = 5 * 60 * 1000;
// Bootstrap SYNC is derived from Bootstrap A's authenticated runtime observations,
// not from scraping HPFS log text. A candidate counts as synchronized only after
// one exact canonical LCL/hash observation where the external
// Bootstrap-A controller measured candidateLag<=4, contract execution enabled,
// the expected pre-UNL view, and a live peer snapshot. This directly proves the
// moving HotPocket state/ledger follower has caught A, after which the final bounded-lag canonical proof is still mandatory.
const SYNC_QUIESCENT_REQUIRED_EXECUTIONS = 1;
const SYNC_QUIESCENT_IDLE_MS = 0; // legacy schema/UI compatibility only.
const SYNC_QUIESCENT_OBSERVATION_FRESH_LCL = 2;
// Fresh bootstrap adds managed validators one at a time. Every committed UNL
// change is followed by a five-ledger sterile stabilization fence before another
// membership change or external lifecycle/admin work can run. This restores the
// sequencing that the older working stitch path relied on.
// AutoCluster consensus is signer-matched from the first bootstrap execution onward.
// The percentage is floor(signerQuorum/targetManagedNodes*100).
// With target=5 and signerQuorum=3 this is 60%. Bootstrap A is temporary and is
// excluded from that ratio; HotPocket applies the resulting percentage to the
// currently committed UNL size. Legacy repair helpers below retain their own
// transition math, but preflight always restores the configured signer ratio.
const DEFAULT_CONSENSUS_THRESHOLD = 80;
// Serial HotPocket clone-and-add bootstrap. Non-UNL managed validators run the
// normal contract path as observers, but ACKNOWLEDGED is only lifecycle maturity.
// Before any UNL patch, Bootstrap A must have independently attested the candidate's
// current canonical LCL/hash and Bootstrap A must observe the candidate at runtime.
// EVERY managed validator is admitted one-at-a-time, including the first 1->2 step.
// After each committed membership change, the existing stabilization fence must
// complete before another validator can be admitted. Policy/mesh may be advisory;
// canonical READY+runtime SYNC may not be bypassed.
const STOCK_CLONE_BOOTSTRAP = true;
// Bootstrap uses EverPocket's node bookkeeping but does not let ClusterContext.init()
// autonomously cross the UNL boundary. The boundary is an authenticated HotPocket
// user input carrying a fresh exact-tip hpcore proof, so every current validator and
// the synchronized observer execute the same one-node membership decision.
// Bootstrap membership is submitted as an authenticated HotPocket user input.
// This keeps the candidate non-UNL until the controller has sampled hpcore at
// exact tip, then makes the proof and the one-node UNL mutation part of the same
// deterministic consensus execution. EverPocket's stock addToUnl primitive is
// still used when a full ClusterContext is present, but autonomous native
// promotion is disabled so no external lifecycle work can share the boundary.
const OFFICIAL_EVERPOCKET_MEMBERSHIP = false;
const OFFICIAL_EVERPOCKET_MATURITY_LCLS = 8;
// Admission transport is deliberately capped as the validator set grows.
// The first 1->2 admission requires one live peer; later one-at-a-time additions
// require at most two live peers. No bootstrap path may add two validators in one
// contract execution.
// A newcomer needs redundant connectivity, not a full mesh to every current UNL
// member. Singleton bootstrap still uses its dedicated 1-peer-per-candidate rule;
// once UNL >= 3, normal 3->4->5 growth requires at most two live peers.
function requiredAdmissionPeers(unlSize) {
  const n = Math.max(1, Number(unlSize) || 1);
  return Math.max(1, Math.min(2, n));
}
const MIN_BOOTSTRAP_GROWTH_THRESHOLD = 66;
const PROMOTED_ACTIVE_FRESH_LCL = 4;
// Maturity acknowledgement is retained as a retryable/idempotent native EverPocket
// message. Shared ACKNOWLEDGED is mandatory for admission, while canonical READY
// remains the independent authoritative pre-UNL health/sync proof.
const MATURITY_RETRY_LCL_INTERVAL = 3;
// Diagnostic heartbeat from every managed non-bootstrap candidate. Observability only.
// Lease purchase/provisioning is initiated from inside deterministic contract
// execution. Even when candidate maturity is allowed to progress concurrently,
// During singleton bootstrap, the acquisition lane is intentionally eager: once
// the real acquireNode()/Xahau purchase has completed, provisioning is allowed to
// continue asynchronously and the next queued lease may start on the next contract
// execution. No materialization/READY/sync settle delay is imposed while A is the
// sole UNL validator.
const ACQUISITION_SETTLE_CLEAN_LEDGERS = 0;
// Fresh bootstrap fills the physical pool while materialized candidates independently
// complete native maturity and prove canonical READY/live-peer connectivity. Every managed instance is provisioned node.role=validator from
// first boot. Consensus membership is controlled only by contract.unl, so a managed
// validator whose pubkey is not yet in contract.unl simply synchronizes as a non-UNL
// candidate until it is CURRENT-ready and peer-qualified.
// Every bootstrap membership patch adds exactly one managed validator. Five clean
// ledgers must close under the expanded set before the next addition;
// lifecycle/admin work is fenced during that stabilization window.
// Bootstrap A remains in the validator set while the complete managed fleet joins.
// For a managed target of 5, bootstrap temporarily runs A + 5 managed validators
// (6 total). After the final managed signer set is prepared, one consensus config
// patch removes Bootstrap A, leaving exactly the configured 5 managed validators.
const CANDIDATE_READY_FRESH_LCL = 4;
// READY requires stable forward progress: two exact canonical Bootstrap
// ledger/hash observations at strictly increasing candidate LCLs (one advance).
// A reported canonical ledger alone is NOT a local-shard readiness proof.
// Final promotion requires voteStatus=synced; the first 1->2 transition additionally
// requires sustained exact/synced evidence across five advancing observations.
const ATOMIC_BOOTSTRAP_READY_FRESH_LCL = 4;
// Bootstrap A accepts a signed pre-UNL report only when its exact candidate
// LCL/hash is canonical and no more than four ledgers behind at observation.
const SIGNED_PREUNL_REPORT_MAX_LAG_LCLS = 4;
// Promotion consumes that committed READY record on the *next* HotPocket
// execution: native ClusterContext promotion runs before the current execution's
// user inputs can update replicated readiness. Therefore a proof accepted at lag
// 1..4 is necessarily lag 2..5 when the promotion gate can first see it. Give the
// proof exactly that one-ledger commit allowance; otherwise the old <=1 rule made
// promotion impossible even though READY=2/2 and SYNC were valid. Observation age
// remains <=1 execution and the exact canonical tuple is still mandatory.
// This changes no heartbeat cadence and causes no extra /state writes.
const ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL = SIGNED_PREUNL_REPORT_MAX_LAG_LCLS + 1;
const ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL = 1;
const CANDIDATE_PROMOTION_FRESH_LCL = 4;
const CANDIDATE_PROMOTION_OBSERVATION_FRESH_LCL = 2;
const CANDIDATE_READY_RETRY_LCL_INTERVAL = 1;
// Bootstrap readiness is a stability proof, not a one-frame status snapshot.
// Each heartbeat is accepted when Bootstrap A's authenticated outside controller
// has verified the candidate's exact LCL/hash against A's canonical recent-ledger
// witness and the candidate LCL strictly advances beyond its previous proof.
// voteStatus is intentionally not an admission gate for a non-UNL candidate.
// Two heartbeats prove one distinct canonical forward advance before the final bounded-lag canonical admission proof.
const CANDIDATE_READY_REQUIRED_HEARTBEATS = 2;
// UNL admission is stricter than ordinary READY. A candidate must report
// HotPocket's own voteStatus=synced at an exact Bootstrap-A tip (measured lag 0)
// on two advancing post-warmup observations before native addToUnl() is released.
// This prevents patch.cfg membership from activating while HPFS primary/raw/state
// synchronization is still in flight.
const ADMISSION_SYNC_REQUIRED_HEARTBEATS = 2;
const ADMISSION_SYNC_OBSERVATION_FRESH_LCLS = 2;

// HotPocket node.role is node-local and is NOT the same thing as contract.unl.
// AutoCluster provisions every managed node as role=validator and never changes
// that role. Before admission, contract.unl simply does not contain the node pubkey.
// READY admission does not gate on local role; the reported role is diagnostic only.
function readLocalHotPocketNodeRole() {
  const candidates = [...new Set([
    process.env.EVERADMIN_HP_CFG_PATH ? path.resolve(process.env.EVERADMIN_HP_CFG_PATH) : null,
    path.resolve('/contract/cfg/hp.cfg'),
    path.resolve(process.cwd(), '../../../../cfg/hp.cfg'),
    path.resolve(process.cwd(), '../../../cfg/hp.cfg')
  ].filter(Boolean))];
  for (const file of candidates) {
    try {
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) continue;
      const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
      const role = cleanString(cfg && cfg.node && cfg.node.role || '', 32).toLowerCase();
      if (role) return role;
    } catch {}
  }
  return null;
}

function readLocalHotPocketUserPort() {
  const candidates = [...new Set([
    process.env.EVERADMIN_HP_CFG_PATH ? path.resolve(process.env.EVERADMIN_HP_CFG_PATH) : null,
    path.resolve('/contract/cfg/hp.cfg'),
    path.resolve(process.cwd(), '../../../../cfg/hp.cfg'),
    path.resolve(process.cwd(), '../../../cfg/hp.cfg')
  ].filter(Boolean))];
  for (const file of candidates) {
    try {
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) continue;
      const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
      const port = validPort(cfg && cfg.user && cfg.user.port);
      if (port) return port;
    } catch {}
  }
  return null;
}
// Keep a READY candidate outside the UNL for several clean Bootstrap/cluster
// ledgers after its first verified ledger-sync heartbeat. MATURED/ACKNOWLEDGED is
// required as native maturity but is never treated as sync proof. VALIDATOR_READY
// independently proves the candidate follows Bootstrap's canonical ledger before stitch.
const CANDIDATE_PREMERGE_CLEAN_LEDGERS = 1;
const RECENT_LEDGER_PROOF_WINDOW = 32;
// EverPocket promotes ACKNOWLEDGED -> UNL using maturityLclThreshold (not
// acknowledgeLclThreshold). A very large maturity threshold is therefore the
// authoritative promotion lock while AutoCluster waits for readiness/stability.
const PROMOTION_HOLD_MATURITY_THRESHOLD = 1000000;
// Xahau may provisionally accept a multisigned SignerListSet with terQUEUED.
// That is not a failure: the transaction can still validate later. Keep the
// intended signer in a reconciliation state and never submit another signer
// transaction while the first one remains pending.
const SIGNER_QUEUE_ORPHAN_GRACE_LCL = 6;
// EverPocket 0.1.6 uses a 10s AllVoteElector timeout by default. In a full
// bootstrap cluster, signer-election / multisign collection can legitimately
// miss that window. Give managed-signer provisioning more room and retry an
// empty vote result instead of persisting it as a fatal blocker.
const MANAGED_SIGNER_VOTE_TIMEOUT_MS = 20000;
// Post-UNL signer identity exchange uses HotPocket Node Party Line (NPL), not a
// re-entrant HPWS call back into the currently executing cluster. NPL is only
// used as the real-time transport. Bootstrap A writes the complete authenticated
// round to a node-local proposal file; the root control plane later commits the
// exact mapping through an ordinary HotPocket consensus input after the Xahau
// SignerListSet + DisableMaster transactions are visibly validated.
const AUTOCLUSTER_SIGNER_NPL_TYPE = 'autocluster_signer_ready_npl_v1';
const AUTOCLUSTER_NODE_STATUS_NPL_TYPE = 'autocluster_node_status_npl_v1';
const AUTOCLUSTER_MATURITY_NPL_TYPE = 'autocluster_maturity_npl_v1';
const AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE = 'autocluster_candidate_attestation_v1';
const AUTOCLUSTER_READY_OBSERVATION_TYPE = 'autocluster_ready_observation';
const AUTOCLUSTER_ATOMIC_READY_BUNDLE_TYPE = 'autocluster_atomic_ready_bundle';
const PROMOTION_PEER_WARMUP_LCLS = 1;
// Final readiness is sampled near the end of EverPocket's native 8-ledger
// ACKNOWLEDGED stability window, rather than after an unrelated 15-minute timer.
const PROMOTION_FINAL_PROOF_DELAY_LCLS = Math.max(1, OFFICIAL_EVERPOCKET_MATURITY_LCLS - 1);
const SIGNED_RELAY_FINAL_RETRY_LCLS = 16;
const AUTOCLUSTER_SIGNER_NPL_WAIT_MS = 2500;
const LEGACY_TERQUEUED_BLOCKER_HOLD_LCL = 8;
// Autonomous maintenance: with the default 5-validator/80% topology, one
// validator may fail while 4/5 consensus continues. Do not remove a dead UNL
// member first. Hold it in place, prepare a fresh non-UNL replacement, then
// retire the dead member only after the replacement is UNL + signed.
const AUTONOMOUS_HEALTH_SUSPECT_LCL = 8;
const AUTONOMOUS_DEAD_TIMEOUT_MS = 5 * 60 * 1000;
// Split expensive EverPocket/Xahau work into two cadences.
//
// ROUTINE housekeeping (lease-extension planning, steady-state reconciliation,
// generic Evernode/Xahau maintenance) is intentionally very cold: once every
// 100 committed ledgers. There is no value waking Xahau every few seconds merely
// to ask whether a long-lived lease still has plenty of time remaining.
//
// ACTIVE lifecycle work (an acquisition transaction/provisioning response in
// flight, bootstrap pool fill, autonomous repair, or handover transaction work)
// keeps the faster four-ledger cadence. Any real HotPocket user input bypasses
// both cadences immediately. The decision uses only replicated state + committed
// LCL/input-count, so every validator takes the same path.
const ROUTINE_LIFECYCLE_CADENCE_LCLS = 100;
const ACTIVE_LIFECYCLE_CADENCE_LCLS = 4;
// Bootstrap A is the sole validator during the acquisition phase, so stock
// EverPocket acquisition/provisioning bookkeeping is allowed to persist normally.
// Poll at the normal ACTIVE cadence so validated purchases and newly materialized
// instances are observed promptly. Consensus-purity fencing begins only after the
// full managed fleet exists and before the first UNL admission.
const SINGLETON_ACQUIRE_LIFECYCLE_CADENCE_LCLS = 1;

function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJson(file, value) {
  // HotPocket owns this filesystem. Shared state is written only from a normal
  // consensus execution; read requests never reach this writer.
  // alpha53.34: avoid touching HPFS when the serialized value is byte-identical.
  // A surprising amount of controller code intentionally calls saveState() as a
  // safety flush; making no-op flushes truly no-op cuts filesystem/state churn
  // without changing any replicated state transition.
  const serialized = JSON.stringify(value, null, 2);
  try {
    try {
      if (fs.readFileSync(file, 'utf8') === serialized) return false;
    } catch (_) {}
    fs.writeFileSync(file, serialized);
  } catch (e) {
    const code = e && e.code ? e.code : 'ERR';
    const syscall = e && e.syscall ? e.syscall : 'write';
    throw new Error(`STATE_WRITE_FAILED ${file}: ${code}/${syscall}: ${e && e.message ? e.message : e}`);
  }
  try {
    const dir = path.dirname(file), prefix = path.basename(file) + '.tmp-';
    for (const name of fs.readdirSync(dir)) {
      if (name.startsWith(prefix)) { try { fs.rmSync(path.join(dir, name), { force: true }); } catch {} }
    }
  } catch {}
  return true;
}
// Singleton-bootstrap acquisition shadow.
//
// Bootstrap A must periodically let stock EverPocket/Xahau inspect an unresolved
// lease acquisition.  That inspection mutates EverPocket's replicated bookkeeping
// even when the only result is "still pending" (transactions.json validation
// cache, operations.json queue state, acquires.json pending state, cluster.json
// activeOnLcl/aliveCheckCount).  Pre-UNL followers intentionally do not execute
// those external calls, so exposing those poll-only mutations in /state makes them
// miss the next ledger and HPFS-catch-up.
//
// During the singleton A-only acquisition poll we therefore use a node-local
// working shadow for EverPocket's four bookkeeping files.  The shadow is loaded
// before ClusterContext.init(), then captured again after deinit().  If the poll
// produced no durable AutoCluster semantic event, the exact replicated bytes from
// the start of the execution are restored before HotPocket hashes /state.  Stock
// EverPocket still sees its prior local polling progress on the next wakeup.
//
// A real milestone is deliberately allowed to commit: a new/changed cluster.nodes
// row, a native acquiredNodes record, or durable AutoCluster queue/blocker state
// (queued->attempting/pending, terminal failure/requeue, AcquireSuccess identity,
// etc.).  This keeps acquisition progress functional without turning every poll
// into a consensus-state write.
const SINGLETON_SHADOW_FILES = ['cluster.json','operations.json','acquires.json','transactions.json'];

function readFileSnapshot(file) {
  try { return { exists:true, bytes:fs.readFileSync(file) }; }
  catch { return { exists:false, bytes:null }; }
}
function restoreFileSnapshot(file, snap) {
  try {
    if (snap && snap.exists) fs.writeFileSync(file, snap.bytes);
    else fs.rmSync(file, { force:true });
    return true;
  } catch { return false; }
}
function sha256Snapshot(snap) {
  return snap && snap.exists && snap.bytes ? crypto.createHash('sha256').update(snap.bytes).digest('hex') : null;
}
function shadowReadJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function singletonClusterVolatileProjection(value) {
  const scrub = input => {
    if (Array.isArray(input)) return input.map(scrub);
    if (!input || typeof input !== 'object') return input;
    const out = {};
    for (const [key,val] of Object.entries(input)) {
      if (key === 'activeOnLcl') continue;
      out[key] = scrub(val);
    }
    return out;
  };
  return JSON.stringify(scrub(value));
}
function singletonClusterDurableProjection(value) {
  const nodes = value && Array.isArray(value.nodes) ? value.nodes : [];
  // pendingNodes is intentionally excluded.  Its aliveCheckCount/probe lifecycle
  // is exactly the stock EverPocket poll state being moved node-local.  A real
  // instance crossing the boundary appears in nodes and is therefore durable.
  const scrub = input => {
    if (Array.isArray(input)) return input.map(scrub);
    if (!input || typeof input !== 'object') return input;
    const out = {};
    for (const [key,val] of Object.entries(input)) {
      if (['activeOnLcl','aliveCheckCount','lastAliveCheckAt','lastAliveCheckLcl','lastCheckedAt','lastCheckedLcl'].includes(key)) continue;
      out[key] = scrub(val);
    }
    return out;
  };
  return JSON.stringify(nodes.map(scrub).sort((a,b)=>String(a && (a.pubkey||a.host||a.refId)||'').localeCompare(String(b && (b.pubkey||b.host||b.refId)||''))));
}
function singletonAcquiredDurableProjection(value) {
  const rows = value && Array.isArray(value.acquiredNodes) ? value.acquiredNodes : [];
  return JSON.stringify(rows.map(r => safeAcquireRecordSummary(r)).filter(Boolean)
    .sort((a,b)=>String(a.refId||a.host||a.pubkey||'').localeCompare(String(b.refId||b.host||b.pubkey||''))));
}
function singletonAutoClusterDurableProjection(value) {
  const queue = value && Array.isArray(value.hostQueue) ? value.hostQueue : [];
  const projected = queue.map(h => h && ({
    address:normalizeHostAddress(h.address), status:cleanString(h.status||'',64), attempts:Number(h.attempts)||0,
    refId:cleanString(h.refId||'',256)||null, lastError:cleanString(h.lastError||'',512)||null,
    acquireRequestTxId:cleanString(h.acquireRequestTxId||'',256)||null,
    acquireRequestCode:cleanString(h.acquireRequestCode||'',128)||null,
    transientFailureStreak:Number(h.transientFailureStreak)||0,
    retryAfterLcl:Number(h.retryAfterLcl)||null,
    acquireSuccessAtLcl:Number(h.acquireSuccessAtLcl)||null,
    acquireSuccessPubkey:cleanString(h.acquireSuccessPubkey||'',256)||null,
    acquireSuccessDomain:normalizeEndpointHost(h.acquireSuccessDomain),
    acquireSuccessUserPort:validPort(h.acquireSuccessUserPort), acquireSuccessPeerPort:validPort(h.acquireSuccessPeerPort),
    acquireSuccessGpTcp1Port:validPort(h.acquireSuccessGpTcp1Port), acquireSuccessGpUdp1Port:validPort(h.acquireSuccessGpUdp1Port),
    acquireSuccessContractId:cleanString(h.acquireSuccessContractId||'',256)||null
  })).filter(Boolean).sort((a,b)=>String(a.address||'').localeCompare(String(b.address||'')));
  const blocker = value && value.blocker && typeof value.blocker === 'object' ? {
    type:cleanString(value.blocker.type||'',64)||null,
    stage:cleanString(value.blocker.stage||'',96)||null,
    host:normalizeHostAddress(value.blocker.host),
    message:cleanString(value.blocker.message||'',512)||null
  } : null;
  return JSON.stringify({ queue:projected, activeHostAttempt:normalizeHostAddress(value && value.activeHostAttempt), waitingForHosts:!!(value && value.waitingForHosts), blocker });
}
function singletonShadowQueueFingerprint(state) {
  const q = state && Array.isArray(state.hostQueue) ? state.hostQueue : [];
  return crypto.createHash('sha256').update(JSON.stringify(q.map(h => h && ({
    address:normalizeHostAddress(h.address), status:cleanString(h.status||'',64), refId:cleanString(h.refId||'',256)||null
  })).filter(Boolean).sort((a,b)=>String(a.address||'').localeCompare(String(b.address||''))))).digest('hex');
}
function clearSingletonAcquireShadow(reason = '') {
  try { fs.rmSync(LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR, { recursive:true, force:true }); }
  catch {}
  if (reason) console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW cleared (${cleanString(reason,160)}).`);
}
function loadSingletonAcquireShadowIntoWorkingSet(guard) {
  if (!guard || !guard.shadowMode) return false;
  const meta = readJson(LOCAL_SINGLETON_ACQUIRE_SHADOW_META_FILE, null);
  if (!meta || Number(meta.schema) !== 1 || cleanString(meta.bootstrapPubkey||'',256) !== cleanString(guard.bootstrapPubkey||'',256)) return false;
  // Do not reuse a shadow from a different acquisition set.  Maturity/READY may
  // legitimately change autocluster.state.json between polls, so only the host/
  // ref/status acquisition identity is used as the compatibility key.
  if (cleanString(meta.queueFingerprint||'',128) !== cleanString(guard.queueFingerprint||'',128)) {
    clearSingletonAcquireShadow('acquisition-set-changed');
    return false;
  }
  let loaded = 0;
  for (const name of SINGLETON_SHADOW_FILES) {
    const shadowFile = path.resolve(LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR, name);
    if (!fs.existsSync(shadowFile)) continue;
    const target = path.resolve(process.cwd(), name);
    try {
      if (name === 'cluster.json') {
        // Keep the currently committed durable node rows (maturity/ACK may have
        // advanced since the previous poll) but restore the local pending/liveness
        // working set that stock EverPocket needs to continue polling.
        const current = readJson(target, {}) || {};
        const shadow = readJson(shadowFile, {}) || {};
        const merged = { ...shadow, ...current };
        if (Array.isArray(shadow.pendingNodes)) merged.pendingNodes = shadow.pendingNodes;
        if (shadow.activeOnLcl != null) merged.activeOnLcl = shadow.activeOnLcl;
        writeJson(target, merged);
      } else {
        fs.copyFileSync(shadowFile, target);
      }
      loaded++;
    } catch (e) {
      console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW could not load ${name}: ${errText(e)}.`);
    }
  }
  if (loaded) console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW resumed ${loaded}/${SINGLETON_SHADOW_FILES.length} EverPocket working file(s) at LCL ${guard.lcl || '?'}; poll progress remains node-local until a durable milestone.`);
  return loaded > 0;
}
function captureSingletonAcquireShadow(guard) {
  if (!guard || !guard.shadowMode) return false;
  try {
    fs.mkdirSync(LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR, { recursive:true });
    for (const name of SINGLETON_SHADOW_FILES) {
      const source = path.resolve(process.cwd(), name);
      const dest = path.resolve(LOCAL_SINGLETON_ACQUIRE_SHADOW_DIR, name);
      try { if (fs.existsSync(source)) fs.copyFileSync(source, dest); else fs.rmSync(dest,{force:true}); } catch {}
    }
    writeJson(LOCAL_SINGLETON_ACQUIRE_SHADOW_META_FILE, {
      schema:1, bootstrapPubkey:guard.bootstrapPubkey, queueFingerprint:guard.queueFingerprint,
      updatedAtLcl:guard.lcl || null
    });
    return true;
  } catch (e) {
    console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW capture failed: ${errText(e)}.`);
    return false;
  }
}
function prepareSingletonLifecycleStateGuard(state, hpContext, committedUnl, localIsUnl, shadowMode = false) {
  if (!state || state.phase !== 'growing' || !localIsUnl || !hpContext || hpContext.publicKey !== state.bootstrapPubkey) return null;
  const unl = normalizePubkeyList(committedUnl || []);
  if (unl.length !== 1 || !unl.includes(state.bootstrapPubkey)) return null;
  const snapshots = {};
  for (const name of [...SINGLETON_SHADOW_FILES, path.basename(STATE_FILE)]) {
    const f = name === path.basename(STATE_FILE) ? STATE_FILE : path.resolve(process.cwd(), name);
    snapshots[name] = readFileSnapshot(f);
  }
  const originalCluster = readJson(path.resolve(process.cwd(),'cluster.json'), {}) || {};
  const originalAcquires = readJson(path.resolve(process.cwd(),'acquires.json'), {}) || {};
  const originalAuto = readJson(STATE_FILE, {}) || {};
  const guard = {
    lcl:Number(hpContext.lclSeqNo)||0,
    bootstrapPubkey:state.bootstrapPubkey,
    shadowMode:!!shadowMode,
    queueFingerprint:singletonShadowQueueFingerprint(state),
    snapshots,
    clusterDurable:singletonClusterDurableProjection(originalCluster),
    acquiredDurable:singletonAcquiredDurableProjection(originalAcquires),
    autoDurable:singletonAutoClusterDurableProjection(originalAuto),
    restored:false,
    shadowLoaded:false
  };
  if (guard.shadowMode) guard.shadowLoaded = loadSingletonAcquireShadowIntoWorkingSet(guard);
  return guard;
}
function restoreSingletonLifecycleStateGuard(guard) {
  if (!guard || guard.restored) return false;
  guard.restored = true;

  // Non-acquisition singleton lifecycle keeps the old narrow protection: only
  // cluster.json.activeOnLcl is suppressible. Promotion and user-driven semantic
  // work must never be hidden by the acquisition shadow.
  if (!guard.shadowMode) {
    const snap = guard.snapshots && guard.snapshots['cluster.json'];
    if (!snap || !snap.exists) return false;
    try {
      const original = JSON.parse(snap.bytes.toString('utf8'));
      const current = readJson(path.resolve(process.cwd(),'cluster.json'), null);
      if (current && singletonClusterVolatileProjection(current) === singletonClusterVolatileProjection(original)) {
        const curBytes = fs.readFileSync(path.resolve(process.cwd(),'cluster.json'));
        if (!curBytes.equals(snap.bytes)) {
          fs.writeFileSync(path.resolve(process.cwd(),'cluster.json'), snap.bytes);
          console.log(`AutoCluster: SINGLETON SEMANTIC-STATE GUARD at LCL ${guard.lcl || '?'} restored cluster.json because only non-durable singleton bookkeeping changed.`);
          return true;
        }
      }
    } catch (e) { console.log(`AutoCluster: SINGLETON SEMANTIC-STATE GUARD restore failed: ${errText(e)}.`); }
    return false;
  }

  const currentCluster = readJson(path.resolve(process.cwd(),'cluster.json'), {}) || {};
  const currentAcquires = readJson(path.resolve(process.cwd(),'acquires.json'), {}) || {};
  const currentAuto = readJson(STATE_FILE, {}) || {};
  const clusterChanged = singletonClusterDurableProjection(currentCluster) !== guard.clusterDurable;
  const acquiredChanged = singletonAcquiredDurableProjection(currentAcquires) !== guard.acquiredDurable;
  const autoChanged = singletonAutoClusterDurableProjection(currentAuto) !== guard.autoDurable;
  const durable = clusterChanged || acquiredChanged || autoChanged;

  if (durable) {
    clearSingletonAcquireShadow('durable-acquisition-milestone-committed');
    const reasons = [clusterChanged?'cluster-nodes':null,acquiredChanged?'acquire-success':null,autoChanged?'autocluster-queue':null].filter(Boolean);
    console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW COMMIT at LCL ${guard.lcl || '?'} durable=[${reasons.join(',')}]; EverPocket working files are allowed into replicated /state exactly for this milestone.`);
    return false;
  }

  // Capture the advanced EverPocket working set locally first, then restore every
  // replicated byte exactly as it was at execution start.  This is the critical
  // invariant: an idle/pending poll can never create a new HotPocket /state hash.
  captureSingletonAcquireShadow(guard);
  let restored = 0;
  for (const name of [...SINGLETON_SHADOW_FILES, path.basename(STATE_FILE)]) {
    const f = name === path.basename(STATE_FILE) ? STATE_FILE : path.resolve(process.cwd(), name);
    if (restoreFileSnapshot(f, guard.snapshots[name])) restored++;
  }
  console.log(`AutoCluster: SINGLETON LOCAL-ACQUIRE SHADOW QUIESCENT at LCL ${guard.lcl || '?'} restored ${restored}/${SINGLETON_SHADOW_FILES.length + 1} replicated file(s) byte-for-byte; stock EverPocket/Xahau polling progress was retained node-locally and /state remains unchanged.`);
  return true;
}

function cleanString(v, max = 512) {
  const s = String(v == null ? '' : v).trim();
  return s.slice(0, max);
}
function int(v, fallback, min, max) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}
function num(v, fallback, min, max) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}
function bool(v, fallback = false) {
  return typeof v === 'boolean' ? v : fallback;
}
function normalizeConsensusTimestampMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  // HotPocket contract timestamps may be exposed as Unix seconds by the raw
  // contract ctx while wrappers can expose milliseconds. Normalize once so
  // wall-clock watchdog thresholds are actually five minutes in either form.
  return n < 100000000000 ? Math.floor(n * 1000) : Math.floor(n);
}
function consensusNowMs(run) {
  if (!run) return 0;
  return normalizeConsensusTimestampMs(run.ctx && run.ctx.timestamp) ||
    normalizeConsensusTimestampMs(run.hpContext && run.hpContext.timestamp) || 0;
}
function validPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : null;
}

const RPC_CHAIN_KEYS = ['xahau','xrpl','solana','stellar','ethereum','bitcoin'];
function defaultXahauRpc(network) {
  if (network === 'mainnet') return 'wss://xahau.network';
  if (network === 'testnet') return 'wss://xahau-test.net';
  return null;
}
function normalizeRpcUrl(value, chain) {
  const raw = cleanString(value, 512);
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
    const priority = int(obj.priority, (i + 1) * 10, 1, 1000000);
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
function rpcPoolUrls(state, chain) {
  return normalizeRpcPool(state && state.rpcPools && state.rpcPools[chain], chain).map(x => x.url);
}
function orderedStickyRpcUrls(urls, stickyFile) {
  const cleanUrls = [...new Set((Array.isArray(urls) ? urls : []).map(x => normalizeRpcUrl(x, 'xahau')).filter(Boolean))];
  const sticky = readJson(stickyFile, null);
  const preferred = normalizeRpcUrl(sticky && sticky.url, 'xahau');
  if (!preferred || !cleanUrls.includes(preferred)) return cleanUrls;
  return [preferred, ...cleanUrls.filter(x => x !== preferred)];
}
function writeNodeLocalJsonBestEffort(file, value, label = 'LOCAL-CACHE') {
  // Node-local runtime caches are optimizations only. They must NEVER become
  // consensus/lifecycle failure authorities. In particular, a successfully
  // connected Xahau RPC remains usable even when this host cannot persist the
  // sticky endpoint hint. Create the parent directory lazily because HPFS may
  // materialize a fresh mnt/rw tree without our sibling autocluster-local dir.
  try {
    fs.mkdirSync(path.dirname(file), { recursive:true });
    writeJson(file, value);
    return true;
  } catch (e) {
    console.log(`${label}: node-local cache write WARN ${file}: ${cleanString(errText(e), 220)}. Continuing; cache persistence is non-fatal.`);
    return false;
  }
}
async function connectXahauRpcSequential(urls, network, label = 'AutoCluster') {
  const evernode = require('evernode-js-client');
  await evernode.Defaults.useNetwork(network || 'mainnet');
  const ordered = orderedStickyRpcUrls(urls, LOCAL_XAHAU_RPC_FILE);
  if (!ordered.length) throw new Error('XAHAU_RPC_POOL_EMPTY: no configured Xahau RPC endpoints.');
  const errors = [];
  for (let i = 0; i < ordered.length; i++) {
    const url = ordered[i];
    let api = null;
    try {
      console.log(`${label}: Xahau RPC TRY ${i + 1}/${ordered.length} ${url}.`);
      // Use fallback-only mode with exactly one endpoint. This bypasses the
      // library's misleading primary reconnect loop and gives AutoCluster true
      // ordered one-server-at-a-time failover.
      api = new evernode.XrplApi('-', { fallbackRippledServers:[url], autoReconnect:false });
      await api.connect();
      // AutoCluster fee policy: preserve the network/library-calculated fee,
      // then add exactly 13 drops before any transaction is signed. Wrapping
      // getTransactionFee here covers EverPocket acquisitions and multisigned
      // lifecycle transactions without ever mutating an already-signed blob.
      if (typeof api.getTransactionFee === 'function' && !api.__everSmartNodeFeePlus13) {
        const originalGetTransactionFee = api.getTransactionFee.bind(api);
        api.getTransactionFee = async (...args) => {
          const calculated = await originalGetTransactionFee(...args);
          try {
            const bumped = BigInt(String(calculated)) + 13n;
            console.log(`${label}: Xahau fee bump ${String(calculated)} -> ${bumped.toString()} drops (+13).`);
            return bumped.toString();
          } catch {
            throw new Error(`XAHAU_FEE_INVALID: expected integer drops, got ${String(calculated)}`);
          }
        };
        api.__everSmartNodeFeePlus13 = true;
      }
      const stickyPersisted = writeNodeLocalJsonBestEffort(
        LOCAL_XAHAU_RPC_FILE,
        { url, connectedAt:Date.now() },
        `${label}: XAHAU_RPC_STICKY_CACHE`
      );
      console.log(`${label}: Xahau RPC CONNECTED ${url}; ${stickyPersisted ? 'keeping it sticky until it fails or leaves the configured pool' : 'sticky cache unavailable, but the live RPC connection remains valid'}.`);
      return { api, url };
    } catch (e) {
      const msg = errText(e);
      errors.push(`${url}: ${msg}`);
      console.log(`${label}: Xahau RPC FAIL ${url}: ${cleanString(msg, 220)}. Trying next configured server.`);
      try { if (api) await api.disconnect(); } catch {}
      const sticky = readJson(LOCAL_XAHAU_RPC_FILE, null);
      if (sticky && normalizeRpcUrl(sticky.url, 'xahau') === url) {
        try { fs.rmSync(LOCAL_XAHAU_RPC_FILE, { force:true }); } catch {}
      }
    }
  }
  throw new Error(`XAHAU_RPC_POOL_UNAVAILABLE: ${errors.join(' | ')}`);
}
function normalizeEndpointHost(v) {
  let s = cleanString(v, 255).replace(/^wss?:\/\//i, '').replace(/^https?:\/\//i, '');
  if (!s) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes('/')) s = s.split('/')[0];
  if (!s || /\s/.test(s) || !/^[A-Za-z0-9._:-]+$/.test(s)) return null;
  return s;
}
function normalizeBootstrapEndpoint(raw) {
  raw = raw && typeof raw === 'object' ? raw : {};
  const src = raw.bootstrapEndpoint && typeof raw.bootstrapEndpoint === 'object' ? raw.bootstrapEndpoint : raw;
  const domain = normalizeEndpointHost(src.domain || src.host || raw.bootstrapDomain);
  const userPort = validPort(src.userPort || raw.bootstrapUserPort);
  const peerPort = validPort(src.peerPort || src.meshPort || raw.bootstrapPeerPort || raw.bootstrapMeshPort);
  return domain && (userPort || peerPort) ? { domain, userPort, peerPort } : null;
}
// Canonicalize peer endpoints before the HotPocket control channel. Persistent
// mesh.known_peers and live peer_changeset both keep stable hostname:port entries;
// malformed placeholders (notably EverPocket's bootstrap undefined:undefined row)
// are repaired from the already-synced trusted peer seed before reaching hpcore.
function parseLivePeerEndpoint(value) {
  let raw = cleanString(value, 512).trim();
  if (!raw) return null;
  raw = raw.replace(/^(?:wss?|https?):\/\//i, '');
  raw = raw.split(/[/?#]/, 1)[0].trim();
  let host = '', portText = '';
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end < 2 || raw[end + 1] !== ':') return null;
    host = raw.slice(1, end);
    portText = raw.slice(end + 2);
  } else {
    const idx = raw.lastIndexOf(':');
    if (idx <= 0) return null;
    host = raw.slice(0, idx).trim();
    portText = raw.slice(idx + 1).trim();
    // Unbracketed IPv6 is ambiguous once a port is appended. Reject instead of
    // ever producing host:port:port or another hpcore-invalid peer string.
    if (host.includes(':') && net.isIP(host) !== 6) return null;
  }
  const port = Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (!host || /\s/.test(host)) return null;
  const ipKind = net.isIP(host);
  if (!ipKind && !/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$/.test(host)) return null;
  return { host: host.replace(/\.$/, '').toLowerCase(), port, ipKind };
}

function livePeerValue(value) {
  if (typeof value === 'string') return value.trim();
  if (!value || typeof value !== 'object') return '';
  for (const key of ['endpoint','peer','address']) {
    if (typeof value[key] === 'string' && value[key].trim()) return value[key].trim();
  }
  const host = normalizeEndpointHost(value.domain || value.host || value.hostname || value.ip);
  const port = validPort(value.peerPort || value.meshPort || value.port);
  return host && port ? `${host}:${port}` : '';
}

function canonicalLivePeer(value) {
  const raw = livePeerValue(value);
  const parsed = parseLivePeerEndpoint(raw);
  if (!parsed) return null;
  return parsed.ipKind === 6 ? `[${parsed.host}]:${parsed.port}` : `${parsed.host}:${parsed.port}`;
}

async function livePeerFallbackSeeds(hpContext) {
  const peers = [];
  const add = value => {
    const peer = canonicalLivePeer(value);
    if (peer && !peers.includes(peer)) peers.push(peer);
  };
  // New EverPocket instances are already seeded by AutoCluster with the current
  // trusted UNL in mesh.known_peers. This is the authoritative fallback when
  // stock EverPocket's initial bootstrap ClusterNode has no domain/peerPort and
  // #checkForMatured() constructs "undefined:undefined" from that incomplete row.
  try {
    if (hpContext && typeof hpContext.getContractConfig === 'function') {
      const cfg = await hpContext.getContractConfig();
      const mesh = cfg && cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
      const known = Array.isArray(mesh.known_peers) ? mesh.known_peers
        : (Array.isArray(mesh.knownPeers) ? mesh.knownPeers : []);
      for (const peer of known) add(peer);
    }
  } catch {}
  try {
    const state = readJson(STATE_FILE, null);
    const b = state && state.bootstrapEndpoint;
    const d = normalizeEndpointHost(b && b.domain);
    const p = validPort(b && b.peerPort);
    if (d && p) add(`${d}:${p}`);
  } catch {}
  peers.sort();
  return peers;
}

function installHotPocketLivePeerAdapter(hpContext) {
  if (!hpContext || typeof hpContext.updatePeers !== 'function' || hpContext.__everSmartLivePeerAdapter) return;
  const original = hpContext.updatePeers.bind(hpContext);
  hpContext.__everSmartLivePeerAdapter = true;
  hpContext.updatePeers = async (toAdd, toRemove = null) => {
    const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
    const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
    const localKey = String(hpContext.publicKey || '').toLowerCase();
    let selfPeer = null;
    for (const n of nodes) {
      const domain = normalizeEndpointHost(n && n.domain);
      const peerPort = validPort(n && (n.peerPort || n.meshPort));
      if (String(n && n.pubkey || '').toLowerCase() === localKey && domain && peerPort)
        selfPeer = canonicalLivePeer(`${domain}:${peerPort}`);
    }

    const normalizeList = async (input, label) => {
      if (input == null || input === '*') return [];
      const list = Array.isArray(input) ? input : [input];
      const out = [];
      const invalid = [];
      for (const raw of list) {
        if (raw == null || raw === '*') continue;
        const peer = canonicalLivePeer(raw);
        if (!peer) {
          invalid.push(livePeerValue(raw) || cleanString(raw, 300) || '<empty>');
          continue;
        }
        if (label === 'add' && selfPeer && peer === selfPeer) continue;
        if (!out.includes(peer)) out.push(peer);
      }

      // Stock EverPocket currently initializes the original UNL ClusterNode with
      // no endpoint fields. A joining node can therefore be handed the literal
      // peer "undefined:undefined" during #checkForMatured(). Do not weaken the
      // HotPocket wire validator. Repair the missing bootstrap/full-UNL entries
      // from the instance's already-synced mesh.known_peers/bootstrap endpoint.
      if (label === 'add' && invalid.length) {
        const fallback = await livePeerFallbackSeeds(hpContext);
        for (const peer of fallback) {
          if (selfPeer && peer === selfPeer) continue;
          if (!out.includes(peer)) out.push(peer);
        }
        console.log(`AutoCluster: LIVE PEER_CHANGESET repaired ${invalid.length} invalid upstream add entr${invalid.length === 1 ? 'y' : 'ies'} [${invalid.join(', ')}] using ${fallback.length} persisted trusted peer seed(s).`);
      }

      out.sort();
      if (label === 'add' && list.length && !out.length) {
        throw new Error(`NO_VALID_LIVE_PEERS_AFTER_NORMALIZATION: input=[${list.map(v => livePeerValue(v) || cleanString(v,120) || '<empty>').join(', ')}]`);
      }
      if (label === 'remove' && invalid.length) {
        console.log(`AutoCluster: LIVE PEER_CHANGESET ignored ${invalid.length} malformed remove entr${invalid.length === 1 ? 'y' : 'ies'} [${invalid.join(', ')}].`);
      }
      return out;
    };

    const add = await normalizeList(toAdd, 'add');
    const remove = await normalizeList(toRemove, 'remove');
    if (!add.length && !remove.length) return;
    console.log(`AutoCluster: LIVE PEER_CHANGESET add=[${add.join(', ')}] remove=[${remove.join(', ')}].`);
    return original(add, remove);
  };
}

function normalizeHostAddress(v) {
  const s = cleanString(v, 64);
  // Xahau/XRPL classic addresses are base58 and begin with r. Final validity is
  // deliberately checked by EverPocket/Evernode at acquisition time; this is
  // only a queue-shape guard, never a trust decision.
  return /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(s) ? s : null;
}
function normalizeHostQueue(rawQueue, legacyHosts = []) {
  const source = Array.isArray(rawQueue) && rawQueue.length
    ? rawQueue
    : (Array.isArray(legacyHosts) ? legacyHosts.map(address => ({ address })) : []);
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const address = normalizeHostAddress(typeof item === 'string' ? item : item && item.address);
    if (!address || seen.has(address)) continue;
    seen.add(address);
    const obj = item && typeof item === 'object' ? item : {};
    let status = ['queued','attempting','pending','provisioning-stalled','acquired','failed','price-rejected','funding-wait','endpoint-stalled','readiness-stalled','readiness-retired','maturity-stalled','maturity-retired','auto-kicked','drop-termination-pending','dropped','skipped','removed'].includes(obj.status) ? obj.status : 'queued';
    let legacyError = cleanString(obj.lastError || '', 512);
    // alpha.37.35 and earlier could quarantine a perfectly working materialized
    // candidate solely because the MATURED/ACKNOWLEDGED callback was missed. Reopen
    // that state: .37.36 judges the node by canonical VALIDATOR_READY instead.
    if (status === 'maturity-stalled' || (status === 'auto-kicked' && /without reaching MATURED\/ACKNOWLEDGED/i.test(legacyError))) {
      status = 'acquired';
      legacyError = '';
    }
    // alpha.37.37 and earlier could quarantine a native AcquireSuccess solely
    // because a validator-local WSS probe timed out. Reopen it; endpoint reachability
    // is no longer allowed to decide replicated state.
    if (status === 'endpoint-stalled') {
      status = obj.refId ? 'pending' : 'queued';
      legacyError = '';
    }
    // alpha.37.16 could discard a paid/accepted acquisition merely because the
    // transient EverPocket pending view disappeared or because provisioning took
    // longer than five minutes. Never repurchase those hosts automatically.
    // Keep them as late-recoverable provisioning records instead.
    if (obj.refId && (
        (status === 'auto-kicked' && /pending without joining the cluster/i.test(legacyError)) ||
        (status === 'failed' && /pending acquisition disappeared/i.test(legacyError))
      )) status = 'provisioning-stalled';
    // alpha.53.30 could falsely mark a host failed solely because EverPocket's
    // transient operation/pending view was empty on the next ledger. Repair that
    // state on upgrade. If transaction correlation exists, preserve it as a
    // pending/provisioning watch; otherwise safely re-queue the same host.
    if (status === 'failed' && /EverPocket acquisition produced no pending node/i.test(legacyError)) {
      status = (obj.refId || obj.acquireRequestTxId) ? 'pending' : 'queued';
      legacyError = '';
    }
    // alpha.37.67 injected a per-candidate READY relay key into instanceCfg.
    // That altered the Evernode acquisition payload and could make URITokenBuy
    // fail before submission. Re-arm only those specifically identifiable failed
    // attempts on upgrade; the relay now uses HotPocket's existing node key and
    // does not touch acquisition config at all.
    const legacyReadyRelayPublicKey = cleanString(obj.readyRelayPublicKey || '', 256).toLowerCase() || null;
    if (legacyReadyRelayPublicKey && status === 'failed' && /Could not consider as a valid submission/i.test(legacyError || '')) {
      status = 'queued';
      legacyError = '';
    }
    out.push({
      address,
      status,
      attempts: int(obj.attempts, 0, 0, 100000),
      addedAtLcl: Number(obj.addedAtLcl) || null,
      lastAttemptLcl: Number(obj.lastAttemptLcl) || null,
      pendingSinceAt: Number(obj.pendingSinceAt) || null,
      pendingSinceLcl: Number(obj.pendingSinceLcl) || null,
      lastError: legacyError || null,
      lastObservedLeaseAmount: obj.lastObservedLeaseAmount != null && Number.isFinite(Number(obj.lastObservedLeaseAmount)) ? Number(obj.lastObservedLeaseAmount) : null,
      refId: cleanString(obj.refId || '', 256) || null,
      nativeStage: cleanString(obj.nativeStage || '', 64) || null,
      nativeStageAtLcl: Number(obj.nativeStageAtLcl) || null,
      acquireRequestTxId: cleanString(obj.acquireRequestTxId || '', 256) || null,
      acquireRequestCode: cleanString(obj.acquireRequestCode || '', 64) || null,
      acquireRequestLedgerIndex: Number(obj.acquireRequestLedgerIndex) || null,
      transientFailureStreak: int(obj.transientFailureStreak, 0, 0, 1000),
      retryAfterLcl: Number(obj.retryAfterLcl) || null,
      acquireSuccessAtLcl: Number(obj.acquireSuccessAtLcl) || null,
      acquireSuccessPubkey: cleanString(obj.acquireSuccessPubkey || '', 256) || null,
      acquireSuccessDomain: normalizeEndpointHost(obj.acquireSuccessDomain),
      acquireSuccessUserPort: validPort(obj.acquireSuccessUserPort),
      acquireSuccessPeerPort: validPort(obj.acquireSuccessPeerPort),
      acquireSuccessGpTcp1Port: validPort(obj.acquireSuccessGpTcp1Port),
      acquireSuccessGpUdp1Port: validPort(obj.acquireSuccessGpUdp1Port),
      acquireSuccessName: cleanString(obj.acquireSuccessName || '', 256) || null,
      acquireSuccessContractId: cleanString(obj.acquireSuccessContractId || '', 256) || null,
      nativeTraceFingerprint: cleanString(obj.nativeTraceFingerprint || '', 512) || null
    });
    if (out.length >= 256) break;
  }
  return out;
}
function normalizeBlocker(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const type = ['funding','encryption','maturity','network','signing','cluster'].includes(raw.type) ? raw.type : 'cluster';
  return {
    type,
    stage: cleanString(raw.stage || 'autocluster', 96),
    message: cleanString(raw.message || '', 768) || 'AutoCluster operation is blocked.',
    atLcl: Number(raw.atLcl) || null,
    nodePubkey: cleanString(raw.nodePubkey || '', 256) || null,
    host: normalizeHostAddress(raw.host)
  };
}
function blockerTypeFor(text, stage = '') {
  const t = String(text || '');
  if (fundingError(t)) return 'funding';
  if (/Bad MAC|MAC check|decrypt|decryption|ciphertext|authentication tag/i.test(t)) return 'encryption';
  if (/undefined:undefined|matur|acknowledg|peer endpoint|user endpoint/i.test(t) || /maturity/i.test(stage)) return 'maturity';
  if (/ECONN|ENET|EHOST|ETIMEDOUT|socket|websocket|connect/i.test(t)) return 'network';
  if (/signer/i.test(stage) || /SignerList|addXrplSigner|multisign/i.test(t)) return 'signing';
  return 'cluster';
}
function setBlocker(state, error, stage, lcl = null, extra = {}) {
  if (!state) return null;
  const message = errText(error);
  const blocker = {
    type: blockerTypeFor(message, stage),
    stage: cleanString(stage || 'autocluster', 96),
    message,
    atLcl: Number(lcl) || null,
    nodePubkey: cleanString(extra.nodePubkey || '', 256) || null,
    host: normalizeHostAddress(extra.host)
  };
  state.blocker = blocker;
  saveState(state);
  console.log(`AutoCluster: BLOCKED type=${blocker.type} stage=${blocker.stage}: ${blocker.message}`);
  return blocker;
}
function clearBlocker(state, type = null, stage = null) {
  if (!state || !state.blocker) return false;
  if (type && state.blocker.type !== type) return false;
  if (stage && state.blocker.stage !== stage) return false;
  state.blocker = null;
  saveState(state);
  return true;
}

function normalizePubkeyList(raw) {
  if (!Array.isArray(raw)) return [];
  return [...new Set(raw.map(v => cleanString(v, 256)).filter(Boolean))].sort();
}
function normalizeStabilization(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    active: raw.active === true,
    reason: cleanString(raw.reason || 'validator-set-change', 160),
    startedAtLcl: Number(raw.startedAtLcl) || null,
    lastCleanLcl: Number(raw.lastCleanLcl) || null,
    cleanLedgers: int(raw.cleanLedgers, 0, 0, 1000000),
    requiredCleanLedgers: int(raw.requiredCleanLedgers, VALIDATOR_STABILIZATION_CLEAN_LEDGERS, 2, 100),
    targetUnlPubkeys: normalizePubkeyList(raw.targetUnlPubkeys),
    addedPubkeys: normalizePubkeyList(raw.addedPubkeys),
    removedPubkeys: normalizePubkeyList(raw.removedPubkeys),
    completedAtLcl: Number(raw.completedAtLcl) || null
  };
}

function normalizeCandidateReadiness(raw) {
  if (!Array.isArray(raw)) return [];
  const byKey = new Map();
  for (const r of raw) {
    const pubkey = cleanString(r && r.pubkey || '', 256);
    if (!pubkey) continue;
    const item = {
      pubkey,
      candidateLcl: Number(r && r.candidateLcl) || null,
      observedAtLcl: Number(r && r.observedAtLcl) || null,
      candidateHash: cleanString(r && r.candidateHash || '', 256) || null,
      buildFingerprint: cleanString(r && r.buildFingerprint || '', 256).toLowerCase() || null,
      // Authenticated Bootstrap-A candidate snapshot of live HotPocket peer
      // connections.  This is consensus-safe because the network observation is
      // made outside contract execution and enters as signed READY input.  The
      // atomic bootstrap gate uses the latest fresh value to ensure B/C/D/E are
      // already connected as a mesh before they become validators.
      peerCount: r && (r.peerCount != null || r.peers != null)
        ? Math.max(0, Number(r.peerCount != null ? r.peerCount : r.peers) || 0)
        : null,
      candidateLag: r && r.candidateLag != null ? Math.max(0, Number(r.candidateLag) || 0) : null,
      voteStatus: cleanString(r && r.voteStatus || '', 32).toLowerCase() || null,
      admissionSyncHeartbeats: int(r && r.admissionSyncHeartbeats, 0, 0, 1000000),
      admissionSyncFirstAtLcl: Number(r && r.admissionSyncFirstAtLcl) || null,
      transport: cleanString(r && r.transport || '', 32).toLowerCase() || null,
      hpfsReady: r && r.hpfsReady === true,
      primaryHash: cleanString(r && r.primaryHash || '',128).toLowerCase() || null,
      rawHash: cleanString(r && r.rawHash || '',128).toLowerCase() || null,
      stateHash: cleanString(r && r.stateHash || '',128).toLowerCase() || null,
      patchHash: cleanString(r && r.patchHash || '',128).toLowerCase() || null,
      syncHeartbeats: int(r && r.syncHeartbeats, 0, 0, 1000000),
      readyHeartbeats: int(r && r.readyHeartbeats, 0, 0, 1000000),
      firstReadyAtLcl: Number(r && r.firstReadyAtLcl) || null,
      // Set only when a post-warmup admission proof is committed. This lets the
      // candidate sidecar stay quiet instead of submitting a new consensus input
      // for every advancing ledger after readiness has already been established.
      finalReadyAtLcl: Number(r && r.finalReadyAtLcl) || null,
      proofHistory: (() => {
        const rows = Array.isArray(r && r.proofHistory) ? r.proofHistory : [];
        const byTuple = new Map();
        for (const p of rows) {
          const candidateLcl = Number(p && p.candidateLcl) || 0;
          const candidateHash = cleanString(p && p.candidateHash || '', 256).toLowerCase();
          const observedAtLcl = Number(p && p.observedAtLcl) || null;
          const candidateLag = p && p.candidateLag != null ? Math.max(0, Number(p.candidateLag) || 0) : null;
          if (!candidateLcl || !/^[0-9a-f]{64}$/.test(candidateHash)) continue;
          byTuple.set(`${candidateLcl}:${candidateHash}`, { candidateLcl, candidateHash, observedAtLcl, candidateLag });
        }
        return [...byTuple.values()].sort((a,b)=>a.candidateLcl-b.candidateLcl).slice(-12);
      })()
    };
    const old = byKey.get(pubkey);
    if (!old || Number(item.observedAtLcl || 0) >= Number(old.observedAtLcl || 0)) byKey.set(pubkey, item);
  }
  return [...byKey.values()].sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
}

function normalizeCandidateSyncQuiescence(raw) {
  if (!Array.isArray(raw)) return [];
  const byKey = new Map();
  for (const r of raw) {
    const pubkey = cleanString(r && r.pubkey || '', 256).toLowerCase();
    if (!/^ed[0-9a-f]{64}$/i.test(pubkey)) continue;
    const item = {
      pubkey,
      candidateLcl:Number(r && r.candidateLcl) || null,
      candidateHash:cleanString(r && r.candidateHash || '', 256).toLowerCase() || null,
      observedAtLcl:Number(r && r.observedAtLcl) || null,
      streak:Math.max(0, Number(r && r.streak) || 0),
      idleMs:Math.max(0, Number(r && r.idleMs) || 0),
      primaryHash:cleanString(r && r.primaryHash || '', 128).toLowerCase() || null,
      rawHash:cleanString(r && r.rawHash || '', 128).toLowerCase() || null,
      stateHash:cleanString(r && r.stateHash || '', 128).toLowerCase() || null,
      patchHash:cleanString(r && r.patchHash || '', 128).toLowerCase() || null
    };
    const old = byKey.get(pubkey);
    if (!old || Number(item.observedAtLcl || 0) >= Number(old.observedAtLcl || 0)) byKey.set(pubkey, item);
  }
  return [...byKey.values()].sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
}

function isCanonicalControllerTransport(value) {
  const transport = cleanString(value || '', 64).toLowerCase();
  return ['bootstrap-canonical-controller','client-stat','npl','signed-canonical-relay','signed-hpfs-relay'].includes(transport);
}

function verifiedSharedRecentLedger(state, lcl, hash) {
  const seq = Number(lcl) || 0;
  const digest = cleanString(hash || '', 256).toLowerCase();
  if (!seq || !digest) return false;
  return normalizeRecentLedgers(state && state.recentLedgers).some(x => x.lcl === seq && x.hash === digest);
}

function syncQuiescenceStatus(state, pubkey, currentLcl) {
  const key = cleanString(pubkey || '', 256).toLowerCase();
  const readyRec = normalizeCandidateReadiness(state && state.candidateReadiness).find(r => String(r.pubkey || '').toLowerCase() === key) || null;
  const nowLcl = Number(currentLcl) || 0;
  const observed = Number(readyRec && readyRec.observedAtLcl) || 0;
  const age = nowLcl && observed ? nowLcl - observed : Number.POSITIVE_INFINITY;
  const proofHistory = readyRec && Array.isArray(readyRec.proofHistory) ? readyRec.proofHistory : [];
  const canonicalController = !!(readyRec && isCanonicalControllerTransport(readyRec.transport));
  // A signed candidate LCL/hash is admitted only after Bootstrap A has matched it
  // against its node-local canonical recent-ledger witness. That exact verified
  // tuple is persisted in proofHistory. HPFS log scraping is diagnostic only: a
  // successfully executing HotPocket ledger that matches A's canonical history is
  // the stronger end-to-end proof and does not depend on log retention/timing.
  const latestCanonical = !!(readyRec && Number(readyRec.candidateLcl) > 0 && /^[0-9a-f]{64}$/.test(cleanString(readyRec.candidateHash || '', 256).toLowerCase()) && proofHistory.some(p =>
        Number(p && p.candidateLcl) === Number(readyRec.candidateLcl) &&
        cleanString(p && p.candidateHash || '', 256).toLowerCase() === cleanString(readyRec.candidateHash || '', 256).toLowerCase()
      ));
  const observedLag = readyRec && readyRec.candidateLag != null ? Number(readyRec.candidateLag) : Number.POSITIVE_INFINITY;
  const lagWithinTolerance = Number.isFinite(observedLag) && observedLag >= 0 && observedLag <= BOOTSTRAP_ADMISSION_MAX_LAG_LCLS;
  const candidateLcl = Number(readyRec && readyRec.candidateLcl) || 0;
  const currentLag = nowLcl && candidateLcl ? nowLcl - candidateLcl : Number.POSITIVE_INFINITY;
  const streak = Math.max(0, Number(readyRec && readyRec.syncHeartbeats) || 0);
  // Qualification tolerates a follower up to four canonical ledgers behind. The
  // final membership proof repeats the same bounded-lag canonical-history check
  // immediately before ADD_UNL, so ordinary one-ledger jitter does not reset admission.
  const ready = !!(readyRec && streak >= SYNC_QUIESCENT_REQUIRED_EXECUTIONS && lagWithinTolerance &&
    currentLag >= 0 && currentLag <= BOOTSTRAP_ADMISSION_MAX_LAG_LCLS &&
    age >= 0 && age <= SYNC_QUIESCENT_OBSERVATION_FRESH_LCL && latestCanonical);
  const rec = readyRec ? {
    pubkey:key,
    candidateLcl:Number(readyRec.candidateLcl) || null,
    candidateHash:cleanString(readyRec.candidateHash || '',256).toLowerCase() || null,
    observedAtLcl:Number(readyRec.observedAtLcl) || null,
    streak,
    candidateLag:readyRec.candidateLag,
    currentLag:Number.isFinite(currentLag) ? currentLag : null,
    source:canonicalController ? 'bootstrap-controller-canonical-ledger' : 'replicated-canonical-lag24'
  } : null;
  return { ready, rec, age, canonicalMatched:latestCanonical, freshLimit:SYNC_QUIESCENT_OBSERVATION_FRESH_LCL, source:canonicalController ? 'bootstrap-controller-canonical-ledger' : 'replicated-canonical-lag24' };
}

function admissionSyncStatus(state, pubkey, currentLcl) {
  const key = cleanString(pubkey || '', 256).toLowerCase();
  const rec = normalizeCandidateReadiness(state && state.candidateReadiness)
    .find(r => String(r.pubkey || '').toLowerCase() === key) || null;
  const nowLcl = Number(currentLcl) || 0;
  const observedAtLcl = Number(rec && rec.observedAtLcl) || 0;
  const candidateLcl = Number(rec && rec.candidateLcl) || 0;
  const age = nowLcl && observedAtLcl ? nowLcl - observedAtLcl : Number.POSITIVE_INFINITY;
  const currentLag = nowLcl && candidateLcl ? nowLcl - candidateLcl : Number.POSITIVE_INFINITY;
  const exactAtObservation = !!(rec && cleanString(rec.voteStatus || '', 32).toLowerCase() === 'synced' && Number(rec.candidateLag) === 0);
  const heartbeats = Math.max(0, Number(rec && rec.admissionSyncHeartbeats) || 0);
  const ready = !!(exactAtObservation && heartbeats >= ADMISSION_SYNC_REQUIRED_HEARTBEATS &&
    age >= 0 && age <= ADMISSION_SYNC_OBSERVATION_FRESH_LCLS &&
    currentLag >= 0 && currentLag <= ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL);
  return {
    ready, rec, heartbeats, exactAtObservation, age,
    currentLag:Number.isFinite(currentLag) ? currentLag : null,
    voteStatus:cleanString(rec && rec.voteStatus || '',32).toLowerCase() || null,
    candidateLag:rec && rec.candidateLag != null ? Number(rec.candidateLag) : null
  };
}

function normalizeRecentLedgers(raw) {
  if (!Array.isArray(raw)) return [];
  const byLcl = new Map();
  for (const x of raw) {
    const lcl = Number(x && x.lcl) || 0;
    const hash = cleanString(x && x.hash || '', 256).toLowerCase();
    if (lcl > 0 && hash) byLcl.set(lcl, { lcl, hash });
  }
  return [...byLcl.values()].sort((a,b)=>a.lcl-b.lcl).slice(-RECENT_LEDGER_PROOF_WINDOW);
}

let BUILD_FINGERPRINT_CACHE = null;
function localBuildFingerprint() {
  if (BUILD_FINGERPRINT_CACHE) return BUILD_FINGERPRINT_CACHE;
  const h = crypto.createHash('sha256');
  for (const name of ['index.js','sidedish.js','cluster-controller.js']) {
    // Runtime-package contract versions live under contract-versions/<id>/ and
    // deliberately do not copy the protected index.js bootloader into that
    // directory. Hash version-local contract files when present, but fall back
    // to the HotPocket state root for protected/base files such as index.js.
    const local = path.resolve(__dirname, name);
    const root = path.resolve(process.cwd(), name);
    const file = fs.existsSync(local) ? local : root;
    h.update(name); h.update('\0'); h.update(fs.readFileSync(file)); h.update('\0');
  }
  BUILD_FINGERPRINT_CACHE = h.digest('hex');
  return BUILD_FINGERPRINT_CACHE;
}
function rememberCurrentLedger(state, hpContext, localIsUnl = true) {
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const hash = cleanString(hpContext && hpContext.lclHash || '', 256).toLowerCase();
  if (!lcl || !hash) return false;

  // BOOTSTRAP QUIESCENCE RULE:
  // canonical ledger witnesses are node-local runtime evidence, not contract
  // state. During growth every CURRENT UNL validator records the same committed
  // LCL/hash outside the HotPocket state tree. Non-UNL followers never write this
  // witness. This lets signed candidate reports be checked against canonical
  // history without changing the replicated /state hash every ledger.
  const maintainLocalWitness = !!localIsUnl || !state || state.phase === 'autonomous' || hpContext.publicKey === state.bootstrapPubkey;
  if (maintainLocalWitness) {
    const local = readJson(LOCAL_RECENT_LEDGERS_FILE, null);
    const localBefore = normalizeRecentLedgers(local && local.recentLedgers);
    const localNext = normalizeRecentLedgers([...localBefore, { lcl, hash }]);
    if (JSON.stringify(localBefore) !== JSON.stringify(localNext)) {
      try { fs.mkdirSync(LOCAL_AUTOCLUSTER_ROOT, { recursive:true }); } catch {}
      writeJson(LOCAL_RECENT_LEDGERS_FILE, { schema:2, updatedAtLcl:lcl, recentLedgers:localNext });
    }
  }

  // Legacy autonomous recovery may still use the replicated ring. Fresh growth
  // MUST NOT: a per-ledger ring in autocluster.state.json makes /state a moving
  // target forever and prevents pre-UNL HPFS followers from settling.
  if (!localIsUnl || !state || state.phase !== 'autonomous') return false;
  const before = normalizeRecentLedgers(state.recentLedgers);
  const next = normalizeRecentLedgers([...before, { lcl, hash }]);
  const changed = JSON.stringify(before) !== JSON.stringify(next);
  state.recentLedgers = next;
  return changed;
}
function normalizePromotionBatch(raw) {
  if (!raw || typeof raw !== 'object') return null;
  return {
    active: raw.active === true,
    armedAtLcl: Number(raw.armedAtLcl) || null,
    submittedAtLcl: Number(raw.submittedAtLcl) || null,
    submittedPubkey: /^ed[0-9a-f]{64}$/i.test(cleanString(raw.submittedPubkey || '',256)) ? cleanString(raw.submittedPubkey,256).toLowerCase() : null,
    pubkeys: normalizePubkeyList(raw.pubkeys),
    lastFinalProofAtLcl: Number(raw.lastFinalProofAtLcl) || null,
    admissionGraceUntilLcl: Number(raw.admissionGraceUntilLcl) || null,
    skipPubkey: /^ed[0-9a-f]{64}$/i.test(cleanString(raw.skipPubkey || '',256)) ? cleanString(raw.skipPubkey,256).toLowerCase() : null,
    skipUntilLcl: Number(raw.skipUntilLcl) || null,
    reason: cleanString(raw.reason || 'prepared-candidate-batch', 160)
  };
}

function normalizePromotionPeerWarmup(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const mode = cleanString(raw.mode || '', 64);
  const startedAtMs = Number(raw.startedAtMs) || null;
  const startedAtLcl = Number(raw.startedAtLcl) || null;

  // Upgrade safety: discard any persisted legacy atomic 1->3 warmup. Fresh
  // bootstrap now stages exactly one candidate, so carrying the pair forward could
  // revive a multi-add transport plan after upgrade.
  if (mode === 'atomic-bootstrap-1to3') return null;

  // Legacy/steady-state one-candidate peer warmup.
  const pubkey = cleanString(raw.pubkey || '', 256).toLowerCase();
  const endpoint = canonicalLivePeer(raw.endpoint);
  if (!/^ed[0-9a-f]{64}$/i.test(pubkey) || !endpoint) return null;
  return { pubkey, endpoint, startedAtMs, startedAtLcl };
}

function normalizePromotionTransition(raw) {
  if (!raw || typeof raw !== 'object' || raw.active !== true) return null;
  const pubkey = cleanString(raw.pubkey || '', 256);
  if (!pubkey) return null;
  const phase = ['lowering-threshold','ready-to-stitch','membership-submitted','awaiting-active','active-confirmed','restoring-threshold'].includes(raw.phase)
    ? raw.phase : 'lowering-threshold';
  return {
    active: true,
    pubkey,
    phase,
    mode: cleanString(raw.mode || '', 64) || null,
    fromUnlSize: int(raw.fromUnlSize, 1, 1, 64),
    toUnlSize: int(raw.toUnlSize, 2, 2, 64),
    transitionThreshold: int(raw.transitionThreshold, 50, 1, 100),
    normalThreshold: int(raw.normalThreshold, DEFAULT_CONSENSUS_THRESHOLD, 1, 100),
    startedAtLcl: Number(raw.startedAtLcl) || null,
    thresholdAppliedAtLcl: Number(raw.thresholdAppliedAtLcl) || null,
    membershipSubmittedAtLcl: Number(raw.membershipSubmittedAtLcl) || null,
    membershipObservedAtLcl: Number(raw.membershipObservedAtLcl) || null,
    activeObservedAtLcl: Number(raw.activeObservedAtLcl) || null,
    restoredAtLcl: Number(raw.restoredAtLcl) || null
  };
}

function contractConfigSection(cfg) {
  return cfg && cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : cfg;
}
function readConsensusThreshold(cfg) {
  const c = contractConfigSection(cfg) || {};
  const n = Number(c.consensus && c.consensus.threshold);
  return Number.isInteger(n) && n >= 1 && n <= 100 ? n : DEFAULT_CONSENSUS_THRESHOLD;
}
function setConsensusThreshold(cfg, threshold) {
  const c = contractConfigSection(cfg);
  if (!c || typeof c !== 'object') throw new Error('HotPocket contract config is unavailable.');
  c.consensus = c.consensus && typeof c.consensus === 'object' ? c.consensus : {};
  c.consensus.threshold = int(threshold, DEFAULT_CONSENSUS_THRESHOLD, 1, 100);
  return cfg;
}
function readContractUnlFromConfig(cfg) {
  const c = contractConfigSection(cfg) || {};
  return normalizePubkeyList(Array.isArray(c.unl) ? c.unl : []);
}
function setContractUnl(cfg, pubkeys) {
  const c = contractConfigSection(cfg);
  if (!c || typeof c !== 'object') throw new Error('HotPocket contract config is unavailable.');
  c.unl = normalizePubkeyList(pubkeys);
  return cfg;
}
function jsonDiffPaths(a, b, prefix = '', out = []) {
  if (a === b) return out;
  const aa = Array.isArray(a), bb = Array.isArray(b);
  if (aa || bb) {
    if (JSON.stringify(a) !== JSON.stringify(b)) out.push(prefix || '$');
    return out;
  }
  const ao = a && typeof a === 'object', bo = b && typeof b === 'object';
  if (!ao || !bo) { out.push(prefix || '$'); return out; }
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  for (const k of keys) jsonDiffPaths(a[k], b[k], prefix ? `${prefix}.${k}` : k, out);
  return out;
}

function requiredVotesForThreshold(unlSize, threshold) {
  const n = Math.max(1, Number(unlSize) || 1);
  const pct = int(threshold, DEFAULT_CONSENSUS_THRESHOLD, 1, 100);
  return Math.max(1, Math.ceil(n * pct / 100));
}
function signerMatchedBootstrapThreshold(state) {
  // AutoCluster uses the SAME quorum ratio for HotPocket consensus as the managed
  // Xahau signer set. Bootstrap A is temporary infrastructure and is deliberately
  // excluded from the denominator. Example: signerQuorum=3, targetManagedNodes=5
  // => floor(3/5*100)=60%.
  const target = Math.max(1, Number(state && state.targetManagedNodes) || 1);
  const quorum = Math.max(1, Math.min(target, Number(state && state.signerQuorum) || 1));
  return Math.max(1, Math.min(100, Math.floor((quorum * 100) / target)));
}
function thresholdForRequiredVotes(requiredVotes, unlSize) {
  const n = Math.max(1, Number(unlSize) || 1);
  const votes = Math.max(1, Math.min(n, Number(requiredVotes) || 1));
  // Smallest integer percentage whose ceil(n*pct/100) is `votes`.
  if (votes <= 1) return 1;
  return Math.max(1, Math.min(100, Math.floor((votes - 1) * 100 / n) + 1));
}
function bootstrapGrowthThreshold(targetUnlSize, normalThreshold) {
  const target = Math.max(2, Number(targetUnlSize) || 2);
  const normal = int(normalThreshold, DEFAULT_CONSENSUS_THRESHOLD, 1, 100);
  const finalVotes = requiredVotesForThreshold(target, normal);
  const finalEquivalentFloor = thresholdForRequiredVotes(finalVotes, target);
  // >=66% prevents the 2-node split-brain hole. Raising this floor when needed
  // also guarantees that, at the final target size, restoring `normal` cannot
  // increase the integer vote requirement.
  return Math.max(MIN_BOOTSTRAP_GROWTH_THRESHOLD, finalEquivalentFloor);
}
function safeExpansionThreshold(fromUnlSize, toUnlSize) {
  const from = Math.max(1, Number(fromUnlSize) || 1);
  const to = Math.max(from + 1, Number(toUnlSize) || (from + 1));
  // Used only outside initial bootstrap growth (normally autonomous 4->5 repair).
  // Never permit a <=50% dynamic quorum.
  return Math.max(51, Math.min(100, Math.floor(from * 100 / to)));
}

function normalizeCandidateWatchdogs(raw) {
  if (!Array.isArray(raw)) return [];
  const byKey = new Map();
  for (const x of raw) {
    const pubkey = cleanString(x && x.pubkey || '', 256);
    if (!pubkey) continue;
    const rec = {
      pubkey,
      host: normalizeHostAddress(x && x.host),
      firstSeenAt: Number(x && x.firstSeenAt) || null,
      firstSeenLcl: Number(x && x.firstSeenLcl) || null,
      materializedAt: Number(x && (x.materializedAt || x.firstSeenAt)) || null,
      materializedAtLcl: Number(x && (x.materializedAtLcl || x.firstSeenLcl)) || null,
      refId: cleanString(x && x.refId || '', 256) || null,
      stalledAt: Number(x && x.stalledAt) || null,
      stalledAtLcl: Number(x && x.stalledAtLcl) || null,
      staleSinceAt: Number(x && x.staleSinceAt) || null,
      staleSinceLcl: Number(x && x.staleSinceLcl) || null,
      finalizationQualifiedAt: Number(x && x.finalizationQualifiedAt) || null,
      finalizationQualifiedAtLcl: Number(x && x.finalizationQualifiedAtLcl) || null,
      finalizationGraceUntilAt: Number(x && x.finalizationGraceUntilAt) || null,
      kickedAt: Number(x && x.kickedAt) || null
    };
    const old = byKey.get(pubkey);
    if (!old || Number(rec.firstSeenAt || 0) >= Number(old.firstSeenAt || 0)) byKey.set(pubkey, rec);
  }
  return [...byKey.values()].sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
}


function normalizeCandidateDiagnostics(raw) {
  if (!Array.isArray(raw)) return [];
  const byKey = new Map();
  for (const x of raw) {
    const pubkey = cleanString(x && x.pubkey || '', 256);
    if (!pubkey) continue;
    const rec = {
      pubkey,
      host: normalizeHostAddress(x && x.host),
      observedAtLcl: Number(x && x.observedAtLcl) || null,
      candidateLcl: Number(x && x.candidateLcl) || null,
      candidateHash: cleanString(x && x.candidateHash || '', 256) || null,
      canonicalAtObservation: !!(x && x.canonicalAtObservation),
      localNodePresent: !!(x && x.localNodePresent),
      localIsUnl: !!(x && x.localIsUnl),
      localSharedStatus: cleanString(x && x.localSharedStatus || '', 64) || null,
      privateStatus: cleanString(x && x.privateStatus || '', 64) || null,
      nodeRole: cleanString(x && x.nodeRole || '', 32).toLowerCase() || null,
      bootstrapSharedStatus: cleanString(x && x.bootstrapSharedStatus || '', 64) || null,
      bootstrapIsUnl: !!(x && x.bootstrapIsUnl),
      buildFingerprint: cleanString(x && x.buildFingerprint || '', 256) || null
    };
    const old = byKey.get(pubkey);
    if (!old || Number(rec.observedAtLcl || 0) >= Number(old.observedAtLcl || 0)) byKey.set(pubkey, rec);
  }
  return [...byKey.values()].sort((a,b)=>a.pubkey.localeCompare(b.pubkey)).slice(-64);
}

function normalizeMaturitySignals(raw) {
  if (!Array.isArray(raw)) return [];
  const byKey = new Map();
  for (const x of raw) {
    const pubkey = cleanString(x && x.pubkey || '', 256);
    if (!pubkey) continue;
    const rec = {
      pubkey,
      host: normalizeHostAddress(x && x.host),
      firstReceivedAtLcl: Number(x && x.firstReceivedAtLcl) || null,
      lastReceivedAtLcl: Number(x && x.lastReceivedAtLcl) || null,
      count: Math.max(1, Number(x && x.count) || 1),
      sharedStatusAtLastReceive: cleanString(x && x.sharedStatusAtLastReceive || '', 64) || null
    };
    const old = byKey.get(pubkey);
    if (!old || Number(rec.lastReceivedAtLcl || 0) >= Number(old.lastReceivedAtLcl || 0)) byKey.set(pubkey, rec);
  }
  return [...byKey.values()].sort((a,b)=>a.pubkey.localeCompare(b.pubkey)).slice(-64);
}

function normalizeQueuedSigner(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const nodePubkey = cleanString(raw.nodePubkey || '', 256);
  const signerAddress = normalizeHostAddress(raw.signerAddress);
  if (!nodePubkey || !signerAddress) return null;
  return {
    nodePubkey,
    signerAddress,
    hash: cleanString(raw.hash || '', 256) || null,
    lastLedgerSequence: Number(raw.lastLedgerSequence) || null,
    queuedAtLcl: Number(raw.queuedAtLcl) || null,
    lastObservedAtLcl: Number(raw.lastObservedAtLcl) || null,
    resultCode: cleanString(raw.resultCode || 'terQUEUED', 64) || 'terQUEUED'
  };
}


function normalizeValidatorRecords(raw) {
  const source = Array.isArray(raw) ? raw : [];
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const publicKey = cleanString(item && (item.publicKey || item.pubkey) || '', 256);
    if (!publicKey || seen.has(publicKey)) continue;
    seen.add(publicKey);
    const health = ['healthy','suspect','dead','unknown','candidate','retired'].includes(item && item.health) ? item.health : 'unknown';
    out.push({
      publicKey,
      hostAddress: normalizeHostAddress(item && (item.hostAddress || item.host)),
      refId: cleanString(item && item.refId || '', 256) || null,
      domain: normalizeEndpointHost(item && item.domain),
      peerPort: validPort(item && (item.peerPort || item.meshPort)),
      userPort: validPort(item && item.userPort),
      gpTcp1Port: validPort(item && (item.gpTcp1Port || item.gpTcpPort || item.gptcp1 || item.gp_tcp_port || item.gp_tcp1_port)),
      gpUdp1Port: validPort(item && (item.gpUdp1Port || item.gpUdpPort || item.gpudp1 || item.gp_udp_port || item.gp_udp1_port)),
      signerAddress: normalizeHostAddress(item && item.signerAddress),
      isUnl: !!(item && item.isUnl),
      present: item && item.present === false ? false : true,
      maturityStatus: cleanString(item && item.maturityStatus || '', 64) || null,
      health,
      activeOnLcl: Number(item && item.activeOnLcl) || null,
      createdOnTimestamp: Number(item && item.createdOnTimestamp) || null,
      lifeMoments: Number.isFinite(Number(item && item.lifeMoments)) ? Number(item.lifeMoments) : null,
      targetLifeMoments: Number.isFinite(Number(item && item.targetLifeMoments)) ? Number(item.targetLifeMoments) : null,
      maxLifeMoments: Number.isFinite(Number(item && item.maxLifeMoments)) ? Number(item.maxLifeMoments) : null,
      firstSeenAt: Number(item && item.firstSeenAt) || null,
      firstSeenLcl: Number(item && item.firstSeenLcl) || null,
      lastUpdatedAt: Number(item && item.lastUpdatedAt) || null,
      lastUpdatedLcl: Number(item && item.lastUpdatedLcl) || null,
      retiredAt: Number(item && item.retiredAt) || null,
      retiredAtLcl: Number(item && item.retiredAtLcl) || null
    });
    if (out.length >= 64) break;
  }
  return out;
}

function normalizeMaintenance(raw, targetManagedNodes = 5) {
  raw = raw && typeof raw === 'object' ? raw : {};
  const health = Array.isArray(raw.health) ? raw.health.map(x => ({
    pubkey: cleanString(x && x.pubkey || '', 256),
    host: normalizeHostAddress(x && x.host),
    status: ['healthy','suspect','dead','unknown'].includes(x && x.status) ? x.status : 'unknown',
    activeOnLcl: Number(x && x.activeOnLcl) || null,
    lastObservedLcl: Number(x && x.lastObservedLcl) || null,
    suspectSinceAt: Number(x && x.suspectSinceAt) || null,
    deadSinceAt: Number(x && x.deadSinceAt) || null
  })).filter(x => x.pubkey).slice(0, 32) : [];
  let repair = null;
  if (raw.repair && typeof raw.repair === 'object') {
    const deadPubkey = cleanString(raw.repair.deadPubkey || '', 256);
    if (deadPubkey) repair = {
      active: raw.repair.active !== false,
      phase: cleanString(raw.repair.phase || 'replacement-needed', 96),
      deadPubkey,
      deadHost: normalizeHostAddress(raw.repair.deadHost),
      startedAt: Number(raw.repair.startedAt) || null,
      startedAtLcl: Number(raw.repair.startedAtLcl) || null,
      baselineUnlPubkeys: normalizePubkeyList(raw.repair.baselineUnlPubkeys),
      replacementPubkey: cleanString(raw.repair.replacementPubkey || '', 256) || null,
      replacementHost: normalizeHostAddress(raw.repair.replacementHost),
      lastUpdatedAt: Number(raw.repair.lastUpdatedAt) || null,
      lastError: cleanString(raw.repair.lastError || '', 768) || null
    };
  }
  return {
    enabled: raw.enabled !== false,
    targetManagedNodes: int(raw.targetManagedNodes, targetManagedNodes, 1, 16),
    signerQuorum: int(raw.signerQuorum, Math.max(1, Math.floor(targetManagedNodes / 2) + 1), 1, targetManagedNodes),
    healthTimeoutMs: int(raw.healthTimeoutMs, AUTONOMOUS_DEAD_TIMEOUT_MS, 60000, 60 * 60 * 1000),
    suspectAfterLcl: int(raw.suspectAfterLcl, AUTONOMOUS_HEALTH_SUSPECT_LCL, 2, 10000),
    health,
    repair,
    lastHealthyAt: Number(raw.lastHealthyAt) || null,
    lastHealthyLcl: Number(raw.lastHealthyLcl) || null,
    lastAction: cleanString(raw.lastAction || '', 256) || null
  };
}

function normalizeBootstrapReplacement(raw) {
  if (!raw || typeof raw !== 'object' || raw.active !== true) return null;
  const failedPubkey = cleanString(raw.failedPubkey || '', 256);
  return {
    active:true,
    failedPubkey: failedPubkey || null,
    failedHost: normalizeHostAddress(raw.failedHost),
    startedAtLcl: Number(raw.startedAtLcl) || null,
    baselinePubkeys: normalizePubkeyList(raw.baselinePubkeys),
    reason: cleanString(raw.reason || 'readiness-stalled', 128) || 'readiness-stalled'
  };
}

function normalizeBootstrapMeshOverride(raw) {
  if (!raw || typeof raw !== 'object' || raw.active !== true) return null;
  const forcedPubkey = cleanString(raw.forcedPubkey || '', 256).toLowerCase();
  return {
    active:true,
    armedAtLcl:Number(raw.armedAtLcl) || null,
    forcedPubkey:/^ed[0-9a-f]{64}$/i.test(forcedPubkey) ? forcedPubkey : null,
    proofObservedAtLcl:Number(raw.proofObservedAtLcl) || null,
    proofCandidateLcl:Number(raw.proofCandidateLcl) || null,
    proofCandidateHash:cleanString(raw.proofCandidateHash || '', 256).toLowerCase() || null,
    bypassAll:raw.bypassAll === true,
    reason:cleanString(raw.reason || 'operator-force-add-best-now', 160) || 'operator-force-add-best-now'
  };
}

// Bootstrap membership is changed only by an authenticated HotPocket user input.
// The replicated controller may prepare an intent, but it never mutates contract.unl
// autonomously. Bootstrap A's root-side control-plane user submits the intent back
// through HotPocket, so every CURRENT UNL validator receives the same command as a
// normal consensus input before ctx.updateConfig() is called.
function normalizeMembershipCommand(raw) {
  if (!raw || typeof raw !== 'object' || raw.active !== true) return null;
  const operation = cleanString(raw.operation || raw.op || '', 32).toLowerCase();
  const pubkey = cleanString(raw.pubkey || raw.publicKey || '', 256).toLowerCase();
  if (!['add','remove-bootstrap','swap-bootstrap','demote-managed'].includes(operation) || !/^ed[0-9a-f]{64}$/i.test(pubkey)) return null;
  return {
    active:true,
    operation,
    pubkey,
    requestedAtLcl:Number(raw.requestedAtLcl) || null,
    submittedAtLcl:Number(raw.submittedAtLcl) || null,
    proofObservedAtLcl:Number(raw.proofObservedAtLcl) || null,
    proofCandidateLcl:Number(raw.proofCandidateLcl) || null,
    proofCandidateHash:cleanString(raw.proofCandidateHash || '', 256).toLowerCase() || null,
    maturityStatus:cleanString(raw.maturityStatus || '', 64).toLowerCase() || null,
    syncObservedAtLcl:Number(raw.syncObservedAtLcl) || null,
    syncCandidateLcl:Number(raw.syncCandidateLcl) || null,
    syncCandidateHash:cleanString(raw.syncCandidateHash || '', 256).toLowerCase() || null,
    reason:cleanString(raw.reason || '', 240) || null
  };
}
function makeBootstrapAddMembershipCommand(state, node, lcl, reason) {
  const pubkey = cleanString(node && node.pubkey || '', 256).toLowerCase();
  const ready = normalizeCandidateReadiness(state && state.candidateReadiness)
    .find(r => String(r.pubkey || '').toLowerCase() === pubkey) || null;
  return {
    active:true, operation:'add', pubkey,
    requestedAtLcl:Number(lcl) || null, submittedAtLcl:null,
    proofObservedAtLcl:Number(ready && ready.observedAtLcl) || null,
    proofCandidateLcl:Number(ready && ready.candidateLcl) || null,
    proofCandidateHash:cleanString(ready && ready.candidateHash || '', 256).toLowerCase() || null,
    maturityStatus:diskNodeStatus(node),
    syncObservedAtLcl:Number(syncQuiescenceStatus(state, pubkey, lcl).rec && syncQuiescenceStatus(state, pubkey, lcl).rec.observedAtLcl) || null,
    syncCandidateLcl:Number(syncQuiescenceStatus(state, pubkey, lcl).rec && syncQuiescenceStatus(state, pubkey, lcl).rec.candidateLcl) || null,
    syncCandidateHash:cleanString(syncQuiescenceStatus(state, pubkey, lcl).rec && syncQuiescenceStatus(state, pubkey, lcl).rec.candidateHash || '', 256).toLowerCase() || null,
    reason:cleanString(reason || '', 240) || null
  };
}

function normalize(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const priorSchema = Number(raw.schema) || 0;
  const legacyMaturityHosts = new Set((Array.isArray(raw.hostQueue) ? raw.hostQueue : []).filter(h => h && (h.status === 'maturity-stalled' || (h.status === 'auto-kicked' && /without reaching MATURED\/ACKNOWLEDGED/i.test(String(h.lastError || ''))))).map(h => normalizeHostAddress(h.address)).filter(Boolean));
  const target = int(raw.targetManagedNodes, 5, 1, 16);
  const network = ['mainnet', 'testnet', 'devnet'].includes(raw.network) ? raw.network : 'mainnet';
  const rpcPools = normalizeRpcPools(raw.rpcPools, raw.rippleServer, network);
  return {
    schema: 32,
    enabled: raw.enabled !== false,
    phase: cleanString(raw.phase || 'growing', 64),
    network,
    rpcPools,
    rippleServer: rpcPools.xahau[0]?.url || cleanString(raw.rippleServer || '', 512) || null,
    clusterAddress: cleanString(raw.clusterAddress, 128),
    bootstrapPubkey: cleanString(raw.bootstrapPubkey, 256),
    bootstrapSignerAddress: cleanString(raw.bootstrapSignerAddress, 128),
    bootstrapEndpoint: normalizeBootstrapEndpoint(raw),
    readyControllerPublicKey: /^ed[0-9a-f]{64}$/i.test(cleanString(raw.readyControllerPublicKey || '',80)) ? cleanString(raw.readyControllerPublicKey,80).toLowerCase() : null,
    targetManagedNodes: target,
    signerQuorum: int(raw.signerQuorum, Math.max(1, Math.floor(target / 2) + 1), 1, target),
    managedImage: cleanString(raw.managedImage, 512),
    maxLeaseAmountEvrPerMoment: num(raw.maxLeaseAmountEvrPerMoment, 0, 0, 1000000),
    lifeIncrMomentMinLimit: int(raw.lifeIncrMomentMinLimit, 2, 1, 96),
    maxLifeMomentLimit: int(raw.maxLifeMomentLimit, 0, 0, 100000),
    parallelGrow: bool(raw.parallelGrow, false),
    preferredHosts: Array.isArray(raw.preferredHosts) ? raw.preferredHosts.map(v => cleanString(v, 128)).filter(Boolean).slice(0, 256) : [],
    hostQueue: normalizeHostQueue(raw.hostQueue, raw.preferredHosts),
    activeHostAttempt: normalizeHostAddress(raw.activeHostAttempt),
    waitingForHosts: bool(raw.waitingForHosts, false),
    nextAcquireAfterLcl: Number(raw.nextAcquireAfterLcl) || null,
    maturityLclThreshold: int(raw.maturityLclThreshold, 2, 1, 1000),
    acknowledgeLclThreshold: int(raw.acknowledgeLclThreshold, 2, 1, 1000),
    candidateReadyTimeoutMs: int(raw.candidateReadyTimeoutMs, DEFAULT_CANDIDATE_READY_TIMEOUT_MS, 30 * 1000, 30 * 60 * 1000),
    candidateAdmissionTimeoutMs: int(raw.candidateAdmissionTimeoutMs, DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS, MIN_CANDIDATE_ADMISSION_TIMEOUT_MS, MAX_CANDIDATE_ADMISSION_TIMEOUT_MS),
    candidatePoolSize: int(raw.candidatePoolSize, DEFAULT_CANDIDATE_POOL_SIZE, 1, MAX_CANDIDATE_POOL_SIZE),
    candidateSpeculativeAcquireDelayMs: int(raw.candidateSpeculativeAcquireDelayMs, DEFAULT_CANDIDATE_SPECULATIVE_ACQUIRE_DELAY_MS, 30 * 1000, 15 * 60 * 1000),
    candidateReadyStaleGraceMs: int(raw.candidateReadyStaleGraceMs, DEFAULT_CANDIDATE_READY_STALE_GRACE_MS, 15 * 1000, 10 * 60 * 1000),
    readyProbeUnreachableTimeoutMs: int(raw.readyProbeUnreachableTimeoutMs, DEFAULT_READY_PROBE_UNREACHABLE_TIMEOUT_MS, 15 * 1000, 10 * 60 * 1000),
    evernodeMomentSizeSeconds: num(raw.evernodeMomentSizeSeconds, 0, 0, 1000000000),
    endpointGrace: [], // schema 21: legacy contract-side WSS gate removed; bootstrap admission is atomic
    unlSnapshot: normalizePubkeyList(raw.unlSnapshot),
    stabilization: normalizeStabilization(raw.stabilization),
    // schema <11 may contain weak MATURED-derived readiness from alpha.37.4-.37.8.
    // Never carry those proofs into the strong ledger-sync admission gate.
    candidateReadiness: priorSchema >= 11 ? normalizeCandidateReadiness(raw.candidateReadiness) : [],
    candidateSyncQuiescence: normalizeCandidateSyncQuiescence(raw.candidateSyncQuiescence),
    // During bootstrap this field is deliberately empty. The per-node ledger
    // witness lives in ../autocluster-local/recent-ledgers.json so a lagging
    // follower cannot alter consensus state merely by recording its own LCL.
    recentLedgers: cleanString(raw.phase || 'growing', 64) === 'growing' ? [] : normalizeRecentLedgers(raw.recentLedgers),
    candidateWatchdogs: normalizeCandidateWatchdogs(raw.candidateWatchdogs).filter(w => !(priorSchema < 18 && w.host && legacyMaturityHosts.has(w.host))),
    candidateDiagnostics: normalizeCandidateDiagnostics(raw.candidateDiagnostics),
    maturitySignals: normalizeMaturitySignals(raw.maturitySignals),
    promotionBatch: priorSchema >= 11 ? normalizePromotionBatch(raw.promotionBatch) : null,
    promotionTransition: normalizePromotionTransition(raw.promotionTransition),
    membershipCommand: normalizeMembershipCommand(raw.membershipCommand),
    bootstrapReplacement: normalizeBootstrapReplacement(raw.bootstrapReplacement),
    bootstrapMeshOverride: cleanString(raw.phase || 'growing', 64) === 'growing' ? normalizeBootstrapMeshOverride(raw.bootstrapMeshOverride) : null,
    promotionPeerWarmup: normalizePromotionPeerWarmup(raw.promotionPeerWarmup),
    bootstrapNormalConsensusThreshold: Number(raw.bootstrapNormalConsensusThreshold) >= 1 && Number(raw.bootstrapNormalConsensusThreshold) <= 100 ? Number(raw.bootstrapNormalConsensusThreshold) : null,
    bootstrapGrowthConsensusThreshold: Number(raw.bootstrapGrowthConsensusThreshold) >= 1 && Number(raw.bootstrapGrowthConsensusThreshold) <= 100 ? Number(raw.bootstrapGrowthConsensusThreshold) : null,
    queuedSigner: normalizeQueuedSigner(raw.queuedSigner),
    validators: normalizeValidatorRecords(raw.validators),
    maintenance: normalizeMaintenance(raw.maintenance, target),
    blocker: normalizeBlocker(raw.blocker),
    handoverPreparedAtLcl: Number(raw.handoverPreparedAtLcl) || Number(raw.masterHandoverConfirmedAtLcl) || null,
    masterHandoverConfirmedAtLcl: Number(raw.masterHandoverConfirmedAtLcl) || null, // legacy alpha<=38 field; no longer gates A removal
    handoverSignerPubkeys: normalizePubkeyList(raw.handoverSignerPubkeys),
    finalInventoryFingerprint: cleanString(raw.finalInventoryFingerprint || '', 128) || null,
    finalInventoryAtLcl: Number(raw.finalInventoryAtLcl) || null,
    createdAt: Number(raw.createdAt) || null,
    handoverObservedAtLcl: Number(raw.handoverObservedAtLcl) || null,
    autonomousAtLcl: Number(raw.autonomousAtLcl) || null
  };
}
function loadState() { return normalize(readJson(STATE_FILE, null) || readJson(LEGACY_STATE_FILE, null)); }
function saveState(state) { return writeJson(STATE_FILE, state); }
function isConfigured() {
  const s = loadState();
  return !!(s && s.enabled && s.clusterAddress && s.bootstrapPubkey && s.managedImage);
}
function addHosts(addresses, lcl = null, liveState = null) {
  const state = liveState || loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  const list = Array.isArray(addresses) ? addresses : String(addresses || '').split(/[\s,]+/);
  const existing = new Map(state.hostQueue.map(h => [h.address, h]));
  const added = [], reset = [];
  for (const raw of list) {
    const address = normalizeHostAddress(raw);
    if (!address) throw new Error(`Invalid Evernode host r-address: ${cleanString(raw, 80)}`);
    const old = existing.get(address);
    if (old) {
      if (['failed','price-rejected','funding-wait','dropped','removed'].includes(old.status)) {
        old.status = 'queued'; old.lastError = null; old.refId = null; old.pendingSinceAt = null; old.pendingSinceLcl = null; reset.push(address);
      }
      continue;
    }
    const entry = { address, status: 'queued', attempts: 0, addedAtLcl: Number(lcl) || null, lastAttemptLcl: null, pendingSinceAt: null, pendingSinceLcl: null, lastError: null, lastObservedLeaseAmount: null, refId: null };
    state.hostQueue.push(entry); existing.set(address, entry); added.push(address);
  }
  state.preferredHosts = state.hostQueue.map(h => h.address);
  if (added.length) state.waitingForHosts = false;
  saveState(state);
  return { added, reset, hostQueue: state.hostQueue };
}
function removeHost(address) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  const wanted = normalizeHostAddress(address);
  if (!wanted) throw new Error('Invalid Evernode host r-address.');
  const item = state.hostQueue.find(h => h.address === wanted);
  if (!item) return { removed: false, hostQueue: state.hostQueue };
  if (['attempting','pending','acquired'].includes(item.status)) throw new Error(`Host ${wanted} is already ${item.status} and cannot be removed from the acquisition queue.`);
  state.hostQueue = state.hostQueue.filter(h => h.address !== wanted);
  state.preferredHosts = state.hostQueue.map(h => h.address);
  saveState(state);
  return { removed: true, hostQueue: state.hostQueue };
}
function retryFailedHosts() {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  let count = 0;
  for (const item of state.hostQueue) {
    if (['failed','price-rejected','funding-wait','dropped'].includes(item.status)) {
      const previousStatus = item.status;
      item.status = 'queued'; item.lastError = null; item.pendingSinceAt = null;
      // Keep a previous refId until the next EverPocket tick has had a chance
      // to reconcile it with acquires.json. If that refId/host is already in
      // acquiredNodes, recoverCompletedAcquisitions() restores it instead of
      // purchasing another lease. A genuinely new acquire overwrites refId.
      if (previousStatus === 'price-rejected') item.refId = null;
      count++;
    }
  }
  if (count) state.waitingForHosts = false;
  saveState(state);
  return { reset: count, hostQueue: state.hostQueue };
}

// Funding the Xahau treasury does not itself create a HotPocket contract
// execution. This operator action re-arms only hosts paused by a treasury
// funding error on the *live* AutoCluster state for the current execution.
// The ordinary tick that follows the input then retries the same host using
// the existing acquisition path; failed/price-rejected hosts are untouched.
function retryFundingWait(run) {
  if (!run || !run.state || !run.state.enabled) throw new Error('AutoCluster runtime is unavailable in this ledger.');
  const state = run.state;
  let count = 0;
  for (const item of state.hostQueue) {
    if (item && item.status === 'funding-wait') {
      item.status = 'queued';
      item.lastError = null;
      item.pendingSinceAt = null;
      count++;
    }
  }
  if (state.blocker && state.blocker.type === 'funding' && state.blocker.stage === 'acquire-node') state.blocker = null;
  if (count) {
    state.waitingForHosts = false;
    state.activeHostAttempt = null;
  }
  saveState(state);
  return { reset: count, hostQueue: state.hostQueue };
}

function persistEverPocketAcquireArrays(run) {
  const file = path.resolve(process.cwd(), 'acquires.json');
  const existing = readJson(file, {}) || {};
  existing.acquiredNodes = Array.isArray(run.evernodeContext.getAcquiredNodes()) ? run.evernodeContext.getAcquiredNodes() : [];
  existing.pendingAcquires = Array.isArray(run.evernodeContext.getPendingAcquires()) ? run.evernodeContext.getPendingAcquires() : [];
  writeJson(file, existing);
}
function removePendingAcquireRecord(run, item) {
  const pendingAcquires = typeof run.evernodeContext.getPendingAcquires === 'function' ? run.evernodeContext.getPendingAcquires() : [];
  const removed = [];
  for (let i = pendingAcquires.length - 1; i >= 0; i--) {
    const a = pendingAcquires[i];
    if (!a) continue;
    if ((item.refId && a.refId === item.refId) || a.host === item.address) {
      removed.push(a);
      pendingAcquires.splice(i, 1);
    }
  }
  for (const a of removed) {
    const messageKey = cleanString(a && a.messageKey || '', 256);
    if (messageKey) {
      const keyFile = path.resolve(process.cwd(), '..', `${messageKey}.txt`);
      try { if (fs.existsSync(keyFile)) fs.unlinkSync(keyFile); } catch (e) { console.log(`AutoCluster: could not remove abandoned acquisition key file ${messageKey}: ${errText(e)}`); }
    }
  }
  return removed;
}
function skipPendingAttempt(run, address, force = false) {
  if (!run || !run.state || !run.evernodeContext || !run.clusterContext || !run.xrplContext)
    throw new Error('AutoCluster runtime is not available for pending-attempt reconciliation.');
  const state = run.state;
  const wanted = normalizeHostAddress(address);
  if (!wanted) throw new Error('Invalid Evernode host r-address.');
  const item = hostEntry(state, wanted);
  if (!item) throw new Error(`Host ${wanted} is not in the AutoCluster queue.`);
  if (!['attempting','pending','provisioning-stalled','endpoint-stalled'].includes(item.status))
    throw new Error(`Host ${wanted} is ${item.status}; only an attempting/pending/stalled acquisition can be skipped here.`);

  const nodes = run.clusterContext.getClusterNodes();
  if (nodes.some(n => n && n.host === wanted))
    throw new Error(`Host ${wanted} has already joined the cluster. Remove/replace the cluster node instead of dropping its acquisition record.`);

  const pendingAcquires = typeof run.evernodeContext.getPendingAcquires === 'function' ? run.evernodeContext.getPendingAcquires() : [];
  const acquiredNodes = typeof run.evernodeContext.getAcquiredNodes === 'function' ? run.evernodeContext.getAcquiredNodes() : [];
  const pendingAcquire = pendingAcquires.find(a => a && ((item.refId && a.refId === item.refId) || a.host === wanted)) || null;
  const completed = acquiredNodes.find(a => a && ((item.refId && a.refId === item.refId) || a.host === wanted)) || null;
  const refId = cleanString((completed && completed.refId) || (pendingAcquire && pendingAcquire.refId) || item.refId || '', 256) || null;
  const validated = refId && typeof run.xrplContext.getValidatedTransaction === 'function' ? run.xrplContext.getValidatedTransaction(refId) : null;
  const pendingTxs = typeof run.xrplContext.getPendingTransactions === 'function' ? run.xrplContext.getPendingTransactions() : [];
  const pendingTx = refId ? pendingTxs.find(t => t && t.hash === refId) || null : null;
  const currentLedger = Number(run.xrplContext.xrplApi && run.xrplContext.xrplApi.ledgerIndex) || null;
  const sentLcl = Number((pendingAcquire && pendingAcquire.acquireSentOnLcl) || item.lastAttemptLcl) || null;
  const ageLcl = sentLcl ? Math.max(0, Number(run.hpContext.lclSeqNo || 0) - sentLcl) : null;
  const successLike = validated && ['tesSUCCESS','tefPAST_SEQ','tefALREADY'].includes(String(validated.resultCode || ''));
  const txExpired = pendingTx && currentLedger && Number(pendingTx.lastLedgerSequence) && Number(pendingTx.lastLedgerSequence) < currentLedger;
  const provenFailed = validated && !successLike;
  const neverSubmitted = !refId && !pendingAcquire && item.status === 'attempting';
  const safe = !!(provenFailed || txExpired || neverSubmitted);

  if (!force && !safe) {
    let reason;
    if (completed) reason = `EverPocket already has a completed acquisition for refId ${refId || 'unknown'}. The lease may already be paid.`;
    else if (successLike) reason = `The acquisition transaction ${refId || ''} validated with ${validated.resultCode}; dropping it would abandon a potentially paid lease.`;
    else if (pendingTx) reason = `The acquisition transaction ${refId || ''} is still within its Xahau submission window (LastLedgerSequence ${pendingTx.lastLedgerSequence || 'unknown'}, current ${currentLedger || 'unknown'}).`;
    else if (pendingAcquire) reason = `EverPocket still has acquisition ${refId || ''} pending${ageLcl != null ? ` (${ageLcl} HotPocket ledger(s) old)` : ''}, but its transaction outcome is not proven failed/expired.`;
    else reason = 'The acquisition outcome cannot be proven failed or expired from current EverPocket/Xahau state.';
    console.log(`AutoCluster: operator requested safe skip for ${wanted}, but force confirmation is required: ${reason}`);
    return { skipped:false, forceRequired:true, safe:false, address:wanted, refId, ageLcl, transactionResult:validated && validated.resultCode || null, message:`${reason} Use the force-abandon confirmation only if you accept that an already-paid lease may be left unused.` };
  }

  const manager = run.clusterContext.clusterManager;
  const clusterPending = run.clusterContext.getPendingNodes();
  const pendingRefs = clusterPending.filter(n => n && (n.host === wanted || (refId && n.refId === refId))).map(n => n.refId).filter(Boolean);
  if (manager && typeof manager.removePending === 'function') for (const r of pendingRefs) manager.removePending(r);

  const removedPending = removePendingAcquireRecord(run, item);
  let removedCompleted = 0;
  if (force) {
    for (let i = acquiredNodes.length - 1; i >= 0; i--) {
      const a = acquiredNodes[i];
      if (a && ((refId && a.refId === refId) || a.host === wanted)) { acquiredNodes.splice(i, 1); removedCompleted++; }
    }
  }
  persistEverPocketAcquireArrays(run);

  // Stop polling an explicitly abandoned, still-unvalidated transaction. Keep
  // validated transaction history as an audit trail.
  if (refId && pendingTxs.length) {
    for (let i = pendingTxs.length - 1; i >= 0; i--) if (pendingTxs[i] && pendingTxs[i].hash === refId) pendingTxs.splice(i, 1);
    const txFile = path.resolve(process.cwd(), 'transactions.json');
    const txData = readJson(txFile, {}) || {};
    txData.pending = pendingTxs;
    if (!Array.isArray(txData.validated) && typeof run.xrplContext.getValidatedTransactions === 'function') txData.validated = run.xrplContext.getValidatedTransactions();
    writeJson(txFile, txData);
  }

  item.status = 'skipped';
  item.refId = refId;
  item.lastError = force
    ? 'Operator force-abandoned this pending acquisition and continued to the next host. A paid lease may remain unused.'
    : 'Operator safely dropped this acquisition after its transaction was proven failed/expired.';
  if (state.activeHostAttempt === wanted) state.activeHostAttempt = null;
  if (Array.isArray(state.endpointGrace) && refId) state.endpointGrace = state.endpointGrace.filter(g => !g || g.refId !== refId);
  if (state.blocker && state.blocker.host === wanted) state.blocker = null;
  state.waitingForHosts = !state.hostQueue.some(h => h.status === 'queued' || h.status === 'funding-wait');
  saveState(state);
  console.log(`AutoCluster: ${force ? 'FORCE-ABANDONED' : 'safely skipped'} pending acquisition for ${wanted}${refId ? ` refId=${refId}` : ''}; next queued host may proceed immediately.`);
  return {
    skipped:true, forceRequired:false, safe:!force, forced:!!force, address:wanted, refId,
    removedPending:removedPending.length, removedCompleted,
    message: force
      ? `Abandoned ${wanted} and released AutoCluster to try the next queued host. Warning: an already-paid lease may remain unused.`
      : `Dropped stale acquisition for ${wanted}; AutoCluster can try the next queued host.`
  };
}
function setMaxLeaseAmount(value) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  const amount = num(value, NaN, 0.000000001, 1000000);
  if (!Number.isFinite(amount) || amount <= 0) throw new Error('Maximum lease cost must be greater than 0 EVR per moment.');
  state.maxLeaseAmountEvrPerMoment = amount;
  let reset = 0;
  for (const item of state.hostQueue) {
    if (item.status === 'price-rejected') { item.status = 'queued'; item.lastError = null; item.refId = null; reset++; }
  }
  if (reset) state.waitingForHosts = false;
  saveState(state);
  return { maxLeaseAmountEvrPerMoment: amount, resetPriceRejected: reset, hostQueue: state.hostQueue };
}


async function armBootstrapMeshOverride(run, requestedPubkey = null) {
  if (!run || !run.ctx || !run.hpContext || !run.clusterContext) {
    throw new Error('Force-add requires the active AutoCluster consensus runtime.');
  }
  const state = run.state || loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  if (state.phase !== 'growing') throw new Error(`Force-add is available only during growing phase; current phase=${state.phase || 'unknown'}.`);
  const requested = cleanString(requestedPubkey || '', 256).toLowerCase();
  if (requested && !/^ed[0-9a-f]{64}$/i.test(requested)) throw new Error('Force-add candidate public key is invalid.');

  const lcl = Number(run.hpContext.lclSeqNo) || Number(run.ctx.lclSeqNo) || 0;
  const cfg = await run.ctx.getConfig();
  const currentUnl = readContractUnlFromConfig(cfg);
  const bootstrap = cleanString(state.bootstrapPubkey || '', 256).toLowerCase();
  if (!bootstrap || !currentUnl.includes(bootstrap)) {
    throw new Error('FORCE ADD refused: Bootstrap A must still be present in the committed HotPocket UNL.');
  }
  const targetSize = bootstrapBridgeUnlTarget(state);
  if (currentUnl.length >= targetSize) {
    throw new Error(`FORCE ADD refused: temporary bootstrap bridge already has ${currentUnl.length}/${targetSize} validators.`);
  }

  const existingMembership = normalizeMembershipCommand(state.membershipCommand);
  if (existingMembership) {
    const alreadyCommitted = currentUnl.includes(existingMembership.pubkey);
    if (requested && existingMembership.pubkey !== requested) {
      throw new Error(`FORCE ADD refused: ${existingMembership.operation}:${existingMembership.pubkey} is already armed; wait for that membership transition to finish before selecting another candidate.`);
    }
    console.log(`AutoCluster: FORCE-ADD clicked while ${existingMembership.operation}:${cleanString(existingMembership.pubkey,24)} is already ${existingMembership.submittedAtLcl ? `submitted at LCL ${existingMembership.submittedAtLcl}` : 'armed'}. No second membership patch will be created.`);
    return {
      armed:true, alreadyArmed:true, executed:false, bypassAll:true,
      forcedPubkey:existingMembership.pubkey, membershipCommand:existingMembership,
      alreadyCommitted
    };
  }

  const nodes = run.clusterContext && typeof run.clusterContext.getClusterNodes === 'function'
    ? run.clusterContext.getClusterNodes()
    : ((readJson(path.resolve(process.cwd(), 'cluster.json'), null) || {}).nodes || []);
  const readiness = normalizeCandidateReadiness(state.candidateReadiness);
  const accepted = acceptedReadyPubkeys(state);
  const stalled = new Set(normalizeCandidateWatchdogs(state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => cleanString(w.pubkey || '', 256).toLowerCase()));

  // Emergency operator path: deterministically choose the BEST materialized
  // non-UNL candidate, but use health/ACK/READY/SYNC/mesh only as ranking hints.
  // Maturity/mesh/watchdog are ranking/policy hints on this path, but CURRENT canonical READY and runtime SYNC remain hard consensus-safety gates.
  const candidates = (Array.isArray(nodes) ? nodes : [])
    .filter(n => n && /^ed[0-9a-f]{64}$/i.test(cleanString(n.pubkey || '',256)))
    .filter(n => String(n.pubkey).toLowerCase() !== bootstrap)
    .filter(n => !currentUnl.includes(String(n.pubkey).toLowerCase()))
    .map(n => {
      const pubkey = String(n.pubkey).toLowerCase();
      const rec = readiness.find(r => String(r.pubkey || '').toLowerCase() === pubkey) || null;
      const sync = syncQuiescenceStatus(state, pubkey, lcl);
      const observed = Number(rec && rec.observedAtLcl) || 0;
      const candidateLcl = Number(rec && rec.candidateLcl) || 0;
      const observationAge = lcl && observed ? lcl - observed : Number.POSITIVE_INFINITY;
      const candidateLag = lcl && candidateLcl ? lcl - candidateLcl : Number.POSITIVE_INFINITY;
      const currentReady = !!(rec && Number(rec.readyHeartbeats || 0) >= CANDIDATE_READY_REQUIRED_HEARTBEATS &&
        observationAge >= 0 && observationAge <= ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL &&
        candidateLag >= 0 && candidateLag <= ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL &&
        /^[0-9a-f]{64}$/i.test(cleanString(rec.candidateHash || '',256)));
      return {
        node:n, pubkey, rec, sync,
        stalled:stalled.has(pubkey),
        acknowledged:diskNodeStatus(n) === 'acknowledged',
        historicalReady:accepted.has(pubkey),
        currentReady,
        peers:Math.max(0, Number(rec && rec.peerCount) || 0),
        candidateLcl
      };
    })
    .sort((a,b) =>
      (Number(!b.stalled) - Number(!a.stalled)) ||
      (Number(b.currentReady) - Number(a.currentReady)) ||
      (Number(b.acknowledged) - Number(a.acknowledged)) ||
      (Number(!!(b.sync && b.sync.ready)) - Number(!!(a.sync && a.sync.ready))) ||
      (Number(b.historicalReady) - Number(a.historicalReady)) ||
      (b.peers - a.peers) ||
      (b.candidateLcl - a.candidateLcl) ||
      a.pubkey.localeCompare(b.pubkey)
    );

  if (!candidates.length) {
    throw new Error('No materialized non-UNL managed candidate exists yet. Force-add bypasses qualification, but it still needs a real candidate public key to add.');
  }

  const chosen = requested ? candidates.find(c => c.pubkey === requested) : candidates[0];
  if (!chosen) {
    throw new Error(`Force-add target ${requested || 'candidate'} is not a materialized non-UNL managed candidate.`);
  }

  // FORCE may bypass maturity/mesh/watchdog policy, but it must NEVER bypass
  // canonical-ledger and HPFS-state safety. If either hard safety proof is not
  // current, DO NOT throw after HotPocket has already accepted the operator input.
  // Persist the exact selected candidate as a pending force intent instead. The
  // normal bootstrap tick keeps READY/SYNC probing alive and automatically
  // executes the one-key stitch as soon as BOTH hard gates are current.
  const forcedPubkey = chosen.pubkey;
  const hardGateBlockers = [];
  if (!chosen.currentReady) hardGateBlockers.push('READY');
  if (!(chosen.sync && chosen.sync.ready)) hardGateBlockers.push('SYNC');
  if (hardGateBlockers.length) {
    state.bootstrapMeshOverride = {
      active:true,
      armedAtLcl:lcl || null,
      forcedPubkey,
      proofObservedAtLcl:Number(chosen.rec && chosen.rec.observedAtLcl) || null,
      proofCandidateLcl:Number(chosen.rec && chosen.rec.candidateLcl) || null,
      proofCandidateHash:cleanString(chosen.rec && chosen.rec.candidateHash || '', 256).toLowerCase() || null,
      bypassAll:true,
      reason:`operator-force-add-pending-hard-gates:${hardGateBlockers.join('+').toLowerCase()}`
    };
    saveState(state);
    console.log(`AutoCluster: *** OPERATOR FORCE-ADD PENDING *** at LCL ${lcl || '?'} pinned candidate ${cleanString(forcedPubkey,24)}; waitingFor=[${hardGateBlockers.join(',')}]. READY=${chosen.currentReady} SYNC=${!!(chosen.sync&&chosen.sync.ready)} ACK=${chosen.acknowledged} peers=${chosen.peers}. The exact candidate will be added automatically once CURRENT canonical READY + fresh runtime SYNC are simultaneously true; no second operator click is required.`);
    return {
      armed:true,
      pending:true,
      alreadyArmed:false,
      executed:false,
      bypassAll:true,
      forcedPubkey,
      blockers:hardGateBlockers,
      currentReady:!!chosen.currentReady,
      syncReady:!!(chosen.sync && chosen.sync.ready),
      acknowledged:!!chosen.acknowledged,
      peers:chosen.peers,
      state
    };
  }
  // READY/SYNC are currently qualified, but FORCE still MUST NOT write contract.unl
  // directly. Pin the exact candidate and let the normal lockstep path arm a
  // membership intent; the root controller will take a final canonical lag<=24 proof and send
  // the ADD as a consensus user input. This makes Force and automatic admission use
  // exactly the same safe transition mechanism.
  state.bootstrapMeshOverride = {
    active:true, armedAtLcl:lcl || null, forcedPubkey,
    proofObservedAtLcl:Number(chosen.rec && chosen.rec.observedAtLcl) || null,
    proofCandidateLcl:Number(chosen.rec && chosen.rec.candidateLcl) || null,
    proofCandidateHash:cleanString(chosen.rec && chosen.rec.candidateHash || '', 256).toLowerCase() || null,
    bypassAll:true, reason:'operator-force-add-lockstep-intent'
  };
  saveState(state);
  console.log(`AutoCluster: *** OPERATOR FORCE-ADD ARMED *** at LCL ${lcl || '?'} pinned ${cleanString(forcedPubkey,24)}. No config patch was written by the button input. The normal lockstep path will arm ADD_UNL and the Bootstrap-A controller will require a final canonical-history lag<=24 proof before submitting it as a HotPocket user input.`);
  return {
    armed:true, pending:true, alreadyArmed:false, executed:false, bypassAll:true,
    forcedPubkey, blockers:[], currentReady:true, syncReady:true,
    acknowledged:!!chosen.acknowledged, peers:chosen.peers, state
  };

}

function setRuntimeSettings(raw) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster / EverPocket is not configured yet.');
  raw = raw && typeof raw === 'object' ? raw : {};
  const target = raw.targetManagedNodes === undefined ? state.targetManagedNodes : int(raw.targetManagedNodes, state.targetManagedNodes, 1, 16);
  const quorum = raw.signerQuorum === undefined ? Math.min(state.signerQuorum, target) : int(raw.signerQuorum, Math.min(state.signerQuorum, target), 1, target);
  if (!['autonomous','handover'].includes(state.phase) && quorum > target) {
    throw new Error(`Signer quorum ${quorum} cannot exceed the ${target} managed validators that will remain after Bootstrap A retires.`);
  }
  if (raw.maxLeaseAmountEvrPerMoment !== undefined) {
    const cap = num(raw.maxLeaseAmountEvrPerMoment, NaN, 0.000000001, 1000000);
    if (!Number.isFinite(cap) || cap <= 0) throw new Error('Maximum lease cost must be greater than 0 EVR per moment.');
    state.maxLeaseAmountEvrPerMoment = cap;
  }
  state.targetManagedNodes = target;
  state.signerQuorum = quorum;
  if (raw.managedImage !== undefined) { const image = cleanString(raw.managedImage, 512); if (!image) throw new Error('Managed Evernode image cannot be empty.'); state.managedImage = image; }
  if (raw.lifeIncrMomentMinLimit !== undefined) state.lifeIncrMomentMinLimit = int(raw.lifeIncrMomentMinLimit, state.lifeIncrMomentMinLimit, 1, 96);
  if (raw.maxLifeMomentLimit !== undefined) state.maxLifeMomentLimit = int(raw.maxLifeMomentLimit, state.maxLifeMomentLimit, 0, 100000);
  if (raw.parallelGrow !== undefined) state.parallelGrow = bool(raw.parallelGrow, state.parallelGrow);
  if (raw.maturityLclThreshold !== undefined) state.maturityLclThreshold = int(raw.maturityLclThreshold, state.maturityLclThreshold, 1, 1000);
  if (raw.acknowledgeLclThreshold !== undefined) state.acknowledgeLclThreshold = int(raw.acknowledgeLclThreshold, state.acknowledgeLclThreshold, 1, 1000);
  if (raw.candidateReadyTimeoutMs !== undefined) state.candidateReadyTimeoutMs = int(raw.candidateReadyTimeoutMs, state.candidateReadyTimeoutMs || DEFAULT_CANDIDATE_READY_TIMEOUT_MS, 30 * 1000, 30 * 60 * 1000);
  if (raw.candidateAdmissionTimeoutMs !== undefined) state.candidateAdmissionTimeoutMs = int(raw.candidateAdmissionTimeoutMs, state.candidateAdmissionTimeoutMs || DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS, MIN_CANDIDATE_ADMISSION_TIMEOUT_MS, MAX_CANDIDATE_ADMISSION_TIMEOUT_MS);
  if (raw.candidatePoolSize !== undefined) state.candidatePoolSize = int(raw.candidatePoolSize, state.candidatePoolSize || DEFAULT_CANDIDATE_POOL_SIZE, 1, MAX_CANDIDATE_POOL_SIZE);
  if (raw.candidateSpeculativeAcquireDelayMs !== undefined) state.candidateSpeculativeAcquireDelayMs = int(raw.candidateSpeculativeAcquireDelayMs, state.candidateSpeculativeAcquireDelayMs || DEFAULT_CANDIDATE_SPECULATIVE_ACQUIRE_DELAY_MS, 30 * 1000, 15 * 60 * 1000);
  if (raw.candidateReadyStaleGraceMs !== undefined) state.candidateReadyStaleGraceMs = int(raw.candidateReadyStaleGraceMs, state.candidateReadyStaleGraceMs || DEFAULT_CANDIDATE_READY_STALE_GRACE_MS, 15 * 1000, 10 * 60 * 1000);
  if (raw.readyProbeUnreachableTimeoutMs !== undefined) state.readyProbeUnreachableTimeoutMs = int(raw.readyProbeUnreachableTimeoutMs, state.readyProbeUnreachableTimeoutMs || DEFAULT_READY_PROBE_UNREACHABLE_TIMEOUT_MS, 15 * 1000, 10 * 60 * 1000);
  if (raw.rpcPools !== undefined || raw.rippleServer !== undefined) {
    const mergedPools = raw.rpcPools && typeof raw.rpcPools === 'object' ? { ...(state.rpcPools || {}), ...raw.rpcPools } : state.rpcPools;
    state.rpcPools = normalizeRpcPools(mergedPools, raw.rippleServer !== undefined ? raw.rippleServer : state.rippleServer, state.network);
    state.rippleServer = state.rpcPools.xahau[0]?.url || null;
  }
  const maint = normalizeMaintenance(state.maintenance, target);
  maint.targetManagedNodes = target; maint.signerQuorum = quorum;
  if (raw.healthTimeoutMs !== undefined) maint.healthTimeoutMs = int(raw.healthTimeoutMs, maint.healthTimeoutMs, 60000, 60 * 60 * 1000);
  if (raw.suspectAfterLcl !== undefined) maint.suspectAfterLcl = int(raw.suspectAfterLcl, maint.suspectAfterLcl, 2, 10000);
  state.maintenance = maint;
  saveState(state);
  return { state };
}


function setRpcPools(rawPools) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster / EverPocket is not configured yet.');
  const merged = rawPools && typeof rawPools === 'object' ? { ...(state.rpcPools || {}), ...rawPools } : (state.rpcPools || {});
  state.rpcPools = normalizeRpcPools(merged, state.rippleServer, state.network);
  state.rippleServer = state.rpcPools.xahau[0]?.url || null;
  saveState(state);
  console.log(`AutoCluster: chain RPC pools updated in consensus state (Xahau ${state.rpcPools.xahau.length}, XRPL ${state.rpcPools.xrpl.length}, Solana ${state.rpcPools.solana.length}, Stellar ${state.rpcPools.stellar.length}, Ethereum ${state.rpcPools.ethereum.length}, Bitcoin ${state.rpcPools.bitcoin.length}).`);
  return { rpcPools: state.rpcPools, xahauPrimary: state.rpcPools.xahau[0]?.url || null, xahauFallbacks: state.rpcPools.xahau.slice(1).map(x => x.url) };
}
function retryRpcPool() {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster / EverPocket is not configured yet.');
  // The current contract execution attempts AutoCluster.begin() before user
  // inputs are routed, so submitting this action itself is the immediate retry.
  // Do not erase a freshly-recorded init failure here; successful begin() clears
  // the old network blocker deterministically.
  return { rpcPools: state.rpcPools, blocker: state.blocker || null, message:'Xahau RPC pool retry execution requested.' };
}

function addValidatorViaEverPocket(hostAddress, lcl = null) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster / EverPocket is not configured yet.');
  if (state.targetManagedNodes >= 16) throw new Error('Managed validator target is already at the maximum of 16.');
  const host = normalizeHostAddress(hostAddress);
  if (!host) throw new Error('Enter a valid Evernode host r-address.');
  const q = addHosts([host], lcl);
  const eligible = q.hostQueue.find(x => x && x.address === host);
  if (!eligible || eligible.status !== 'queued') throw new Error(`Host ${host} is already ${eligible && eligible.status || 'in use'}; choose a fresh/queued Evernode host for the new validator.`);
  const next = loadState();
  next.targetManagedNodes = Math.min(16, next.targetManagedNodes + 1);
  next.maintenance = normalizeMaintenance(next.maintenance, next.targetManagedNodes);
  next.maintenance.targetManagedNodes = next.targetManagedNodes;
  next.maintenance.signerQuorum = next.signerQuorum;
  next.waitingForHosts = false;
  saveState(next);
  console.log(`AutoCluster: operator requested one additional validator through EverPocket host ${host}; managed target is now ${next.targetManagedNodes}.`);
  return { host, targetManagedNodes: next.targetManagedNodes, signerQuorum: next.signerQuorum, hostQueue: q.hostQueue };
}

function bootstrapConfig(raw, ctx) {
  raw = raw && typeof raw === 'object' ? raw : {};
  const target = int(raw.targetManagedNodes, 5, 1, 16);
  const clusterAddress = cleanString(raw.clusterAddress, 128);
  const managedImage = cleanString(raw.managedImage, 512);
  const localPubkey = cleanString(ctx && ctx.publicKey, 256);
  if (!clusterAddress || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(clusterAddress)) throw new Error('A valid cluster treasury r-address is required.');
  if (!managedImage) throw new Error('Managed Evernode image is required.');
  if (!localPubkey) throw new Error('HotPocket did not provide the bootstrap node public key.');
  if (!/^ed[0-9a-f]{64}$/i.test(cleanString(raw.readyControllerPublicKey || '',80))) throw new Error('Bootstrap READY controller public key is required. Save Cluster Settings before starting bootstrap.');
  const cap = num(raw.maxLeaseAmountEvrPerMoment, NaN, 0.000000001, 1000000);
  if (!Number.isFinite(cap) || cap <= 0) throw new Error('Maximum lease cost must be greater than 0 EVR per moment.');
  const preferredHosts = Array.isArray(raw.preferredHosts) ? raw.preferredHosts.map(normalizeHostAddress).filter(Boolean).slice(0,256) : [];
  const network = ['mainnet','testnet','devnet'].includes(raw.network) ? raw.network : 'mainnet';
  const rpcPools = normalizeRpcPools(raw.rpcPools, raw.rippleServer, network);
  return {
    schema: 29, enabled: true, phase: 'awaiting-bootstrap-signerlist',
    network,
    rpcPools,
    rippleServer: rpcPools.xahau[0]?.url || cleanString(raw.rippleServer || '', 512) || null,
    clusterAddress, bootstrapPubkey: localPubkey, bootstrapSignerAddress: null,
    bootstrapEndpoint: normalizeBootstrapEndpoint(raw),
    readyControllerPublicKey: cleanString(raw.readyControllerPublicKey,80).toLowerCase(),
    targetManagedNodes: target,
    signerQuorum: int(raw.signerQuorum, Math.max(1, Math.floor(target / 2) + 1), 1, target),
    managedImage, maxLeaseAmountEvrPerMoment: cap,
    lifeIncrMomentMinLimit: int(raw.lifeIncrMomentMinLimit, 2, 1, 96),
    maxLifeMomentLimit: int(raw.maxLifeMomentLimit, 0, 0, 100000),
    parallelGrow: bool(raw.parallelGrow, false),
    preferredHosts,
    hostQueue: preferredHosts.map(address => ({ address, status:'queued', attempts:0, addedAtLcl:Number(ctx && ctx.lclSeqNo)||null, lastAttemptLcl:null, pendingSinceAt:null, pendingSinceLcl:null, lastError:null, lastObservedLeaseAmount:null, refId:null })),
    activeHostAttempt:null, waitingForHosts: preferredHosts.length === 0,
    maturityLclThreshold:int(raw.maturityLclThreshold,2,1,1000),
    acknowledgeLclThreshold:int(raw.acknowledgeLclThreshold,2,1,1000),
    candidateReadyTimeoutMs:int(raw.candidateReadyTimeoutMs,DEFAULT_CANDIDATE_READY_TIMEOUT_MS,30 * 1000,30 * 60 * 1000),
    candidateAdmissionTimeoutMs:int(raw.candidateAdmissionTimeoutMs,DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS,MIN_CANDIDATE_ADMISSION_TIMEOUT_MS,MAX_CANDIDATE_ADMISSION_TIMEOUT_MS),
    candidatePoolSize:int(raw.candidatePoolSize,DEFAULT_CANDIDATE_POOL_SIZE,1,MAX_CANDIDATE_POOL_SIZE),
    candidateSpeculativeAcquireDelayMs:int(raw.candidateSpeculativeAcquireDelayMs,DEFAULT_CANDIDATE_SPECULATIVE_ACQUIRE_DELAY_MS,30 * 1000,15 * 60 * 1000),
    candidateReadyStaleGraceMs:int(raw.candidateReadyStaleGraceMs,DEFAULT_CANDIDATE_READY_STALE_GRACE_MS,15 * 1000,10 * 60 * 1000),
    readyProbeUnreachableTimeoutMs:int(raw.readyProbeUnreachableTimeoutMs,DEFAULT_READY_PROBE_UNREACHABLE_TIMEOUT_MS,15 * 1000,10 * 60 * 1000),
    evernodeMomentSizeSeconds:0,
    unlSnapshot:[], stabilization:null, candidateReadiness:[], candidateSyncQuiescence:[], recentLedgers:[], candidateWatchdogs:[], candidateDiagnostics:[], maturitySignals:[], promotionBatch:null, promotionTransition:null, membershipCommand:null, bootstrapReplacement:null, bootstrapMeshOverride:null, bootstrapNormalConsensusThreshold:null, bootstrapGrowthConsensusThreshold:null, queuedSigner:null, validators:[], maintenance:normalizeMaintenance(null, target),
    blocker:null,
    handoverPreparedAtLcl:null, masterHandoverConfirmedAtLcl:null, handoverSignerPubkeys:[], finalInventoryFingerprint:null, finalInventoryAtLcl:null,
    createdAt:Number(ctx && ctx.timestamp)||Date.now(), handoverObservedAtLcl:null, autonomousAtLcl:null
  };
}
function setBootstrapEndpoint(raw) {
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  const endpoint = normalizeBootstrapEndpoint(raw);
  if (!endpoint || !endpoint.domain || !endpoint.userPort || !endpoint.peerPort)
    throw new Error('Bootstrap endpoint requires a reachable domain/IP, user.port and mesh/peer port.');
  state.bootstrapEndpoint = endpoint;
  saveState(state);
  console.log(`AutoCluster: Bootstrap A endpoint set to ${endpoint.domain} user=${endpoint.userPort} peer=${endpoint.peerPort}.`);
  return { bootstrapEndpoint: endpoint, state };
}

function confirmMasterHandover(ctx, raw = {}) {
  if (!ctx || ctx.readonly) throw new Error('Confirming master-key handover requires a consensus execution.');
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster is not configured yet.');
  if (!['signing','ready-to-handover','handover','autonomous'].includes(state.phase)) {
    throw new Error(`Cannot confirm master-key handover from phase ${state.phase || 'unknown'}.`);
  }
  if (raw.removalReady !== true) throw new Error('Handover preparation must explicitly assert removalReady=true.');
  if (raw.masterDisabled === true) throw new Error('DisableMaster must occur only AFTER Bootstrap A has been removed from HotPocket UNL.');
  const quorum = Number(raw.signerQuorum || raw.quorum || 0);
  if (quorum !== Number(state.signerQuorum || 0)) {
    throw new Error(`Handover preparation quorum mismatch: received ${quorum || 'none'}, expected ${state.signerQuorum}.`);
  }
  const confirmedAccounts = [...new Set((Array.isArray(raw.signers) ? raw.signers : [])
    .map(x => normalizeHostAddress(x && typeof x === 'object' ? x.account : x)).filter(Boolean))].sort();

  // alpha.37.64: initial signer identities are exchanged over NPL and accumulated
  // node-locally across signing ledgers; they are not
  // allowed to mutate replicated state directly. The root control plane returns
  // the exact authenticated NPL pubkey->signer mapping only after it has used
  // that set to install the validated Xahau SignerList and initialize reward tracking. This
  // consensus input is therefore the single canonical commit point for the map.
  const rawMappings = Array.isArray(raw.signerMappings) ? raw.signerMappings : [];
  let mappings = rawMappings.map(m => ({
    pubkey: cleanString(m && (m.pubkey || m.publicKey) || '', 256).toLowerCase(),
    signerAddress: normalizeHostAddress(m && (m.signerAddress || m.account))
  })).filter(m => m.pubkey && m.signerAddress).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));

  const expectedCount = finalManagedTarget(state);
  const expectedPubkeys = normalizePubkeyList(state.handoverSignerPubkeys).slice(0, expectedCount);
  if (expectedPubkeys.length !== expectedCount) {
    throw new Error(`Handover preparation rejected: frozen final managed set is incomplete (${expectedPubkeys.length}/${expectedCount}).`);
  }

  if (mappings.length) {
    const mappingPubkeys = normalizePubkeyList(mappings.map(m => m.pubkey));
    if (expectedPubkeys.length !== expectedCount || JSON.stringify(mappingPubkeys) !== JSON.stringify(expectedPubkeys)) {
      throw new Error(`Handover preparation rejected: NPL signer mapping pubkeys [${mappingPubkeys.join(',')}] do not exactly match the ${expectedCount} managed committed-UNL validators [${expectedPubkeys.join(',')}].`);
    }
    const mappedAccounts = mappings.map(m => m.signerAddress).sort();
    if (new Set(mappedAccounts).size !== mappings.length) throw new Error('Handover preparation rejected: duplicate managed signer accounts in NPL mapping.');
    if (JSON.stringify(confirmedAccounts) !== JSON.stringify(mappedAccounts)) {
      throw new Error(`Handover preparation signer mismatch: control plane confirmed [${confirmedAccounts.join(',')}], NPL mapping contains [${mappedAccounts.join(',')}].`);
    }

    // Commit signerAddress into EverPocket cluster.json deterministically from
    // this authenticated admin consensus input. Never do this from the NPL
    // callback itself.
    const clusterFile = path.resolve(process.cwd(), 'cluster.json');
    const cluster = readJson(clusterFile, null);
    if (!cluster || !Array.isArray(cluster.nodes)) throw new Error('Handover preparation rejected: cluster.json is unavailable.');
    const byPk = new Map(mappings.map(m => [m.pubkey, m.signerAddress]));
    for (const pk of expectedPubkeys) {
      const node = cluster.nodes.find(n => cleanString(n && n.pubkey || '',256).toLowerCase() === String(pk).toLowerCase());
      if (!node || node.pubkey === state.bootstrapPubkey) throw new Error(`Handover preparation rejected: managed validator ${pk} is not a materialized final managed node in cluster.json.`);
      node.signerAddress = byPk.get(String(pk).toLowerCase());
    }
    writeJson(clusterFile, cluster);

    const registry = normalizeValidatorRecords(state.validators);
    const registryByPk = new Map(registry.map(v => [cleanString(v.publicKey || '',256).toLowerCase(), v]));
    for (const m of mappings) {
      let rec = registryByPk.get(m.pubkey);
      if (!rec) {
        rec = { publicKey:m.pubkey, hostAddress:null, refId:null, domain:null, peerPort:null, userPort:null, gpTcp1Port:null, gpUdp1Port:null, signerAddress:null, isUnl:true, present:true, maturityStatus:null, health:'healthy', activeOnLcl:null, createdOnTimestamp:null, lifeMoments:null, targetLifeMoments:null, maxLifeMoments:null, firstSeenAt:null, firstSeenLcl:null, lastUpdatedAt:null, lastUpdatedLcl:null, retiredAt:null, retiredAtLcl:null };
        registry.push(rec);
        registryByPk.set(m.pubkey, rec);
      }
      rec.signerAddress = m.signerAddress;
      rec.isUnl = expectedPubkeys.includes(m.pubkey) && normalizePubkeyList(state.unlSnapshot).includes(m.pubkey);
      rec.present = true;
    }
    state.validators = registry;
    state.handoverSignerPubkeys = expectedPubkeys;
    if (state.phase === 'signing') state.phase = 'ready-to-handover';
    mappings = mappings.sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
    console.log(`AutoCluster: NPL signer mapping COMMITTED through handover confirmation for ${mappings.length}/${expectedCount} managed validators.`);
  } else {
    const frozen = normalizePubkeyList(state.handoverSignerPubkeys);
    const byPubkey = new Map(normalizeValidatorRecords(state.validators).map(v => [v.publicKey, v]));
    const expectedAccounts = frozen.map(pk => byPubkey.get(pk)).filter(Boolean).map(v => normalizeHostAddress(v.signerAddress)).filter(Boolean).sort();
    if (!frozen.length || expectedAccounts.length !== frozen.length) {
      throw new Error('Handover preparation rejected: frozen managed signer identities are incomplete in replicated state and no NPL signer mapping was supplied.');
    }
    if (JSON.stringify(confirmedAccounts) !== JSON.stringify(expectedAccounts)) {
      throw new Error(`Handover preparation signer mismatch: control plane confirmed [${confirmedAccounts.join(',')}], expected [${expectedAccounts.join(',')}].`);
    }
  }

  if (!Number(state.handoverPreparedAtLcl)) {
    state.handoverPreparedAtLcl = Number(ctx.lclSeqNo) || null;
    saveState(state);
    console.log(`AutoCluster: HANDOVER PREPARATION committed at LCL ${state.handoverPreparedAtLcl || '?'} for quorum=${quorum} signers=[${confirmedAccounts.join(',')}]. All final managed validators are already in UNL; Bootstrap A may now request its removal. DisableMaster remains forbidden until A is absent from committed UNL.`);
  } else {
    saveState(state);
  }
  return { state, handoverPreparedAtLcl: state.handoverPreparedAtLcl };
}

function prepareBootstrap(ctx, raw) {
  if (!ctx || ctx.readonly) throw new Error('Preparing AutoCluster bootstrap requires a consensus execution.');
  let state = loadState();
  if (state && state.enabled) {
    if (state.phase === 'awaiting-bootstrap-signerlist' && state.bootstrapSignerAddress) return { state, bootstrapSignerAddress: state.bootstrapSignerAddress };
    throw new Error(`AutoCluster state already exists (phase=${state.phase || 'unknown'}).`);
  }
  state = bootstrapConfig(raw, ctx);
  const kp = require('ripple-keypairs');
  const keyPath = path.resolve(process.cwd(), '..', `${state.clusterAddress}.key`);
  let signer = readJson(keyPath, null);
  if (!signer || !signer.account || !signer.secret) {
    const secret = kp.generateSeed({ algorithm:'ecdsa-secp256k1' });
    const pair = kp.deriveKeypair(secret);
    signer = { account: kp.deriveAddress(pair.publicKey), secret };
    fs.writeFileSync(keyPath, JSON.stringify(signer, null, 2));
  }
  state.bootstrapSignerAddress = signer.account;
  saveState(state);
  console.log(`AutoCluster: bootstrap signer ${signer.account} prepared inside HotPocket execution.`);
  return { state, bootstrapSignerAddress: signer.account };
}
function activateBootstrap(ctx) {
  if (!ctx || ctx.readonly) throw new Error('Activating AutoCluster requires a consensus execution.');
  const state = loadState();
  if (!state || !state.enabled) throw new Error('AutoCluster bootstrap has not been prepared.');
  if (!state.bootstrapSignerAddress) throw new Error('Bootstrap signer is missing.');
  if (state.phase === 'growing') return { state };
  if (state.phase !== 'awaiting-bootstrap-signerlist') throw new Error(`Cannot activate AutoCluster from phase ${state.phase}.`);
  state.phase = 'growing';
  saveState(state);
  console.log('AutoCluster: bootstrap signer list authorized; growth phase activated.');
  return { state };
}

let deps;
function getDeps() {
  if (!deps) {
    deps = require('everpocket-nodejs-contract');
  }
  return deps;
}

function installConsensusNeutralLiveness(hpContext, state) {
  if (!hpContext || hpContext.__everSmartNodeConsensusNeutralLiveness) return;
  // ClusterContext.init() calls hpContext.checkLiveness() from INSIDE deterministic
  // HotPocket contract execution. A real DNS/TLS/WebSocket result is inherently
  // node-local and can differ across validators; allowing it to increment
  // aliveCheckCount/remove pending nodes makes cluster.json diverge. Do not touch
  // the network here. Native Evernode AcquireSuccess is the provisioning boundary;
  // canonical VALIDATOR_READY/JIT is the admission boundary. A provisioned but
  // dead/unreachable instance simply never produces READY and is quarantined by
  // the deterministic readiness watchdog, opening replacement capacity safely.
  hpContext.checkLiveness = async node => {
    const refId = cleanString(node && node.refId || '', 256) || null;
    const address = node && typeof node.toString === 'function' ? cleanString(node.toString(), 512) : '';
    const queueItem = state && Array.isArray(state.hostQueue) ? state.hostQueue.find(h => h && refId && h.refId === refId) || null : null;
    const host = queueItem && queueItem.address || normalizeHostAddress(node && node.host) || null;
    console.log(`AutoCluster: CONSENSUS_NEUTRAL_LIVENESS_BYPASS host=${host || 'unknown'} refId=${refId || 'unknown'} endpoint=${address || 'unknown'} result=ASSUMED_TRUE. No DNS/TLS/WSS call is allowed to mutate replicated cluster state; canonical VALIDATOR_READY remains mandatory before UNL.`);
    return true;
  };
  hpContext.__everSmartNodeConsensusNeutralLiveness = true;
}



function candidateAttestationCanonical(report) {
  const currentUnl = normalizePubkeyList(report && report.currentUnl);
  return JSON.stringify([
    AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE,
    cleanString(report && report.pubkey || '', 256).toLowerCase(),
    Number(report && report.lcl) || 0,
    cleanString(report && report.lclHash || '', 256).toLowerCase(),
    currentUnl,
    cleanString(report && report.privateStatus || '', 64).toLowerCase(),
    report && report.maturityReady === true,
    report && report.hpfsReady === true,
    cleanString(report && report.primaryHash || '', 128).toLowerCase(),
    cleanString(report && report.rawHash || '', 128).toLowerCase(),
    cleanString(report && report.stateHash || '', 128).toLowerCase(),
    cleanString(report && report.patchHash || '', 128).toLowerCase(),
    cleanString(report && report.signerAddress || '', 96),
    cleanString(report && report.buildFingerprint || '', 256).toLowerCase()
  ]);
}

function hotPocketKeyHex(value, expectedBytes) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    let buf = Buffer.from(value);
    // HotPocket JS key material may be binary-prefixed with 0xed: public keys are
    // 33 bytes (0xed + 32), private keys are 65 bytes (0xed + 64). Strip only
    // that transport/type prefix before validating the raw Ed25519 material.
    if (buf.length === expectedBytes + 1 && buf[0] === 0xed) buf = buf.subarray(1);
    const hex = buf.toString('hex').toLowerCase();
    return hex.length === expectedBytes * 2 ? hex : null;
  }
  let raw = cleanString(value || '', expectedBytes * 2 + 8).toLowerCase().replace(/^0x/, '');
  if (raw.startsWith('ed') && raw.length === expectedBytes * 2 + 2) raw = raw.slice(2);
  return new RegExp(`^[0-9a-f]{${expectedBytes * 2}}$`).test(raw) ? raw : null;
}

function hotPocketEd25519PrivateKey(privateKey, expectedPublicKey) {
  const raw = hotPocketKeyHex(privateKey, 64);
  const expected = hotPocketKeyHex(expectedPublicKey, 32);
  if (!raw || !expected) throw new Error('CANDIDATE_ATTESTATION_NODE_KEY_UNAVAILABLE');
  const embeddedPub = raw.slice(64);
  if (embeddedPub !== expected) throw new Error('CANDIDATE_ATTESTATION_NODE_KEY_MISMATCH');
  const seed = Buffer.from(raw.slice(0, 64), 'hex');
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key:der, format:'der', type:'pkcs8' });
}

function hotPocketEd25519PublicKey(publicKey) {
  const raw = hotPocketKeyHex(publicKey, 32);
  if (!raw) throw new Error('CANDIDATE_ATTESTATION_PUBLIC_KEY_INVALID');
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw, 'hex')]);
  return crypto.createPublicKey({ key:der, format:'der', type:'spki' });
}

function verifySignedCandidateAttestation(report) {
  try {
    if (!report || report.type !== AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE) return false;
    const pubkey = cleanString(report.pubkey || '', 256).toLowerCase();
    const lcl = Number(report.lcl) || 0;
    const lclHash = cleanString(report.lclHash || '', 256).toLowerCase();
    const sig = cleanString(report.signature || '', 512);
    if (!/^ed[0-9a-f]{64}$/.test(pubkey) || !lcl || !/^[0-9a-f]{64}$/.test(lclHash) || !sig) return false;
    return crypto.verify(null, Buffer.from(candidateAttestationCanonical(report)), hotPocketEd25519PublicKey(pubkey), Buffer.from(sig, 'base64'));
  } catch (_) { return false; }
}

function writeSignedCandidateAttestation(run) {
  try {
    if (!run || !run.hpContext || !run.state || run.state.phase !== 'growing') return false;
    const hpContext = run.hpContext;
    const pubkey = cleanString(hpContext.publicKey || '', 256).toLowerCase();
    const bootstrap = cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase();
    // During an upgrade from the legacy A+target signing bridge, managed nodes
    // that are already UNL may still need to publish their durable public signer
    // account into shared cluster state. Let every non-bootstrap managed instance
    // emit the same node-signed envelope while phase=growing; maturity writes are
    // naturally no-ops for nodes already in UNL.
    if (!pubkey || pubkey === bootstrap) return false;
    const lcl = Number(hpContext.lclSeqNo) || 0;
    const lclHash = cleanString(hpContext.lclHash || '', 256).toLowerCase();
    if (!/^ed[0-9a-f]{64}$/.test(pubkey) || !lcl || !/^[0-9a-f]{64}$/.test(lclHash)) return false;
    const privateInfo = readJson(path.resolve(process.cwd(), '../node_private_info.json'), null);
    const privateStatus = statusNameFromRaw(privateInfo && privateInfo.status) || 'missing';
    const maturityReady = /^(?:acknowledged|added_to_unl|unl)$/.test(privateStatus);
    const hpfs = inspectLocalHpfsQuiescence(hpContext);
    // Generate the final managed Xahau signer while the instance is still pre-UNL.
    // Only the public account is attested; the secret stays in the node-local vault.
    const managedSigner = ensureManagedSignerVault(run);
    const report = {
      type:AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE,
      pubkey,
      lcl,
      lclHash,
      currentUnl:normalizePubkeyList(hpContext.__everSmartNodeCommittedUnl || []),
      privateStatus,
      maturityReady,
      hpfsReady:hpfs && hpfs.ready === true,
      primaryHash:cleanString(hpfs && hpfs.primaryHash || '',128).toLowerCase() || null,
      rawHash:cleanString(hpfs && hpfs.rawHash || '',128).toLowerCase() || null,
      stateHash:cleanString(hpfs && hpfs.stateHash || '',128).toLowerCase() || null,
      patchHash:cleanString(hpfs && hpfs.patchHash || '',128).toLowerCase() || null,
      signerAddress:managedSigner && managedSigner.account || null,
      buildFingerprint:localBuildFingerprint()
    };
    // EverPocket's HotPocketContext wrapper intentionally exposes the node public
    // key but not the private key. The underlying hp-nodejs-contract ContractContext
    // DOES receive hpargs.private_key from hpcore. AutoCluster keeps a private
    // reference to that raw context solely for local candidate attestation signing.
    // The key is never persisted or logged.
    const rawCtx = hpContext.__everSmartNodeRawContractContext || null;
    const key = hotPocketEd25519PrivateKey((rawCtx && rawCtx.privateKey) || hpContext.privateKey, pubkey);
    report.signature = crypto.sign(null, Buffer.from(candidateAttestationCanonical(report)), key).toString('base64');
    fs.mkdirSync(LOCAL_AUTOCLUSTER_ROOT, { recursive:true });
    const tmp = `${LOCAL_CANDIDATE_ATTESTATION_FILE}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(report), { mode:0o600 });
    fs.renameSync(tmp, LOCAL_CANDIDATE_ATTESTATION_FILE);
    try { fs.chmodSync(LOCAL_CANDIDATE_ATTESTATION_FILE, 0o600); } catch {}
    return true;
  } catch (e) {
    console.log(`AutoCluster: candidate signed-attestation write failed: ${errText(e)}.`);
    return false;
  }
}

function readNplNodeStatusCache() {
  const raw = readJson(LOCAL_NPL_NODE_STATUS_FILE, null);
  if (!raw || typeof raw !== 'object') return { schemaVersion:1, observations:{}, maturities:{} };
  return {
    schemaVersion:1,
    observations: raw.observations && typeof raw.observations === 'object' ? raw.observations : {},
    maturities: raw.maturities && typeof raw.maturities === 'object' ? raw.maturities : {}
  };
}

function writeNplNodeStatusCache(cache) {
  try {
    fs.mkdirSync(LOCAL_AUTOCLUSTER_ROOT, { recursive:true });
    const body = {
      schemaVersion:1,
      updatedAt:Date.now(),
      observations: cache && cache.observations && typeof cache.observations === 'object' ? cache.observations : {},
      maturities: cache && cache.maturities && typeof cache.maturities === 'object' ? cache.maturities : {}
    };
    const tmp = `${LOCAL_NPL_NODE_STATUS_FILE}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(body, null, 2), { mode:0o600 });
    fs.renameSync(tmp, LOCAL_NPL_NODE_STATUS_FILE);
    try { fs.chmodSync(LOCAL_NPL_NODE_STATUS_FILE, 0o600); } catch {}
    return true;
  } catch (e) {
    console.log(`AutoCluster: NPL node-status cache write failed: ${errText(e)}`);
    return false;
  }
}

function cacheAuthenticatedNplStatus(sender, parsed, hpContext) {
  const pubkey = cleanString(sender || '', 256).toLowerCase();
  const claimed = cleanString(parsed && parsed.pubkey || '', 256).toLowerCase();
  if (!pubkey || claimed !== pubkey) return false;
  const lcl = Number(parsed && parsed.lcl) || 0;
  const lclHash = cleanString(parsed && parsed.lclHash || '', 256).toLowerCase();
  if (!lcl || !/^[0-9a-f]{64}$/.test(lclHash)) return false;
  const cache = readNplNodeStatusCache();
  cache.observations[pubkey] = {
    pubkey,
    lcl,
    lclHash,
    currentUnl:normalizePubkeyList(parsed.currentUnl),
    isUnl:!!parsed.isUnl,
    phase:cleanString(parsed.phase || '', 64) || null,
    receivedAtLocalMs:Date.now(),
    receivedBy:cleanString(hpContext && hpContext.publicKey || '', 256).toLowerCase() || null,
    receivedAtLocalLcl:Number(hpContext && hpContext.lclSeqNo) || null
  };
  writeNplNodeStatusCache(cache);
  return true;
}

function cacheAuthenticatedNplMaturity(sender, parsed, hpContext) {
  const pubkey = cleanString(sender || '', 256).toLowerCase();
  const claimed = cleanString(parsed && parsed.pubkey || '', 256).toLowerCase();
  if (!pubkey || claimed !== pubkey) return false;
  const cache = readNplNodeStatusCache();
  cache.maturities[pubkey] = {
    pubkey,
    lcl:Number(parsed && parsed.lcl) || null,
    lclHash:cleanString(parsed && parsed.lclHash || '', 256).toLowerCase() || null,
    receivedAtLocalMs:Date.now(),
    receivedBy:cleanString(hpContext && hpContext.publicKey || '', 256).toLowerCase() || null,
    receivedAtLocalLcl:Number(hpContext && hpContext.lclSeqNo) || null
  };
  writeNplNodeStatusCache(cache);
  return true;
}

async function broadcastAutoClusterNplStatus(ctx, hpContext, state, committedUnl, localIsUnl) {
  if (!ctx || ctx.readonly || !ctx.unl || typeof ctx.unl.send !== 'function' || !hpContext) return false;
  const pubkey = cleanString(hpContext.publicKey || ctx.publicKey || '', 256).toLowerCase();
  const lcl = Number(hpContext.lclSeqNo || ctx.lclSeqNo) || 0;
  const lclHash = cleanString(hpContext.lclHash || ctx.lclHash || '', 256).toLowerCase();
  if (!pubkey || !lcl || !/^[0-9a-f]{64}$/.test(lclHash)) return false;
  const msg = {
    type:AUTOCLUSTER_NODE_STATUS_NPL_TYPE,
    pubkey,
    lcl,
    lclHash,
    currentUnl:normalizePubkeyList(committedUnl),
    isUnl:!!localIsUnl,
    phase:cleanString(state && state.phase || '',64) || null
  };
  try {
    await ctx.unl.send(JSON.stringify(msg));
    return true;
  } catch (e) {
    console.log(`AutoCluster: NPL STATUS broadcast failed for ${cleanString(pubkey,24)} at LCL ${lcl}: ${errText(e)}.`);
    return false;
  }
}

async function broadcastAutoClusterNplMaturity(ctx, hpContext) {
  if (!ctx || ctx.readonly || !ctx.unl || typeof ctx.unl.send !== 'function' || !hpContext) {
    throw new Error('NPL_MATURITY_UNAVAILABLE: HotPocket Node Party Line send() is unavailable.');
  }
  const pubkey = cleanString(hpContext.publicKey || ctx.publicKey || '', 256).toLowerCase();
  const lcl = Number(hpContext.lclSeqNo || ctx.lclSeqNo) || 0;
  const lclHash = cleanString(hpContext.lclHash || ctx.lclHash || '', 256).toLowerCase();
  if (!pubkey) throw new Error('NPL_MATURITY_INVALID_LOCAL_IDENTITY');
  await ctx.unl.send(JSON.stringify({
    type:AUTOCLUSTER_MATURITY_NPL_TYPE,
    pubkey,
    lcl:lcl || null,
    lclHash:/^[0-9a-f]{64}$/.test(lclHash) ? lclHash : null
  }));
  console.log(`AutoCluster: MATURED NPL broadcast by ${cleanString(pubkey,80)} at candidate LCL ${lcl || '?'}. No candidate user WebSocket was opened.`);
  return true;
}

function attachVotePipe(ctx, hpContext, state) {
  if (!ctx || !ctx.unl || typeof ctx.unl.onMessage !== 'function') return;
  // Execution-local diagnostics only. HotPocket invokes a fresh contract process
  // each ledger, so these counters are deliberately NOT persisted. They let the
  // signer path tell us whether NPL traffic from peer validators was actually
  // observed during this one election/submission attempt.
  const nplStats = { messages: 0, senders: new Set() };
  const signerAnnouncements = new Map();
  hpContext.__everSmartNodeNplStats = nplStats;
  hpContext.__autoClusterSignerNpl = signerAnnouncements;
  ctx.unl.onMessage((node, msg) => {
    try {
      nplStats.messages += 1;
      const sender = cleanString(node && (node.publicKey || node.public_key || node.pubkey || node.key || node.id || node) || '', 256).toLowerCase();
      if (sender) nplStats.senders.add(sender);

      // AutoCluster NPL messages are multiplexed beside EverPocket's existing
      // multisign/election traffic. Do not feed our JSON envelope into
      // voteContext; authenticate it from HotPocket's UNL sender identity and
      // retain it only for this execution/round.
      let parsed = null;
      try { parsed = JSON.parse(Buffer.from(msg).toString('utf8')); } catch {}
      if (parsed && parsed.type === AUTOCLUSTER_NODE_STATUS_NPL_TYPE) {
        cacheAuthenticatedNplStatus(sender, parsed, hpContext);
        return;
      }
      if (parsed && parsed.type === AUTOCLUSTER_MATURITY_NPL_TYPE) {
        cacheAuthenticatedNplMaturity(sender, parsed, hpContext);
        return;
      }
      if (parsed && parsed.type === AUTOCLUSTER_SIGNER_NPL_TYPE) {
        const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
        const signerAddress = cleanString(parsed.signerAddress || '', 96);
        const roundId = cleanString(parsed.roundId || '', 320);
        if (sender && claimed === sender && roundId && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(signerAddress)) {
          signerAnnouncements.set(`${roundId}|${sender}`, { pubkey: sender, signerAddress, roundId });
        }
        return;
      }

      hpContext.voteContext.feedUnlMessage(node, Buffer.from(msg));
    }
    catch (e) { console.log(`AutoCluster NPL feed failed: ${e && e.message ? e.message : e}`); }
  });
}

function nplHandoverProposalPath(state) {
  if (!state || !state.clusterAddress) return null;
  return path.resolve(process.cwd(), '..', `${state.clusterAddress}.npl-handover.json`);
}

function nplSignerCachePath(state) {
  if (!state || !state.clusterAddress) return null;
  return path.resolve(process.cwd(), '..', `${state.clusterAddress}.npl-signer-cache.json`);
}

function signerNplRoundId(state, expectedManaged, expectedUnl) {
  const payload = {
    clusterAddress: cleanString(state && state.clusterAddress || '', 128),
    bootstrapPubkey: cleanString(state && state.bootstrapPubkey || '', 256).toLowerCase(),
    bootstrapRunCreatedAt: Number(state && state.createdAt) || 0,
    signerQuorum: Number(state && state.signerQuorum) || 0,
    managed: normalizePubkeyList(expectedManaged),
    unl: normalizePubkeyList(expectedUnl)
  };
  return `signer-v2:${crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex')}`;
}

function readNplSignerCache(run, roundId, expectedManaged, expectedUnl) {
  const out = new Map();
  const file = nplSignerCachePath(run && run.state);
  if (!file) return out;
  const raw = readJson(file, null);
  if (!raw || typeof raw !== 'object') return out;
  const managed = normalizePubkeyList(expectedManaged);
  const unl = normalizePubkeyList(expectedUnl);
  if (Number(raw.schemaVersion) !== 1 || cleanString(raw.roundId || '', 320) !== roundId ||
      cleanString(raw.clusterAddress || '', 128) !== cleanString(run.state.clusterAddress || '', 128) ||
      cleanString(raw.bootstrapPubkey || '', 256).toLowerCase() !== cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase() ||
      JSON.stringify(normalizePubkeyList(raw.expectedManaged)) !== JSON.stringify(managed) ||
      JSON.stringify(normalizePubkeyList(raw.expectedUnl)) !== JSON.stringify(unl)) return out;
  const expectedSet = new Set(managed.map(x => String(x).toLowerCase()));
  for (const m of Array.isArray(raw.mappings) ? raw.mappings : []) {
    const pubkey = cleanString(m && m.pubkey || '', 256).toLowerCase();
    const signerAddress = cleanString(m && m.signerAddress || '', 96);
    if (!expectedSet.has(pubkey) || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(signerAddress)) continue;
    const existing = out.get(pubkey);
    if (existing && existing.signerAddress !== signerAddress) return new Map();
    out.set(pubkey, { pubkey, signerAddress, roundId });
  }
  return out;
}

function writeNplSignerCache(run, roundId, expectedManaged, expectedUnl, cache) {
  const file = nplSignerCachePath(run && run.state);
  if (!file || !(cache instanceof Map)) return false;
  const mappings = [...cache.values()].map(m => ({
    pubkey: cleanString(m && m.pubkey || '', 256).toLowerCase(),
    signerAddress: cleanString(m && m.signerAddress || '', 96)
  })).filter(m => m.pubkey && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(m.signerAddress)).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
  const body = {
    schemaVersion: 1,
    clusterAddress: cleanString(run.state.clusterAddress || '', 128),
    bootstrapPubkey: cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase(),
    bootstrapRunCreatedAt: Number(run.state.createdAt) || null,
    roundId,
    expectedManaged: normalizePubkeyList(expectedManaged),
    expectedUnl: normalizePubkeyList(expectedUnl),
    updatedAtLcl: Number(run.hpContext && run.hpContext.lclSeqNo) || null,
    mappings
  };
  try {
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(body, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch {}
    return true;
  } catch (e) {
    console.log(`AutoCluster: NPL signer cache write failed: ${errText(e)}`);
    return false;
  }
}

function writeNplHandoverProposal(run, roundId, mappings, expectedUnl) {
  if (!run || !run.state || !run.ctx || !Array.isArray(mappings) || !mappings.length) return false;
  const file = nplHandoverProposalPath(run.state);
  if (!file) return false;
  const normalized = mappings.map(m => ({
    pubkey: cleanString(m && m.pubkey || '', 256).toLowerCase(),
    signerAddress: cleanString(m && m.signerAddress || '', 96)
  })).filter(m => m.pubkey && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(m.signerAddress)).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
  if (normalized.length !== mappings.length) return false;
  const proposal = {
    schemaVersion: 1,
    clusterAddress: run.state.clusterAddress,
    bootstrapPubkey: cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase(),
    targetManagedNodes: Number(run.state.targetManagedNodes) || 0,
    signerQuorum: Number(run.state.signerQuorum) || 0,
    roundId: cleanString(roundId || '', 320),
    observedAtLcl: Number(run.hpContext && run.hpContext.lclSeqNo) || null,
    lclHash: cleanString(run.hpContext && run.hpContext.lclHash || '', 256) || null,
    unlPubkeys: normalizePubkeyList(expectedUnl),
    mappings: normalized
  };
  try {
    const tmp = `${file}.tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify(proposal, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch {}
    return true;
  } catch (e) {
    console.log(`AutoCluster: NPL signer proposal write failed: ${errText(e)}`);
    return false;
  }
}

function managedNodes(run, onlyUnl = false) {
  const list = onlyUnl ? run.clusterContext.getClusterUnlNodes() : run.clusterContext.getClusterNodes();
  return list.filter(n => n && n.pubkey !== run.state.bootstrapPubkey).sort((a, b) => String(a.pubkey).localeCompare(String(b.pubkey)));
}

function fixedSizeBootstrapHandoverSet(run) {
  const state = run && run.state;
  const target = finalManagedTarget(state);
  const bridgeManagedTarget = bootstrapManagedUnlTarget(state);
  const bridgeTarget = bootstrapBridgeUnlTarget(state);
  const currentUnl = currentUnlPubkeys(run);
  const currentUnlSet = new Set(currentUnl);
  const bootstrap = cleanString(state && state.bootstrapPubkey || '', 256).toLowerCase();
  const all = managedNodes(run, false);
  const stalled = new Set(normalizeCandidateWatchdogs(state && state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => cleanString(w.pubkey || '',256).toLowerCase()));
  const unlManaged = all
    .filter(n => n && currentUnlSet.has(cleanString(n.pubkey || '',256).toLowerCase()))
    .sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
  const waiting = all
    .filter(n => n && !currentUnlSet.has(cleanString(n.pubkey || '',256).toLowerCase()) && !stalled.has(cleanString(n.pubkey || '',256).toLowerCase()))
    .sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));

  // Handover begins only after every target managed validator is already a committed
  // UNL member beside Bootstrap A. For target=5 this means a temporary six-validator
  // bridge: A + M1..M5. There is no pre-UNL replacement and no atomic A->M swap.
  // The final consensus membership operation simply removes A.
  const bridgeReady = currentUnl.length === bridgeTarget &&
    currentUnl.includes(bootstrap) &&
    unlManaged.length === bridgeManagedTarget;
  const allBridgeSigners = unlManaged.length === bridgeManagedTarget &&
    unlManaged.every(n => /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')));
  const pubkeys = bridgeReady && allBridgeSigners
    ? normalizePubkeyList(unlManaged.map(n => n.pubkey))
    : [];
  return {
    target, bridgeTarget, bridgeManagedTarget, currentUnl, all, unlManaged, waiting,
    eligible:[], replacement:null, bridgeReady, allBridgeSigners,
    ready:pubkeys.length === target, pubkeys
  };
}

function markSharedMaturityAcknowledged(clusterContext, pubkey, lcl) {
  const claimed = cleanString(pubkey || '', 256).toLowerCase();
  if (!claimed) return { found:false, changed:false, status:'missing' };

  // When the full EverPocket ClusterContext is active, update its in-memory
  // ClusterManager rather than writing cluster.json behind its back. deinit()
  // persists that manager later in the same execution; a direct file write here
  // would otherwise be vulnerable to being overwritten by stale manager state.
  const manager = clusterContext && clusterContext.clusterManager;
  if (manager && typeof manager.getNode === 'function' && typeof manager.markAsMatured === 'function') {
    const node = manager.getNode(claimed) || null;
    if (!node) return { found:false, changed:false, status:'missing' };
    const prior = diskNodeStatus(node);
    if (node.isUnl || /^(?:acknowledged|added_to_unl|unl)$/.test(prior)) {
      return { found:true, changed:false, status:prior || (node.isUnl ? 'added_to_unl' : 'acknowledged'), via:'cluster-manager' };
    }
    manager.markAsMatured(claimed, Number(lcl) || 0);
    return { found:true, changed:true, status:'acknowledged', via:'cluster-manager' };
  }

  // Under the post-join consensus-purity fence we intentionally use a lightweight
  // cluster view with no EverPocket lifecycle object. In that case perform exactly
  // the small replicated state transition that ClusterManager.markAsMatured()
  // would persist: keep the row and move only status -> ACKNOWLEDGED.
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const disk = readJson(clusterFile, null);
  if (!disk || !Array.isArray(disk.nodes)) return { found:false, changed:false, status:'missing' };
  const node = disk.nodes.find(n => n && String(n.pubkey || '').toLowerCase() === claimed) || null;
  if (!node) return { found:false, changed:false, status:'missing' };
  const prior = diskNodeStatus(node);
  if (node.isUnl || /^(?:acknowledged|added_to_unl|unl)$/.test(prior)) {
    return { found:true, changed:false, status:prior || (node.isUnl ? 'added_to_unl' : 'acknowledged'), via:'cluster-file' };
  }
  node.status = { status:3, onLcl:Number(lcl) || 0 };
  writeJson(clusterFile, disk);
  return { found:true, changed:true, status:'acknowledged', via:'cluster-file' };
}

function markSharedSignerAddress(clusterContext, pubkey, signerAddress) {
  const claimed = cleanString(pubkey || '', 256).toLowerCase();
  const signer = cleanString(signerAddress || '', 96);
  if (!claimed || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(signer)) return { found:false, changed:false, signerAddress:null };
  const manager = clusterContext && clusterContext.clusterManager;
  if (manager && typeof manager.getNode === 'function') {
    const node = manager.getNode(claimed) || null;
    if (!node) return { found:false, changed:false, signerAddress:null };
    if (node.signerAddress && node.signerAddress !== signer) return { found:true, changed:false, conflict:true, signerAddress:node.signerAddress };
    if (node.signerAddress === signer) return { found:true, changed:false, signerAddress:signer, via:'cluster-manager' };
    node.signerAddress = signer;
    return { found:true, changed:true, signerAddress:signer, via:'cluster-manager' };
  }
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const disk = readJson(clusterFile, null);
  if (!disk || !Array.isArray(disk.nodes)) return { found:false, changed:false, signerAddress:null };
  const node = disk.nodes.find(n => n && String(n.pubkey || '').toLowerCase() === claimed) || null;
  if (!node) return { found:false, changed:false, signerAddress:null };
  if (node.signerAddress && node.signerAddress !== signer) return { found:true, changed:false, conflict:true, signerAddress:node.signerAddress };
  if (node.signerAddress === signer) return { found:true, changed:false, signerAddress:signer, via:'cluster-file' };
  node.signerAddress = signer;
  writeJson(clusterFile, disk);
  return { found:true, changed:true, signerAddress:signer, via:'cluster-file' };
}

function readTailText(file, maxBytes = 1024 * 1024) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size <= 0) return '';
    const len = Math.min(st.size, maxBytes);
    const start = Math.max(0, st.size - len);
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(len);
      const got = fs.readSync(fd, buf, 0, len, start);
      return buf.subarray(0, got).toString('utf8');
    } finally { fs.closeSync(fd); }
  } catch { return ''; }
}

function parseHpLogTimestampMs(line) {
  const m = String(line || '').match(/(?:^|\s)(\d{4})(\d{2})(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})/);
  if (!m) return null;
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]), Number(m[7]));
}

function inspectLocalHpfsQuiescence(hpContext) {
  const file = '/var/log/supervisor/hotpocket.err.log';
  const text = readTailText(file);
  if (!text) return { ready:false, reason:'hotpocket-log-unavailable' };
  const paths = ['/primary/0','/raw/0','/state','/patch.cfg'];
  const latest = Object.fromEntries(paths.map(p => [p, { targetHash:null, targetLine:-1, achievedHash:null, achievedLine:-1 }]));
  let lastHistoryLine = -1, lastMismatchLine = -1, lastActivityMs = 0;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const ts = parseHpLogTimestampMs(line);
    const target = line.match(/Hpfs\s+(?:ldgr|cont)\s+sync:\s+Target\s+(?:added|updated)\.\s+(?:New hash:|Hash:)([0-9a-f]+)\s+(\/primary\/0|\/raw\/0|\/state|\/patch\.cfg)/i);
    if (target) {
      const p = target[2]; latest[p].targetHash = target[1].toLowerCase(); latest[p].targetLine = i;
      latest[p].achievedHash = null; latest[p].achievedLine = -1;
      if (ts) lastActivityMs = Math.max(lastActivityMs, ts);
      continue;
    }
    const achieved = line.match(/Hpfs\s+(?:ldgr|cont)\s+sync:\s+Achieved target:([0-9a-f]+)\s+(\/primary\/0|\/raw\/0|\/state|\/patch\.cfg)/i);
    if (achieved) {
      const p = achieved[2], h = achieved[1].toLowerCase();
      if (latest[p].targetHash === h || latest[p].targetLine < 0) {
        latest[p].achievedHash = h; latest[p].achievedLine = i;
        if (latest[p].targetLine < 0) { latest[p].targetHash = h; latest[p].targetLine = i; }
      }
      if (ts) lastActivityMs = Math.max(lastActivityMs, ts);
      continue;
    }
    if (/We are not on the consensus ledger, we must request history from a peer/i.test(line)) {
      lastHistoryLine = i; if (ts) lastActivityMs = Math.max(lastActivityMs, ts);
    }
    if (/Skipping mismatched hashmap response/i.test(line)) {
      lastMismatchLine = i; if (ts) lastActivityMs = Math.max(lastActivityMs, ts);
    }
  }
  const required = ['/primary/0','/raw/0','/state'];
  for (const p of required) {
    const r = latest[p];
    if (r.targetLine < 0 || r.achievedLine < r.targetLine || r.achievedHash !== r.targetHash) {
      return { ready:false, reason:`outstanding-${p.replace(/\//g,'') || 'sync'}`, latest };
    }
  }
  const patch = latest['/patch.cfg'];
  if (patch.targetLine >= 0 && (patch.achievedLine < patch.targetLine || patch.achievedHash !== patch.targetHash)) {
    return { ready:false, reason:'outstanding-patch', latest };
  }
  const settledLine = Math.min(...required.map(p => latest[p].achievedLine));
  if (lastHistoryLine > settledLine) return { ready:false, reason:'history-request-after-sync', latest };
  if (lastMismatchLine > settledLine) return { ready:false, reason:'hashmap-mismatch-after-sync', latest };
  // Do NOT require an idle wall-clock window here. During bootstrap qualification
  // Bootstrap A now stays on the lightweight path, so ClusterContext.init()/deinit()
  // cannot churn cluster.json.activeOnLcl merely because a signed candidate report
  // arrived. The meaningful native HPFS invariant is still that the candidate has
  // achieved the LATEST target for each required tree and has no newer history or
  // mismatch event after those achievements.
  const now = Date.now(); // diagnostics only; never written directly to consensus.
  const idleMs = lastActivityMs ? Math.max(0, now - lastActivityMs) : 0;
  const hash = cleanString(hpContext && hpContext.lclHash || '', 256).toLowerCase();
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  if (!lcl || !/^[0-9a-f]{64}$/.test(hash)) return { ready:false, reason:'local-ledger-identity-missing', idleMs, latest };
  return {
    ready:true, reason:'hpfs-latest-targets-achieved', idleMs, lcl, hash,
    primaryHash:latest['/primary/0'].achievedHash,
    rawHash:latest['/raw/0'].achievedHash,
    stateHash:latest['/state'].achievedHash,
    patchHash:latest['/patch.cfg'].achievedHash || null
  };
}

async function runPreUnlSyncQuiescenceHandshake(state, hpContext, maturityStage) {
  if (!state || !hpContext || !hpContext.publicKey || hpContext.publicKey === state.bootstrapPubkey) return { stage:'skip' };
  if (maturityStage !== 'shared-acknowledged') return { stage:'waiting-shared-ack' };
  // Do not scrape local HPFS logs and do not open a candidate-side HotPocket user
  // session for SYNC. Bootstrap A's isolated READY controller already observes the
  // candidate over stat, verifies its exact LCL/hash against A's private canonical
  // ledger witness, measures lag, and submits that observation as an authenticated
  // HotPocket input. Canonical observations within lag<=24 are the SYNC proof.
  return { stage:'runtime-sync-observed-by-bootstrap-controller' };
}

async function runPreUnlMaturityHandshake(state, hpContext, bootstrapEndpoint) {
  if (!state || !hpContext || !hpContext.publicKey || hpContext.publicKey === state.bootstrapPubkey) return { stage:'skip' };
  const lcl = Number(hpContext.lclSeqNo) || 0;
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const cluster = readJson(clusterFile, null);
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const self = nodes.find(n => n && String(n.pubkey || '').toLowerCase() === String(hpContext.publicKey).toLowerCase()) || null;
  if (!self || self.isUnl) return { stage:self && self.isUnl ? 'already-unl' : 'waiting-shared-row' };

  const sharedStatus = diskNodeStatus(self);
  const currentUnlNodes = nodes.filter(diskNodeIsUnl);
  const singletonBootstrapMesh = currentUnlNodes.length === 1 &&
    String(currentUnlNodes[0] && currentUnlNodes[0].pubkey || '').toLowerCase() === String(state.bootstrapPubkey || '').toLowerCase();

  // Reference cluster-manager behavior: a non-UNL node is explicitly given the
  // COMPLETE current UNL peer list before it announces MATURED. During the fragile
  // singleton bootstrap we go one step further and live-peer materialized followers
  // to one another as well. This prebuilds A<->B, A<->C and B<->C BEFORE the atomic
  // A one-at-a-time membership patch is allowed to leave an execution. Live peer changes are node-local
  // transport and do not rewrite replicated /state.
  const candidatePeers = new Set();
  const peerSourceNodes = singletonBootstrapMesh
    ? nodes.filter(n => n && String(n.pubkey || '').toLowerCase() !== String(hpContext.publicKey || '').toLowerCase())
    : currentUnlNodes;
  for (const n of peerSourceNodes) {
    const d = normalizeEndpointHost(n && n.domain), p = validPort(n && (n.peerPort || n.meshPort));
    if (d && p) candidatePeers.add(`${d}:${p}`);
  }
  if (bootstrapEndpoint && bootstrapEndpoint.domain && validPort(bootstrapEndpoint.peerPort)) {
    candidatePeers.add(`${normalizeEndpointHost(bootstrapEndpoint.domain)}:${validPort(bootstrapEndpoint.peerPort)}`);
  }
  if (candidatePeers.size && typeof hpContext.updatePeers === 'function') {
    const fullPeers = [...candidatePeers].sort();
    try {
      await hpContext.updatePeers(fullPeers);
      console.log(`AutoCluster: PRE-UNL FULL MESH installed for ${cleanString(hpContext.publicKey,24)} before MATURED: ${fullPeers.join(', ')}.`);
    } catch (e) {
      console.log(`AutoCluster: PRE-UNL FULL MESH update failed for ${cleanString(hpContext.publicKey,24)}: ${errText(e)}.`);
      return { stage:'peer-mesh-update-failed', sharedStatus };
    }
  }

  // After shared ACKNOWLEDGED, ordinary (>1 UNL) candidates can stop replaying the
  // peer changeset. Under singleton bootstrap we intentionally keep the follower
  // mesh asserted until the one-at-a-time membership change commits; this avoids a transport
  // race without touching replicated state.
  if (/^(?:acknowledged|added_to_unl|unl)$/.test(sharedStatus)) return { stage:'shared-acknowledged', sharedStatus, singletonBootstrapMesh };

  const privateFile = path.resolve(process.cwd(), '../node_private_info.json');
  let info = readJson(privateFile, null);
  let privateStatus = statusNameFromRaw(info && info.status);

  // Mirror EverPocket #checkForMatured(), but explicitly maintain the full
  // current-UNL live peer set first, matching the reference cluster manager.
  if (!info) {
    info = { status:{ status:2, onLcl:lcl }, acknowledgeTries:0 };
    writeJson(privateFile, info);
    privateStatus = 'configured';
    console.log(`AutoCluster: PRE-UNL MATURITY CONFIGURED ${cleanString(hpContext.publicKey,80)} at LCL ${lcl || '?'} using synchronized cluster row after explicit full-UNL peer installation.`);
    return { stage:'configured', configuredAtLcl:lcl };
  }

  const statusObj = info && info.status && typeof info.status === 'object' ? info.status : {};
  const statusLcl = Number(statusObj.onLcl) || 0;
  const ackDelay = Math.max(1, Number(state.acknowledgeLclThreshold) || 2);
  const retryDelay = Math.max(5, ackDelay);
  const tries = Math.max(0, Number(info.acknowledgeTries) || 0);
  const dueInitial = privateStatus === 'configured' && lcl > statusLcl + ackDelay;
  const dueRetry = privateStatus === 'acknowledged' && lcl > statusLcl + retryDelay;
  if (!dueInitial && !dueRetry) return { stage:'waiting-ack-threshold', privateStatus, statusLcl, lcl };

  if (!bootstrapEndpoint || !bootstrapEndpoint.domain || !validPort(bootstrapEndpoint.userPort)) {
    console.log(`AutoCluster: PRE-UNL MATURITY cannot send for ${cleanString(hpContext.publicKey,80)}: Bootstrap A user endpoint is unavailable.`);
    return { stage:'missing-bootstrap-user-endpoint' };
  }

  const msg = JSON.stringify({ type:'maturity_ack', data:hpContext.publicKey });
  console.log(`AutoCluster: PRE-UNL MATURITY sending REAL authenticated MATURED for ${cleanString(hpContext.publicKey,80)} at LCL ${lcl}; private=${privateStatus} tries=${tries}.`);
  try {
    await hpContext.sendMessage(msg, []);
    // Same private transition as stock EverPocket after a successful send. Keep
    // retrying idempotently every few ledgers until synchronized shared state says
    // ACKNOWLEDGED; unlike the stock three-attempt cap this cannot dead-end forever
    // after a transient response loss.
    info.status = { status:3, onLcl:lcl };
    info.acknowledgeTries = tries + 1;
    writeJson(privateFile, info);
    console.log(`AutoCluster: PRE-UNL MATURITY MATURED submitted for ${cleanString(hpContext.publicKey,80)}; private state -> ACKNOWLEDGED attempt=${info.acknowledgeTries}. Waiting for shared ACKNOWLEDGED to synchronize back.`);
    return { stage:'matured-sent', attempts:info.acknowledgeTries };
  } catch (e) {
    console.log(`AutoCluster: PRE-UNL MATURITY MATURED send failed for ${cleanString(hpContext.publicKey,80)}: ${errText(e)}. Private state remains ${privateStatus}; retry will occur after the normal threshold.`);
    return { stage:'matured-send-failed' };
  }
}

function createSigningClusterView() {
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const loadNodes = () => {
    const disk = readJson(clusterFile, null);
    return disk && Array.isArray(disk.nodes) ? disk.nodes : [];
  };
  return {
    getClusterNodes: () => loadNodes(),
    getClusterUnlNodes: () => loadNodes().filter(diskNodeIsUnl),
    // Signing deliberately does not initialize EverPocket. Authenticated MATURED
    // is handled deterministically by AutoCluster before this compatibility hook;
    // all other stock lifecycle callbacks remain disabled in the purity fence.
    feedUserMessage: async () => null,
    deinit: async () => {}
  };
}
function bootstrapQualificationSnapshot(state, hpContext) {
  const out = { active:false, readyToPromote:false, managed:0, usable:0, green:0, target:Math.max(1, Number(state && state.targetManagedNodes) || 1) };
  if (!state || state.phase !== 'growing') return out;
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const managed = nodes.filter(n => n && n.pubkey && n.pubkey !== state.bootstrapPubkey && !diskNodeIsUnl(n));
  const stalled = new Set(normalizeCandidateWatchdogs(state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => w.pubkey));
  const usable = managed.filter(n => !stalled.has(n.pubkey));
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const currentGreen = currentCanonicalBootstrapReadyPubkeys(state, lcl);
  const green = usable.filter(n => currentGreen.has(n.pubkey));
  out.managed = managed.length;
  out.usable = usable.length;
  out.green = green.length;
  // Qualification becomes a deliberately quiet phase only after enough usable
  // physical candidates exist. If one is quarantined, active becomes false on
  // the next committed ledger and Bootstrap A is free to acquire a replacement.
  out.active = managed.length >= out.target && usable.length >= out.target;
  out.readyToPromote = out.active && green.length >= out.target;
  return out;
}

function finalManagedTarget(state) {
  return Math.max(1, Number(state && state.targetManagedNodes) || 1);
}

function bootstrapManagedUnlTarget(state) {
  // Bootstrap bridge includes every managed validator plus Bootstrap A.
  // For target=5 the temporary bridge is A + five managed validators (6 total).
  return finalManagedTarget(state);
}

function bootstrapBridgeUnlTarget(state) {
  return finalManagedTarget(state) + 1;
}

function bootstrapInitialPhysicalManagedGoal(state) {
  // Acquire the complete final managed fleet up front. Membership admission is a
  // separate lane, but all target managed validators are allowed to join while
  // Bootstrap A is still present. The bridge is therefore temporarily target+1.
  return finalManagedTarget(state);
}

function bootstrapDiskPoolStatus(state) {
  const finalTarget = finalManagedTarget(state);
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const bootstrapKey = cleanString(state && state.bootstrapPubkey || '', 256).toLowerCase();
  const committedUnl = nodes.filter(n => n && n.pubkey && diskNodeIsUnl(n));
  const singletonBootstrap = committedUnl.length === 1 && !!bootstrapKey &&
    committedUnl.some(n => cleanString(n.pubkey || '', 256).toLowerCase() === bootstrapKey);
  // Physical provisioning is intentionally front-loaded: the full managed fleet
  // exists before the temporary bridge is completed. This keeps handover
  // deterministic and avoids late acquisition after the cluster reaches target size.
  const target = finalTarget;
  const managed = nodes.filter(n => n && n.pubkey && n.pubkey !== (state && state.bootstrapPubkey));
  const stalled = new Set(normalizeCandidateWatchdogs(state && state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => w.pubkey));
  const usable = managed.filter(n => n && (diskNodeIsUnl(n) || !stalled.has(n.pubkey)));
  return { target, finalTarget, singletonBootstrap, managed:managed.length, usable:usable.length };
}


function bootstrapFreezeQualificationSnapshot(state, hpContext, committedUnl = null) {
  const target = finalManagedTarget(state);
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const stalled = new Set(normalizeCandidateWatchdogs(state && state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => cleanString(w.pubkey || '', 256).toLowerCase()));
  const managed = nodes.filter(n => n && n.pubkey && cleanString(n.pubkey,256).toLowerCase() !== cleanString(state && state.bootstrapPubkey || '',256).toLowerCase());
  const usable = managed.filter(n => n && (diskNodeIsUnl(n) || !stalled.has(cleanString(n.pubkey || '',256).toLowerCase())));
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const unl = Array.isArray(committedUnl)
    ? normalizePubkeyList(committedUnl)
    : (hpContext && typeof hpContext.getContractUnl === 'function' ? normalizePubkeyList(hpContext.getContractUnl()) : []);
  const requiredPeers = requiredAdmissionPeers(Math.max(1, unl.length || 1));
  const readiness = normalizeCandidateReadiness(state && state.candidateReadiness);
  const rows = usable
    .filter(n => n && !diskNodeIsUnl(n))
    .map(node => {
      const pubkey = cleanString(node.pubkey || '',256).toLowerCase();
      const rec = readiness.find(r => cleanString(r && r.pubkey || '',256).toLowerCase() === pubkey) || null;
      const durable = durableBootstrapQualificationStatus(state, pubkey);
      const maturity = nodeMaturityStability(node, state, lcl);
      const observedAtLcl = Number(rec && rec.observedAtLcl) || 0;
      const observationAge = lcl && observedAtLcl ? lcl - observedAtLcl : Number.POSITIVE_INFINITY;
      const candidateLag = rec && rec.candidateLag != null ? Number(rec.candidateLag) : Number.POSITIVE_INFINITY;
      const peerCount = rec && rec.peerCount != null ? Math.max(0, Number(rec.peerCount) || 0) : 0;
      const candidateLcl = Number(rec && rec.candidateLcl) || 0;
      const candidateHash = cleanString(rec && rec.candidateHash || '',256).toLowerCase();
      const canonicalTuple = !!(rec && candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash) &&
        Array.isArray(rec.proofHistory) && rec.proofHistory.some(ph => Number(ph && ph.candidateLcl) === candidateLcl &&
          cleanString(ph && ph.candidateHash || '',256).toLowerCase() === candidateHash));
      const voteSynced = cleanString(rec && rec.voteStatus || '',32).toLowerCase() === 'synced';
      const liveSync = !!(rec && voteSynced && canonicalTuple &&
        Number.isFinite(candidateLag) && candidateLag >= 0 && candidateLag <= BOOTSTRAP_ADMISSION_MAX_LAG_LCLS &&
        Number.isFinite(observationAge) && observationAge >= 0 && observationAge <= ATOMIC_BOOTSTRAP_READY_FRESH_LCL);
      const ack = diskNodeStatus(node) === 'acknowledged';
      const signer = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(node.signerAddress || ''));
      const peerReady = peerCount >= requiredPeers;
      // Hard freeze is intentionally based only on DURABLE pre-freeze qualification.
      // Live sync and live peer count are sampled outside consensus and can legitimately
      // become stale while Bootstrap A is still moving. Requiring either here recreates
      // a moving-target barrier. Both are checked per candidate by the atomic FINAL proof.
      const qualified = !!(ack && signer && maturity.ready && durable.ready);
      return { node, pubkey, ack, signer, maturity, durable, liveSync, voteSynced, canonicalTuple, observationAge, candidateLag, peerCount, peerReady, qualified };
    })
    .sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
  const qualified = rows.filter(r => r.qualified);
  return {
    target,
    managed: managed.length,
    usable: usable.length,
    qualified: qualified.length,
    ready: usable.length >= target && qualified.length >= target,
    requiredPeers,
    rows
  };
}

function singletonStockAcquisitionOpen(state, hpContext, localIsUnl, committedUnl = null) {
  if (!state || state.phase !== 'growing' || !hpContext || !localIsUnl ||
      hpContext.publicKey !== state.bootstrapPubkey) return false;
  const unl = Array.isArray(committedUnl)
    ? normalizePubkeyList(committedUnl)
    : (typeof hpContext.getContractUnl === 'function' ? normalizePubkeyList(hpContext.getContractUnl()) : []);
  const bootstrapKey = cleanString(state.bootstrapPubkey || '', 256).toLowerCase();
  if (unl.length !== 1 || !bootstrapKey || !unl.includes(bootstrapKey)) return false;
  const pool = bootstrapDiskPoolStatus(state);
  // Bootstrap A is the sole validator here. Let stock EverPocket own acquisition
  // completely until the five-node managed fleet exists; pre-UNL candidates can
  // safely HPFS-catch A's changing state because they have no consensus vote.
  return pool.usable < pool.target;
}
function currentUnlPubkeys(run) {
  // Consensus membership must come from the committed HotPocket contract config.
  // ClusterContext and ctx.unl are runtime/materialized views and may lag for the
  // first execution after a live config patch. Never let that transient lag pick
  // a different replicated control-flow branch on different validators.
  if (run && Array.isArray(run.committedUnl)) return normalizePubkeyList(run.committedUnl);
  if (run && run.hpContext && Array.isArray(run.hpContext.__everSmartNodeCommittedUnl)) {
    return normalizePubkeyList(run.hpContext.__everSmartNodeCommittedUnl);
  }
  if (!run || !run.clusterContext || typeof run.clusterContext.getClusterUnlNodes !== 'function') return [];
  return normalizePubkeyList(run.clusterContext.getClusterUnlNodes().map(n => n && n.pubkey));
}
function samePubkeySet(a, b) {
  return JSON.stringify(normalizePubkeyList(a)) === JSON.stringify(normalizePubkeyList(b));
}

// Bootstrap membership changes are handled entirely through committed config.
// AutoCluster does not restart Bootstrap A as part of the singleton->full switch.
function armValidatorStabilization(run, current, prior, reason) {
  const state = run.state, lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
  const now = normalizePubkeyList(current), before = normalizePubkeyList(prior);
  const beforeSet = new Set(before), nowSet = new Set(now);
  const added = now.filter(k => !beforeSet.has(k));
  const removed = before.filter(k => !nowSet.has(k));
  const requiredCleanLedgers = VALIDATOR_STABILIZATION_CLEAN_LEDGERS;
  state.unlSnapshot = now;
  state.stabilization = {
    active: true, reason: cleanString(reason || 'validator-set-change', 160),
    startedAtLcl: lcl, lastCleanLcl: null, cleanLedgers: 0,
    requiredCleanLedgers,
    targetUnlPubkeys: now, addedPubkeys: added, removedPubkeys: removed, completedAtLcl: null
  };
  saveState(state);
  console.log(`AutoCluster: validator-set stabilization ARMED at LCL ${lcl || '?'} (${before.length}->${now.length} UNL; added=${added.length}, removed=${removed.length}). External acquisitions/extensions/signer work are paused until ${requiredCleanLedgers} clean committed ledgers confirm the new set.`);
}
async function validatorStabilizationPreflight(ctx) {
  const state = loadState();
  if (!state || !state.enabled || !state.clusterAddress || !state.managedImage) return false;
  if (!ctx || ctx.readonly || typeof ctx.getConfig !== 'function') return false;

  // FIRST AutoCluster action on every consensus execution: keep HotPocket's
  // threshold aligned to the managed signer quorum ratio. This happens before
  // local-health refresh, EverPocket/Xahau initialization, acquisition, or any
  // membership work. The temporary Bootstrap-A validator does not change the
  // ratio: 3-of-5 managed signers means a 60% HotPocket threshold throughout.
  const thresholdCfg = await ctx.getConfig();
  thresholdCfg.mesh = thresholdCfg.mesh && typeof thresholdCfg.mesh === 'object' ? thresholdCfg.mesh : {};
  thresholdCfg.mesh.peer_discovery = thresholdCfg.mesh.peer_discovery && typeof thresholdCfg.mesh.peer_discovery === 'object' ? thresholdCfg.mesh.peer_discovery : {};
  thresholdCfg.npl = thresholdCfg.npl && typeof thresholdCfg.npl === 'object' ? thresholdCfg.npl : {};
  thresholdCfg.consensus = thresholdCfg.consensus && typeof thresholdCfg.consensus === 'object' ? thresholdCfg.consensus : {};
  const peerModeChanged = thresholdCfg.mesh.peer_discovery.enabled !== false;
  const nplModeChanged = thresholdCfg.npl.mode !== 'public';
  const consensusModeChanged = thresholdCfg.consensus.mode !== 'public';
  if (peerModeChanged || nplModeChanged || consensusModeChanged) {
    thresholdCfg.mesh.peer_discovery.enabled = false;
    // Public consensus lets a non-UNL follower inject an ordinary user input
    // through its own local HotPocket doorway. NPL remains public for post-UNL
    // signer coordination, but pre-UNL readiness no longer depends on NPL.
    thresholdCfg.consensus.mode = 'public';
    thresholdCfg.npl.mode = 'public';
    await ctx.updateConfig(thresholdCfg);
    console.log(`AutoCluster: GROWTH TRANSPORT MODE committed at LCL ${Number(ctx.lclSeqNo)||'?'}: mesh.peer_discovery.enabled=false consensus.mode=public npl.mode=public. Pre-UNL readiness uses signed sidecar user-input relay; this execution is otherwise sterile.`);
    return true;
  }
  const desiredSignerThreshold = signerMatchedBootstrapThreshold(state);
  const currentSignerThreshold = readConsensusThreshold(thresholdCfg);
  if (currentSignerThreshold !== desiredSignerThreshold) {
    setConsensusThreshold(thresholdCfg, desiredSignerThreshold);
    await ctx.updateConfig(thresholdCfg);
    state.bootstrapNormalConsensusThreshold = desiredSignerThreshold;
    state.bootstrapGrowthConsensusThreshold = desiredSignerThreshold;
    saveState(state);
    console.log(`AutoCluster: SIGNER-MATCHED CONSENSUS threshold submitted BEFORE lifecycle work at LCL ${Number(ctx.lclSeqNo)||'?'}: ${currentSignerThreshold}% -> ${desiredSignerThreshold}% = floor(${Number(state.signerQuorum)||1}/${Number(state.targetManagedNodes)||1}*100). This execution is otherwise sterile.`);
    return true;
  }
  if (state.phase === 'awaiting-bootstrap-signerlist') return false;

  // This guard intentionally runs BEFORE XrplContext/EvernodeContext/ClusterContext
  // initialization. ClusterContext.init() may perform lease-extension/reconciliation
  // work, which is unsafe on the very first execution after a UNL config patch commits.
  // HotPocket's committed contract config is already available directly from ctx, so
  // use that as the authoritative membership view and keep the whole execution sterile
  // while a validator-set change is being proven stable.
  const cfg = await ctx.getConfig();
  const current = readContractUnlFromConfig(cfg);
  if (!current.length) return false;
  const prior = normalizePubkeyList(state.unlSnapshot);
  const lcl = Number(ctx.lclSeqNo) || null;

  const arm = (before, reason) => {
    const prev = normalizePubkeyList(before);
    const beforeSet = new Set(prev), nowSet = new Set(current);
    const added = current.filter(k => !beforeSet.has(k));
    const removed = prev.filter(k => !nowSet.has(k));
    const requiredCleanLedgers = VALIDATOR_STABILIZATION_CLEAN_LEDGERS;
    state.unlSnapshot = current;
    state.stabilization = {
      active: true, reason: cleanString(reason || 'validator-set-change', 160),
      startedAtLcl: lcl, lastCleanLcl: null, cleanLedgers: 0,
      requiredCleanLedgers,
      targetUnlPubkeys: current, addedPubkeys: added, removedPubkeys: removed, completedAtLcl: null
    };
    saveState(state);
    console.log(`AutoCluster: validator-set PRE-FLIGHT fence ARMED at LCL ${lcl || '?'} (${prev.length}->${current.length} UNL; added=${added.length}, removed=${removed.length}). This execution will do no Xahau/Evernode init, extension, signer, acquisition, health refresh, or admin-input work. ${requiredCleanLedgers} clean committed ledger(s) are required before the next membership step.`);
  };

  // Migration/baseline safety. Streaming bootstrap never pauses merely because
  // the snapshot was absent on upgrade/redeploy; adopt the committed bootstrap
  // set as baseline and continue. Other expanded sets retain conservative fencing.
  if (!prior.length) {
    state.unlSnapshot = current;
    if (state.phase === 'growing' && current.includes(state.bootstrapPubkey)) {
      state.stabilization = null;
      saveState(state);
      console.log(`AutoCluster: STREAMING BOOTSTRAP adopted ${current.length}-validator committed baseline at LCL ${lcl || '?'} with no stabilization pause.`);
      return false;
    }
    if (current.length > 1) {
      arm([], 'existing validator-set baseline');
      return true;
    }
    saveState(state);
    return false;
  }

  if (!samePubkeySet(prior, current)) {
    const transition = normalizePromotionTransition(state.promotionTransition);
    if (transition && current.includes(transition.pubkey) && !prior.includes(transition.pubkey)) {
      transition.phase = 'awaiting-active';
      transition.membershipObservedAtLcl = lcl || transition.membershipObservedAtLcl;
      state.promotionTransition = transition;
      console.log(`AutoCluster: promotion transition observed ${cleanString(transition.pubkey,80)} in committed UNL at LCL ${lcl || '?'}. Legacy transition marker observed; fresh bootstrap now uses committed-ledger progress instead of post-join candidate proof.`);
    }

    const beforeSet = new Set(prior), nowSet = new Set(current);
    const added = current.filter(k => !beforeSet.has(k));
    const removed = prior.filter(k => !nowSet.has(k));
    const membershipCommand = normalizeMembershipCommand(state.membershipCommand);
    if (membershipCommand) {
      const addCommitted = membershipCommand.operation === 'add' && current.includes(membershipCommand.pubkey) && !prior.includes(membershipCommand.pubkey);
      const removeCommitted = membershipCommand.operation === 'remove-bootstrap' && !current.includes(membershipCommand.pubkey) && prior.includes(membershipCommand.pubkey);
      const swapCommitted = membershipCommand.operation === 'swap-bootstrap' && current.includes(membershipCommand.pubkey) && !prior.includes(membershipCommand.pubkey) && !current.includes(state.bootstrapPubkey) && prior.includes(state.bootstrapPubkey) && current.length === prior.length;
      const demoteCommitted = membershipCommand.operation === 'demote-managed' && !current.includes(membershipCommand.pubkey) && prior.includes(membershipCommand.pubkey) && current.includes(state.bootstrapPubkey) && current.length === prior.length - 1;
      if (addCommitted || removeCommitted || swapCommitted || demoteCommitted) {
        const label = membershipCommand.operation === 'add' ? 'ADD_UNL' : (membershipCommand.operation === 'swap-bootstrap' ? 'SWAP_BOOTSTRAP' : (membershipCommand.operation === 'demote-managed' ? 'DEMOTE_MANAGED' : 'REMOVE_UNL(A)'));
        console.log(`AutoCluster: HotPocket ${label} command COMMITTED at LCL ${lcl || '?'} for ${cleanString(membershipCommand.pubkey,24)}. Clearing command intent.`);
        state.membershipCommand = null;
      }
    }
    const streamingBootstrapAdd = state.phase === 'growing' && current.includes(state.bootstrapPubkey) && added.length === 1 && removed.length === 0;
    state.unlSnapshot = current;
    if (streamingBootstrapAdd) {
      // Restore the proven old sequencing rule: after each one-at-a-time bootstrap
      // membership patch, fence the entire contract before lifecycle/admin work and
      // require clean committed ledgers from the expanded validator set. This does
      // not require candidates to be on the same LCL before admission.
      arm(prior, 'bootstrap UNL membership changed');
      console.log(`AutoCluster: BOOTSTRAP membership ${prior.length}->${current.length} committed at LCL ${lcl || '?'}; ${VALIDATOR_STABILIZATION_CLEAN_LEDGERS} clean committed ledgers are required before the next ADD_UNL may be armed.`);
      return true;
    }

    // Autonomous repair/final Bootstrap-A retirement use the same conservative
    // multi-ledger stabilization fence.
    arm(prior, 'UNL membership changed');
    return true;
  }

  const stab = normalizeStabilization(state.stabilization);
  if (!stab || !stab.active) return false;
  if (!samePubkeySet(stab.targetUnlPubkeys, current)) {
    arm(stab.targetUnlPubkeys, 'UNL changed while stabilizing');
    return true;
  }

  // Count at most once per committed LCL. If this execution ever diverges, its
  // increment cannot become the next shared state, so this is a consensus-backed
  // clean-ledger counter rather than a wall-clock assumption.
  if (stab.lastCleanLcl !== lcl) {
    stab.cleanLedgers += 1;
    stab.lastCleanLcl = lcl;
  }
  state.stabilization = stab;
  state.unlSnapshot = current;

  if (stab.cleanLedgers >= stab.requiredCleanLedgers) {
    stab.active = false;
    stab.completedAtLcl = lcl;
    saveState(state);
    console.log(`AutoCluster: validator-set PRE-FLIGHT stabilization COMPLETE at LCL ${lcl || '?'} after ${stab.cleanLedgers}/${stab.requiredCleanLedgers} sterile committed ledgers. External work may resume on the NEXT ledger.`);
    return true;
  }

  saveState(state);
  console.log(`AutoCluster: validator-set PRE-FLIGHT stabilization ${stab.cleanLedgers}/${stab.requiredCleanLedgers} at LCL ${lcl || '?'}. Entire contract execution remains fenced from external/lifecycle work.`);
  return true;
}

function validatorStabilizationGate(run) {
  const state = run.state, current = currentUnlPubkeys(run), prior = normalizePubkeyList(state.unlSnapshot);
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;

  // The preflight normally catches committed membership changes before begin().
  // Keep this in-tick gate conservative as defense in depth: bootstrap additions
  // are never allowed to bypass the clean-ledger stabilization sequence.
  const streamingBootstrap = state.phase === 'growing' && current.includes(state.bootstrapPubkey);

  // Migration safety: a singleton Bootstrap-A baseline may be adopted directly.
  // Any already-expanded set is fenced before lifecycle work resumes.
  if (!prior.length) {
    state.unlSnapshot = current;
    if (streamingBootstrap && current.length === 1) {
      state.stabilization = null;
      saveState(state);
      return false;
    }
    if (current.length > 1) {
      armValidatorStabilization(run, current, [], 'existing validator-set baseline');
      return true;
    }
    saveState(state);
    return false;
  }

  if (!samePubkeySet(prior, current)) {
    armValidatorStabilization(run, current, prior, streamingBootstrap ? 'bootstrap UNL membership changed' : 'UNL membership changed');
    return true;
  }

  const stab = normalizeStabilization(state.stabilization);
  if (!stab || !stab.active) return false;

  // The target set must stay byte-for-byte identical throughout stabilization.
  // If membership moves again, restart from zero.
  if (!samePubkeySet(stab.targetUnlPubkeys, current)) {
    armValidatorStabilization(run, current, stab.targetUnlPubkeys, 'UNL changed while stabilizing');
    return true;
  }

  // Count at most one confirmation per LCL. This mutation only survives if the
  // HotPocket ledger closes successfully, making the counter a deterministic
  // committed-ledger health signal rather than a wall-clock timer.
  if (stab.lastCleanLcl !== lcl) {
    stab.cleanLedgers += 1;
    stab.lastCleanLcl = lcl;
  }
  state.stabilization = stab;
  state.unlSnapshot = current;
  if (stab.cleanLedgers >= stab.requiredCleanLedgers) {
    stab.active = false;
    stab.completedAtLcl = lcl;
    saveState(state);
    console.log(`AutoCluster: validator-set stabilization COMPLETE at LCL ${lcl || '?'} after ${stab.cleanLedgers}/${stab.requiredCleanLedgers} clean committed ledgers. External AutoCluster work may resume on the next ledger.`);
    // Deliberately defer one more time: never perform an irreversible external
    // action in the same execution that declares the stabilization gate complete.
    return true;
  }
  saveState(state);
  console.log(`AutoCluster: validator-set stabilization ${stab.cleanLedgers}/${stab.requiredCleanLedgers} clean committed ledgers at LCL ${lcl || '?'}. External AutoCluster work remains paused.`);
  return true;
}
function signerListComparable(list) {
  return (list || []).map(x => ({ account: String(x.account), weight: Number(x.weight || 0) }))
    .sort((a, b) => a.account.localeCompare(b.account));
}
function sameSignerList(a, b) {
  const aa = signerListComparable(a), bb = signerListComparable(b);
  return JSON.stringify(aa) === JSON.stringify(bb);
}
function errText(e) {
  if (e == null) return '';
  if (typeof e === 'string' || typeof e === 'number' || typeof e === 'boolean') return cleanString(e, 512);
  const parts = [];
  const add = v => { const t = cleanString(v, 256); if (t && !parts.includes(t)) parts.push(t); };
  try {
    add(e.message); add(e.code); add(e.resultCode); add(e.engine_result); add(e.error); add(e.error_message);
    if (e.result && typeof e.result === 'object') {
      add(e.result.engine_result); add(e.result.resultCode); add(e.result.code); add(e.result.error); add(e.result.error_message);
      if (e.result.meta && typeof e.result.meta === 'object') add(e.result.meta.TransactionResult);
    }
    if (e.details && typeof e.details === 'object') {
      add(e.details.engine_result); add(e.details.resultCode); add(e.details.code); add(e.details.error); add(e.details.error_message);
      if (e.details.meta && typeof e.details.meta === 'object') add(e.details.meta.TransactionResult);
    }
    if (e.cause && e.cause !== e) add(errText(e.cause));
    if (!parts.length) add(JSON.stringify(e));
  } catch {}
  return cleanString(parts.length ? parts.join(' | ') : String(e), 512);
}
function ledgerResultCode(value) {
  const seen = new Set();
  const walk = (v, depth = 0) => {
    if (v == null || depth > 5) return null;
    if (typeof v === 'string') {
      const m = v.match(/\b(?:tes|tec|tef|ter|tem)[A-Z0-9_]+\b/i);
      return m ? m[0] : null;
    }
    if (typeof v !== 'object' || seen.has(v)) return null;
    seen.add(v);
    const keys = ['engine_result','resultCode','TransactionResult','code'];
    for (const k of keys) {
      if (typeof v[k] === 'string' && /^(?:tes|tec|tef|ter|tem)[A-Z0-9_]+$/i.test(v[k])) return v[k];
    }
    for (const k of ['result','details','meta','data','cause','error']) {
      const found = walk(v[k], depth + 1);
      if (found) return found;
    }
    for (const x of Object.values(v)) {
      const found = walk(x, depth + 1);
      if (found) return found;
    }
    return null;
  };
  return walk(value);
}
function submissionHash(value, fallbackTx = null) {
  const seen = new Set();
  const walk = (v, depth = 0) => {
    if (!v || depth > 5) return null;
    if (typeof v !== 'object' || seen.has(v)) return null;
    seen.add(v);
    for (const k of ['hash','tx_hash','txHash']) {
      const x = cleanString(v[k] || '', 256);
      if (/^[A-Fa-f0-9]{64}$/.test(x)) return x.toUpperCase();
    }
    for (const k of ['result','details','tx_json','tx','transaction','data']) {
      const x = walk(v[k], depth + 1);
      if (x) return x;
    }
    return null;
  };
  return walk(value) || walk(fallbackTx);
}
function submissionLastLedgerSequence(value, fallbackTx = null) {
  const seen = new Set();
  const walk = (v, depth = 0) => {
    if (!v || depth > 5) return null;
    if (typeof v !== 'object' || seen.has(v)) return null;
    seen.add(v);
    for (const k of ['lastLedgerSequence','LastLedgerSequence','last_ledger_sequence']) {
      const n = Number(v[k]);
      if (Number.isFinite(n) && n > 0) return n;
    }
    for (const k of ['result','details','tx_json','tx','transaction','data']) {
      const n = walk(v[k], depth + 1);
      if (n) return n;
    }
    return null;
  };
  return walk(value) || walk(fallbackTx);
}
function fundingError(text) { return /(insufficient|reserve|unfunded|balance|tecINSUF|tecUNFUNDED|tecNO_LINE|trust.?line|not enough.*xah|not enough.*evr)/i.test(String(text || '')); }
function transientAcquireError(e, text = errText(e)) {
  const t = String(text || '');
  if (e && e.retryAcquireSameHost === true) return true;
  if (/tefPAST_SEQ|terQUEUED|telCAN_NOT_QUEUE|telINSUF_FEE_P/i.test(t)) return true;
  return /ECONN|ENET|EHOST|ETIMEDOUT|EAI_AGAIN|socket|websocket|connect(?:ion)?|timed?\s*out|temporar(?:y|ily)|unavailable|network|server.*busy|too many requests|429|502|503|504/i.test(t);
}
function validateBootstrapSignerFile(state) {
  const keyPath = path.resolve(process.cwd(), '..', `${state.clusterAddress}.key`);
  if (!fs.existsSync(keyPath)) {
    throw new Error(`BOOTSTRAP_SIGNER_KEY_MISSING: expected ${state.bootstrapSignerAddress || 'unknown'} in ../${state.clusterAddress}.key on Bootstrap A.`);
  }
  let signer;
  try { signer = JSON.parse(fs.readFileSync(keyPath, 'utf8')); }
  catch (e) {
    throw new Error(`BOOTSTRAP_SIGNER_KEY_INVALID_JSON: ../${state.clusterAddress}.key exists but cannot be parsed as JSON (${errText(e)}).`);
  }
  if (!signer || !signer.account || !signer.secret) {
    throw new Error(`BOOTSTRAP_SIGNER_KEY_INCOMPLETE: ../${state.clusterAddress}.key must contain account and secret fields.`);
  }
  if (signer.account !== state.bootstrapSignerAddress) {
    throw new Error(`BOOTSTRAP_SIGNER_KEY_ACCOUNT_MISMATCH: state expects ${state.bootstrapSignerAddress || 'unknown'} but ../${state.clusterAddress}.key contains ${signer.account || 'unknown'}.`);
  }
  try {
    const kp = require('ripple-keypairs');
    const pair = kp.deriveKeypair(signer.secret);
    const derived = kp.deriveAddress(pair.publicKey);
    if (derived !== signer.account) throw new Error(`secret derives ${derived}`);
  } catch (e) {
    throw new Error(`BOOTSTRAP_SIGNER_KEY_SECRET_MISMATCH: ../${state.clusterAddress}.key has an invalid signer secret or it does not derive account ${signer.account} (${errText(e)}).`);
  }
  return signer;
}
function managedSignerVaultPath(state) {
  return path.resolve(process.cwd(), '..', `${state.clusterAddress}.managed-signer.json`);
}
function validateManagedSignerKey(signer, label = 'managed signer') {
  if (!signer || !signer.account || !signer.secret) throw new Error(`${label} is incomplete.`);
  if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(signer.account))) throw new Error(`${label} has invalid account ${cleanString(signer.account,96)}.`);
  const kp = require('ripple-keypairs');
  const pair = kp.deriveKeypair(String(signer.secret));
  const derived = kp.deriveAddress(pair.publicKey);
  if (derived !== signer.account) throw new Error(`${label} secret derives ${derived}, expected ${signer.account}.`);
  return { account:String(signer.account), secret:String(signer.secret) };
}
function readManagedSignerVault(state) {
  const file = managedSignerVaultPath(state);
  if (!fs.existsSync(file)) return null;
  try { return validateManagedSignerKey(JSON.parse(fs.readFileSync(file, 'utf8')), `managed signer vault ${path.basename(file)}`); }
  catch (e) {
    console.log(`AutoCluster: MANAGED SIGNER VAULT INVALID at ${path.basename(file)}: ${cleanString(errText(e),220)}.`);
    return null;
  }
}
function writeManagedSignerVault(state, signer) {
  const clean = validateManagedSignerKey(signer, 'generated managed signer');
  const file = managedSignerVaultPath(state);
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ schemaVersion:1, account:clean.account, secret:clean.secret }, null, 2), { mode:0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch (_) {}
  return clean;
}
function ensureManagedSignerVault(run) {
  const existing = readManagedSignerVault(run.state);
  if (existing) return existing;
  const ms = run.xrplContext && run.xrplContext.multiSigner;
  // If a valid active EverPocket signer already exists (for example after an
  // upgrade), back it up into the durable AutoCluster vault. During the strict
  // bootstrap signing fence xrplContext is intentionally absent, so generate the
  // same XRPL/Xahau keypair directly without initializing EverPocket or an RPC.
  if (ms && typeof ms.getSigner === 'function') {
    const active = ms.getSigner();
    if (active && active.account && active.secret) return writeManagedSignerVault(run.state, active);
  }
  let generated = null;
  if (ms && typeof ms.generateSigner === 'function') generated = ms.generateSigner();
  else {
    const kp = require('ripple-keypairs');
    const secret = kp.generateSeed();
    const pair = kp.deriveKeypair(secret);
    generated = { account:kp.deriveAddress(pair.publicKey), secret };
  }
  const saved = writeManagedSignerVault(run.state, generated);
  console.log(`AutoCluster: durable managed signer vault created for local validator ${cleanString(run.hpContext && run.hpContext.publicKey || '',80)} account=${saved.account}. It is NOT activated in EverPocket until this account is visible in the validated Xahau SignerList.`);
  return saved;
}
function activateManagedSignerVaultIfOnLedger(state, hpContext, xrplContext) {
  if (!state || !hpContext || !xrplContext || hpContext.publicKey === state.bootstrapPubkey) return false;
  const disk = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const local = cleanString(hpContext.publicKey || '',256).toLowerCase();
  const node = disk && Array.isArray(disk.nodes) ? disk.nodes.find(n => n && cleanString(n.pubkey || '',256).toLowerCase() === local) : null;
  if (!node || !node.isUnl || !node.signerAddress) return false;
  const expected = String(node.signerAddress);
  const list = typeof xrplContext.getSignerList === 'function' ? xrplContext.getSignerList() : null;
  const visible = !!(list && Array.isArray(list.signerList) && list.signerList.some(s => s && s.account === expected));
  if (!visible) return false;
  const ms = xrplContext.multiSigner;
  if (!ms || typeof ms.getSigner !== 'function' || typeof ms.setSigner !== 'function') return false;
  const active = ms.getSigner();
  if (active && active.account === expected && active.secret) return true;
  const vault = readManagedSignerVault(state);
  if (!vault) {
    console.log(`AutoCluster: CRITICAL MANAGED_SIGNER_SECRET_MISSING local=${cleanString(hpContext.publicKey,80)} expected=${expected}. The validated Xahau SignerList contains this account, but this node has no durable private signer vault. It cannot contribute treasury signature weight.`);
    return false;
  }
  if (vault.account !== expected) {
    console.log(`AutoCluster: CRITICAL MANAGED_SIGNER_VAULT_MISMATCH local=${cleanString(hpContext.publicKey,80)} expected=${expected} vault=${vault.account}. Refusing to activate the wrong private key.`);
    return false;
  }
  ms.setSigner(vault);
  const activated = ms.getSigner();
  if (!activated || activated.account !== expected) {
    console.log(`AutoCluster: CRITICAL MANAGED_SIGNER_ACTIVATION_FAILED local=${cleanString(hpContext.publicKey,80)} expected=${expected}.`);
    return false;
  }
  console.log(`AutoCluster: MANAGED SIGNER ACTIVATED local=${cleanString(hpContext.publicKey,80)} signer=${expected} after validated on-ledger SignerList visibility. Future EverPocket payments can contribute signer weight.`);
  return true;
}
function hostEntry(state, address) { return state.hostQueue.find(h => h.address === address) || null; }
function leaseAmountFromOffer(evernodeContext, leaseOffer) {
  if (!leaseOffer || !leaseOffer.URI) throw new Error('LEASE_OFFER_URI_MISSING');
  const info = evernodeContext.decodeLeaseTokenUri(leaseOffer.URI);
  const amount = Number(info && info.leaseAmount);
  if (!Number.isFinite(amount) || amount < 0) throw new Error('LEASE_OFFER_PRICE_INVALID');
  return amount;
}
function enforceLeaseCap(state, evernodeContext, hostAddress, leaseOffer) {
  const cap = Number(state.maxLeaseAmountEvrPerMoment || 0);
  if (!(cap > 0)) throw new Error('MAX_LEASE_COST_NOT_CONFIGURED: set a hard EVR-per-moment cap before acquisition.');
  const amount = leaseAmountFromOffer(evernodeContext, leaseOffer);
  const item = hostEntry(state, hostAddress);
  if (item) item.lastObservedLeaseAmount = amount;
  if (amount > cap) {
    if (item) { item.status = 'price-rejected'; item.lastError = `Live lease price ${amount} EVR/moment exceeds hard cap ${cap}.`; }
    saveState(state);
    throw new Error(`MAX_LEASE_COST_EXCEEDED: host ${hostAddress} is ${amount} EVR/moment; cap is ${cap}.`);
  }
  return amount;
}

function clearLegacyEndpointLivenessState(state) {
  if (!state) return false;
  let changed = false;
  if (Array.isArray(state.endpointGrace) && state.endpointGrace.length) {
    state.endpointGrace = [];
    changed = true;
  }
  for (const item of state.hostQueue || []) {
    if (!item || item.status !== 'endpoint-stalled') continue;
    item.status = item.refId ? 'pending' : 'queued';
    item.lastError = null;
    changed = true;
    console.log(`AutoCluster: reopened legacy endpoint-stalled host ${item.address || 'unknown'}; contract-side WSS liveness is no longer a state gate.`);
  }
  if (changed) saveState(state);
  return changed;
}

function statusNameFromRaw(raw) {
  // EverPocket persists node status as a numeric enum in cluster.json
  // (0 NONE, 1 CREATED, 2 CONFIGURED, 3 ACKNOWLEDGED, 4 ADDED_TO_UNL).
  // Some library/code paths may expose symbolic strings instead, so normalize
  // both representations here and use this helper everywhere admission logic
  // evaluates maturity. Treating numeric 3 as the literal string "3" caused
  // Numeric status normalization remains for stock EverPocket compatibility.
  // Bootstrap admission requires the shared ACKNOWLEDGED state plus fresh READY.
  const value = raw && typeof raw === 'object' && Object.prototype.hasOwnProperty.call(raw, 'status') ? raw.status : raw;
  const numeric = Number(value);
  if (Number.isFinite(numeric)) {
    return ({ 0:'none', 1:'created', 2:'configured', 3:'acknowledged', 4:'added_to_unl' })[numeric] || String(numeric);
  }
  return cleanString(value || '', 64).toLowerCase();
}
function diskNodeStatus(node) { return statusNameFromRaw(node && node.status); }
function diskNodeIsUnl(node) { return !!(node && node.isUnl); }
function markClusterNodesUnl(clusterContext, pubkeys) {
  const wanted = new Set(normalizePubkeyList(pubkeys));
  if (!wanted.size) return 0;
  let changed = 0;
  try {
    const nodes = clusterContext && typeof clusterContext.getClusterNodes === 'function' ? clusterContext.getClusterNodes() : [];
    for (const node of nodes || []) {
      if (!node || !wanted.has(node.pubkey)) continue;
      if (!node.isUnl || Number(node.status) !== 4) changed++;
      node.isUnl = true;
      node.status = 4; // EverPocket ADDED_TO_UNL.
    }
  } catch {}

  // Also persist directly. ClusterContext.deinit() may serialize its own in-memory
  // copy later, so end() reapplies this after deinit as well for crash-safe parity
  // between EverPocket bookkeeping and the consensused contract.unl patch.
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const disk = readJson(clusterFile, null);
  if (disk && Array.isArray(disk.nodes)) {
    let diskChanged = false;
    for (const node of disk.nodes) {
      if (!node || !wanted.has(node.pubkey)) continue;
      if (!node.isUnl || Number(node.status) !== 4) diskChanged = true;
      node.isUnl = true;
      node.status = 4;
    }
    if (diskChanged) writeJson(clusterFile, disk);
  }
  return changed;
}
function hotPocketUserPubkey(user) {
  const v = user && (user.publicKey || user.pubkey || user.key || user.id);
  if (!v) return '';
  if (typeof v === 'string') return cleanString(v, 256).toLowerCase();
  try { return Buffer.from(v).toString('hex').toLowerCase(); } catch { return cleanString(v, 256).toLowerCase(); }
}
function acceptedReadyPubkeys(state) {
  const out = new Set();
  for (const r of normalizeCandidateReadiness(state && state.candidateReadiness)) {
    if (Number(r.readyHeartbeats || 0) >= CANDIDATE_READY_REQUIRED_HEARTBEATS) out.add(r.pubkey);
  }
  return out;
}
function freshReadyPubkeys(state, lcl) {
  const out = new Set();
  for (const r of normalizeCandidateReadiness(state.candidateReadiness)) {
    const proofs = Number(r.readyHeartbeats || 0);
    const soaked = !!(lcl && r.firstReadyAtLcl && Math.max(0, lcl - r.firstReadyAtLcl) >= CANDIDATE_PREMERGE_CLEAN_LEDGERS);
    // Used by autonomous one-at-a-time maintenance. Fresh bootstrap has a simpler
    // follower gate below: one accepted canonical READY from a node whose UNL is [A].
    if (soaked && proofs >= CANDIDATE_READY_REQUIRED_HEARTBEATS) out.add(r.pubkey);
  }
  return out;
}
function promotionProofStatus(state, pubkey, lcl, batch, freshness) {
  const key = cleanString(pubkey || '', 256).toLowerCase();
  const currentLcl = Number(lcl) || 0;
  const readiness = normalizeCandidateReadiness(state && state.candidateReadiness);
  const rec = readiness.find(r => String(r.pubkey || '').toLowerCase() === key) || null;
  const atomicBootstrap = !!(freshness && freshness.atomicBootstrap);
  // Fresh bootstrap deliberately skips the autonomous soak/cohort machinery, but
  // it MUST NOT latch READY forever. The candidate must have an accepted proof
  // and that exact proof must still be current at the ledger that publishes the
  // atomic UNL patch.
  const stickyPrepared = atomicBootstrap
    ? acceptedReadyPubkeys(state).has(pubkey)
    : freshReadyPubkeys(state, currentLcl).has(pubkey);
  const stab = normalizeStabilization(state && state.stabilization);
  const barrierLcl = Math.max(
    Number(batch && batch.armedAtLcl) || 0,
    Number(stab && stab.completedAtLcl) || 0
  );
  const observedAtLcl = Number(rec && rec.observedAtLcl) || 0;
  const candidateLcl = Number(rec && rec.candidateLcl) || 0;
  const peerCount = rec && rec.peerCount != null ? Math.max(0, Number(rec.peerCount) || 0) : 0;
  const candidateLagNow = currentLcl && candidateLcl ? currentLcl - candidateLcl : Number.POSITIVE_INFINITY;
  const proofLagAtObservation = observedAtLcl && candidateLcl ? observedAtLcl - candidateLcl : Number.POSITIVE_INFINITY;
  const observationAge = currentLcl && observedAtLcl ? currentLcl - observedAtLcl : Number.POSITIVE_INFINITY;
  const postBarrier = !!observedAtLcl && (!barrierLcl || observedAtLcl >= barrierLcl);
  const proofFreshLimit = Math.max(0, Number(freshness && freshness.proofFreshLcl) || CANDIDATE_PROMOTION_FRESH_LCL);
  const observationFreshLimit = Math.max(0, Number(freshness && freshness.observationFreshLcl) || CANDIDATE_PROMOTION_OBSERVATION_FRESH_LCL);
  const proofFreshAtObservation = Number.isFinite(proofLagAtObservation) && proofLagAtObservation >= 0 && proofLagAtObservation <= proofFreshLimit;
  const observationFreshNow = Number.isFinite(observationAge) && observationAge >= 0 && observationAge <= observationFreshLimit;
  const candidateFreshNow = Number.isFinite(candidateLagNow) && candidateLagNow >= 0 && candidateLagNow <= proofFreshLimit;
  const freshNow = proofFreshAtObservation && observationFreshNow && candidateFreshNow;
  // During fresh bootstrap the exact candidate LCL/hash was already checked
  // by Bootstrap A's node-local READY controller against A's private recent-ledger
  // witness before this authenticated consensus input was submitted. The shared
  // recentLedgers ring is intentionally empty while growing, so consulting it
  // here would make every accepted bootstrap proof immediately look non-canonical.
  const canonicalController = !!(rec && isCanonicalControllerTransport(rec.transport));
  const signedCanonicalTuple = !!(rec && candidateLcl && /^[0-9a-f]{64}$/.test(cleanString(rec.candidateHash || '', 256).toLowerCase()) &&
    Array.isArray(rec.proofHistory) && rec.proofHistory.some(p => Number(p && p.candidateLcl) === candidateLcl &&
      cleanString(p && p.candidateHash || '',256).toLowerCase() === cleanString(rec.candidateHash || '',256).toLowerCase()));
  const canonicalNow = atomicBootstrap
    ? (canonicalController ? signedCanonicalTuple : !!(rec && candidateLcl && /^[0-9a-f]{64}$/.test(cleanString(rec.candidateHash || '', 256).toLowerCase())))
    : (canonicalController ? signedCanonicalTuple : !!(rec && verifiedSharedRecentLedger(state, candidateLcl, rec.candidateHash)));
  const buildMatches = true; // diagnostic compatibility; build is not an admission gate
  return {
    ready: atomicBootstrap
      ? !!(stickyPrepared && freshNow && canonicalNow)
      : !!(stickyPrepared && postBarrier && freshNow && canonicalNow),
    stickyPrepared, postBarrier, freshNow, proofFreshAtObservation, observationFreshNow, candidateFreshNow, canonicalNow, buildMatches, atomicBootstrap,
    proofFreshLimit, observationFreshLimit,
    barrierLcl, observedAtLcl, candidateLcl, candidateLagNow, proofLagAtObservation, observationAge, peerCount,
    transport:cleanString(rec && rec.transport || '',32).toLowerCase() || null,
    lag:candidateLagNow
  };
}

function durableBootstrapQualificationStatus(state, pubkey) {
  const key = cleanString(pubkey || '', 256).toLowerCase();
  const rec = normalizeCandidateReadiness(state && state.candidateReadiness)
    .find(r => String(r.pubkey || '').toLowerCase() === key) || null;
  const readyHeartbeats = Number(rec && rec.readyHeartbeats || 0);
  const syncHeartbeats = Number(rec && rec.syncHeartbeats || 0);
  const candidateLcl = Number(rec && rec.candidateLcl || 0);
  const candidateHash = cleanString(rec && rec.candidateHash || '', 256).toLowerCase();
  const canonicalTransport = !!(rec && isCanonicalControllerTransport(rec.transport));
  const canonicalTupleRecorded = !!(rec && candidateLcl && /^[0-9a-f]{64}$/.test(candidateHash) &&
    Array.isArray(rec.proofHistory) && rec.proofHistory.some(p => Number(p && p.candidateLcl) === candidateLcl &&
      cleanString(p && p.candidateHash || '',256).toLowerCase() === candidateHash));
  return {
    ready: !!(readyHeartbeats >= CANDIDATE_READY_REQUIRED_HEARTBEATS &&
      syncHeartbeats >= SYNC_QUIESCENT_REQUIRED_EXECUTIONS && canonicalTransport && canonicalTupleRecorded),
    readyHeartbeats, syncHeartbeats, candidateLcl, candidateHash,
    peerCount: Math.max(0, Number(rec && rec.peerCount || 0)),
    transport: cleanString(rec && rec.transport || '',32).toLowerCase() || null,
    canonicalTransport, canonicalTupleRecorded
  };
}

function candidateFinalizationProtectionStatus(state, node, watch, lcl, now, currentUnl, admissionTimeoutMs) {
  const pubkey = cleanString(node && node.pubkey || '', 256).toLowerCase();
  const requiredPeers = requiredAdmissionPeers(Array.isArray(currentUnl) ? currentUnl.length : 0);
  const proof = promotionProofStatus(state, pubkey, lcl, null, {
    proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
    observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
    atomicBootstrap:true
  });
  const sync = syncQuiescenceStatus(state, pubkey, lcl);
  const peerCount = Math.max(0, Number(proof && proof.peerCount) || 0);
  const acknowledged = diskNodeStatus(node) === 'acknowledged';
  const qualifiedNow = !!(acknowledged && proof && proof.ready && isCanonicalControllerTransport(proof.transport) && sync && sync.ready && peerCount >= requiredPeers);
  let changed = false;

  if (qualifiedNow && watch && !Number(watch.finalizationQualifiedAt)) {
    const materializedAt = Number(watch.materializedAt || watch.firstSeenAt) || Number(now) || 0;
    const hardDeadlineAt = materializedAt + Math.max(1, Number(admissionTimeoutMs) || DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS);
    watch.finalizationQualifiedAt = Number(now) || null;
    watch.finalizationQualifiedAtLcl = Number(lcl) || null;
    // Always provide at least five minutes beyond the original hard deadline, or
    // five minutes from a late qualification if controller transport itself was
    // what delayed READY.  This is a one-shot deadline: it never slides forward.
    watch.finalizationGraceUntilAt = Math.max(Number(now) || 0, hardDeadlineAt) + CANDIDATE_FINALIZATION_GRACE_MS;
    changed = true;
  }

  const graceUntilAt = Number(watch && watch.finalizationGraceUntilAt) || 0;
  const graceActive = !!(graceUntilAt && Number(now) && Number(now) <= graceUntilAt);
  return { qualifiedNow, graceActive, graceUntilAt, requiredPeers, peerCount, proof, sync, acknowledged, changed };
}

// Bootstrap health must use the same CURRENT canonical proof rule as the
// temporary bootstrap bridge. Historical READY is not health: the candidate proof must
// still be recent, canonical, and recently observed by Bootstrap A.
function currentCanonicalBootstrapReadyPubkeys(state, lcl) {
  const out = new Set();
  const currentLcl = Number(lcl) || 0;
  for (const rec of normalizeCandidateReadiness(state && state.candidateReadiness)) {
    if (Number(rec.readyHeartbeats || 0) < CANDIDATE_READY_REQUIRED_HEARTBEATS) continue;
    const proof = promotionProofStatus(state, rec.pubkey, currentLcl, null, {
      proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
      observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
      atomicBootstrap:true
    });
    if (proof.ready) out.add(rec.pubkey);
  }
  return out;
}

// Health and promotion are intentionally different concepts during bootstrap.
// Any recently observed, advancing canonical ledger means the outside controller is
// still synchronized/following A, even if that candidate is several ledgers back
// or HotPocket's transient voteStatus says desync. This set is used ONLY to keep
// the readiness watchdog from replacing a live follower. Promotion still uses
// currentCanonicalBootstrapReadyPubkeys(), which requires 3 advances plus a
// current proof at the actual validator-set switch.
function currentCanonicalBootstrapReportingPubkeys(state, lcl) {
  const out = new Set();
  const currentLcl = Number(lcl) || 0;
  const maxObservationAge = Math.max(ATOMIC_BOOTSTRAP_READY_FRESH_LCL, ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL);
  for (const rec of normalizeCandidateReadiness(state && state.candidateReadiness)) {
    const candidateLcl = Number(rec && rec.candidateLcl) || 0;
    const observedAtLcl = Number(rec && rec.observedAtLcl) || 0;
    const candidateHash = cleanString(rec && rec.candidateHash || '', 256).toLowerCase();
    if (!candidateLcl || !observedAtLcl || !/^[0-9a-f]{64}$/.test(candidateHash)) continue;
    const age = currentLcl ? currentLcl - observedAtLcl : 0;
    if (age >= 0 && age <= maxObservationAge) out.add(rec.pubkey);
  }
  return out;
}

async function prepareOfficialPromotionPeerWarmup(ctx, state, hpContext, committedUnl, localIsUnl) {
  hpContext.__everSmartPromotionPeerPrepared = false;
  hpContext.__everSmartPromotionPeerWarmupThisExecution = false;
  if (!OFFICIAL_EVERPOCKET_MEMBERSHIP || !localIsUnl) return false;
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  if (!cluster || !Array.isArray(cluster.nodes) || !lcl) return false;
  const committedSet = new Set(normalizePubkeyList(committedUnl));
  // Never let a quarantined never-READY candidate head-of-line block peer warmup
  // for healthy ACKNOWLEDGED candidates. The non-official promotion path already
  // applies this same watchdog quarantine rule; official EverPocket must do so too.
  const stalledPubkeys = new Set(normalizeCandidateWatchdogs(state && state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => String(w.pubkey || '').toLowerCase()));
  const finalTarget = finalManagedTarget(state);
  const managedMaterialized = cluster.nodes.filter(n => n && String(n.pubkey || '').toLowerCase() !== String(state.bootstrapPubkey || '').toLowerCase());
  const usableManaged = managedMaterialized.filter(n => n && !stalledPubkeys.has(String(n.pubkey || '').toLowerCase()));
  // Bootstrap acquires the complete final managed fleet BEFORE any membership
  // promotion. All target managed validators may then join while A remains, so
  // target=5 temporarily reaches six validators (A + five managed).
  if (usableManaged.length < finalTarget) return false;
  if (committedSet.has(String(state.bootstrapPubkey || '').toLowerCase()) && committedSet.size >= finalTarget + 1) return false;

  const acknowledged = cluster.nodes
    .filter(n => n && !committedSet.has(String(n.pubkey || '').toLowerCase()) && !stalledPubkeys.has(String(n.pubkey || '').toLowerCase()) && diskNodeStatus(n) === 'acknowledged' && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')))
    .map(n => {
      const st = n.status && typeof n.status === 'object' ? n.status : {};
      return { node:n, ackLcl:Number(st.onLcl || n.acknowledgedOnLcl) || 0 };
    })
    .filter(x => x.ackLcl > 0)
    .sort((a,b)=>(a.ackLcl-b.ackLcl)||String(a.node.pubkey||'').localeCompare(String(b.node.pubkey||'')));

  // Bootstrap peer warmup is always one candidate at a time, including the
  // singleton 1->2 transition. Persist the selected candidate as an old-UNL peer
  // first, then require the normal committed warmup ledger before native promotion.
  const selected = acknowledged[0] || null;
  if (!selected) return false;
  const domain = normalizeEndpointHost(selected.node && selected.node.domain);
  const port = validPort(selected.node && (selected.node.peerPort || selected.node.meshPort));
  if (!domain || !port) return false;
  const endpoint = `${domain}:${port}`;
  const candidatePubkey = cleanString(selected.node && selected.node.pubkey || '', 256).toLowerCase();
  const nowMs = normalizeConsensusTimestampMs(ctx && ctx.timestamp) ||
    normalizeConsensusTimestampMs(hpContext && hpContext.timestamp) || 0;
  let warm = state && state.promotionPeerWarmup && typeof state.promotionPeerWarmup === 'object'
    ? state.promotionPeerWarmup : null;
  if (!warm || cleanString(warm.pubkey || '',256).toLowerCase() !== candidatePubkey) {
    warm = { pubkey:candidatePubkey, endpoint, startedAtMs:nowMs || null, startedAtLcl:lcl };
    state.promotionPeerWarmup = warm;
    saveState(state);
  }

  // Reassert the old-UNL -> candidate live transport BEFORE membership changes.
  // This is deliberately done while the candidate is still non-UNL.
  if (typeof hpContext.updatePeers === 'function') await hpContext.updatePeers([endpoint]);

  const cfg = await ctx.getConfig();
  if (!cfg.mesh || typeof cfg.mesh !== 'object') cfg.mesh = {};
  cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
  cfg.mesh.peer_discovery.enabled = false;
  const known = Array.isArray(cfg.mesh.known_peers) ? cfg.mesh.known_peers.map(v => canonicalLivePeer(v)).filter(Boolean) : [];
  const alreadyPersisted = known.includes(endpoint);
  if (!alreadyPersisted) {
    cfg.mesh.known_peers = [...new Set([...known, endpoint])].sort();
    await ctx.updateConfig(cfg);
    hpContext.__everSmartPromotionPeerWarmupThisExecution = true;
    hpContext.__everSmartNodeConfigTransitionThisExecution = true;
    console.log(`AutoCluster: EVERPOCKET NATIVE PEER-WARMUP at LCL ${lcl}: old UNL live-added candidate=${cleanString(selected.node.pubkey,24)} endpoint=${endpoint} and persisted it before any UNL change. One committed ledger with the persisted peer is required before release.`);
    return true;
  }
  const startedAtLcl = Number(warm && warm.startedAtLcl) || lcl;
  const warmAgeLcls = Math.max(0, lcl - startedAtLcl);
  if (warmAgeLcls < PROMOTION_PEER_WARMUP_LCLS) {
    console.log(`AutoCluster: EVERPOCKET NATIVE PEER-WARMUP HOLD at LCL ${lcl}: candidate=${cleanString(candidatePubkey,24)} age=${warmAgeLcls}/${PROMOTION_PEER_WARMUP_LCLS} committed ledger(s). Old UNL keeps the candidate live-peered while the mesh patch commits.`);
    return false;
  }
  hpContext.__everSmartPromotionPeerPrepared = true;
  return false;
}

function prepareOfficialEverPocketPromotionGate(state, hpContext) {
  const hold = extra => ({
    maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD,
    holding:true,
    officialEverPocket:true,
    ...(extra || {})
  });
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  if (!cluster || !Array.isArray(cluster.nodes) || !lcl) return hold({ reason:'cluster-state-not-ready' });

  const nodes = cluster.nodes;
  const committedUnl = normalizePubkeyList((hpContext && hpContext.__everSmartNodeCommittedUnl) || nodes.filter(diskNodeIsUnl).map(n => n && n.pubkey));
  const committedSet = new Set(committedUnl);
  const currentUnl = nodes.filter(n => n && committedSet.has(String(n.pubkey || '').toLowerCase()));
  const localPubkey = cleanString(hpContext && hpContext.publicKey || '', 256).toLowerCase();
  // Stock EverPocket executes ClusterContext.init() on both UNL and non-UNL
  // nodes. A candidate needs that init for peer setup and MATURED, but must
  // never be the actor that releases #checkForAcknowledged()->addToUnl().
  // Its own upstream comment explicitly says non-UNL nodes cannot perform
  // shared-state operations. Keep native promotion hard-held off-UNL.
  if (!localPubkey || !committedSet.has(localPubkey)) {
    return hold({ reason:'native-promotion-unl-only', currentUnl:currentUnl.length });
  }
  if (hpContext.__everSmartPromotionPeerWarmupThisExecution) {
    return hold({ reason:'native-promotion-peer-warmup-committing', currentUnl:currentUnl.length });
  }
  // A never-READY candidate may remain ACKNOWLEDGED in EverPocket while the
  // readiness watchdog has quarantined it. Do not allow that stale oldest ACK to
  // starve later candidates that have valid READY/SYNC proofs. Peer warmup and
  // promotion use this same filtered oldest-ACKNOWLEDGED ordering.
  const stalledPubkeys = new Set(normalizeCandidateWatchdogs(state && state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => String(w.pubkey || '').toLowerCase()));
  const finalTarget = finalManagedTarget(state);
  const managedMaterialized = nodes.filter(n => n && String(n.pubkey || '').toLowerCase() !== String(state.bootstrapPubkey || '').toLowerCase());
  const usableManaged = managedMaterialized.filter(n => n && !stalledPubkeys.has(String(n.pubkey || '').toLowerCase()));
  // Acquire the whole final managed fleet up front. Promotion begins only after
  // target healthy/materialized managed instances exist. While Bootstrap A remains,
  // the committed UNL may temporarily reach target+1 (A + every managed validator).
  if (usableManaged.length < finalTarget) {
    return hold({ reason:'waiting-full-upfront-managed-fleet', materialized:usableManaged.length, target:finalTarget, currentUnl:currentUnl.length });
  }
  if (committedSet.has(String(state.bootstrapPubkey || '').toLowerCase()) && committedUnl.length >= finalTarget + 1) {
    return hold({ reason:'bootstrap-bridge-complete', currentUnl:committedUnl.length, target:finalTarget + 1 });
  }

  const acknowledged = nodes
    .filter(n => n && !committedSet.has(String(n.pubkey || '').toLowerCase()) && !stalledPubkeys.has(String(n.pubkey || '').toLowerCase()) && diskNodeStatus(n) === 'acknowledged' && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')))
    .map(n => {
      const st = n.status && typeof n.status === 'object' ? n.status : {};
      return { node:n, ackLcl:Number(st.onLcl || n.acknowledgedOnLcl) || 0 };
    })
    .filter(x => x.ackLcl > 0)
    .sort((a,b) => (a.ackLcl - b.ackLcl) || String(a.node.pubkey || '').localeCompare(String(b.node.pubkey || '')));

  if (!acknowledged.length) {
    return hold({ reason:'waiting-native-acknowledged', currentUnl:currentUnl.length });
  }

  // Bootstrap promotion is one-at-a-time at every size, including singleton 1->2.
  // The newly expanded validator set must then pass the normal committed-ledger
  // stabilization fence before another candidate can be released.
  // Stock EverPocket oldest-ACKNOWLEDGED promotion behavior is used for every
  // bootstrap step. AutoCluster only releases one candidate after READY/SYNC/mesh.
  const selected = acknowledged[0];
  const pubkey = cleanString(selected.node.pubkey || '', 256).toLowerCase();
  const age = Math.max(0, lcl - selected.ackLcl);
  const ready = promotionProofStatus(state, pubkey, lcl, null, {
    proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
    observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
    atomicBootstrap:true
  });
  const sync = syncQuiescenceStatus(state, pubkey, lcl);
  const admissionSync = admissionSyncStatus(state, pubkey, lcl);
  // A non-UNL candidate needs redundant live transport before admission, but does
  // not need a full mesh to every CURRENT UNL member. Cap the admission gate at
  // two live peers once the singleton bridge has committed.
  const requiredPeers = requiredAdmissionPeers(currentUnl.length);
  const peerCount = Math.max(0, Number(ready && ready.peerCount) || 0);
  const maturityReady = age >= OFFICIAL_EVERPOCKET_MATURITY_LCLS;
  const safe = !!(maturityReady && hpContext.__everSmartPromotionPeerPrepared === true && ready && ready.ready && isCanonicalControllerTransport(ready.transport) && sync && sync.ready && admissionSync && admissionSync.ready && peerCount >= requiredPeers);

  if (!safe) {
    console.log(`AutoCluster: EVERPOCKET NATIVE PROMOTION HOLD at LCL ${lcl}: candidate=${cleanString(pubkey,24)} ackAge=${age}/${OFFICIAL_EVERPOCKET_MATURITY_LCLS} peerWarm=${hpContext.__everSmartPromotionPeerPrepared === true} ready=${!!(ready&&ready.ready)} prepared=${!!(ready&&ready.stickyPrepared)} fresh=${!!(ready&&ready.freshNow)} canonical=${!!(ready&&ready.canonicalNow)} transport=${ready&&ready.transport||'none'} candidateLag=${ready && Number.isFinite(ready.candidateLagNow) ? ready.candidateLagNow : '?'} observationAge=${ready && Number.isFinite(ready.observationAge) ? ready.observationAge : '?'} sync=${!!(sync&&sync.ready)} admissionSync=${!!(admissionSync&&admissionSync.ready)} exactTip=${!!(admissionSync&&admissionSync.exactAtObservation)} vote=${admissionSync&&admissionSync.voteStatus||'missing'} exactHeartbeats=${admissionSync&&admissionSync.heartbeats||0}/${ADMISSION_SYNC_REQUIRED_HEARTBEATS} sampledLag=${admissionSync&&admissionSync.candidateLag!=null?admissionSync.candidateLag:'?'} peers=${peerCount}/${requiredPeers}. ClusterContext.addToUnl remains blocked until hpcore itself is exactly synced.`);
    return hold({ reason:'native-promotion-proof-not-ready', pubkeys:[pubkey], ackAge:age, requiredPeers, peerCount });
  }

  // ClusterContext.#checkForAcknowledged uses: status.onLcl + threshold < lcl.
  // Threshold 7 therefore means 8 fully elapsed old-UNL ledgers.
  const nativeThreshold = Math.max(1, OFFICIAL_EVERPOCKET_MATURITY_LCLS - 1);
  console.log(`AutoCluster: EVERPOCKET NATIVE PROMOTION RELEASE at LCL ${lcl}: candidate=${cleanString(pubkey,24)} ACKNOWLEDGED age=${age}, READY+SYNC current, hpcore exact-tip synced ${admissionSync.heartbeats}/${ADMISSION_SYNC_REQUIRED_HEARTBEATS}, peers=${peerCount}/${requiredPeers}. Releasing stock ClusterContext.addToUnl one-at-a-time.`);
  return {
    maturityLclThreshold:nativeThreshold,
    holding:false,
    officialEverPocket:true,
    nativePromotion:true,
    pubkeys:[pubkey],
    ackAge:age,
    requiredPeers,
    peerCount
  };
}

function prepareCandidatePromotionGate(state, hpContext) {
  if (OFFICIAL_EVERPOCKET_MEMBERSHIP) return prepareOfficialEverPocketPromotionGate(state, hpContext);
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const cluster = readJson(clusterFile, null);
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const hold = extra => ({ maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD, holding:true, ...(extra || {}) });
  if (!cluster || !Array.isArray(cluster.nodes)) return hold();
  const nodes = cluster.nodes;
  const unl = nodes.filter(diskNodeIsUnl);
  const managed = nodes.filter(n => n && n.pubkey !== state.bootstrapPubkey);
  // A readiness-stalled node is still a paid/materialized instance, but it has
  // failed to prove canonical contract execution via VALIDATOR_READY. Keep it
  // quarantined outside UNL while allowing replacement acquisition. EverPocket
  // MATURED/ACKNOWLEDGED does not decide health replacement by itself, but ACKNOWLEDGED
  // is a mandatory admission prerequisite together with a fresh canonical READY proof.
  const stalledPubkeys = new Set(normalizeCandidateWatchdogs(state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => w.pubkey));
  const usableManaged = managed.filter(n => n && (diskNodeIsUnl(n) || !stalledPubkeys.has(n.pubkey)));
  const currentUnl = normalizePubkeyList(unl.map(n => n && n.pubkey));
  const snapshot = normalizePubkeyList(state.unlSnapshot);

  // If the preceding execution changed the UNL, do not allow another admission
  // in begin() before tick() gets a chance to arm the committed-ledger
  // stabilization gate. This closes a one-ledger chaining window.
  if (snapshot.length && !samePubkeySet(snapshot, currentUnl)) {
    return hold({ membershipChanged:true });
  }

  if (state.promotionBatch && state.promotionBatch.active && Array.isArray(state.promotionBatch.pubkeys) && state.promotionBatch.pubkeys.length > 0 && state.promotionBatch.pubkeys.every(k => nodes.some(n => n && n.pubkey === k && diskNodeIsUnl(n)))) {
    console.log(`AutoCluster: prepared validator admission step is committed (${state.promotionBatch.pubkeys.length} tracked node(s) now in UNL); clearing the pool. Fresh bootstrap has no post-join candidate gate; committed HotPocket progress gates the next admission.`);
    state.promotionBatch = null;
    saveState(state);
    return hold({ promotionCompleted:true });
  }

  // Keep stock EverPocket auto-promotion locked. Fresh bootstrap acquires and
  // qualifies continuously, admits exactly one peer-qualified validator per config
  // patch. The next committed ledger under the expanded UNL unlocks the next addition.
  // Autonomous repair may use
  // direct addToUnl. Native EverPocket ACKNOWLEDGED is again a mandatory
  // admission prerequisite, paired with the modern canonical READY/mesh proof.
  const stab = normalizeStabilization(state.stabilization);
  if (stab && stab.active) return hold({ stabilizing:true });

  let transition = normalizePromotionTransition(state.promotionTransition);
  if (transition && state.phase === 'growing' && transition.mode === 'bootstrap-membership-proof') {
    // alpha.37.99 compatibility: streaming bootstrap no longer uses a special
    // post-join candidate/VALIDATOR_ACTIVE proof. If HotPocket can execute this
    // ledger with the newly committed UNL, that membership set has already proven
    // it can make progress. Clear the legacy marker and continue immediately.
    state.promotionTransition = null;
    if (state.promotionBatch && state.promotionBatch.active) state.promotionBatch.submittedAtLcl = null;
    saveState(state);
    transition = null;
    console.log(`AutoCluster: cleared legacy bootstrap post-join transition at LCL ${lcl || '?'}; HotPocket committed-ledger progress is now the only post-add proof.`);
  }
  if (transition) {
    const transitionNode = nodes.find(n => n && n.pubkey === transition.pubkey) || null;
    if (transition.phase === 'lowering-threshold' || transition.phase === 'ready-to-stitch') {
      const jit = transitionNode ? promotionProofStatus(state, transition.pubkey, lcl, state.promotionBatch) : null;
      if (transitionNode && !transitionNode.isUnl && jit && jit.ready) {
        return { maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD, holding:false, promoting:true, directPromotion:true, transition:true, pubkeys:[transition.pubkey] };
      }
      return hold({ promotionTransition:true, transitionPhase:transition.phase, transitionPubkey:transition.pubkey });
    }
    return hold({ promotionTransition:true, transitionPhase:transition.phase, transitionPubkey:transition.pubkey });
  }

  // STOCK CLONE BOOTSTRAP: preserve serial provisioning, but never confuse
  // EverPocket maturity with HotPocket synchronization. Before the 1->2 (and each
  // later) validator-set patch, require all three independent facts:
  //   1) shared EverPocket status is ACKNOWLEDGED;
  //   2) Bootstrap A independently observed >=2 advancing canonical LCL/hash proofs
  //      and the latest proof is CURRENT at this exact execution;
  //   3) Bootstrap A observed at least one canonical candidate sample within lag<=24
  //      appears in that canonical proof history.
  if (STOCK_CLONE_BOOTSTRAP && state.phase === 'growing' && currentUnl.includes(state.bootstrapPubkey)) {
    const finalManagedTarget = Math.max(1, Number(state.targetManagedNodes) || 1);
    const bridgeTargetSize = finalManagedTarget + 1;
    const bridgeManagedTarget = finalManagedTarget;
    const managedAlreadyUnl = Math.max(0, currentUnl.filter(k => k !== state.bootstrapPubkey).length);
    if (usableManaged.length < finalManagedTarget) {
      console.log(`AutoCluster: FULL-FLEET ADMISSION WAIT: acquiring full managed fleet ${usableManaged.length}/${finalManagedTarget} before any UNL promotion; Bootstrap A remains singleton/bridge authority.`);
      return hold({ stockCloneBootstrap:true, waitingFullUpfrontFleet:true, usableManaged:usableManaged.length, finalManagedTarget });
    }
    if (currentUnl.length >= bridgeTargetSize || managedAlreadyUnl >= bridgeManagedTarget) {
      if (state.promotionBatch) { state.promotionBatch = null; saveState(state); }
      return hold({ stockCloneBootstrap:true, bridgeComplete:true, managedAlreadyUnl, finalManagedTarget });
    }
    const readinessRows = normalizeCandidateReadiness(state && state.candidateReadiness);
    const evaluatedStock = usableManaged
      .filter(n => n && !diskNodeIsUnl(n))
      .map(n => {
        const rec = readinessRows.find(r => cleanString(r && r.pubkey || '',256).toLowerCase() === cleanString(n.pubkey || '',256).toLowerCase()) || null;
        const observedAtLcl = Number(rec && rec.observedAtLcl) || 0;
        const candidateLag = rec && rec.candidateLag != null ? Number(rec.candidateLag) : Number.POSITIVE_INFINITY;
        const voteSynced = cleanString(rec && rec.voteStatus || '',32).toLowerCase() === 'synced';
        const peerCount = Math.max(0, Number(rec && rec.peerCount) || 0);
        return {
          node:n,
          status:diskNodeStatus(n),
          maturity:nodeMaturityStability(n, state, lcl),
          durable:durableBootstrapQualificationStatus(state, n.pubkey),
          observedAtLcl, candidateLag, voteSynced, peerCount,
          liveHint: !!(voteSynced && Number.isFinite(candidateLag) && candidateLag === 0 && peerCount >= requiredAdmissionPeers(currentUnl.length))
        };
      });
    // Once the upfront fleet has frozen replicated state, CURRENT READY/SYNC can no
    // longer be a selector prerequisite: refreshing those records would itself move
    // /state and make the candidate chase a new tip. Select only from durable
    // pre-freeze qualification here. Bootstrap A's root controller performs the
    // authoritative live exact-tip/SYNC/UNL/peer proof immediately before ADD_UNL.
    const qualifiedBase = evaluatedStock.filter(x => x.status === 'acknowledged' &&
      /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(x.node && x.node.signerAddress || '')) &&
      x.maturity.ready && x.durable.ready);
    const batchForSkip = normalizePromotionBatch(state && state.promotionBatch);
    const skipPubkey = batchForSkip && batchForSkip.skipUntilLcl && lcl < batchForSkip.skipUntilLcl ? batchForSkip.skipPubkey : null;
    let qualified = qualifiedBase.filter(x => !skipPubkey || cleanString(x.node && x.node.pubkey || '',256).toLowerCase() !== skipPubkey);
    if (!qualified.length) qualified = qualifiedBase; // never deadlock if every alternate is unavailable
    qualified.sort((a,b) =>
      Number(!!b.liveHint) - Number(!!a.liveHint) ||
      (Number(b.observedAtLcl)||0) - (Number(a.observedAtLcl)||0) ||
      String(a.node.pubkey).localeCompare(String(b.node.pubkey))
    );
    if (!qualified.length) {
      const summary = evaluatedStock.map(x => `${cleanString(x.node.pubkey,12)}:ack=${x.status==='acknowledged'} mature=${x.maturity.age}/${x.maturity.required} durableReady=${x.durable.ready} readyHb=${x.durable.readyHeartbeats}/${CANDIDATE_READY_REQUIRED_HEARTBEATS} syncHb=${x.durable.syncHeartbeats}/${SYNC_QUIESCENT_REQUIRED_EXECUTIONS}`).join(',');
      console.log(`AutoCluster: STOCK CLONE SAFE-WAIT at LCL ${lcl || '?'}: ${managedAlreadyUnl}/${finalManagedTarget} managed validator(s) in UNL; frozen-state admission selector requires ACKNOWLEDGED + signer + >=8 old-UNL stability ledgers + durable pre-freeze READY/SYNC qualification. Live exact-tip/SYNC/peer checks are deferred to the atomic FINAL proof. candidates=[${summary}]`);
      return hold({ stockCloneBootstrap:true, qualifying:true, managedAlreadyUnl, finalManagedTarget });
    }
    const chosen = qualified[0];
    console.log(`AutoCluster: STOCK CLONE FINAL-PROOF TARGET at LCL ${lcl || '?'}: selecting ${cleanString(chosen.node.pubkey,24)} for ${currentUnl.length}->${currentUnl.length + 1}; ACKNOWLEDGED=true MATURITY_STABLE=${chosen.maturity.age}/${chosen.maturity.required} durableReady=${chosen.durable.readyHeartbeats}/${CANDIDATE_READY_REQUIRED_HEARTBEATS} durableSync=${chosen.durable.syncHeartbeats}/${SYNC_QUIESCENT_REQUIRED_EXECUTIONS} liveHint=${chosen.liveHint}. A lagging candidate never globally blocks a different qualified candidate; FINAL proof is per-target and bounded by rotation.`);
    return {
      maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD,
      holding:false,
      promoting:true,
      directPromotion:true,
      incrementalBootstrap:true,
      stockCloneBootstrap:true,
      pubkeys:[chosen.node.pubkey]
    };
  }

  const ready = freshReadyPubkeys(state, lcl);
  const readyObserved = acceptedReadyPubkeys(state);
  const eligible = usableManaged.filter(n => !diskNodeIsUnl(n) && diskNodeStatus(n) === 'acknowledged' && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')) && ready.has(n.pubkey)).sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
  let batch = state.promotionBatch && state.promotionBatch.active ? state.promotionBatch : null;

  if (state.phase === 'growing') {
    // STREAMING BOOTSTRAP: acquisition and validator admission are independent
    // lanes. Missing or quarantined candidates keep acquisition/replacement open,
    // but they never block a different healthy candidate from joining the UNL.
    const targetCount = Math.max(1, Number(state.targetManagedNodes) || 1);
    if (managed.length < targetCount || usableManaged.length < targetCount) {
      console.log(`AutoCluster: STREAMING POOL ${managed.length}/${targetCount} materialized, ${usableManaged.length}/${targetCount} usable; admission stays open for every currently qualified candidate while acquisition/replacement continues.`);
    }

    // Retain every already-UNL managed validator, but DO NOT pre-select the remaining
    // target slots by pubkey. Replacement-first acquisition can legitimately leave
    // more healthy candidates than targetManagedNodes (for example 8 paid, 2 stalled,
    // 6 usable). Slicing the lexicographically first five created another head-of-line
    // deadlock: a stale candidate inside that slice could hold readyCount at 3/5 forever
    // while a sixth healthy candidate behind the slice kept sending canonical READY.
    //
    // Treat every healthy non-UNL managed candidate as a deterministic candidate pool.
    // targetManagedNodes limits how many managed validators may ultimately enter UNL;
    // it must not hide surplus healthy replacement capacity from admission.
    const managedUnl = usableManaged.filter(diskNodeIsUnl).sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
    const waiting = usableManaged.filter(n => !diskNodeIsUnl(n)).sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
    const currentGreen = currentCanonicalBootstrapReadyPubkeys(state, lcl);
    const prepared = waiting.filter(n => diskNodeStatus(n) === 'acknowledged' && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || '')) && currentGreen.has(n.pubkey)).sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey))); // native ACKNOWLEDGED + signed public signer identity + current canonical freshness
    const safeBootstrapUnlTarget = Math.max(1, targetCount); // Fixed-size bridge: Bootstrap A occupies one target slot.
    const safeSlotsNeeded = Math.max(0, safeBootstrapUnlTarget - currentUnl.length);

    // Bootstrap A is NOT an extra validator. For target=5 bootstrap admission stops
    // at A + four managed validators. The fifth managed instance is already
    // acquired and remains pre-UNL for the atomic handover swap.
    const bootstrapManagedTarget = bootstrapManagedUnlTarget(state);
    if (currentUnl.length >= safeBootstrapUnlTarget || managedUnl.length >= bootstrapManagedTarget) {
      if (batch) {
        state.promotionBatch = null;
        batch = null;
        saveState(state);
      }
      return hold({ acquisitionComplete:true, bootstrapUnlTargetReached:true, managedUnl:managedUnl.length, bootstrapManagedTarget, totalUnl:currentUnl.length, target:safeBootstrapUnlTarget });
    }

    // A batch is a sticky pool, not a fixed head-of-line queue. Candidates that
    // become PREPARED after the batch was armed may join the pool as long as
    // they are part of the deterministic targetManaged set. This lets a newly
    // healthy candidate replace a previously prepared candidate that later stops
    // producing canonical READY proofs, without changing the final target size.
    if (batch) {
      const existing = new Set(batch.pubkeys);
      const additions = prepared.map(n => n.pubkey).filter(k => !existing.has(k)).sort();
      if (additions.length) {
        batch.pubkeys = normalizePubkeyList([...batch.pubkeys, ...additions]);
        state.promotionBatch = batch;
        saveState(state);
        console.log(`AutoCluster: admission pool expanded with ${additions.length} newly PREPARED target candidate(s); stale prepared candidates no longer block healthier replacements.`);
      }
    }

    // Arm admission as soon as at least one materialized candidate has current
    // canonical READY. Acquisition of later managed nodes keeps running in the
    // same phase; the pool expands whenever another candidate becomes ready.
    if (!batch) {
      if (!waiting.length) return hold({ acquisitionComplete:managed.length >= targetCount, alreadyPromoted:managedUnl.length > 0 });
      if (!prepared.length) {
        const proofCount = waiting.filter(n=>readyObserved.has(n.pubkey)).length;
        console.log(`AutoCluster: STREAMING BOOTSTRAP waiting for an ACKNOWLEDGED + peer-qualified canonical candidate: ${proofCount}/${waiting.length} waiting candidate(s) have accepted READY history; acquisition remains active at ${managed.length}/${targetCount} managed lease(s).`);
        return hold({ qualifying:true, waiting:waiting.length, readyObserved:proofCount, ready:0, safeBootstrapTarget:safeBootstrapUnlTarget, safeSlotsNeeded });
      }
      batch = {
        active:true,
        armedAtLcl:lcl || null,
        submittedAtLcl:null,
        pubkeys:prepared.map(n=>n.pubkey).sort(),
        reason:'bootstrap: native ACKNOWLEDGED + canonical READY + peer mesh; add one validator with an UNL-only HotPocket patch'
      };
      state.promotionBatch = batch;
      saveState(state);
      console.log(`AutoCluster: ACK+READY+SYNC bootstrap admission pool ARMED at LCL ${lcl || '?'} with ${batch.pubkeys.length} CURRENT-ready candidate(s); acquisition=${managed.length}/${targetCount}. One peer-qualified validator may join now; the committed membership change will then require five clean ledgers before another addition.`);
    }
  } else if (state.phase === 'autonomous' && !batch) {
    // Only autonomous maintenance may arm a new one-at-a-time promotion outside
    // bootstrap growth. In particular, signing/ready-to-handover must not admit
    // the final candidate while Bootstrap A still occupies its UNL slot.
    if (eligible.length) {
      batch = { active:true, armedAtLcl:lcl || null, submittedAtLcl:null, pubkeys:[eligible[0].pubkey], reason:'fresh ready-candidate promotion' };
      state.promotionBatch = batch;
      saveState(state);
      console.log(`AutoCluster: validator promotion ARMED at LCL ${lcl || '?'} for ${cleanString(eligible[0].pubkey,80)} with >=${CANDIDATE_READY_REQUIRED_HEARTBEATS} verified ledger-sync heartbeat(s) and >=${CANDIDATE_PREMERGE_CLEAN_LEDGERS} clean pre-merge ledger(s).`);
    }
  }

  if (!batch) {
    if (readyObserved.size) console.log(`AutoCluster: holding ${readyObserved.size} candidate(s) with accepted canonical READY outside UNL; ${eligible.length} candidate(s) currently have enough verified/soaked ledger-sync proof for promotion.`);
    return hold({ eligible:eligible.length });
  }

  const pending = batch.pubkeys
    .map(k => nodes.find(n => n && n.pubkey === k) || null)
    .filter(n => n && !diskNodeIsUnl(n));
  if (!pending.length) {
    state.promotionBatch = null;
    saveState(state);
    return hold({ promotionCompleted:true });
  }

  // The prepared batch is a deterministic candidate pool, not a head-of-line
  // queue. A single candidate can disappear after becoming PREPARED (the real
  // alpha.37.23 failure was a candidate last observed at LCL 392 pinning the
  // queue at LCL 531+ while other candidates were actively sending READY). Pick
  // the lexicographically first candidate that is *currently* JIT-ready from the
  // previously committed readiness state. This remains deterministic across the
  // current UNL while allowing healthy candidates to rotate around a stale one.
  const orderedPending = pending.sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
  const evaluated = orderedPending.map(node => ({
    node,
    status: diskNodeStatus(node),
    stalled: stalledPubkeys.has(node.pubkey),
    jit: promotionProofStatus(
      state, node.pubkey, lcl, batch,
      state.phase === 'growing' && currentUnl.includes(state.bootstrapPubkey)
        ? { proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL, observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL, atomicBootstrap:true }
        : null
    ),
    sync: syncQuiescenceStatus(state, node.pubkey, lcl)
  }));
  const selectable = evaluated.filter(x => !x.stalled && x.status === 'acknowledged' && /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(x.node && x.node.signerAddress || '')) && x.jit.ready && (state.phase !== 'growing' || x.sync.ready));

  // Fresh bootstrap is deliberately simple: a managed validator-role candidate
  // first proves canonical HotPocket sync plus the live-peer threshold while it is
  // outside UNL. Admit exactly ONE pubkey by changing contract.unl and nothing
  // else in that config patch. There is no post-join candidate status or callback.
  // The very next committed ledger is the proof that the expanded HotPocket UNL
  // can make progress, and the next candidate may then be admitted.
  if (state.phase === 'growing' && currentUnl.includes(state.bootstrapPubkey)) {
    const finalManagedTarget = Math.max(1, Number(state.targetManagedNodes) || 1);
    const bridgeTargetSize = finalManagedTarget + 1;
    const bridgeManagedTarget = finalManagedTarget;
    const managedAlreadyUnl = Math.max(0, currentUnl.filter(k => k !== state.bootstrapPubkey).length);
    if (usableManaged.length < finalManagedTarget) {
      return hold({ promotionQueued:false, incrementalBootstrap:true, waitingFullUpfrontFleet:true, usableManaged:usableManaged.length, finalManagedTarget });
    }
    if (currentUnl.length >= bridgeTargetSize || managedAlreadyUnl >= bridgeManagedTarget) {
      return hold({ promotionQueued:false, incrementalBootstrap:true, bridgeComplete:true, managedAlreadyUnl, finalManagedTarget });
    }

    const requiredBootstrapPeers = requiredAdmissionPeers(currentUnl.length);
    const currentReady = selectable.slice().sort((a,b) =>
      (Number(b.jit.peerCount || 0) - Number(a.jit.peerCount || 0)) ||
      String(a.node.pubkey).localeCompare(String(b.node.pubkey))
    );
    const forceOverride = normalizeBootstrapMeshOverride(state.bootstrapMeshOverride);
    const forced = forceOverride && forceOverride.forcedPubkey
      ? evaluated.find(x => x && x.node && String(x.node.pubkey).toLowerCase() === forceOverride.forcedPubkey) || null
      : null;
    const forcedEligible = !!(forced && forceOverride && forceOverride.bypassAll === true);

    if (forceOverride && forceOverride.forcedPubkey && !forcedEligible) {
      console.log(`AutoCluster: FORCE-ADD target ${cleanString(forceOverride.forcedPubkey,24)} is not present in the current materialized candidate set; waiting only for the exact selected row to exist.`);
      return hold({ promotionQueued:true, incrementalBootstrap:true, forced:true, forcedPubkey:forceOverride.forcedPubkey, forcePrerequisiteWait:true, managedAlreadyUnl, finalManagedTarget });
    }

    if (!currentReady.length && !forcedEligible) {
      console.log(`AutoCluster: INCREMENTAL BOOTSTRAP WAIT at LCL ${lcl || '?'}: ${managedAlreadyUnl}/${finalManagedTarget} managed validator(s) are already in UNL, but no remaining ACKNOWLEDGED prepared candidate has CURRENT canonical READY + fresh runtime SYNC for the next ${currentUnl.length}->${currentUnl.length + 1} stitch.`);
      return hold({ promotionQueued:true, incrementalBootstrap:true, managedAlreadyUnl, finalManagedTarget, followersReady:0 });
    }

    const meshReady = currentReady.filter(x => Number(x.jit.peerCount || 0) >= requiredBootstrapPeers);
    if (!meshReady.length && !forcedEligible) {
      const meshSummary = currentReady.map(x => `${cleanString(x.node.pubkey,16)}:${Number(x.jit.peerCount || 0)}/${requiredBootstrapPeers}`).join(',');
      console.log(`AutoCluster: INCREMENTAL PRE-PROMOTION MESH WAIT at LCL ${lcl || '?'}: next stitch ${currentUnl.length}->${currentUnl.length + 1} needs one CURRENT-ready candidate with >=${requiredBootstrapPeers} live peer connection(s); newcomer admission is capped at two peers independent of signer quorum. candidates=[${meshSummary}]. Head admin may arm the one-shot FORCE for the next addition.`);
      return hold({ promotionQueued:true, incrementalBootstrap:true, followersReady:currentReady.length, meshReady:0, requiredBootstrapPeers, managedAlreadyUnl, finalManagedTarget, meshOverrideArmed:false });
    }

    const chosen = forcedEligible ? forced : meshReady[0];
    if (forcedEligible) {
      console.log(`AutoCluster: *** FORCE-ADD BEST VALIDATOR *** at LCL ${lcl || '?'}: ${cleanString(chosen.node.pubkey,24)} currentReady=${chosen.jit.ready} ack=${chosen.status} sync=${chosen.sync && chosen.sync.ready} peers=${Number(chosen.jit.peerCount || 0)}/${requiredBootstrapPeers}. Operator bypassAll is active for this exact stitch.`);
    } else {
      console.log(`AutoCluster: INCREMENTAL BOOTSTRAP ACK+READY+SYNC+MESH at LCL ${lcl || '?'}: selecting ${cleanString(chosen.node.pubkey,24)} with peers=${Number(chosen.jit.peerCount || 0)}/${requiredBootstrapPeers} for the next ${currentUnl.length}->${currentUnl.length + 1} validator stitch. After HotPocket commits the expanded UNL, ${VALIDATOR_STABILIZATION_CLEAN_LEDGERS} clean committed ledgers must complete before another candidate may be armed.`);
    }
    return {
      maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD,
      holding:false,
      promoting:true,
      directPromotion:true,
      batchPromotion:false,
      incrementalBootstrap:true,
      bootstrapMeshOverrideUsed:forcedEligible,
      forcedAdmission:forcedEligible,
      pubkeys:[chosen.node.pubkey]
    };
  }

  // Partial-upgrade recovery and autonomous maintenance retain the conservative
  // one-at-a-time path. Fresh alpha.37.43 bootstraps never enter this branch.
  const chosen = selectable.length ? selectable[0] : null;
  if (!chosen) {
    const head = evaluated[0];
    const lagText = head && Number.isFinite(head.jit.candidateLagNow) ? head.jit.candidateLagNow : 'unknown';
    const proofLagText = head && Number.isFinite(head.jit.proofLagAtObservation) ? head.jit.proofLagAtObservation : 'unknown';
    const observationAgeText = head && Number.isFinite(head.jit.observationAge) ? head.jit.observationAge : 'unknown';
    if (head) console.log(`AutoCluster: JIT admission pool waiting; no prepared candidate is currently stitch-safe at LCL ${lcl || '?'}. Oldest deterministic candidate ${cleanString(head.node.pubkey,80)} has status=${head.status || 'unknown'}, stalled=${head.stalled}, barrierLcl=${head.jit.barrierLcl || 0}, lastObserved=${head.jit.observedAtLcl || 0}, candidateLcl=${head.jit.candidateLcl || 0}, proofLag=${proofLagText}/${CANDIDATE_PROMOTION_FRESH_LCL}, observedAge=${observationAgeText}/${CANDIDATE_PROMOTION_OBSERVATION_FRESH_LCL}, candidateLagNow=${lagText}, canonical=${head.jit.canonicalNow}.`);
    return hold({ promotionQueued:true, waitingPubkey:head && head.node.pubkey || null, jitBarrier:true });
  }
  const next = chosen.node;
  if (orderedPending[0] && orderedPending[0].pubkey !== next.pubkey) {
    console.log(`AutoCluster: JIT admission ROTATED around stale candidate ${cleanString(orderedPending[0].pubkey,80)}; selecting fresh prepared candidate ${cleanString(next.pubkey,80)} at LCL ${lcl || '?'}.`);
  }

  return {
    maturityLclThreshold:PROMOTION_HOLD_MATURITY_THRESHOLD,
    holding:false,
    promoting:true,
    directPromotion:true,
    batchPromotion:false,
    pubkeys:[next.pubkey]
  };
}

function prepareMembershipOnlyClusterInit(state, hpContext, localIsUnl, authoritativeCommittedUnl = null) {
  const promotion = normalizePromotionBatch(state && state.promotionBatch);
  // IMPORTANT: the pre-init fence must use the exact same committed HotPocket UNL
  // authority as the rest of bootstrap control flow. hpContext.getContractUnl() is a
  // runtime/materialized EverPocket view and can lag the committed config by an
  // execution. Using that stale view here caused the membership fence to delete a
  // queued acquire operation while the later stock-acquisition check correctly saw
  // A as the sole validator.
  const committedUnl = normalizePubkeyList(Array.isArray(authoritativeCommittedUnl)
    ? authoritativeCommittedUnl
    : ((hpContext && Array.isArray(hpContext.__everSmartNodeCommittedUnl))
        ? hpContext.__everSmartNodeCommittedUnl
        : (hpContext && typeof hpContext.getContractUnl === 'function' ? hpContext.getContractUnl() : [])));
  const safeBootstrapTarget = finalManagedTarget(state);
  if (singletonStockAcquisitionOpen(state, hpContext, localIsUnl, committedUnl)) {
    // During A-only fleet fill, EverPocket's acquisition queue/state is authoritative.
    // Do not defer/mask/restore any EverPocket operation. Membership-only fencing
    // begins only after the complete usable managed fleet exists.
    console.log(`AutoCluster: SINGLETON ACQUIRE PRE-INIT BYPASS at LCL ${hpContext && hpContext.lclSeqNo || '?'} (${committedUnl.length}/${safeBootstrapTarget} validators): committed UNL confirms Bootstrap A is sole authority and fleet fill is incomplete; EverPocket operation queue is untouched.`);
    return null;
  }
  const clusterFile = path.resolve(process.cwd(), 'cluster.json');
  const operationsFile = path.resolve(process.cwd(), 'operations.json');
  const cluster = readJson(clusterFile, null);
  const hasMaterializedNonUnl = !!(cluster && Array.isArray(cluster.nodes) && cluster.nodes.some(n =>
    n && n.pubkey && n.pubkey !== (state && state.bootstrapPubkey) && !diskNodeIsUnl(n)
  ));
  // While a serial bootstrap candidate is materialized, BOTH A and the observer run
  // ClusterContext.init(), but background acquire/extend operations are masked. This
  // preserves EverPocket's deterministic cluster bookkeeping without allowing an
  // external Xahau operation to make only one copy's transition execution run long
  // or mutate state differently. The queue is restored before commit.
  const atomicMembershipWindow = !!(STOCK_CLONE_BOOTSTRAP && state && state.phase === 'growing' && hasMaterializedNonUnl);
  // Once the atomic A->full-set patch has committed, keep EverPocket's automatic
  // operation processor quiet all the way through signer/master handover. The
  // first alpha.37.46 full-set run proved that ClusterContext.init() can otherwise
  // immediately submit a lease-extension Payment before AutoCluster has even
  // advanced growing->signing. That long external operation can starve the brand
  // new 5-validator consensus round and strand it at 2/3 proposers. Signer work
  // remains explicit in AutoCluster.tick(); only background acquire/extend queues
  // are masked here until autonomous mode.
  const preHandoverQuietWindow = !!(localIsUnl && state && (((['growing','signing','ready-to-handover'].includes(state.phase)) && committedUnl.length >= safeBootstrapTarget) || state.phase === 'handover'));
  if (!atomicMembershipWindow && !preHandoverQuietWindow) return null;

  const operationsExisted = fs.existsSync(operationsFile);
  const operations = readJson(operationsFile, { operations: [] }) || { operations: [] };
  if (!Array.isArray(operations.operations)) operations.operations = [];

  // EverPocket ClusterContext.init() calls #checkForExtends() and then
  // #processOperations() before AutoCluster can reach tick(). During the fragile
  // bootstrap admission sequence that means a queued lease extension can submit
  // a Xahau Payment in the *same execution* that then calls addToUnl(). The new
  // validator did not participate in that external operation and can enter the
  // next UNL with a different /state hash. Temporarily make every current UNL
  // lease look fully extended and hide the persisted operation queue. Both are
  // restored before the execution commits; only external operation processing is
  // suppressed. Cluster/maturity bookkeeping and the deterministic addToUnl()
  // path still run normally.
  const originalTargets = {};
  let maskedTargets = 0;
  if (cluster && Array.isArray(cluster.nodes)) {
    for (const node of cluster.nodes) {
      if (!node || !node.pubkey || !node.isUnl) continue;
      const life = Number(node.lifeMoments);
      const target = Number(node.targetLifeMoments);
      if (!Number.isFinite(life) || !Number.isFinite(target) || target <= life) continue;
      originalTargets[String(node.pubkey)] = target;
      node.targetLifeMoments = life;
      maskedTargets++;
    }
    if (maskedTargets) writeJson(clusterFile, cluster);
  }

  const deferredOperations = operations.operations.slice();
  // Write an empty queue even when there are no current operations so the
  // ClusterContext constructor deterministically starts from a sterile queue.
  writeJson(operationsFile, { ...operations, operations: [] });

  const quietMode = atomicMembershipWindow ? 'MEMBERSHIP-ONLY' : 'PRE-HANDOVER QUIET';
  console.log(`AutoCluster: ${quietMode} pre-init fence active at LCL ${hpContext && hpContext.lclSeqNo || '?'} (${committedUnl.length}/${safeBootstrapTarget} validators); deferred ${deferredOperations.length} EverPocket operation(s) and masked ${maskedTargets} lease-extension target(s) before ClusterContext.init().`);
  return { clusterFile, operationsFile, operationsExisted, originalOperations: operations, originalTargets };
}

function restoreMembershipOnlyTargets(clusterContext, guard, persistDisk = false) {
  if (!guard || !guard.originalTargets) return;
  const targets = guard.originalTargets;
  try {
    const nodes = clusterContext && typeof clusterContext.getClusterNodes === 'function' ? clusterContext.getClusterNodes() : [];
    for (const node of nodes || []) {
      if (node && Object.prototype.hasOwnProperty.call(targets, String(node.pubkey))) node.targetLifeMoments = targets[String(node.pubkey)];
    }
  } catch {}
  if (persistDisk) {
    const disk = readJson(guard.clusterFile, null);
    if (disk && Array.isArray(disk.nodes)) {
      let changed = false;
      for (const node of disk.nodes) {
        const key = node && String(node.pubkey || '');
        if (key && Object.prototype.hasOwnProperty.call(targets, key) && Number(node.targetLifeMoments) !== Number(targets[key])) {
          node.targetLifeMoments = targets[key];
          changed = true;
        }
      }
      if (changed) writeJson(guard.clusterFile, disk);
    }
  }
}

function restoreMembershipOnlyOperations(guard) {
  if (!guard || !guard.operationsFile) return;
  // Restore the exact pre-fence filesystem shape. EverPocket may remove an empty
  // operations.json during ClusterContext.init(); if no queue file existed before
  // the fence, recreating it is both unnecessary and can fail while HotPocket is
  // rotating the state view. Leave it absent. Only restore a file that actually
  // existed before we masked the queue.
  if (!guard.operationsExisted) {
    try { fs.rmSync(guard.operationsFile, { force:true }); } catch {}
    return;
  }
  writeJson(guard.operationsFile, guard.originalOperations && typeof guard.originalOperations === 'object'
    ? guard.originalOperations
    : { operations: [] });
}


// alpha41 consensus-purity bridge -------------------------------------------------
// Once Bootstrap A has admitted the first managed validator, contract execution
// must stop depending on node-private signer files, external Xahau RPC timing,
// EverPocket operation queues, or host-local lifecycle observations.  The only
// allowed bootstrap mutation until the full bridge is assembled is an authenticated
// HotPocket user command that changes contract.unl.  Once the full fleet is
// qualified, READY/SYNC records are durable history only: refreshing them would
// move replicated state and defeat the hard quiescence window before admission.
function syncPureClusterUnlView(committedUnl) {
  const wanted = new Set(normalizePubkeyList(committedUnl));
  const file = path.resolve(process.cwd(), 'cluster.json');
  const disk = readJson(file, null);
  if (!disk || !Array.isArray(disk.nodes)) return false;
  let changed = false;
  for (const node of disk.nodes) {
    if (!node || !node.pubkey) continue;
    const next = wanted.has(String(node.pubkey).toLowerCase());
    if (!!node.isUnl !== next) {
      node.isUnl = next;
      changed = true;
    }
  }
  if (changed) writeJson(file, disk);
  return changed;
}

async function preparePurePostJoinMembershipIntent(ctx, state, hpContext, clusterContext) {
  // STOCK_CLONE_BOOTSTRAP uses an out-of-band atomic FINAL-proof controller.
  // Never publish a replicated ADD intent before the proof: doing so advances A's
  // state/LCL and makes every pre-UNL follower chase a moving target. The root
  // controller selects a durably-qualified candidate from the frozen state, samples
  // its exact current LCL/hash/UNL/mesh, and submits proof + ADD_UNL as ONE input.
  if (STOCK_CLONE_BOOTSTRAP) {
    const legacy = normalizeMembershipCommand(state.membershipCommand);
    if (legacy && legacy.operation === 'add' && !Number(legacy.submittedAtLcl)) {
      state.membershipCommand = null;
      state.promotionBatch = null;
      saveState(state);
      console.log(`AutoCluster: ATOMIC FINAL-PROOF MIGRATION cleared legacy unsubmitted ADD intent ${cleanString(legacy.pubkey,24)} at LCL ${Number(hpContext && hpContext.lclSeqNo)||'?'}; one stable catch-up ledger may follow, then proof-first ADD_UNL resumes without a replicated pre-intent.`);
    }

    // Full temporary bridge completion must be reachable INSIDE the permanent
    // consensus-purity fence. The final managed validator is admitted normally,
    // producing A + target managed validators. Only after that complete bridge is
    // committed do we freeze the managed signer set and enter signer preparation.
    const cfg = await ctx.getConfig();
    const currentUnl = readContractUnlFromConfig(cfg);
    const local = cleanString(hpContext && hpContext.publicKey || '',256).toLowerCase();
    const bootstrap = cleanString(state.bootstrapPubkey || '',256).toLowerCase();
    const target = finalManagedTarget(state);
    const bridgeTarget = bootstrapBridgeUnlTarget(state);
    if (state.phase === 'growing' && currentUnl.includes(local) && currentUnl.includes(bootstrap) && currentUnl.length === bridgeTarget) {
      const handover = fixedSizeBootstrapHandoverSet({ state, hpContext, clusterContext, committedUnl:currentUnl });
      if (handover.bridgeReady) {
        if (!handover.ready) {
          const signed = handover.unlManaged.filter(n => /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || ''))).length;
          console.log(`AutoCluster: TEMPORARY BRIDGE handover fence waiting for managed signer identities ${signed}/${handover.target}; UNL already contains Bootstrap A + all ${handover.target} managed validators.`);
        } else {
          const keep = new Set(handover.pubkeys);
          const currentSet = new Set(handover.currentUnl);
          const surplusPreUnl = handover.all.filter(n => {
            const pk = cleanString(n && n.pubkey || '',256).toLowerCase();
            return pk && !currentSet.has(pk) && !keep.has(pk);
          });
          state.promotionBatch = null;
          state.handoverSignerPubkeys = handover.pubkeys;
          state.phase = 'signing';
          saveState(state);
          console.log(`AutoCluster: HANDOVER READY INSIDE PURITY FENCE at LCL ${Number(hpContext && hpContext.lclSeqNo)||'?'}: UNL=${handover.currentUnl.length}/${bridgeTarget} (Bootstrap A + ${handover.bridgeManagedTarget} managed), signer identities=${handover.pubkeys.length}/${handover.target}${surplusPreUnl.length?`, surplus-pre-UNL-retained=${surplusPreUnl.length}`:''}. Entering signing; final membership step will remove Bootstrap A only.`);
          return true;
        }
      }
    }
    return false;
  }

  const gate = prepareCandidatePromotionGate(state, hpContext);
  if (!(gate && gate.directPromotion && gate.incrementalBootstrap === true && Array.isArray(gate.pubkeys) && gate.pubkeys.length)) return false;

  const selectedPubkey = gate.pubkeys[0];
  const selectedNode = clusterContext.getClusterNodes().find(n => n && n.pubkey === selectedPubkey) || null;
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const jit = promotionProofStatus(state, selectedPubkey, lcl, state.promotionBatch, {
    proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
    observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
    atomicBootstrap:true
  });
  const durable = durableBootstrapQualificationStatus(state, selectedPubkey);
  const forceOverride = normalizeBootstrapMeshOverride(state.bootstrapMeshOverride);
  const syncNow = syncQuiescenceStatus(state, selectedPubkey, lcl);
  const forcedAdmission = !!(selectedNode && forceOverride && forceOverride.forcedPubkey === selectedPubkey && forceOverride.bypassAll === true);
  // In stock-clone bootstrap, the replicated state is intentionally frozen before
  // admission. Durable READY/SYNC history selects the candidate; CURRENT readiness
  // is proven out-of-band and carried atomically in the ADD_UNL input.
  if (!selectedNode || selectedNode.isUnl || (STOCK_CLONE_BOOTSTRAP ? !durable.ready : (!syncNow.ready || !jit.ready))) return false;

  const cfg = await ctx.getConfig();
  const currentUnl = readContractUnlFromConfig(cfg);
  const targetManaged = Math.max(1, Number(state.targetManagedNodes) || 1);
  const bridgeTarget = targetManaged + 1;
  if (!currentUnl.includes(state.bootstrapPubkey) || currentUnl.length >= bridgeTarget || currentUnl.includes(selectedPubkey)) return false;

  const requiredPeers = requiredAdmissionPeers(currentUnl.length);
  if (!STOCK_CLONE_BOOTSTRAP && Number(jit.peerCount || 0) < requiredPeers && !forcedAdmission) return false;

  // Stock-clone live peer count is checked by the FINAL proof immediately before
  // submission; consulting a stale replicated READY record here would reintroduce
  // the frozen-state deadlock.

  const existing = normalizeMembershipCommand(state.membershipCommand);
  if (existing && (existing.operation !== 'add' || existing.pubkey !== selectedPubkey)) {
    console.log(`AutoCluster: alpha41 pure membership path is waiting for existing ${existing.operation}:${cleanString(existing.pubkey,24)}.`);
    return false;
  }
  if (!existing) {
    if (diskNodeStatus(selectedNode) !== 'acknowledged' && !forcedAdmission) {
      console.log(`AutoCluster: pure membership path refused ${cleanString(selectedPubkey,24)} because native EverPocket status=${diskNodeStatus(selectedNode) || 'unknown'}; ACKNOWLEDGED is required before normal ADD_UNL intent.`);
      return false;
    }
    state.membershipCommand = makeBootstrapAddMembershipCommand(
      state, selectedNode, lcl,
      `ACKNOWLEDGED + durable pre-freeze qualification; atomic live FINAL proof required for temporary-bridge ADD_UNL ${currentUnl.length}->${currentUnl.length + 1}`
    );
    if (state.promotionBatch && state.promotionBatch.active) {
      state.promotionBatch.reason = `alpha41 consensus-purity: awaiting authenticated HotPocket ADD_UNL command for ${selectedPubkey}`;
    }
    saveState(state);
    console.log(`AutoCluster: CONSENSUS-PURITY ADD_UNL COMMAND REQUESTED at LCL ${lcl || '?'} for ${cleanString(selectedPubkey,24)} (${currentUnl.length}->${currentUnl.length + 1}). No Xahau/EverPocket lifecycle context is initialized in this execution.`);
    return true;
  }
  return false;
}



function completedNativeAcquireResponse(evernodeContext, item) {
  if (!evernodeContext || !item) return null;
  const acquired = typeof evernodeContext.getAcquiredNodes === 'function' ? (evernodeContext.getAcquiredNodes() || []) : [];
  const wantedHost = normalizeHostAddress(item.address);
  const wantedRef = cleanString(item.refId || item.acquireRequestTxId || '', 256) || null;
  return acquired.find(a => {
    if (!a) return false;
    const ref = cleanString(a.refId || a.acquireRefId || '', 256) || null;
    const host = normalizeHostAddress(a.host);
    return !!((wantedRef && ref && wantedRef === ref) || (wantedHost && host && wantedHost === host));
  }) || null;
}

function nativeAcquireTransactionFinality(xrplContext, item) {
  if (!xrplContext || !item) return { settled:false, validated:null, pending:null, resultCode:null, refId:null };
  const refId = cleanString(item.refId || item.acquireRequestTxId || '', 256) || null;
  if (!refId) return { settled:false, validated:null, pending:null, resultCode:null, refId:null };
  let validated = null;
  let pending = null;
  try {
    if (typeof xrplContext.getValidatedTransaction === 'function') validated = xrplContext.getValidatedTransaction(refId) || null;
  } catch (_) {}
  try {
    if (!validated && typeof xrplContext.getValidatedTransactions === 'function') {
      const wanted = String(refId).toUpperCase();
      validated = (xrplContext.getValidatedTransactions() || []).find(t => t && String(t.hash || t.id || '').toUpperCase() === wanted) || null;
    }
  } catch (_) {}
  try {
    if (typeof xrplContext.getPendingTransactions === 'function') {
      const wanted = String(refId).toUpperCase();
      pending = (xrplContext.getPendingTransactions() || []).find(t => t && String(t.hash || t.id || '').toUpperCase() === wanted) || null;
    }
  } catch (_) {}
  const resultCode = cleanString(validated && (validated.resultCode || validated.code || validated.engine_result) || '', 64) || null;
  return { settled:!!validated, validated, pending, resultCode, refId };
}

// Only an UNSETTLED Xahau acquisition transaction serializes the next purchase.
// Once the transaction is validated, host provisioning is asynchronous and must
// not block another host. A successful tx waits independently for native
// AcquireSuccess; a failed tx is reconciled by pendingAcquisitionWatchdog().
function unresolvedNativeAcquireResponses(state, xrplContext, evernodeContext, materializedHosts = new Set()) {
  if (!state || !Array.isArray(state.hostQueue)) return [];
  return state.hostQueue.filter(item => {
    if (!item || !['attempting','pending'].includes(item.status)) return false;
    const host = normalizeHostAddress(item.address);
    if (host && materializedHosts.has(host)) return false;
    if (completedNativeAcquireResponse(evernodeContext, item)) return false;
    const finality = nativeAcquireTransactionFinality(xrplContext, item);
    // Ledger finality, not EverPocket's transient pending view, releases the
    // purchase pipeline. tesSUCCESS then remains on the durable provisioning watch.
    if (finality.settled) return false;
    return true;
  });
}

// The ordinary provisioning watchdog runs from tick(), but stock-clone lockstep can
// deliberately return from begin() before tick() while any materialized non-UNL
// candidate exists. Therefore the native acquire-response fence needs its OWN
// deterministic timeout check here. This never deletes EverPocket pending/message-key
// material: timed-out purchases become provisioning-stalled late-watch records, so a
// delayed AcquireSuccess can still be recovered by recoverCompletedAcquisitions().
function releaseExpiredNativeAcquireResponseFences(state, ctx, hpContext, evernodeContext, materializedHosts = new Set()) {
  if (!state || !Array.isArray(state.hostQueue)) return [];
  const now = consensusNowMs({ ctx, hpContext });
  const lcl = Number(hpContext && hpContext.lclSeqNo) || 0;
  const released = [];
  let changed = false;

  for (const item of state.hostQueue) {
    if (!item || !['attempting','pending'].includes(item.status)) continue;
    const host = normalizeHostAddress(item.address);
    if (host && materializedHosts.has(host)) continue;
    if (completedNativeAcquireResponse(evernodeContext, item)) continue;

    if (!item.pendingSinceAt && now) {
      item.pendingSinceAt = now;
      changed = true;
    }
    if (!item.pendingSinceLcl && lcl) {
      item.pendingSinceLcl = Number(item.lastAttemptLcl) || lcl;
      changed = true;
    }

    const age = now && item.pendingSinceAt ? Math.max(0, now - Number(item.pendingSinceAt)) : 0;
    const ageLcl = lcl && item.pendingSinceLcl ? Math.max(0, lcl - Number(item.pendingSinceLcl)) : 0;
    if (age < PENDING_ACQUISITION_TIMEOUT_MS && ageLcl < PENDING_ACQUISITION_TIMEOUT_LCL) continue;

    const priorStatus = item.status;
    item.status = 'provisioning-stalled';
    item.nativeStage = 'acquire-response-timeout-late-watch';
    item.nativeStageAtLcl = lcl || null;
    item.lastError = `Native Evernode provisioning did not complete within ${PENDING_ACQUISITION_TIMEOUT_MS / 60000} minutes / ${PENDING_ACQUISITION_TIMEOUT_LCL} committed ledgers. Original refId/message-key state is preserved for late recovery and this host will not be repurchased automatically.`;
    item.pendingSinceAt = null;
    item.pendingSinceLcl = null;
    if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
    if (state.blocker && state.blocker.host === item.address && ['acquire-node','acquisition-endpoint'].includes(state.blocker.stage)) state.blocker = null;
    state.waitingForHosts = false;
    state.nextAcquireAfterLcl = Math.max(Number(state.nextAcquireAfterLcl) || 0, lcl + ACQUISITION_SETTLE_CLEAN_LEDGERS);
    released.push({ item, priorStatus, age, ageLcl });
    changed = true;
  }

  if (changed) saveState(state);
  for (const row of released) {
    console.log(`AutoCluster: PROVISIONING TIMEOUT host=${row.item.address} prior=${row.priorStatus} refId=${row.item.refId || row.item.acquireRequestTxId || 'unknown'} age=${Math.floor(row.age/1000)}s/${row.ageLcl}lcl; moved to provisioning-stalled late-watch. Next queued host may purchase after LCL ${state.nextAcquireAfterLcl || lcl}. Late AcquireSuccess recovery remains enabled.`);
  }
  return released;
}

function bootstrapLockstepMaintenancePlan(state, ctx, hpContext, xrplContext, clusterContext, evernodeContext) {
  if (!STOCK_CLONE_BOOTSTRAP || !state || state.phase !== 'growing' || !hpContext || !clusterContext) {
    return { candidatePresent:false, mode:null };
  }
  const now = consensusNowMs({ ctx, hpContext });
  const lcl = Number(hpContext.lclSeqNo) || 0;
  const candidates = clusterContext.getClusterNodes()
    .filter(n => {
      if (!n || !n.pubkey || n.pubkey === state.bootstrapPubkey || diskNodeIsUnl(n)) return false;
      const host = normalizeHostAddress(n.host);
      const item = host ? state.hostQueue.find(h => h && h.address === host) : null;
      // ClusterManager.removeNode() is persisted at deinit; during the drop ledger
      // the old object can still be visible through getClusterNodes(). Do not plan
      // a second termination for an instance already marked dropped.
      return !(item && item.status === 'dropped');
    })
    .sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
  if (!candidates.length) return { candidatePresent:false, mode:null };

  // This clock MUST exist inside the lockstep path itself. alpha53.13 created it
  // only from tick(), but begin() deliberately returned before tick() whenever a
  // pre-UNL candidate existed. That made both the 5-minute hard timeout and the
  // candidate-pool refill and hard-timeout policy unreachable forever.
  const candidateKeys = new Set(candidates.map(n => n.pubkey));
  const normalizedWatches = normalizeCandidateWatchdogs(state.candidateWatchdogs);
  let watches = normalizedWatches.filter(w => w && candidateKeys.has(w.pubkey));
  let changed = watches.length !== normalizedWatches.length;
  for (const node of candidates) {
    const host = normalizeHostAddress(node.host);
    const item = host ? hostEntry(state, host) : null;
    // LOCKSTEP-LOCAL HOST RECONCILIATION: once ClusterContext already contains a
    // materialized candidate, a durable hostQueue row that still says
    // attempting/pending is stale bookkeeping, not an unresolved acquisition.
    // The ordinary reconcileHostQueue() normally fixes this, but qualification
    // intentionally fences tick() before that code can run. Normalize it here so
    // the stale row cannot block candidate-pool refill forever.
    if (item && ['attempting','pending'].includes(item.status)) {
      item.status = 'acquired';
      item.pendingSinceAt = null;
      item.pendingSinceLcl = null;
      item.lastError = null;
      item.nativeStage = 'materialized';
      item.nativeStageAtLcl = lcl || item.nativeStageAtLcl || null;
      if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
      changed = true;
      console.log(`AutoCluster: LOCKSTEP HOST RECONCILE materialized candidate ${cleanString(node.pubkey,24)} host=${host || 'unknown'} promoted stale hostQueue ${cleanString(item.address,48)} to acquired so it cannot consume a candidate-pool provisioning slot.`);
    }
    let w = watches.find(x => x.pubkey === node.pubkey);
    if (!w) {
      w = {
        pubkey:cleanString(node.pubkey,256), host,
        refId:cleanString(item && item.refId || '',256) || null,
        firstSeenAt:now || null, firstSeenLcl:lcl || null,
        materializedAt:now || null, materializedAtLcl:lcl || null,
        staleSinceAt:null, staleSinceLcl:null,
        stalledAt:null, stalledAtLcl:null, kickedAt:null
      };
      watches.push(w); changed = true;
      console.log(`AutoCluster: LOCKSTEP watchdog clock started for ${cleanString(node.pubkey,80)} at LCL ${lcl || '?'}; pool=${Math.max(1, Math.min(MAX_CANDIDATE_POOL_SIZE, Number(state.candidatePoolSize)||DEFAULT_CANDIDATE_POOL_SIZE))} hard-drop=${Math.floor((Number(state.candidateAdmissionTimeoutMs)||DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS)/1000)}s.`);
    } else {
      if (!w.firstSeenAt && now) { w.firstSeenAt = now; w.firstSeenLcl = w.firstSeenLcl || lcl || null; changed = true; }
      if (!w.materializedAt && now) { w.materializedAt = w.firstSeenAt || now; w.materializedAtLcl = w.firstSeenLcl || lcl || null; changed = true; }
    }
  }
  watches.sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey)));
  if (changed) { state.candidateWatchdogs = watches; saveState(state); }

  const membership = normalizeMembershipCommand(state.membershipCommand);
  if (membership) return { candidatePresent:true, mode:null, watches };

  const hardMs = Number(state.candidateAdmissionTimeoutMs) || DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS;
  const readiness = normalizeCandidateReadiness(state.candidateReadiness);
  const rows = candidates.map(node => {
    const w = watches.find(x => x.pubkey === node.pubkey) || null;
    const born = Number(w && (w.materializedAt || w.firstSeenAt)) || now || 0;
    const age = now && born ? Math.max(0, now - born) : 0;
    const r = readiness.find(x => x.pubkey === node.pubkey) || null;
    const candidateLcl = Number(r && r.candidateLcl) || 0;
    const headLag = lcl && candidateLcl ? Math.max(0, lcl - candidateLcl) : 0;
    return { node, w, born, age, candidateLcl, headLag };
  }).sort((a,b)=>(a.born-b.born)||String(a.node.pubkey).localeCompare(String(b.node.pubkey)));
  const oldest = rows[0] || null;
  if (!oldest) return { candidatePresent:true, mode:null, watches };

  const submittedForOldest = !!(membership && membership.pubkey === oldest.node.pubkey && Number(membership.submittedAtLcl) > 0);
  const currentUnlForFinalization = normalizePubkeyList((hpContext.__everSmartNodeCommittedUnl && Array.isArray(hpContext.__everSmartNodeCommittedUnl))
    ? hpContext.__everSmartNodeCommittedUnl
    : (typeof clusterContext.getClusterUnlNodes === 'function' ? clusterContext.getClusterUnlNodes().map(n => n && n.pubkey).filter(Boolean) : []));
  const qualificationProtection = candidateFinalizationProtectionStatus(state, oldest.node, oldest.w, lcl, now, currentUnlForFinalization, hardMs);
  if (qualificationProtection.changed) {
    state.candidateWatchdogs = watches;
    saveState(state);
    console.log(`AutoCluster: FINALIZATION GRACE ARMED for ${cleanString(oldest.node.pubkey,24)} at LCL ${lcl || '?'}: ACK=${qualificationProtection.acknowledged} READY=true SYNC=true peers=${qualificationProtection.peerCount}/${qualificationProtection.requiredPeers}; hard admission lifetime can no longer kill this qualified candidate before ${qualificationProtection.graceUntilAt}.`);
  }
  const batch = normalizePromotionBatch(state.promotionBatch);
  let finalAdmissionProtected = qualificationProtection.graceActive;
  if (batch && batch.active && batch.pubkeys.includes(oldest.node.pubkey) && Number(batch.lastFinalProofAtLcl) > 0) {
    const currentProof = promotionProofStatus(state, oldest.node.pubkey, lcl, batch, {
      proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
      observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
      atomicBootstrap:true
    });
    const currentSync = syncQuiescenceStatus(state, oldest.node.pubkey, lcl);
    const requiredPeers = requiredAdmissionPeers(currentUnlForFinalization.length);
    const stillAdmissionHealthy = !!(currentProof.ready && currentSync.ready && Number(currentProof.peerCount || 0) >= requiredPeers);
    const graceActive = !!(lcl && Number(batch.admissionGraceUntilLcl) >= lcl);
    finalAdmissionProtected = finalAdmissionProtected || stillAdmissionHealthy || graceActive;
    if (oldest.age >= hardMs && finalAdmissionProtected) {
      console.log(`AutoCluster: HARD ADMISSION TIMEOUT SUSPENDED for ${cleanString(oldest.node.pubkey,24)} age=${Math.floor(oldest.age/1000)}s because finalization is protected; qualificationGrace=${qualificationProtection.graceActive ? qualificationProtection.graceUntilAt : 'expired'} finalProofHealthy=${stillAdmissionHealthy} retryGrace=${graceActive ? `${lcl}/${batch.admissionGraceUntilLcl}` : 'expired'}.`);
    }
  } else if (oldest.age >= hardMs && finalAdmissionProtected) {
    console.log(`AutoCluster: HARD ADMISSION TIMEOUT SUSPENDED for ${cleanString(oldest.node.pubkey,24)} age=${Math.floor(oldest.age/1000)}s: candidate already reached ACK + canonical READY + runtime SYNC + ${qualificationProtection.peerCount}/${qualificationProtection.requiredPeers} peers; one-shot finalization grace remains until ${qualificationProtection.graceUntilAt}.`);
  }
  if (!submittedForOldest && !finalAdmissionProtected && oldest.age >= hardMs) {
    // Clear admission evidence before an A-only maintenance ledger. The surviving
    // observer(s) must catch A again and rebuild READY/SYNC after the lease drop.
    state.candidateReadiness = [];
    state.candidateSyncQuiescence = [];
    state.promotionBatch = null;
    state.bootstrapMeshOverride = null;
    saveState(state);
    return { candidatePresent:true, mode:{ type:'drop', pubkey:oldest.node.pubkey, age:oldest.age, reason:'hard-admission-timeout' }, watches };
  }

  // BOUNDED CANDIDATE POOL: provisioning is deliberately decoupled from admission.
  // Keep up to candidatePoolSize pre-UNL slots occupied by either materialized
  // candidates or in-flight purchases. Xahau transaction submission is serialized
  // only until ledger finality; once a lease tx validates, native Evernode provisioning
  // proceeds asynchronously and later purchases may start (bounded by candidatePoolSize).
  // Admission itself stays strictly serialized through membershipCommand.
  const poolSize = Math.max(1, Math.min(MAX_CANDIDATE_POOL_SIZE, Number(state.candidatePoolSize) || DEFAULT_CANDIDATE_POOL_SIZE));
  const committedUnl = normalizePubkeyList((hpContext.__everSmartNodeCommittedUnl && Array.isArray(hpContext.__everSmartNodeCommittedUnl))
    ? hpContext.__everSmartNodeCommittedUnl
    : (typeof clusterContext.getClusterUnlNodes === 'function' ? clusterContext.getClusterUnlNodes().map(n => n && n.pubkey).filter(Boolean) : []));
  const managedUnlCount = committedUnl.filter(k => k !== state.bootstrapPubkey).length;
  const remainingManaged = Math.max(0, (Number(state.targetManagedNodes) || 1) - managedUnlCount);
  const singletonPhysicalBuild = committedUnl.length === 1 && committedUnl.includes(state.bootstrapPubkey) && managedUnlCount === 0;
  const desiredPool = singletonPhysicalBuild ? bootstrapInitialPhysicalManagedGoal(state) : Math.min(poolSize, remainingManaged);
  const pendingNodes = typeof clusterContext.getPendingNodes === 'function' ? clusterContext.getPendingNodes().filter(Boolean) : [];
  const materializedHosts = new Set(candidates.map(n => normalizeHostAddress(n && n.host)).filter(Boolean));
  const pendingHosts = new Set();
  for (const n of pendingNodes) {
    const host = normalizeHostAddress(n && n.host);
    if (host && !materializedHosts.has(host)) pendingHosts.add(host);
  }
  for (const h of state.hostQueue) {
    if (!h || !['attempting','pending'].includes(h.status)) continue;
    const host = normalizeHostAddress(h.address);
    if (host && !materializedHosts.has(host)) pendingHosts.add(host);
  }
  // Apply the provisioning timeout HERE, before begin() can take the stock-lockstep
  // early return. Timeout is only late-watch/replacement policy; it does not gate
  // purchases whose preceding Xahau transaction is already final.
  releaseExpiredNativeAcquireResponseFences(state, ctx, hpContext, evernodeContext, materializedHosts);
  const effectivePendingHosts = new Set();
  for (const n of pendingNodes) {
    const host = normalizeHostAddress(n && n.host);
    const row = host ? state.hostQueue.find(h => h && h.address === host) : null;
    if (host && !materializedHosts.has(host) && !(row && row.status === 'provisioning-stalled')) effectivePendingHosts.add(host);
  }
  for (const h of state.hostQueue) {
    if (!h || !['attempting','pending'].includes(h.status)) continue;
    const host = normalizeHostAddress(h.address);
    if (host && !materializedHosts.has(host)) effectivePendingHosts.add(host);
  }
  const pendingCount = effectivePendingHosts.size;
  const poolOccupancy = candidates.length + pendingCount;
  const unresolvedNativeResponses = unresolvedNativeAcquireResponses(state, xrplContext, evernodeContext, materializedHosts);
  const hasQueuedHost = state.hostQueue.some(h => h && h.status === 'queued');
  const nextAcquireAfterLcl = Number(state.nextAcquireAfterLcl) || 0;
  const pacingReady = !nextAcquireAfterLcl || !lcl || lcl >= nextAcquireAfterLcl;
  if (desiredPool > poolOccupancy && pendingCount < poolSize && hasQueuedHost && pacingReady && unresolvedNativeResponses.length === 0) {
    // An A-only acquisition ledger invalidates qualification evidence. Every
    // observer must catch the resulting state again before any ADD_UNL can arm.
    state.candidateReadiness = [];
    state.candidateSyncQuiescence = [];
    state.promotionBatch = null;
    state.bootstrapMeshOverride = null;
    saveState(state);
    return { candidatePresent:true, mode:{ type:'pool-fill', pubkey:oldest.node.pubkey, age:oldest.age, poolSize, desiredPool, poolOccupancy, pendingCount, targetCount:committedUnl.length + desiredPool }, watches };
  }
  if (desiredPool > poolOccupancy && unresolvedNativeResponses.length > 0 && lcl % 5 === 0) {
    console.log(`AutoCluster: LOCKSTEP ACQUIRE TX FINALITY at LCL ${lcl}: waiting only for the previous Xahau acquisition transaction to validate before submitting another purchase; unresolved=${unresolvedNativeResponses.map(h=>cleanString(h.address,48)).join(',')}. Native host provisioning does not serialize later purchases once tx finality is known.`);
  }
  return { candidatePresent:true, mode:null, watches, oldestAge:oldest.age, oldestHeadLag:oldest.headLag, poolSize, desiredPool, poolOccupancy, pendingCount, unresolvedNativeResponses:unresolvedNativeResponses.length };
}

function pendingContractInputCount(ctx) {
  try {
    let count = 0;
    const users = ctx && ctx.users && typeof ctx.users.list === 'function' ? ctx.users.list() : [];
    for (const user of users) {
      const inputs = user && Array.isArray(user.inputs) ? user.inputs : [];
      count += inputs.length;
      if (count > 0) break;
    }
    return count;
  } catch (_) { return 0; }
}

async function pendingInputProfile(ctx) {
  const out = { count:0, candidateRelayOnly:false, types:[] };
  // Both pre-UNL signed attestations and Bootstrap-A canonical READY observations
  // are deterministic proof inputs. They only mutate AutoCluster milestone state
  // and must never wake ClusterContext.init()/Evernode/Xahau just because a user
  // input exists. .53.58 introduced the controller READY input but forgot to add
  // it to this lightweight-input classifier, so every READY proof accidentally
  // ran the heavyweight lifecycle and churned cluster/acquire/transaction state.
  const lightweightProofTypes = new Set([
    AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE,
    AUTOCLUSTER_READY_OBSERVATION_TYPE,
    AUTOCLUSTER_ATOMIC_READY_BUNDLE_TYPE
  ]);
  try {
    const users = ctx && ctx.users && typeof ctx.users.list === 'function' ? ctx.users.list() : [];
    let onlyRelay = true;
    for (const user of users) {
      const inputs = user && Array.isArray(user.inputs) ? user.inputs : [];
      for (const input of inputs) {
        out.count++;
        let type = '';
        try {
          const raw = await ctx.users.read(input);
          const parsed = JSON.parse(Buffer.from(raw).toString('utf8'));
          type = cleanString(parsed && parsed.type || '', 96);
        } catch (_) {
          onlyRelay = false;
        }
        if (type) out.types.push(type);
        if (!lightweightProofTypes.has(type)) onlyRelay = false;
      }
    }
    out.candidateRelayOnly = out.count > 0 && onlyRelay;
  } catch (_) {
    out.candidateRelayOnly = false;
  }
  return out;
}

async function begin(ctx) {
  // Defense in depth: sidedish calls this preflight before any other contract
  // work, but begin() also enforces it in case this module is invoked directly.
  if (!STOCK_CLONE_BOOTSTRAP && await validatorStabilizationPreflight(ctx)) return null;
  const state = loadState();
  if (!state || !state.enabled || !state.clusterAddress || !state.managedImage) return null;
  // alpha53.49: retire the old replicated bootstrap ledger ring once. From this
  // point forward growth canonical history is node-local, so /state can settle.
  if (state.phase === 'growing' && normalizeRecentLedgers(state.recentLedgers).length) {
    state.recentLedgers = [];
    saveState(state);
    console.log('AutoCluster: BOOTSTRAP STATE QUIESCENCE migrated canonical recent-ledger witness out of replicated state; future growth ledgers no longer rewrite /state merely to advance the witness.');
  }
  if (ctx && ctx.readonly) return null;
  if (state.phase === 'awaiting-bootstrap-signerlist') return null;
  if (!fs.existsSync(STATE_FILE) && fs.existsSync(LEGACY_STATE_FILE)) {
    saveState(state);
    console.log('AutoCluster: migrated legacy externally-created state into HotPocket-managed consensus state.');
  }
  const { HotPocketContext, XrplContext, EvernodeContext, ClusterContext, Peer } = getDeps();
  const hpContext = new HotPocketContext(ctx);
  // Preserve access to HotPocket's raw execution context for node-local signing.
  // EverPocket's wrapper does not forward privateKey, which made .47's signed
  // candidate relay permanently fail with CANDIDATE_ATTESTATION_NODE_KEY_UNAVAILABLE.
  // This reference stays in-memory only; the private key is never serialized.
  hpContext.__everSmartNodeRawContractContext = ctx;

  if (OFFICIAL_EVERPOCKET_MEMBERSHIP && (state.membershipCommand || state.promotionBatch || state.promotionTransition || state.bootstrapMeshOverride)) {
    state.membershipCommand = null;
    state.promotionBatch = null;
    state.promotionTransition = null;
    state.bootstrapMeshOverride = null;
    saveState(state);
    console.log('AutoCluster: migrated membership control to native EverPocket lifecycle; cleared legacy lockstep/direct-promotion intent state.');
  }

  // Deterministic explicit-peer mode mirrors the reference cluster manager:
  // peer discovery is disabled because HotPocket 0.6.4 otherwise rejects
  // peerChangeset control messages. Candidates receive the complete current UNL
  // mesh before MATURED and the expanded mesh is refreshed after membership changes.

  // CONSENSUS MEMBERSHIP SOURCE OF TRUTH:
  // The committed contract config is replicated state. ctx.unl is HotPocket's
  // live/runtime UNL facade and may update a moment later on a node that has just
  // synchronized the membership patch. Using ctx.unl.find(local) to choose between
  // the follower and validator branches can therefore make A and B execute
  // different smart-contract paths from the same committed ledger. Never do that.
  const committedCfg = await ctx.getConfig();
  const committedUnl = readContractUnlFromConfig(committedCfg);
  const localPublicKey = cleanString((ctx && ctx.publicKey) || hpContext.publicKey || '', 256).toLowerCase();
  const localIsUnl = !!localPublicKey && committedUnl.includes(localPublicKey);
  hpContext.__everSmartNodeCommittedUnl = committedUnl;

  // Diagnostic only. A mismatch is exactly the activation race this build is
  // designed to survive; it MUST NOT affect replicated control flow.
  let runtimeLocalIsUnl = null;
  try {
    runtimeLocalIsUnl = !!(ctx && ctx.unl && typeof ctx.unl.find === 'function' && ctx.unl.find(ctx.publicKey));
  } catch {}
  if (runtimeLocalIsUnl !== null && runtimeLocalIsUnl !== localIsUnl) {
    console.log(`AutoCluster: COMMITTED-UNL AUTHORITY mismatch at LCL ${Number(hpContext.lclSeqNo) || '?'} local=${cleanString(localPublicKey,24)} committed=${localIsUnl} runtimeCtxUnl=${runtimeLocalIsUnl}; following committed ctx.getConfig().unl for replicated control flow.`);
  }

  // Candidate/non-UNL contract copies must still initialize enough EverPocket
  // state to synchronize and send their own MATURED signal, but they must never
  // drive cluster-wide lifecycle mutations. Membership for this decision is
  // derived ONLY from the committed config above.
  // Canonical growth witnesses are node-local runtime evidence. Bootstrap A's
  // root sidecar is the only component allowed to compare a candidate LCL/hash to
  // A's local witness; replicated contract input handling never reads that file.
  if (rememberCurrentLedger(state, hpContext, localIsUnl)) saveState(state);
  attachVotePipe(ctx, hpContext, state);
  // NPL is UNL party-line transport. Pre-UNL candidates report through a signed
  // node-local sidecar attestation instead; only committed validators broadcast NPL.
  if (localIsUnl) await broadcastAutoClusterNplStatus(ctx, hpContext, state, committedUnl, localIsUnl);
  // CONSENSUS SAFETY: EverPocket's checkLiveness() is called from ClusterContext.init().
  // Never let a validator-local DNS/TLS/WSS result mutate replicated cluster.json.
  // Treat native AcquireSuccess as provisioned and require canonical READY/JIT for
  // actual admission. External endpoint probing is diagnostic-only outside this contract.
  clearLegacyEndpointLivenessState(state);
  installConsensusNeutralLiveness(hpContext, state);

  // EverPocket 0.1.6 initializes the first cluster node record without its
  // network endpoint. A newly acquired node later uses that record to configure
  // its peer list and to send the MATURED callback, which otherwise becomes
  // undefined:undefined. Carry Bootstrap A's endpoint in AutoCluster state and
  // transparently repair those calls until EverPocket has endpoint-rich records.
  const bootstrapEndpoint = state.bootstrapEndpoint;
  let maturitySentThisExecution = false;
  if (bootstrapEndpoint && bootstrapEndpoint.domain) {
    // Explicit known_peers/updatePeers own the validator transport mesh.
    if (typeof hpContext.sendMessage === 'function' && typeof Peer === 'function') {
      const originalSendMessage = hpContext.sendMessage.bind(hpContext);
      hpContext.sendMessage = async (message, nodes = []) => {
        const list = Array.isArray(nodes) ? nodes : [];
        let parsed = null;
        try { parsed = typeof message === 'string' ? JSON.parse(message) : message; } catch {}
        const isMaturityAck = parsed && parsed.type === 'maturity_ack';
        const isValidatorReady = parsed && parsed.type === 'autocluster_validator_ready';
        const isValidatorActive = parsed && parsed.type === 'autocluster_validator_active';
        const isSyncQuiescent = parsed && parsed.type === 'autocluster_sync_quiescent';
        const isCandidateDiag = parsed && parsed.type === 'autocluster_candidate_diag';
        const isSignerReady = parsed && parsed.type === 'autocluster_signer_ready';

        // These are ordinary HotPocket user inputs and must enter through an
        // already-running validator doorway. Never call this node's own user.port
        // from inside the currently executing contract: that is re-entrant and can
        // wait on itself. Initial managed signer exchange is handled separately by
        // NPL; READY/ACTIVE/diagnostic compatibility inputs retain a trusted remote
        // doorway until they can be redesigned around a non-reentrant relay.
        if ((isMaturityAck || isValidatorReady || isValidatorActive || isSyncQuiescent || isCandidateDiag || isSignerReady) && hpContext.publicKey !== state.bootstrapPubkey) {
          if (isMaturityAck) {
            // EverPocket must be allowed to complete its candidate-private maturity
            // state, but a pre-UNL node cannot use the UNL NPL as a callback path.
            // Capture the success locally; end() signs that private maturity state
            // with this node's HotPocket validator key and the root sidecar relays
            // it as an ordinary HotPocket input OUTSIDE contract execution.
            maturitySentThisExecution = true;
            console.log(`AutoCluster: MATURED captured locally for signed sidecar relay by ${cleanString(hpContext.publicKey,80)} at candidate LCL ${Number(hpContext.lclSeqNo)||'?'}. No contract-side WebSocket/NPL callback was opened.`);
            return true;
          }
          // Candidate readiness/sync/active diagnostics are carried by the signed
          // node-local attestation relay. Never open a remote HotPocket user
          // WebSocket from inside contract execution for these signals.
          if (isValidatorReady || isValidatorActive || isSyncQuiescent || isCandidateDiag) {
            return true;
          }
          // MATURED must be a REAL authenticated HotPocket user input to a current
          // UNL doorway. Older purity builds swallowed it locally, which made the
          // candidate believe maturity had been acknowledged while the shared
          // cluster row on A never moved to ACKNOWLEDGED.
          let target = null, targetLabel = null;
          const mayUseLocalConsensus = false; // never re-enter local HotPocket user.port from contract execution
          if (mayUseLocalConsensus) {
            const localUserPort = readLocalHotPocketUserPort();
            if (localUserPort) {
              target = new Peer('127.0.0.1', localUserPort);
              targetLabel = `local HotPocket consensus 127.0.0.1:${localUserPort}`;
            } else {
              console.log(`AutoCluster: local HotPocket user.port unavailable for ${cleanString(hpContext.publicKey,80)}; falling back to an existing UNL doorway for this signal.`);
            }
          }
          if (!target && !['handover','autonomous'].includes(state.phase) && bootstrapEndpoint.userPort) {
            target = new Peer(bootstrapEndpoint.domain, bootstrapEndpoint.userPort);
            targetLabel = `Bootstrap A doorway ${bootstrapEndpoint.domain}:${bootstrapEndpoint.userPort}`;
          } else if (!target && state.phase === 'autonomous') {
            // A non-UNL replacement candidate still needs exactly one authenticated
            // doorway into the healthy cluster for MATURED / VALIDATOR_READY.
            // Already-UNL senders normally took the local-consensus path above.
            const disk = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
            const candidates = disk && Array.isArray(disk.nodes) ? disk.nodes.filter(n => n && n.isUnl && n.pubkey !== hpContext.publicKey && normalizeEndpointHost(n.domain) && validPort(n.userPort)).sort((a,b)=>String(a.pubkey).localeCompare(String(b.pubkey))) : [];
            const doorway = candidates[0] || null;
            if (doorway) {
              target = new Peer(normalizeEndpointHost(doorway.domain), validPort(doorway.userPort));
              targetLabel = `autonomous UNL doorway ${doorway.domain}:${doorway.userPort}`;
            }
          }
          if (target) {
            const signalLabel = isMaturityAck ? 'maturity callback' : (isSignerReady ? 'MANAGED_SIGNER_READY' : (isValidatorActive ? 'VALIDATOR_ACTIVE heartbeat' : (isSyncQuiescent ? 'SYNC-QUIESCENT proof' : (isCandidateDiag ? 'CANDIDATE_DIAG heartbeat' : 'VALIDATOR_READY heartbeat'))));
            console.log(`AutoCluster: ${signalLabel} ${cleanString(hpContext.publicKey,80)} -> ${targetLabel} using one serialized session with the managed node's own identity.`);
            try {
              const out = await originalSendMessage(message, [target]);
              console.log(`AutoCluster: ${signalLabel} accepted for ${cleanString(hpContext.publicKey,80)} via ${targetLabel}.`);
              return out;
            } catch (e) {
              console.log(`AutoCluster: ${signalLabel} FAILED for ${cleanString(hpContext.publicKey,80)} via ${targetLabel}: ${errText(e)}`);
              throw e;
            }
          }
        }

        let usable = list.filter(n => n && n.ip && n.port);
        if (!usable.length && bootstrapEndpoint.userPort && state.phase !== 'autonomous') {
          usable = [new Peer(bootstrapEndpoint.domain, bootstrapEndpoint.userPort)];
          console.log(`AutoCluster: repaired missing EverPocket maturity endpoint with Bootstrap A ${bootstrapEndpoint.domain}:${bootstrapEndpoint.userPort}.`);
        }
        return await originalSendMessage(message, usable);
      };
    }
  } else if (hpContext.publicKey !== state.bootstrapPubkey) {
    console.log('AutoCluster: WARNING Bootstrap A endpoint is missing; a managed node may be unable to acknowledge maturity. Use Retry current step from the bootstrap progress screen to publish the endpoint.');
  }

  // Candidate-only maturity handling below can call updatePeers before the heavy
  // EverPocket/Xahau lifecycle is initialized. Install the HotPocket 0.6.4 peer
  // wire adapter here as well as on the validator path so malformed legacy peer
  // shapes can never leak through this lightweight follower path.
  installHotPocketLivePeerAdapter(hpContext);

  // STOCK CLONE OBSERVER LOCKSTEP:
  // A non-UNL clone MUST execute the same EverPocket ClusterContext lifecycle as
  // Bootstrap A. HotPocket invokes the DApp on synchronized observers before UNL
  // admission; skipping ClusterContext here makes A and B generate different
  // post-execution filesystem state, which becomes round N+1 consensus input.
  // Candidate-only maturity bookkeeping remains in EverPocket's ../node_private_info.json
  // and therefore stays outside consensus state. Do not early-return here.

  // STRICT PRE-UNL FOLLOWER FENCE. A bootstrap candidate starts with
  // contract.unl=[A] and known_peers=[A], so it needs no EverPocket/Xahau
  // lifecycle initialization to synchronize. READY is now measured externally:
  // the node-local sidecar signs native HPFS completion and submits that proof
  // through the candidate's localhost user doorway after contract execution.
  // The candidate contract performs no remote callback, NPL send, or websocket work.
  const bootstrapQualification = bootstrapQualificationSnapshot(state, hpContext);
  const preUnlFollowerPhase = ['growing','signing','ready-to-handover','handover'].includes(state.phase);
  const stockPostJoinFollower = !!(STOCK_CLONE_BOOTSTRAP && committedUnl.length >= 2 && committedUnl.includes(state.bootstrapPubkey));
  if (preUnlFollowerPhase && !localIsUnl && hpContext.publicKey !== state.bootstrapPubkey) {
    // A waiting/spare node is a passive HotPocket candidate all the way through
    // handover. Keep ONLY its node-local peer list fresh; never let a non-UNL copy
    // initialize EverPocket/Xahau or write lifecycle state under process.cwd().
    // This mirrors manual clustering: follow the live UNL, stay synced, do no
    // authoritative work until the atomic membership patch includes this node.
    // No explicit peer refresh: discovery learns the live mesh from the bootstrap seed.
    // Restore ONLY EverPocket's candidate-side CONFIGURED -> MATURED handshake.
    // Do not initialize XrplContext/EvernodeContext/ClusterContext here: the
    // candidate remains a pure HotPocket follower except for this node-local
    // maturity file and one authenticated user input to Bootstrap A.
    const maturity = await runPreUnlMaturityHandshake(state, hpContext, bootstrapEndpoint);
    const syncQuiescence = await runPreUnlSyncQuiescenceHandshake(state, hpContext, maturity && maturity.stage || 'unknown');
    console.log(`AutoCluster: PRE-UNL LIGHTWEIGHT FOLLOWER active for ${cleanString(hpContext.publicKey,80)} at candidate LCL ${Number(hpContext.lclSeqNo) || '?'} phase=${state.phase}; maturity=${maturity && maturity.stage || 'unknown'}; readiness is signed from native HPFS latest-target completion. No Xahau/EverPocket ClusterContext.init or remote WebSocket runs on the candidate.`);
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext:createSigningClusterView(), submissionProbe:{last:null}, localIsUnl:false, preUnlFollowerFence:true, bootstrapQualificationFence:false, deferTickOnce:false, closed:false };
  }

  // Once the atomic handover has removed Bootstrap A from the committed UNL,
  // the old bootstrap process may still be alive under Supervisor for UI/recovery.
  // It is no longer authoritative and must never run autonomous EverPocket/Xahau
  // lifecycle work or submit lease extensions. Validator-stabilization preflight
  // runs before begin(), so this fence only applies after the sterile membership
  // window has been handled.
  if (!localIsUnl && hpContext.publicKey === state.bootstrapPubkey && ['handover','autonomous'].includes(state.phase)) {
    console.log(`AutoCluster: RETIRED BOOTSTRAP FENCE active at LCL ${Number(hpContext.lclSeqNo) || '?'} phase=${state.phase}; Bootstrap A is outside UNL and will perform no lifecycle/Xahau work.`);
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext:createSigningClusterView(), submissionProbe:{last:null}, localIsUnl:false, retiredBootstrapFence:true, deferTickOnce:false, closed:false };
  }

  // MEMBERSHIP-TRANSITION QUIET WINDOW. Once an ADD_UNL intent is armed,
  // Bootstrap A must stop producing unrelated consensus-state mutations until
  // that exact membership command either executes/expires or the patch commits.
  // This directly prevents READY/acquisition/lifecycle traffic from sharing the
  // fragile ledger that makes a previously non-UNL follower a voter.
  let pendingMembershipTransition = normalizeMembershipCommand(state.membershipCommand);
  if (STOCK_CLONE_BOOTSTRAP && state.phase === 'growing' && localIsUnl && committedUnl.includes(state.bootstrapPubkey) &&
      pendingMembershipTransition && pendingMembershipTransition.operation === 'add' && !pendingMembershipTransition.submittedAtLcl) {
    const nowLcl = Number(hpContext && hpContext.lclSeqNo) || 0;
    const requestedAtLcl = Number(pendingMembershipTransition.requestedAtLcl) || nowLcl;
    const waitAge = Math.max(0, nowLcl - requestedAtLcl);
    if (waitAge > LOCKSTEP_FINAL_INTENT_WAIT_LCLS) {
      const skipped = pendingMembershipTransition.pubkey;
      const oldBatch = normalizePromotionBatch(state.promotionBatch) || { active:true, armedAtLcl:nowLcl, submittedAtLcl:null, submittedPubkey:null, pubkeys:[], lastFinalProofAtLcl:null, admissionGraceUntilLcl:null, skipPubkey:null, skipUntilLcl:null, reason:'bootstrap-final-proof-rotation' };
      oldBatch.active = true;
      // This batch now carries only the FINAL-proof cooldown. Clear the armed pubkey list
      // so prepareCandidatePromotionGate cannot mistake a rotated/non-admitted intent for
      // a completed promotion (Array.every([]) is true).
      oldBatch.pubkeys = [];
      oldBatch.skipPubkey = skipped;
      oldBatch.skipUntilLcl = nowLcl + LOCKSTEP_FINAL_CANDIDATE_COOLDOWN_LCLS;
      oldBatch.submittedAtLcl = null;
      oldBatch.submittedPubkey = null;
      oldBatch.reason = `FINAL proof head-of-line rotation: ${skipped} waited ${waitAge} ledgers; try another durably-qualified candidate`;
      state.promotionBatch = oldBatch;
      state.membershipCommand = null;
      saveState(state);
      console.log(`AutoCluster: LOCKSTEP FINAL-PROOF ROTATE at LCL ${nowLcl}: ${cleanString(skipped,24)} waited ${waitAge}/${LOCKSTEP_FINAL_INTENT_WAIT_LCLS} ledgers without an accepted exact-tip proof. Cooling it until LCL ${oldBatch.skipUntilLcl}; another durably-qualified candidate may be selected immediately.`);
      pendingMembershipTransition = null;
    }
  }
  if (state.phase === 'growing' && localIsUnl && committedUnl.includes(state.bootstrapPubkey) && pendingMembershipTransition) {
    const clusterContext = createSigningClusterView();
    console.log(`AutoCluster: MEMBERSHIP-TRANSITION QUIET FENCE active at LCL ${Number(hpContext.lclSeqNo) || '?'} for ${pendingMembershipTransition.operation}:${cleanString(pendingMembershipTransition.pubkey,24)}. No Xahau/EverPocket init, acquisition, extension, signer work, readiness mutation or lifecycle work may share the transition ledger.`);
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext, submissionProbe:{last:null}, localIsUnl, membershipTransitionQuietFence:true, deferTickOnce:false, closed:false };
  }

  // Once the physical candidate pool exists, stop running EverPocket/Xahau
  // lifecycle code on Bootstrap A while the candidates qualify. This is the key
  // consensus-state rule: A and every pre-UNL follower now execute the same
  // lightweight replicated path while READY proofs accumulate. If a candidate
  // is quarantined, the deterministic watchdog makes `active` false and A resumes
  // acquisition on the next ledger. When every usable candidate is currently
  // green, A temporarily leaves this fence only to publish the atomic UNL switch.
  if (!STOCK_CLONE_BOOTSTRAP && state.phase === 'growing' && localIsUnl && hpContext.publicKey === state.bootstrapPubkey &&
      bootstrapQualification.active && !bootstrapQualification.readyToPromote) {
    console.log(`AutoCluster: STREAMING BOOTSTRAP qualification at LCL ${Number(hpContext.lclSeqNo) || '?'}: ${bootstrapQualification.green}/${bootstrapQualification.target} green, ${bootstrapQualification.usable}/${bootstrapQualification.target} usable. Normal EverPocket/Xahau lifecycle work remains enabled while candidates qualify.`);
  }

  // alpha41: after the first managed validator joins, cluster.json must reflect
  // the committed HotPocket UNL without invoking EverPocket ClusterContext.init().
  // This tiny deterministic projection is the only shared-file write performed by
  // the post-join bootstrap bridge before membership intent processing.
  let alpha41CommittedUnl = committedUnl;
  if (state.phase === 'growing' && alpha41CommittedUnl.length >= 2 && alpha41CommittedUnl.includes(state.bootstrapPubkey)) {
    try {
      if (syncPureClusterUnlView(alpha41CommittedUnl)) {
        console.log(`AutoCluster: CONSENSUS-PURITY projected committed UNL (${alpha41CommittedUnl.length}) into cluster.json without EverPocket lifecycle initialization.`);
      }
    } catch (e) {
      console.log(`AutoCluster: CONSENSUS-PURITY committed-UNL projection failed: ${errText(e)}.`);
      throw e;
    }
  }

  // Bootstrap temporarily permits target+1 UNL membership. Once A + all target
  // managed validators are committed, normalize the threshold if needed. tick()
  // freezes that exact managed set and then enters the handover fence.
  if (state.phase === 'growing' && localIsUnl) {
    const disk = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
    const diskNodes = disk && Array.isArray(disk.nodes) ? disk.nodes : [];
    const managedUnlCount = diskNodes.filter(n => n && n.pubkey !== state.bootstrapPubkey && diskNodeIsUnl(n)).length;
    const committedUnlCount = alpha41CommittedUnl.length;
    const target = finalManagedTarget(state);
    const bridgeManaged = bootstrapManagedUnlTarget(state);
    if (committedUnlCount >= target + 1 && managedUnlCount >= bridgeManaged) {
      const bridgeCfg = await ctx.getConfig();
      const currentThreshold = readConsensusThreshold(bridgeCfg);
      const desiredThreshold = signerMatchedBootstrapThreshold(state);
      if (currentThreshold !== desiredThreshold) {
        setConsensusThreshold(bridgeCfg, desiredThreshold);
        await ctx.updateConfig(bridgeCfg);
        console.log(`AutoCluster: TEMPORARY BOOTSTRAP BRIDGE threshold normalization submitted at LCL ${Number(hpContext.lclSeqNo) || '?'}: ${currentThreshold}% -> ${desiredThreshold}% on ${committedUnlCount}/${target + 1} validators. UNL size is unchanged.`);
      }
    }
  }

  // STRICT SIGNING FENCE: NPL is real-time validator-to-validator transport and
  // does not require EverPocket/Xahau initialization. Avoid ClusterContext.init(),
  // Xahau RPC, acquisition-event decryption, maturity processing, extensions and
  // all other lifecycle work while the 5-node set is proving stable enough to
  // complete signer handover. The lightweight cluster view reads only committed
  // local HotPocket state (cluster.json); it performs no deinit writes.
  if (state.phase === 'signing') {
    const clusterContext = createSigningClusterView();
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext, submissionProbe:{last:null}, localIsUnl, strictSigningFence:true, deferTickOnce:false, closed:false };
  }

  // CONSENSUS-PURITY FENCE. Bootstrap A first acquires the complete managed fleet
  // while it is the sole validator, then holds in PRE-FREEZE QUALIFICATION until
  // every selected candidate has durable ACK + signer + maturity + READY/SYNC.
  // Live exact-tip sync and live peer mesh are deliberately NOT global here: both are proven
  // per candidate only after the state is frozen. Only then do we freeze
  // external EverPocket/Xahau lifecycle and begin one-at-a-time membership changes.
  // After the first managed validator joins, the purity fence remains permanent for
  // the rest of bootstrap growth; acquisition never reopens under a multi-validator UNL.
  const streamingPool = bootstrapDiskPoolStatus(state);
  const freezeQualification = bootstrapFreezeQualificationSnapshot(state, hpContext, alpha41CommittedUnl);
  const postJoinNeedsLifecycle = streamingPool.usable < streamingPool.target;
  const singletonPhysicalFleetPresent = alpha41CommittedUnl.length === 1 && streamingPool.usable >= streamingPool.target;
  const singletonFullyQualified = singletonPhysicalFleetPresent && freezeQualification.ready;
  const multiValidatorGrowing = alpha41CommittedUnl.length >= 2;

  // PRE-FREEZE QUALIFICATION LANE. Five materialized leases are not enough to
  // freeze replicated state: every selected candidate must already have durable
  // identity/qualification history. Keep READY/ACK/signer/watchdog bookkeeping alive on this lightweight
  // deterministic path until all five are qualified. If a candidate times out,
  // candidateReadinessWatchdog() quarantines it; the next ledger sees usable<target
  // and stock acquisition reopens for a replacement while Bootstrap A is still
  // the sole validator. No candidate can be stranded forever in PROBING behind a
  // hard freeze.
  if (!OFFICIAL_EVERPOCKET_MEMBERSHIP && state.phase === 'growing' && localIsUnl &&
      hpContext.publicKey === state.bootstrapPubkey && alpha41CommittedUnl.length === 1 &&
      alpha41CommittedUnl.includes(state.bootstrapPubkey) && singletonPhysicalFleetPresent && !singletonFullyQualified) {
    const summary = freezeQualification.rows.map(r =>
      `${cleanString(r.pubkey,12)}:ack=${r.ack} signer=${r.signer} mature=${r.maturity.age}/${r.maturity.required} durable=${r.durable.ready} live=${r.liveSync} vote=${r.voteSynced?'synced':'wait'} peers=${r.peerCount}/${freezeQualification.requiredPeers}`
    ).join(',');
    console.log(`AutoCluster: PRE-FREEZE QUALIFICATION at LCL ${Number(hpContext.lclSeqNo) || '?'}: ${freezeQualification.qualified}/${freezeQualification.target} durably qualified (${freezeQualification.usable}/${freezeQualification.target} usable). Hard consensus-state freeze waits only for ACK + signer + maturity + durable READY/SYNC; live exact-tip sync + live peer mesh are per-candidate FINAL proof checks after freeze. candidates=[${summary}]`);
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext:createSigningClusterView(), submissionProbe:{last:null}, localIsUnl, bootstrapQualificationFence:true, preFreezeQualification:true, deferTickOnce:false, closed:false };
  }

  if (!OFFICIAL_EVERPOCKET_MEMBERSHIP && state.phase === 'growing' && alpha41CommittedUnl.includes(state.bootstrapPubkey) && (singletonFullyQualified || multiValidatorGrowing)) {
    const clusterContext = createSigningClusterView();

    if (!localIsUnl && hpContext.publicKey !== state.bootstrapPubkey) {
      await runPreUnlMaturityHandshake(state, hpContext, bootstrapEndpoint);
    }

    // Once the complete managed fleet exists, bootstrap becomes a pure replicated
    // state machine. After the first add this fence is permanent for the rest of
    // growing phase even if a pre-UNL candidate later becomes unhealthy: fail
    // closed rather than re-opening Xahau/EverPocket external work under a
    // multi-validator UNL. Replacement acquisition can only happen while A is
    // still the singleton, or after autonomous handover.
    await preparePurePostJoinMembershipIntent(ctx, state, hpContext, clusterContext);
    console.log(`AutoCluster: BOOTSTRAP CONSENSUS-PURITY FENCE active at LCL ${Number(hpContext.lclSeqNo) || '?'} with ${alpha41CommittedUnl.length} committed validator(s), ${streamingPool.usable}/${streamingPool.target} usable managed candidates and ${alpha41CommittedUnl.length === 1 ? `${freezeQualification.qualified}/${freezeQualification.target} fully qualified before freeze` : 'post-join freeze locked'}. External Xahau/EverPocket lifecycle is disabled; only deterministic proof/membership inputs may mutate replicated state.`);
    return { ctx, state, hpContext, xrplContext:null, evernodeContext:null, clusterContext, submissionProbe:{last:null}, localIsUnl, postJoinConsensusPurityFence:true, deferTickOnce:false, closed:false };
  }
  if (state.phase === 'growing' && alpha41CommittedUnl.length >= 2 && alpha41CommittedUnl.includes(state.bootstrapPubkey) && postJoinNeedsLifecycle && localIsUnl) {
    // Log only on actual lifecycle cadence ledgers below; the old every-ledger
    // message made idle execution look busier than it really was.
  }

  // SLIM LEDGER PATH. EverPocket ClusterContext.init()/deinit() and Xahau setup
  // are the expensive/churny part of AutoCluster. Routine steady-state lifecycle
  // housekeeping now wakes only every 100 committed ledgers. Active acquisition,
  // repair and handover work retains a faster cadence so provisioning/finality is
  // not delayed for hundreds of ledgers. User inputs always bypass the cadence.
  const lifecycleLcl = Number(hpContext.lclSeqNo) || 0;
  const inputProfile = await pendingInputProfile(ctx);
  const pendingInputs = inputProfile.count;
  const candidateRelayOnly = inputProfile.candidateRelayOnly;

  // QUIESCENT BOOTSTRAP MEMBERSHIP PREFLIGHT.
  // A candidate being present is NOT lifecycle work. Running stock EverPocket
  // ClusterContext.init()/deinit() merely because a candidate exists updates
  // cluster.json.activeOnLcl and therefore changes the replicated /state hash.
  // Signed candidate reports are designed specifically to be handled on the
  // lightweight cluster view, so they must not wake EverPocket/Xahau either.
  // The only bootstrap membership reason to wake the heavy lifecycle is an
  // actually releasable native EverPocket promotion.
  let promotionLifecycleNeeded = false;
  if (OFFICIAL_EVERPOCKET_MEMBERSHIP && state.phase === 'growing' && localIsUnl) {
    await prepareOfficialPromotionPeerWarmup(ctx, state, hpContext, committedUnl, localIsUnl);
    const preflightGate = prepareOfficialEverPocketPromotionGate(state, hpContext);
    promotionLifecycleNeeded = !!(preflightGate && preflightGate.holding === false && preflightGate.nativePromotion === true);
  }

  const hostQueue = Array.isArray(state.hostQueue) ? state.hostQueue : [];

  // LIGHTWEIGHT MATERIALIZATION RECONCILIATION. When a lease has already become
  // a real cluster.nodes candidate, stale attempting/pending hostQueue bookkeeping
  // must not keep waking ClusterContext.init()/Xahau on the 4-ledger active cadence.
  // Reconcile from the replicated cluster row without initializing EverPocket;
  // this is one semantic state write per materialized lease, then qualification
  // can remain quiescent until a real acquisition/repair/promotion event occurs.
  if (state.phase === 'growing') {
    const diskCluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
    const materializedHosts = new Set((diskCluster && Array.isArray(diskCluster.nodes) ? diskCluster.nodes : [])
      .map(n => normalizeHostAddress(n && n.host)).filter(Boolean));
    let hostQueueReconciled = false;
    for (const h of hostQueue) {
      if (!h || !['attempting','pending'].includes(h.status)) continue;
      const host = normalizeHostAddress(h.address);
      if (!host || !materializedHosts.has(host)) continue;
      h.status = 'acquired';
      h.pendingSinceAt = null;
      h.pendingSinceLcl = null;
      h.lastError = null;
      h.nativeStage = 'materialized';
      h.nativeStageAtLcl = lifecycleLcl || h.nativeStageAtLcl || null;
      if (state.activeHostAttempt === h.address) state.activeHostAttempt = null;
      if (state.blocker && state.blocker.host === h.address && ['acquire-node','acquisition-endpoint'].includes(state.blocker.stage)) state.blocker = null;
      hostQueueReconciled = true;
    }
    if (hostQueueReconciled) {
      saveState(state);
      console.log(`AutoCluster: QUIESCENT HOST RECONCILE at LCL ${lifecycleLcl || '?'} marked materialized lease rows acquired before lifecycle scheduling; stale acquisition bookkeeping will no longer churn /state.`);
    }
  }

  const inFlightAcquire = hostQueue.some(h => h && ['attempting','pending'].includes(h.status));
  const queuedBootstrapWork = state.phase === 'growing' && postJoinNeedsLifecycle && hostQueue.some(h => h && h.status === 'queued');
  const autonomousRepairActive = state.phase === 'autonomous' && !!(state.maintenance && state.maintenance.repair && state.maintenance.repair.active !== false);
  const handoverWorkActive = ['ready-to-handover','handover'].includes(state.phase);
  const blockerWorkActive = !!(state.blocker && state.blocker.stage);
  const activeLifecycleWork = inFlightAcquire || queuedBootstrapWork || autonomousRepairActive || handoverWorkActive || blockerWorkActive || promotionLifecycleNeeded;
  // During growth there is no periodic housekeeping reason to touch EverPocket.
  // Acquisition/finality and promotion are event-driven. Routine 1/100-ledger
  // maintenance resumes only after bootstrap leaves the growing phase.
  const routineLifecycleDue = state.phase !== 'growing' && (!lifecycleLcl || (lifecycleLcl % ROUTINE_LIFECYCLE_CADENCE_LCLS) === 0);
  const singletonAcquirePolling = state.phase === 'growing'
    && alpha41CommittedUnl.length === 1
    && alpha41CommittedUnl.includes(state.bootstrapPubkey)
    && !promotionLifecycleNeeded
    && (inFlightAcquire || queuedBootstrapWork)
    && !autonomousRepairActive && !handoverWorkActive;
  const activeLifecycleCadence = singletonAcquirePolling
    ? SINGLETON_ACQUIRE_LIFECYCLE_CADENCE_LCLS
    : ACTIVE_LIFECYCLE_CADENCE_LCLS;
  const activeLifecycleDue = activeLifecycleWork && (!lifecycleLcl || (lifecycleLcl % activeLifecycleCadence) === 0);
  const heavyLifecycleDue = promotionLifecycleNeeded || routineLifecycleDue || activeLifecycleDue;
  const inputRequiresHeavyLifecycle = pendingInputs > 0 && !candidateRelayOnly;
  // While Bootstrap A is the sole validator, preserve stock EverPocket acquisition
  // state exactly as produced by ClusterContext. Shadow rollback previously hid
  // pending/materialization bookkeeping and could make a validated acquisition look
  // forgotten on the next poll. The consensus-purity fence starts only after 5/5
  // managed candidates are present, before any validator is admitted.
  const singletonAcquireShadowMode = false;
  if (localIsUnl && !inputRequiresHeavyLifecycle && !heavyLifecycleDue && ['growing','handover','autonomous','ready-to-handover'].includes(state.phase)) {
    if (candidateRelayOnly) {
      console.log(`AutoCluster: QUIESCENT PROOF execution at LCL ${lifecycleLcl || '?'}: ${pendingInputs} candidate/controller proof input(s) types=[${inputProfile.types.join(',')}] will be processed without ClusterContext.init()/deinit(); EverPocket/Xahau replicated bookkeeping remains untouched.`);
    }
    return {
      ctx, state, hpContext, xrplContext:null, evernodeContext:null,
      clusterContext:createSigningClusterView(), submissionProbe:{last:null},
      localIsUnl, lightweightIdleFence:true, deferTickOnce:false, closed:false
    };
  }
  if (state.phase === 'growing' && alpha41CommittedUnl.length >= 2 && alpha41CommittedUnl.includes(state.bootstrapPubkey) && postJoinNeedsLifecycle && localIsUnl) {
    const lifecycleReason = promotionLifecycleNeeded ? 'native-promotion' : (pendingInputs > 0 ? 'user-input' : (activeLifecycleDue ? 'active-work' : 'routine-housekeeping'));
    console.log(`AutoCluster: STREAMING POST-JOIN LIFECYCLE RUN at LCL ${lifecycleLcl || '?'} reason=${lifecycleReason}: ${alpha41CommittedUnl.length} validator(s) committed, ${streamingPool.usable}/${streamingPool.target} usable managed candidate(s) materialized. Routine EverPocket/Xahau housekeeping is 1/${ROUTINE_LIFECYCLE_CADENCE_LCLS} ledgers; active acquisition/repair work is 1/${ACTIVE_LIFECYCLE_CADENCE_LCLS}; user inputs bypass both.`);
  }

  if (singletonAcquirePolling && activeLifecycleDue) {
    console.log(`AutoCluster: SINGLETON STOCK-ACQUIRE POLL at LCL ${lifecycleLcl || '?'}: Bootstrap A is sole UNL; acquisition lifecycle is eligible every committed ledger until the full managed fleet is ready.`);
  }

  const xrplOptions = { network: state.network };
  const xahauServers = rpcPoolUrls(state, 'xahau');
  if (!xahauServers.length && state.rippleServer) xahauServers.push(state.rippleServer);
  const bootstrapSignerExpected = hpContext.publicKey === state.bootstrapPubkey && state.phase === 'growing';
  if (bootstrapSignerExpected) validateBootstrapSignerFile(state);
  // Own Xahau failover instead of delegating to evernode-js-client's primary +
  // fallback race. A successful fallback becomes node-locally sticky, so the
  // next HotPocket execution reconnects directly to the working endpoint rather
  // than hammering a dead priority-1 server every ledger.
  const selectedXahau = await connectXahauRpcSequential(xahauServers, state.network, 'AutoCluster');
  xrplOptions.rippleServer = selectedXahau.url;
  const xrplContext = new XrplContext(hpContext, state.clusterAddress, null, xrplOptions);
  // XrplContext.init() deliberately reuses a pre-supplied API. Inject the
  // already-connected winner so it does not perform another primary/fallback
  // selection internally.
  xrplContext.xrplApi = selectedXahau.api;
  const evernodeContext = new EvernodeContext(xrplContext);
  let latestLedgerSubmission = null;
  const submissionProbe = { last: null };

  // EverPocket 0.1.6 deliberately reduces transaction-vote results to a tiny
  // {hash,lastLedgerSequence,resultCode} object and then throws only
  // "<TransactionType> | Could not consider as a valid submission." when no
  // node reports tesSUCCESS/tefPAST_SEQ/tefALREADY. That discards the actual
  // Xahau engine_result (for example tecINSUFFICIENT_RESERVE) before the caller
  // can classify it. Install the probe immediately after EvernodeContext.init
  // creates xrplAcc, but before ClusterContext processes queued acquisitions.
  const originalEvernodeInit = evernodeContext.init.bind(evernodeContext);
  evernodeContext.init = async (...args) => {
    const initResult = await originalEvernodeInit(...args);
    // XrplContext.init() has now loaded the validated signer list and run its
    // signer-validity cleanup. Activate AutoCluster's durable local signer only
    // after that cleanup, and before ClusterContext starts queued Evernode ops.
    // This prevents pre-handover signer keys being deleted merely because the
    // final SignerListSet has not landed yet.
    activateManagedSignerVaultIfOnLedger(state, hpContext, xrplContext);
    const acc = xrplContext.xrplAcc;
    if (acc && typeof acc.submitMultisigned === 'function' && !acc.__everSmartNodeSubmissionProbe) {
      const originalSubmitMultisigned = acc.submitMultisigned.bind(acc);
      acc.submitMultisigned = async transaction => {
        const txType = cleanString(transaction && transaction.TransactionType || 'XRPL', 64);
        const signerCount = Array.isArray(transaction && transaction.Signers) ? transaction.Signers.length : 0;
        const sequence = Number(transaction && transaction.Sequence) || 0;
        const lastLedgerSequence = Number(transaction && transaction.LastLedgerSequence) || 0;
        console.log(`AutoCluster: Xahau submitMultisigned START type=${txType} local=${cleanString(hpContext.publicKey,80)} lcl=${hpContext.lclSeqNo || '?'} signers=${signerCount} sequence=${sequence || '?'} lastLedger=${lastLedgerSequence || '?'}.`);
        try {
          const res = await originalSubmitMultisigned(transaction);
          const resultCode = ledgerResultCode(res);
          latestLedgerSubmission = { txType, resultCode: resultCode || null, errorText: null, hash: submissionHash(res, transaction), lastLedgerSequence: submissionLastLedgerSequence(res, transaction), response: res };
          submissionProbe.last = latestLedgerSubmission;
          console.log(`AutoCluster: Xahau submitMultisigned RESULT type=${txType} local=${cleanString(hpContext.publicKey,80)} signers=${signerCount} result=${resultCode || 'unknown'} hash=${cleanString(latestLedgerSubmission.hash || '',32) || 'unknown'}.`);
          if (resultCode && !/^(?:tesSUCCESS|tefPAST_SEQ|tefALREADY)$/i.test(resultCode)) {
            console.log(`AutoCluster: Xahau submission result ${txType} => ${resultCode}.`);
          }
          return res;
        } catch (e) {
          const resultCode = ledgerResultCode(e);
          latestLedgerSubmission = { txType, resultCode: resultCode || null, errorText: errText(e), hash: submissionHash(e, transaction), lastLedgerSequence: submissionLastLedgerSequence(e, transaction), response: null };
          submissionProbe.last = latestLedgerSubmission;
          console.log(`AutoCluster: Xahau submitMultisigned ERROR type=${txType} local=${cleanString(hpContext.publicKey,80)} signers=${signerCount} result=${resultCode || 'none'} error=${cleanString(errText(e),220)}.`);
          if (resultCode) console.log(`AutoCluster: Xahau submission rejected ${txType} => ${resultCode}.`);
          throw e;
        }
      };
      acc.__everSmartNodeSubmissionProbe = true;
    }
    if (typeof xrplContext.multiSignAndSubmitTransaction === 'function' && !xrplContext.__everSmartNodeResultEnricher) {
      const originalMultiSignAndSubmit = xrplContext.multiSignAndSubmitTransaction.bind(xrplContext);
      xrplContext.multiSignAndSubmitTransaction = async (transaction, options = {}) => {
        latestLedgerSubmission = null;
        submissionProbe.last = null;
        const txType = cleanString(transaction && transaction.TransactionType || 'XRPL', 64);
        const nplBefore = hpContext.__everSmartNodeNplStats;
        const beforeMessages = Number(nplBefore && nplBefore.messages || 0);
        const beforeSenders = nplBefore && nplBefore.senders ? nplBefore.senders.size : 0;
        console.log(`AutoCluster: Xahau multisign/election START type=${txType} local=${cleanString(hpContext.publicKey,80)} lcl=${hpContext.lclSeqNo || '?'} nplMessages=${beforeMessages} nplSenders=${beforeSenders}.`);
        try {
          const result = await originalMultiSignAndSubmit(transaction, options);
          const nplAfter = hpContext.__everSmartNodeNplStats;
          const observed = submissionProbe.last;
          console.log(`AutoCluster: Xahau multisign/election COMPLETE type=${txType} local=${cleanString(hpContext.publicKey,80)} nplMessages=${Number(nplAfter && nplAfter.messages || 0)} nplSenders=${nplAfter && nplAfter.senders ? nplAfter.senders.size : 0} submission=${observed ? (observed.resultCode || 'observed') : 'not-observed'}.`);
          return result;
        } catch (e) {
          const nplAfter = hpContext.__everSmartNodeNplStats;
          const directCode = ledgerResultCode(e);
          const observedCode = directCode || (latestLedgerSubmission && latestLedgerSubmission.resultCode);
          console.log(`AutoCluster: Xahau multisign/election ERROR type=${txType} local=${cleanString(hpContext.publicKey,80)} nplMessages=${Number(nplAfter && nplAfter.messages || 0)} nplSenders=${nplAfter && nplAfter.senders ? nplAfter.senders.size : 0} engine=${observedCode || 'none'} submissionProbe=${latestLedgerSubmission ? 'yes' : 'no'} error=${cleanString(errText(e),220)}.`);
          const originalText = errText(e);
          if (/^terQUEUED$/i.test(observedCode || '')) {
            const txType = cleanString(transaction && transaction.TransactionType || (latestLedgerSubmission && latestLedgerSubmission.txType) || 'XRPL', 64);
            const provisional = {
              hash: (latestLedgerSubmission && latestLedgerSubmission.hash) || submissionHash(e, transaction) || null,
              lastLedgerSequence: (latestLedgerSubmission && latestLedgerSubmission.lastLedgerSequence) || submissionLastLedgerSequence(e, transaction) || null,
              resultCode: 'terQUEUED',
              queued: true,
              provisional: true
            };
            latestLedgerSubmission = { ...(latestLedgerSubmission || {}), txType, resultCode:'terQUEUED', hash:provisional.hash, lastLedgerSequence:provisional.lastLedgerSequence, response:provisional, errorText:originalText };
            submissionProbe.last = latestLedgerSubmission;
            console.log(`AutoCluster: Xahau ${txType} returned terQUEUED. Treating it as provisional/accepted and waiting for signer-list reconciliation; no duplicate signer transaction will be submitted meanwhile.`);
            return provisional;
          }
          if (observedCode && !originalText.includes(observedCode)) {
            const txType = cleanString(transaction && transaction.TransactionType || (latestLedgerSubmission && latestLedgerSubmission.txType) || 'XRPL', 64);
            const enriched = new Error(`${txType} | ${observedCode} | ${originalText || 'transaction submission failed'}`);
            enriched.code = observedCode;
            enriched.ledgerResult = observedCode;
            throw enriched;
          }
          throw e;
        }
      };
      xrplContext.__everSmartNodeResultEnricher = true;
    }
    return initResult;
  };

  // Hard safety boundary: discovery APIs are only advisory. EverPocket fetches
  // the selected host's actual lease offer from Evernode/Xahau, and this guard
  // checks that live offer immediately before a transaction can be prepared,
  // multisigned or submitted.
  const originalAcquireSubmit = evernodeContext.acquireSubmit.bind(evernodeContext);
  evernodeContext.acquireSubmit = async (hostAddress, leaseOffer, messageKey, options = {}) => {
    latestLedgerSubmission = null;
    const amount = enforceLeaseCap(state, evernodeContext, hostAddress, leaseOffer);
    const publicMessageKey = cleanString(messageKey || '', 256);
    let keyFileState = 'message-key-missing';
    if (publicMessageKey) {
      const keyFile = path.resolve(process.cwd(), '..', `${publicMessageKey}.txt`);
      keyFileState = fs.existsSync(keyFile) ? 'private-key-file-present-owner-node' : 'private-key-file-not-local-expected-on-non-owner';
    }
    const memoFit = fitAcquirePeersToMemo(options, messageKey, state);
    if (memoFit.trimmed) {
      console.log(`AutoCluster: ACQUIRE MEMO PEER TRIM host=${hostAddress} kept=${memoFit.peers.length}/${memoFit.originalPeers.length} projectedMemos=${memoFit.usage.serializedMemoBytes}/${XRPL_ACQUIRE_MEMO_TARGET_BYTES}B memoData=${memoFit.usage.memoDataBytes}B plaintext=${memoFit.usage.plaintextBytes}B dropped=[${memoFit.dropped.join(',')}]. Bootstrap A is retained first; only optional tail peer seeds were removed.`);
    } else if (memoFit.originalPeers.length) {
      console.log(`AutoCluster: ACQUIRE MEMO FIT host=${hostAddress} peers=${memoFit.peers.length} projectedMemos=${memoFit.usage.serializedMemoBytes}/${XRPL_ACQUIRE_MEMO_TARGET_BYTES}B memoData=${memoFit.usage.memoDataBytes}B plaintext=${memoFit.usage.plaintextBytes}B.`);
    }
    console.log(`AutoCluster: acquisition crypto host=${hostAddress} messageKey=${publicMessageKey || 'missing'} keyOwnerHint=${keyFileState}. EverPocket elects exactly one node to retain this private key; absence on other validators is expected. No private key is logged.`);
    console.log(`AutoCluster: live lease price accepted for ${hostAddress}: ${amount} EVR/moment (cap ${state.maxLeaseAmountEvrPerMoment}).`);
    try {
      const result = await originalAcquireSubmit(hostAddress, leaseOffer, messageKey, options);
      const txId = cleanString((latestLedgerSubmission && latestLedgerSubmission.hash) || (result && (result.id || result.hash || result.txHash)) || '', 256) || null;
      const wrapperCode = cleanString((result && (result.code || result.resultCode || result.engine_result)) || '', 64) || null;
      const observedCode = cleanString((latestLedgerSubmission && latestLedgerSubmission.resultCode) || '', 64) || null;
      // EverPocket 0.1.6 can report wrapper=tesSUCCESS while one validator's
      // duplicate submit sees tefPAST_SEQ/tefALREADY. Once validator #2 joins this
      // is expected to become more visible: one signer can successfully submit the
      // exact signed transaction and a later duplicate submit can legitimately see
      // a consumed sequence. A 64-byte transaction hash therefore outranks the
      // immediate engine_result for FINALITY: keep the hash and let validated-ledger
      // reconciliation decide whether THIS transaction landed.
      const code = observedCode || wrapperCode;
      const ledgerIndex = Number(result && result.details && (result.details.ledger_index || result.details.inLedger)) || null;
      const ambiguousDuplicateSubmit = !!(txId && observedCode && /^(?:tefPAST_SEQ|tefALREADY)$/i.test(observedCode));
      if (observedCode && wrapperCode && observedCode !== wrapperCode) {
        console.log(`AutoCluster: ACQUIRE_RESULT_MISMATCH host=${hostAddress} wrapper=${wrapperCode} submit=${observedCode}; transaction hash finality is authoritative.`);
      }
      const item = hostEntry(state, normalizeHostAddress(hostAddress));
      if (ambiguousDuplicateSubmit) {
        if (item) {
          item.nativeStage = 'tx-ambiguous-await-validation';
          item.nativeStageAtLcl = Number(hpContext.lclSeqNo) || null;
          item.acquireRequestTxId = txId;
          item.acquireRequestCode = observedCode;
          item.acquireRequestLedgerIndex = ledgerIndex;
          item.lastError = null;
          saveState(state);
        }
        console.log(`AutoCluster: ACQUIRE_SUBMISSION_AMBIGUOUS host=${hostAddress} txId=${txId} submit=${observedCode} wrapper=${wrapperCode || 'unknown'}; NOT re-queueing. Waiting for validated transaction finality, because another validator may already have submitted this exact signed transaction successfully.`);
        // Preserve EverPocket's normal return shape. originalAcquireNode() can now
        // persist its ordinary pending acquire record/refId; transaction-finality
        // reconciliation will follow this exact hash, while provisioning remains asynchronous.
        return result;
      }
      // A past-sequence/already result with NO transaction hash cannot be correlated
      // safely and remains retryable/failing as before.
      if (observedCode && /^(?:tefPAST_SEQ|tefALREADY)$/i.test(observedCode)) {
        const stale = new Error(`URITokenBuy | ${observedCode} | no correlatable transaction hash; retry acquisition after sequence refresh`);
        stale.code = observedCode;
        stale.ledgerResult = observedCode;
        stale.retryAcquireSameHost = /^tefPAST_SEQ$/i.test(observedCode);
        throw stale;
      }
      if (item) {
        item.nativeStage = 'tx-submitted'; item.nativeStageAtLcl = Number(hpContext.lclSeqNo) || null;
        item.acquireRequestTxId = txId; item.acquireRequestCode = code; item.acquireRequestLedgerIndex = ledgerIndex;
        saveState(state);
      }
      console.log(`AutoCluster: ACQUIRE_REQUEST_SUBMITTED host=${hostAddress} txId=${txId || 'unknown'} code=${code || 'unknown'} ledger=${ledgerIndex || 'unknown'} resultKeys=[${result && typeof result === 'object' ? Object.keys(result).sort().slice(0,32).join(',') : ''}]. Native Evernode now expects an AcquireSuccess/AcquireError response correlated to this tx hash.`);
      return result;
    } catch (e) {
      // The XrplContext wrapper above normally enriches this already. Keep this
      // fallback for builds where the account implementation throws a rich
      // result object but EverPocket replaces it one frame later.
      const observedCode = ledgerResultCode(e) || (latestLedgerSubmission && latestLedgerSubmission.resultCode);
      const text = errText(e);
      const txId = cleanString((latestLedgerSubmission && latestLedgerSubmission.hash) || submissionHash(e) || '', 256) || null;
      // Same ambiguity rule for implementations that throw after the account-level
      // submit. If we have the exact hash, return a provisional accepted shape so
      // EverPocket persists its normal pending-acquire correlation. Validation on a
      // later ledger -- not this duplicate-submit result -- will decide success.
      if (txId && observedCode && /^(?:tefPAST_SEQ|tefALREADY)$/i.test(observedCode)) {
        const item = hostEntry(state, normalizeHostAddress(hostAddress));
        if (item) {
          item.nativeStage = 'tx-ambiguous-await-validation';
          item.nativeStageAtLcl = Number(hpContext.lclSeqNo) || null;
          item.acquireRequestTxId = txId;
          item.acquireRequestCode = observedCode;
          item.lastError = null;
          saveState(state);
        }
        const provisional = {
          hash: txId,
          lastLedgerSequence: (latestLedgerSubmission && latestLedgerSubmission.lastLedgerSequence) || null,
          resultCode: 'tesSUCCESS',
          submissionAmbiguous: true,
          observedSubmitResult: observedCode
        };
        console.log(`AutoCluster: ACQUIRE_SUBMISSION_AMBIGUOUS host=${hostAddress} txId=${txId} submit=${observedCode} path=throw; preserving pending correlation and waiting for validated finality instead of immediate retry.`);
        return provisional;
      }
      if (observedCode && !text.includes(observedCode)) {
        const enriched = new Error(`URITokenBuy | ${observedCode} | ${text || 'acquisition transaction failed'}`);
        enriched.code = observedCode;
        enriched.ledgerResult = observedCode;
        throw enriched;
      }
      throw e;
    }
  };

  const originalAcquireNode = evernodeContext.acquireNode.bind(evernodeContext);
  evernodeContext.acquireNode = async (options = {}) => {
    const address = normalizeHostAddress(options && options.host);
    const item = address ? hostEntry(state, address) : null;
    if (item) {
      if (item.nativeStage === 'transient-rotated') item.transientFailureStreak = 0;
      item.status = 'attempting';
      item.attempts = (Number(item.attempts) || 0) + 1;
      item.lastAttemptLcl = hpContext.lclSeqNo;
      item.pendingSinceAt = null;
      item.pendingSinceLcl = null;
      item.retryAfterLcl = null;
      item.nativeStage = 'acquire-call-in-flight';
      item.nativeStageAtLcl = Number(hpContext && hpContext.lclSeqNo) || null;
      item.lastError = null;
      state.activeHostAttempt = item.address;
      saveState(state);
      console.log(`AutoCluster: ACQUIRE_CALL_STARTED host=${item.address} actualAttempt=${item.attempts}. Status ATTEMPTING now means originalAcquireNode() is genuinely in flight; no ledger-age heuristic can cancel it.`);
    }
    try {
      const pending = await originalAcquireNode(options);
      if (item) { item.status = 'pending'; item.pendingSinceAt = normalizeConsensusTimestampMs(ctx && ctx.timestamp) || normalizeConsensusTimestampMs(hpContext && hpContext.timestamp) || item.pendingSinceAt || null; item.pendingSinceLcl = Number(hpContext && hpContext.lclSeqNo) || item.pendingSinceLcl || item.lastAttemptLcl || null; item.refId = pending && pending.refId ? cleanString(pending.refId, 256) : (item.acquireRequestTxId || null); item.nativeStage = 'waiting-acquire-success'; item.nativeStageAtLcl = Number(hpContext && hpContext.lclSeqNo) || null; item.transientFailureStreak = 0; item.retryAfterLcl = null; state.activeHostAttempt = null; saveState(state); }
      console.log(`AutoCluster: ACQUIRE_CALL_FINISHED host=${address || 'selected host'} result=success refId=${pending && pending.refId ? cleanString(pending.refId, 256) : (item && item.refId) || 'unavailable'} actualAttempt=${item && item.attempts || '?'}; provisioning may continue asynchronously while the next host is acquired.`);
      clearBlocker(state, 'funding', 'acquire-node');
      return pending;
    } catch (e) {
      const text = errText(e);
      if (item) {
        if (/MAX_LEASE_COST/i.test(text)) item.status = 'price-rejected';
        else if (fundingError(text)) {
          item.status = 'funding-wait';
          setBlocker(state, e, 'acquire-node', hpContext.lclSeqNo, { host: address });
          console.log(`AutoCluster: TREASURY_FUNDING_REQUIRED for host ${address || 'selected host'}: ${text}`);
        } else if (transientAcquireError(e, text)) {
          const currentLcl = Number(hpContext && hpContext.lclSeqNo) || 0;
          const streak = (Number(item.transientFailureStreak) || 0) + 1;
          item.status = 'queued';
          item.transientFailureStreak = streak;
          item.acquireRequestTxId = null;
          item.refId = null;
          if (streak < ACQUIRE_TRANSIENT_BURST_ATTEMPTS) {
            item.nativeStage = 'transient-retry';
            item.retryAfterLcl = currentLcl + 1;
            console.log(`AutoCluster: ACQUIRE_CALL_TRANSIENT_FAILURE host=${item.address} actualAttempt=${item.attempts} burst=${streak}/${ACQUIRE_TRANSIENT_BURST_ATTEMPTS}; real acquireNode() call failed: ${text}. Giving the SAME host another genuine attempt at/after LCL ${item.retryAfterLcl}.`);
          } else {
            item.nativeStage = 'transient-rotated';
            item.retryAfterLcl = currentLcl + ACQUIRE_TRANSIENT_ROTATE_COOLDOWN_LCL;
            // Physical queue rotation makes untouched hosts visibly/factually next.
            const idx = state.hostQueue.findIndex(h => h && h.address === item.address);
            if (idx >= 0 && idx < state.hostQueue.length - 1) {
              const [retryLater] = state.hostQueue.splice(idx, 1);
              state.hostQueue.push(retryLater);
              state.preferredHosts = state.hostQueue.map(h => h.address);
            }
            console.log(`AutoCluster: ACQUIRE_CALL_ROTATED host=${item.address} after ${streak} consecutive REAL transient failures; host is NOT abandoned. It moved behind the other hosts and becomes eligible again at/after LCL ${item.retryAfterLcl}.`);
          }
        } else {
          item.status = 'failed';
          item.transientFailureStreak = 0;
          item.retryAfterLcl = null;
          if (/Bad MAC|decrypt|decryption|ciphertext/i.test(text)) setBlocker(state, e, 'acquisition-decrypt', hpContext.lclSeqNo, { host: address });
        }
        item.lastError = text;
        item.pendingSinceAt = null;
        item.pendingSinceLcl = null;
        if (item.status !== 'queued') item.refId = null;
        state.activeHostAttempt = null;
        saveState(state);
      }
      console.log(`AutoCluster: ACQUIRE_CALL_FINISHED host=${address || 'selected host'} result=failure status=${item && item.status || 'unknown'} error=${text}`);
      throw e;
    }
  };

  const originalExtendSubmit = evernodeContext.extendSubmit.bind(evernodeContext);
  evernodeContext.extendSubmit = async (hostAddress, extension, tokenID, options = {}) => {
    const cap = Number(state.maxLeaseAmountEvrPerMoment || 0);
    if (!(cap > 0)) throw new Error('MAX_LEASE_COST_NOT_CONFIGURED: refusing uncapped lease extension.');
    const leaseToken = (await xrplContext.xrplAcc.getURITokens()).find(t => t && t.index === tokenID);
    if (leaseToken) {
      const info = evernodeContext.decodeLeaseTokenUri(leaseToken.URI);
      const amount = Number(info && info.leaseAmount);
      if (Number.isFinite(amount) && amount > cap) throw new Error(`MAX_LEASE_COST_EXCEEDED: extension rate ${amount} EVR/moment exceeds cap ${cap}.`);
    }
    latestLedgerSubmission = null;
    try {
      const result = await originalExtendSubmit(hostAddress, extension, tokenID, options);
      const observedCode = cleanString((latestLedgerSubmission && latestLedgerSubmission.resultCode) || '', 64) || null;
      const txId = cleanString((latestLedgerSubmission && latestLedgerSubmission.hash) || submissionHash(result) || '', 256) || null;
      if (txId && observedCode && /^(?:tefPAST_SEQ|tefALREADY)$/i.test(observedCode)) {
        console.log(`AutoCluster: EXTEND_SUBMISSION_AMBIGUOUS host=${hostAddress} txId=${txId} submit=${observedCode}; duplicate-submit result will not trigger an immediate second extension. The next normal lease-life reconciliation decides whether another extension is needed.`);
      }
      return result;
    } catch (e) {
      const observedCode = ledgerResultCode(e) || (latestLedgerSubmission && latestLedgerSubmission.resultCode);
      const txId = cleanString((latestLedgerSubmission && latestLedgerSubmission.hash) || submissionHash(e) || '', 256) || null;
      if (txId && observedCode && /^(?:tefPAST_SEQ|tefALREADY)$/i.test(observedCode)) {
        // Extensions are idempotently driven by remaining lease life. Do not
        // immediately replay a known-hash transaction after another validator may
        // already have submitted it. Return a provisional accepted result; if the
        // extension did not land, the normal lease-life check will request it again
        // on a later clean ledger with a fresh sequence.
        console.log(`AutoCluster: EXTEND_SUBMISSION_AMBIGUOUS host=${hostAddress} txId=${txId} submit=${observedCode} path=throw; suppressing immediate duplicate replay and deferring to lease-life reconciliation.`);
        return {
          hash: txId,
          lastLedgerSequence: (latestLedgerSubmission && latestLedgerSubmission.lastLedgerSequence) || null,
          resultCode: 'tesSUCCESS',
          submissionAmbiguous: true,
          observedSubmitResult: observedCode
        };
      }
      throw e;
    }
  };

  // Normalize every EverPocket/AutoCluster live peer update before ClusterContext.init().
  // This applies to stock EverPocket #checkForPendingNodes/#checkForMatured too.
  installHotPocketLivePeerAdapter(hpContext);

  // Before EverPocket is ever allowed to add an ACKNOWLEDGED candidate to UNL,
  // the CURRENT UNL must first live-add and persist that candidate as a peer under
  // the old membership. The first execution that does this is always a hold round.
  await prepareOfficialPromotionPeerWarmup(ctx, state, hpContext, committedUnl, localIsUnl);

  // Deterministic bootstrap mesh formation uses peerChangeset + known_peers.
  // Promotion still consumes observed live peer counts and is replicated-state-only;
  // transport topology never replaces EverPocket cluster lifecycle state.
  const promotionGate = prepareCandidatePromotionGate(state, hpContext);
  const singletonStockAcquireOpen = singletonStockAcquisitionOpen(state, hpContext, localIsUnl, committedUnl);
  const singletonLifecycleStateGuard = singletonStockAcquireOpen
    ? null
    : prepareSingletonLifecycleStateGuard(state, hpContext, committedUnl, localIsUnl, singletonAcquireShadowMode);
  const membershipInitGuard = (!OFFICIAL_EVERPOCKET_MEMBERSHIP ||
    (promotionGate && promotionGate.holding === false && promotionGate.nativePromotion === true))
    ? prepareMembershipOnlyClusterInit(state, hpContext, localIsUnl, committedUnl) : null;
  const clusterContext = new ClusterContext(evernodeContext, {
    // AutoCluster owns ACKNOWLEDGED -> UNL admission. EverPocket's native
    // promotion threshold is held behind the replicated promotion gate.
    maturityLclThreshold: promotionGate.maturityLclThreshold,
    acknowledgeLclThreshold: state.acknowledgeLclThreshold
  });
  let clusterInitSucceeded = false;
  try {
    await clusterContext.init();
    clusterInitSucceeded = true;
  } finally {
    if (membershipInitGuard) {
      // On success restore target moments on ClusterManager's live objects so
      // deinit() persists the real lease targets. On init failure EverPocket may
      // already have serialized state, so repair the persisted projection too.
      restoreMembershipOnlyTargets(clusterContext, membershipInitGuard, !clusterInitSucceeded);
      if (!clusterInitSucceeded) restoreMembershipOnlyOperations(membershipInitGuard);
    }
    if (!clusterInitSucceeded && singletonLifecycleStateGuard) restoreSingletonLifecycleStateGuard(singletonLifecycleStateGuard);
  }
  if (membershipInitGuard) {
    const originalClusterDeinit = clusterContext.deinit.bind(clusterContext);
    clusterContext.deinit = async () => {
      try { await originalClusterDeinit(); }
      finally { restoreMembershipOnlyOperations(membershipInitGuard); }
    };
  }
  if (singletonLifecycleStateGuard) {
    const guardedClusterDeinit = clusterContext.deinit.bind(clusterContext);
    clusterContext.deinit = async () => {
      try { await guardedClusterDeinit(); }
      finally { restoreSingletonLifecycleStateGuard(singletonLifecycleStateGuard); }
    };
  }
  if (state.blocker && state.blocker.stage === 'init' && state.blocker.type === 'network') {
    const previous = state.blocker.message;
    clearBlocker(state, 'network', 'init');
    console.log(`AutoCluster: Xahau RPC connectivity recovered; cleared prior init blocker: ${cleanString(previous, 240)}`);
  }

  // Membership-specific peer changes are applied at their transition points
  // (pre-UNL maturity, promotion, and removal). We intentionally avoid an
  // unconditional per-ledger peer rewrite here.

  // EverPocket owns membership one candidate at a time at every bootstrap size.
  // There is deliberately no manual multi-add bridge here: ClusterContext.init() may
  // release at most the single candidate selected by the promotion gate.
  // EverPocket owns membership. If ClusterContext.init() promoted one ACKNOWLEDGED
  // candidate this round, immediately mirror the reference manager's full-mesh
  // persistence: live peerChangeset + patch.cfg known_peers, with discovery OFF.
  if (OFFICIAL_EVERPOCKET_MEMBERSHIP) {
    const cfgAfterNativeInit = await ctx.getConfig();
    const nativeUnlAfter = readContractUnlFromConfig(cfgAfterNativeInit);
    if (!samePubkeySet(nativeUnlAfter, committedUnl)) {
      const added = nativeUnlAfter.filter(k => !committedUnl.includes(k));
      const removed = committedUnl.filter(k => !nativeUnlAfter.includes(k));
      if (added.length === 1 && removed.length === 0) {
        await applyFullUnlPeerMesh({ ctx, state, hpContext, clusterContext }, nativeUnlAfter, `native EverPocket promotion ${cleanString(added[0],24)}`);
        state.membershipCommand = null;
        state.promotionBatch = null;
        state.promotionTransition = null;
        state.bootstrapMeshOverride = null;
        state.promotionPeerWarmup = null;
        // Do NOT advance unlSnapshot here. It intentionally remains the pre-change
        // committed set so validatorStabilizationPreflight() sees the one-node delta
        // on the next execution and fences the next admission for five clean ledgers.
        saveState(state);
        hpContext.__everSmartNodeConfigTransitionThisExecution = true;
        console.log(`AutoCluster: EVERPOCKET NATIVE PROMOTION COMMITTED at LCL ${Number(hpContext.lclSeqNo)||'?'}: ${committedUnl.length}->${nativeUnlAfter.length}, added=${cleanString(added[0],24)}. Full explicit peer mesh persisted/applied.`);
      } else {
        throw new Error(`EVERPOCKET_MEMBERSHIP_DELTA_UNEXPECTED: before=${committedUnl.join(',')} after=${nativeUnlAfter.join(',')}`);
      }
    }
  }

  // EverPocket owns validator admission; AutoCluster only supplies the READY/SYNC/mesh hold gate.
  // Streaming bootstrap admits exactly ONE managed validator per config patch,
  // starting with 1->2. The next committed HotPocket ledger unlocks the next
  // addition. A remains until all target managed validators are in UNL; after
  // treasury preparation the final membership operation removes A.
  // Autonomous repair remains single-node as well, but keeps its longer fence.
  if (!OFFICIAL_EVERPOCKET_MEMBERSHIP && promotionGate && promotionGate.directPromotion && Array.isArray(promotionGate.pubkeys) && promotionGate.pubkeys.length) {
    if (promotionGate.incrementalBootstrap === true && state.phase === 'growing') {
      const selectedPubkey = promotionGate.pubkeys[0];
      const selectedNode = clusterContext.getClusterNodes().find(n => n && n.pubkey === selectedPubkey);
      const currentPromotionLcl = Number(hpContext.lclSeqNo) || 0;
      const jitNow = promotionProofStatus(state, selectedPubkey, currentPromotionLcl, state.promotionBatch, {
        proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
        observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
        atomicBootstrap:true
      });
      const durableNow = durableBootstrapQualificationStatus(state, selectedPubkey);
      const forceOverride = normalizeBootstrapMeshOverride(state.bootstrapMeshOverride);
      const syncGateNow = syncQuiescenceStatus(state, selectedPubkey, currentPromotionLcl);
      const forcedAdmission = !!(selectedNode && forceOverride && forceOverride.forcedPubkey === selectedPubkey && forceOverride.bypassAll === true);
      const stockCloneAdmission = !!(STOCK_CLONE_BOOTSTRAP && promotionGate.stockCloneBootstrap === true && selectedNode &&
        diskNodeStatus(selectedNode) === 'acknowledged' && durableNow.ready);
      // After the hard fleet freeze, do not demand another replicated CURRENT READY
      // write just to arm membership. That write changes /state and makes the proof
      // self-invalidating. The root controller's atomic FINAL proof is the live gate.
      const canonicalAdmissionSafe = STOCK_CLONE_BOOTSTRAP ? !!durableNow.ready : !!(jitNow.ready && syncGateNow.ready);
      if (selectedNode && !selectedNode.isUnl && canonicalAdmissionSafe) {
        try {
          const cfg = await ctx.getConfig();
          const configUnl = readContractUnlFromConfig(cfg);
          const finalManagedTarget = Math.max(1, Number(state.targetManagedNodes) || 1);
          const bridgeTargetSize = finalManagedTarget + 1;
          if (!configUnl.includes(state.bootstrapPubkey)) {
            throw new Error('INCREMENTAL_BOOTSTRAP_REQUIRES_A: Bootstrap A is not present in committed UNL.');
          }
          if (configUnl.length >= bridgeTargetSize) {
            throw new Error(`INCREMENTAL_BOOTSTRAP_ALREADY_COMPLETE: committed UNL has ${configUnl.length}/${bridgeTargetSize} validators.`);
          }
          if (configUnl.includes(selectedPubkey)) {
            throw new Error(`INCREMENTAL_BOOTSTRAP_DUPLICATE: ${selectedPubkey} is already in committed UNL.`);
          }

          const syncNow = syncQuiescenceStatus(state, selectedPubkey, currentPromotionLcl);
          const requiredBootstrapPeers = requiredAdmissionPeers(configUnl.length);
          if (STOCK_CLONE_BOOTSTRAP) {
            if (!durableNow.ready) {
              throw new Error(`INCREMENTAL_BOOTSTRAP_DURABLE_QUALIFICATION_MISSING: ${selectedPubkey} has not completed durable pre-freeze READY/SYNC qualification.`);
            }
          } else {
            if (!jitNow.ready) {
              throw new Error(`INCREMENTAL_BOOTSTRAP_READY_NOT_CURRENT: ${selectedPubkey} no longer has a CURRENT canonical READY proof at the membership execution ledger.`);
            }
            if (!syncNow.ready) {
              throw new Error(`INCREMENTAL_BOOTSTRAP_SYNC_NOT_QUIESCENT: ${selectedPubkey} has no fresh runtime SYNC proof (age=${Number.isFinite(syncNow.age) ? syncNow.age : 'unknown'}/${syncNow.freshLimit} ledgers canonicalMatched=${!!syncNow.canonicalMatched}).`);
            }
            if (Number(jitNow.peerCount || 0) < requiredBootstrapPeers) {
              throw new Error(`INCREMENTAL_BOOTSTRAP_MESH_NOT_CURRENT: ${selectedPubkey} reports ${Number(jitNow.peerCount || 0)}/${requiredBootstrapPeers} live peer connection(s). Explicit peer wiring is required.`);
            }
          }
          if (!stockCloneAdmission && promotionGate.forcedAdmission && !forcedAdmission) {
            throw new Error('INCREMENTAL_BOOTSTRAP_FORCE_NOT_ARMED: forced candidate marker disappeared before intent creation.');
          }

          const endpointHost = normalizeEndpointHost(selectedNode.domain);
          const endpointPort = validPort(selectedNode.peerPort);
          if (!endpointHost || !endpointPort) throw new Error(`INCREMENTAL_BOOTSTRAP_ENDPOINT_MISSING: ${selectedPubkey} has no usable peer endpoint.`);
          // Candidate transport was explicitly wired before MATURED; final membership still requires live-peer proof.

          const nextUnl = normalizePubkeyList([...configUnl, selectedPubkey]);
          if (nextUnl.length !== configUnl.length + 1) throw new Error('INCREMENTAL_BOOTSTRAP_SIZE_MISMATCH: next UNL did not grow by exactly one validator.');

          if (stockCloneAdmission) {
            // Frozen stock-clone bootstrap never publishes a replicated pre-intent.
            // Bootstrap A's root controller owns candidate selection and submits the
            // exact-tip FINAL proof together with ADD_UNL as one authenticated input.
            // This execution remains state-quiescent.
            console.log(`AutoCluster: ATOMIC FINAL-PROOF CONTROLLER owns ${cleanString(selectedPubkey,24)} (${configUnl.length}->${nextUnl.length}); no membership intent or config patch is written by tick().`);
          } else {
            // Qualified/legacy path retains the authenticated external membership
            // command. STOCK_CLONE_BOOTSTRAP intentionally does not use it.
            const existingCommand = normalizeMembershipCommand(state.membershipCommand);
            if (existingCommand && (existingCommand.operation !== 'add' || existingCommand.pubkey !== selectedPubkey)) {
              throw new Error(`BOOTSTRAP_MEMBERSHIP_COMMAND_BUSY: ${existingCommand.operation}:${existingCommand.pubkey} is still pending.`);
            }
            if (!existingCommand) {
              if (diskNodeStatus(selectedNode) !== 'acknowledged' && !forcedAdmission) {
                throw new Error(`BOOTSTRAP_ACK_REQUIRED: ${selectedPubkey} status=${diskNodeStatus(selectedNode) || 'unknown'}; native EverPocket ACKNOWLEDGED is mandatory before normal ADD_UNL intent.`);
              }
              state.membershipCommand = makeBootstrapAddMembershipCommand(
                state, selectedNode, currentPromotionLcl,
                `ACKNOWLEDGED + canonical READY + runtime SYNC selected ${selectedPubkey} for HotPocket consensus ADD_UNL ${configUnl.length}->${nextUnl.length}`
              );
              if (state.promotionBatch && state.promotionBatch.active) {
                state.promotionBatch.reason = `Awaiting authenticated HotPocket ADD_UNL command for ${selectedPubkey}; autonomous tick will not mutate contract.unl`;
              }
              saveState(state);
              console.log(`AutoCluster: HOTPOCKET ADD_UNL COMMAND REQUESTED at LCL ${currentPromotionLcl || '?'} for ${cleanString(selectedPubkey,24)} (${configUnl.length}->${nextUnl.length}). No config patch was written by tick(); Bootstrap A must submit the authenticated command through HotPocket user consensus.`);
            } else {
              console.log(`AutoCluster: waiting for pending HotPocket ADD_UNL command ${cleanString(selectedPubkey,24)} requested at LCL ${existingCommand.requestedAtLcl || '?'}. Autonomous tick remains config-write-free.`);
            }
          }
        } catch (e) {
          console.log(`AutoCluster: INCREMENTAL BOOTSTRAP stitch failed for ${cleanString(selectedPubkey,80)}: ${errText(e)}. Prepared pool remains armed for a deterministic retry.`);
        }
      } else {
        console.log(`AutoCluster: incremental bootstrap candidate ${cleanString(selectedPubkey,80)} is not ready to arm membership (present=${!!selectedNode}, alreadyUnl=${!!(selectedNode&&selectedNode.isUnl)}, durableQualified=${durableNow.ready}, jitReady=${jitNow.ready}, sync=${syncQuiescenceStatus(state, selectedPubkey, currentPromotionLcl).ready}). Stock-clone bootstrap waits for durable qualification, then delegates all live safety checks to the atomic FINAL proof.`);
      }
    } else {
      const selectedPubkey = promotionGate.pubkeys[0];
      const selectedNode = clusterContext.getClusterNodes().find(n => n && n.pubkey === selectedPubkey);
      const selectedStatus = diskNodeStatus(selectedNode);
      const currentPromotionLcl = Number(hpContext.lclSeqNo) || 0;
      const jitNow = promotionProofStatus(state, selectedPubkey, currentPromotionLcl, state.promotionBatch);
      // Validator admission must be deterministic across every current UNL member.
      // Never gate addToUnl() on a local websocket/network observation: two
      // validators can see different probe results in the same execution.
      if (selectedNode && !selectedNode.isUnl && jitNow.ready) {
        try {
          const cfg = await ctx.getConfig();
          const currentThreshold = readConsensusThreshold(cfg);
          const currentUnlSize = Math.max(1, currentUnlPubkeys({ clusterContext, hpContext }).length || 1);
          let transition = normalizePromotionTransition(state.promotionTransition);
          if (!transition) {
            const toUnlSize = currentUnlSize + 1;
            let transitionThreshold;
            let normalThreshold;
            if (state.phase === 'growing') {
              normalThreshold = Number(state.bootstrapNormalConsensusThreshold) || currentThreshold;
              if (normalThreshold < MIN_BOOTSTRAP_GROWTH_THRESHOLD) normalThreshold = DEFAULT_CONSENSUS_THRESHOLD;
              transitionThreshold = Number(state.bootstrapGrowthConsensusThreshold) || bootstrapGrowthThreshold(state.targetManagedNodes, normalThreshold);
              state.bootstrapNormalConsensusThreshold = normalThreshold;
              state.bootstrapGrowthConsensusThreshold = transitionThreshold;
            } else {
              normalThreshold = currentThreshold;
              transitionThreshold = Math.min(currentThreshold, safeExpansionThreshold(currentUnlSize, toUnlSize));
            }
            transition = {
              active:true, pubkey:selectedPubkey, phase:'lowering-threshold',
              fromUnlSize:currentUnlSize, toUnlSize,
              transitionThreshold,
              normalThreshold,
              startedAtLcl:Number(hpContext.lclSeqNo)||null, thresholdAppliedAtLcl:null,
              membershipSubmittedAtLcl:null, membershipObservedAtLcl:null, activeObservedAtLcl:null, restoredAtLcl:null
            };
            state.promotionTransition = transition;
            saveState(state);
          }

          if (transition.pubkey !== selectedPubkey) {
            throw new Error(`PROMOTION_TRANSITION_BUSY: ${transition.pubkey} is still in ${transition.phase}.`);
          }

          if (currentThreshold !== transition.transitionThreshold) {
            setConsensusThreshold(cfg, transition.transitionThreshold);
            await ctx.updateConfig(cfg);
            transition.phase = 'lowering-threshold';
            transition.thresholdAppliedAtLcl = Number(hpContext.lclSeqNo) || transition.thresholdAppliedAtLcl;
            state.promotionTransition = transition;
            saveState(state);
            hpContext.__everSmartNodeConfigTransitionThisExecution = true;
            const oldVotes = requiredVotesForThreshold(currentUnlSize, currentThreshold);
            const newVotesNow = requiredVotesForThreshold(currentUnlSize, transition.transitionThreshold);
            const newVotesAfter = requiredVotesForThreshold(currentUnlSize + 1, transition.transitionThreshold);
            console.log(`AutoCluster: LEGACY/REPAIR QUORUM ${currentUnlSize}->${currentUnlSize + 1}: setting consensus threshold ${currentThreshold}% -> ${transition.transitionThreshold}% at LCL ${hpContext.lclSeqNo || '?'} (votes now ${oldVotes}->${newVotesNow}, after stitch ${newVotesAfter}).`);
          } else {
            transition.phase = 'ready-to-stitch';
            state.promotionTransition = transition;
            saveState(state);
            console.log(`AutoCluster: DIRECT validator stitch executing for ${cleanString(selectedPubkey,80)} at LCL ${hpContext.lclSeqNo || '?'} with transition threshold ${transition.transitionThreshold}% (${transition.fromUnlSize}->${transition.toUnlSize}) after canonical READY proof passed.`);
            await clusterContext.addToUnl(selectedPubkey);
            transition.phase = 'membership-submitted';
            transition.membershipSubmittedAtLcl = Number(hpContext.lclSeqNo) || null;
            state.promotionTransition = transition;
            if (state.promotionBatch && state.promotionBatch.active) state.promotionBatch.submittedAtLcl = Number(hpContext.lclSeqNo) || null;
            saveState(state);
            hpContext.__everSmartNodeConfigTransitionThisExecution = true;
            console.log(`AutoCluster: DIRECT validator stitch submitted for ${cleanString(selectedPubkey,80)} under temporary ${transition.transitionThreshold}% quorum. Normal ${transition.normalThreshold}% quorum will not return until the new validator proves post-promotion synchronization.`);
          }
        } catch (e) {
          console.log(`AutoCluster: DIRECT validator stitch/transition failed for ${cleanString(selectedPubkey,80)}: ${errText(e)}. Prepared promotion remains armed and will retry safely.`);
        }
      } else {
        console.log(`AutoCluster: prepared validator stitch for ${cleanString(selectedPubkey,80)} not admitted yet (present=${!!selectedNode}, status=${selectedStatus || 'missing'}, readinessLatched=${jitNow.stickyPrepared}, jitReady=${jitNow.ready}, barrierLcl=${jitNow.barrierLcl || 0}, lastObserved=${jitNow.observedAtLcl || 0}, candidateLcl=${jitNow.candidateLcl || 0}). Stock promotion remains locked.`);
        if (!selectedNode) {
          state.promotionBatch = null;
          saveState(state);
        }
      }
    }
  }

  // EverPocket's normal maturity acknowledgement can be missed after the managed
  // node has already sent it. Retry MATURED only as an idempotent retransmission;
  // NEVER use this path to bypass EverPocket's own synchronization/configuration
  // prerequisite. node_private_info.json reaches ACKNOWLEDGED only after the managed
  // node has seen itself in synchronized cluster state, configured its peers, waited
  // acknowledgeLclThreshold, and attempted the authenticated MATURED callback.
  if (hpContext.publicKey !== state.bootstrapPubkey && !maturitySentThisExecution && state.phase !== 'handover' &&
      ((bootstrapEndpoint && bootstrapEndpoint.domain && bootstrapEndpoint.userPort) || state.phase === 'autonomous')) {
    const localNode = clusterContext.getClusterNodes().find(n => n && n.pubkey === hpContext.publicKey);
    const localStatus = diskNodeStatus(localNode);
    const maturityProven = !!(localNode && (localNode.isUnl || /^(?:acknowledged|added_to_unl|unl)$/.test(localStatus)));
    const privateInfo = readJson(path.resolve(process.cwd(), '../node_private_info.json'), null);
    const privateStatus = statusNameFromRaw(privateInfo && privateInfo.status);
    // Only retransmit after stock EverPocket has itself reached ACKNOWLEDGED in
    // the candidate's private maturity state. If localNode is absent, or private
    // state is merely CONFIGURED, the node is not allowed to self-promote by
    // sending an early MATURED message through this fallback path.
    if (!maturityProven && localNode && privateStatus === 'acknowledged') {
      const lcl = Number(hpContext.lclSeqNo) || 0;
      const digest = crypto.createHash('sha256').update(String(hpContext.publicKey)).digest();
      const slot = digest[0] % MATURITY_RETRY_LCL_INTERVAL;
      if (lcl > 0 && (lcl % MATURITY_RETRY_LCL_INTERVAL) === slot) {
        const msg = JSON.stringify({ type:'maturity_ack', data:hpContext.publicKey });
        console.log(`AutoCluster: retransmitting previously-sent MATURED for ${cleanString(hpContext.publicKey,80)}; synchronized shared state=${localStatus || 'unknown'}, private maturity state=${privateStatus} at LCL ${lcl}.`);
        try {
          await hpContext.sendMessage(msg, []);
          console.log(`AutoCluster: MATURED retransmit submitted for ${cleanString(hpContext.publicKey,80)}.`);
        } catch (e) {
          console.log(`AutoCluster: MATURED retransmit failed for ${cleanString(hpContext.publicKey,80)}: ${errText(e)}. Will retry.`);
        }
      }
    }
  }

  // No periodic candidate diagnostic HPWS heartbeat in autonomous steady state.
  // Healthy finished clusters must not open user WebSockets merely for diagnostics.
  // Autonomous replacement still uses the explicit VALIDATOR_READY / signer / active
  // doorway below only while a non-UNL candidate is actually being admitted.

  // Authoritative pre-UNL readiness proof. During singleton bootstrap the
  // contract must NEVER open/await an HPWS user session to Bootstrap A: doing so
  // makes the candidate fall behind while it tries to prove it is caught up. Write
  // a node-private intent every local ledger instead. The always-on root control
  // plane relays that intent to A using a bootstrap-issued HotPocket user key,
  // outside contract execution. Autonomous replacement retains the older doorway
  // path for now because it runs after the stable cluster already exists.
  if (hpContext.publicKey !== state.bootstrapPubkey && state.phase !== 'handover' &&
      ((bootstrapEndpoint && bootstrapEndpoint.domain && bootstrapEndpoint.userPort) || state.phase === 'autonomous') &&
      !localIsUnl) {
    const localNode = clusterContext.getClusterNodes().find(n => n && n.pubkey === hpContext.publicKey) || null;
    const privateInfo = readJson(path.resolve(process.cwd(), '../node_private_info.json'), null);
    const lcl = Number(hpContext.lclSeqNo) || 0;
    if (lcl > 0) {
      const diagnostic = {
        buildFingerprint:localBuildFingerprint(),
        nodeRole:readLocalHotPocketNodeRole(),
        localNodePresent:!!localNode,
        localSharedStatus:localNode ? diskNodeStatus(localNode) : 'missing',
        privateStatus:statusNameFromRaw(privateInfo && privateInfo.status) || 'missing'
      };
      if (state.phase === 'growing') {
        // Bootstrap admission is externally observed by Bootstrap A via the
        // native HotPocket client-protocol `stat` request. The strict follower
        // fence above returns before this point on bootstrap candidates.
      } else {
        const msg = JSON.stringify({
          type:'autocluster_validator_ready', pubkey:hpContext.publicKey, lcl,
          lclHash:cleanString(hpContext.lclHash || '',256) || null, ...diagnostic
        });
        try {
          await hpContext.sendMessage(msg, []);
          console.log(`AutoCluster: VALIDATOR_READY heartbeat submitted by autonomous pre-UNL ${cleanString(hpContext.publicKey,80)} at candidate LCL ${lcl}.`);
        } catch (e) {
          console.log(`AutoCluster: VALIDATOR_READY heartbeat send failed for ${cleanString(hpContext.publicKey,80)}: ${errText(e)}. Will retry next ledger without changing UNL.`);
        }
      }
    }
  }

  // Legacy/autonomous post-promotion proof. Fresh streaming bootstrap does NOT
  // use this path; a successful committed ledger under the expanded HotPocket UNL
  // is sufficient proof before the next one-at-a-time addition.
  {
    const transition = normalizePromotionTransition(state.promotionTransition);
    if (transition && transition.phase === 'awaiting-active' && localIsUnl && hpContext.publicKey === transition.pubkey) {
      const lcl = Number(hpContext.lclSeqNo) || 0;
      const minLcl = Number(transition.membershipObservedAtLcl || transition.membershipSubmittedAtLcl) || 0;
      if (lcl > minLcl) {
        const msg = JSON.stringify({ type:'autocluster_validator_active', pubkey:hpContext.publicKey, lcl, lclHash:cleanString(hpContext.lclHash || '',256) || null, buildFingerprint:localBuildFingerprint(), nodeRole:readLocalHotPocketNodeRole() });
        try {
          await hpContext.sendMessage(msg, []);
          console.log(`AutoCluster: VALIDATOR_ACTIVE submitted by newly-promoted ${cleanString(hpContext.publicKey,80)} at post-stitch LCL ${lcl}. Normal lifecycle remains active; only the next validator admission waits for this proof.`);
        } catch (e) {
          console.log(`AutoCluster: VALIDATOR_ACTIVE send failed for ${cleanString(hpContext.publicKey,80)}: ${errText(e)}. The proof will retry without pausing lifecycle work.`);
        }
      }
    }
  }

  // During serial bootstrap qualification, A and the observer must leave this
  // execution with the same replicated state. ClusterContext.init/deinit is allowed
  // (and required for lockstep), but do not run A-only acquisition recovery/signer
  // checks or later lifecycle tick work while a materialized non-UNL candidate is
  // being qualified or an ADD intent is pending.
  const multiValidatorStreamingLifecycle = !!(STOCK_CLONE_BOOTSTRAP && state.phase === 'growing' && committedUnl.length >= 2 && committedUnl.includes(state.bootstrapPubkey) && bootstrapDiskPoolStatus(state).usable < Math.max(1, Number(state.targetManagedNodes) || 1));
  // The singleton lockstep planner contains an A-only pool-fill escape and clears
  // READY/SYNC before taking it. Never even run that planner after A+B while the
  // physical pool is still streaming: every CURRENT UNL validator must execute the
  // same ordinary lifecycle/tick path and EverPocket handles the shared Xahau vote.
  const singletonStockAcquireOpenNow = singletonStockAcquisitionOpen(state, hpContext, localIsUnl, committedUnl);
  const lockstepMaintenance = multiValidatorStreamingLifecycle
    ? { candidatePresent:false, mode:null, streamingPostJoin:true }
    : (singletonStockAcquireOpenNow
        ? { candidatePresent:false, mode:null, singletonStockAcquire:true }
        : bootstrapLockstepMaintenancePlan(state, ctx, hpContext, xrplContext, clusterContext, evernodeContext));
  if (singletonStockAcquireOpenNow) {
    const pool = bootstrapDiskPoolStatus(state);
    console.log(`AutoCluster: SINGLETON STOCK ACQUISITION OPEN at LCL ${Number(hpContext.lclSeqNo)||'?'}: ${pool.usable}/${pool.target} usable managed candidates; stock EverPocket acquisition owns the A-only phase with no AutoCluster correlation/finality hold, membership mask, semantic-state rollback, or candidate lockstep fence.`);
  }
  const stockLockstepCandidatePresent = !!lockstepMaintenance.candidatePresent;
  const maintenanceMode = lockstepMaintenance.mode || null;
  if (!OFFICIAL_EVERPOCKET_MEMBERSHIP && ((!multiValidatorStreamingLifecycle && stockLockstepCandidatePresent) || normalizeMembershipCommand(state.membershipCommand))) {
    // Non-UNL observers always remain fenced. Bootstrap A normally remains fenced
    // too, EXCEPT for one deliberately sterile maintenance ledger when a candidate-pool
    // purchase or hard-drop is due. That A-only ledger invalidates READY/SYNC
    // first; observers HPFS-catch the resulting state before admission can re-arm.
    const bootstrapMayEscape = !!(maintenanceMode && localIsUnl && hpContext.publicKey === state.bootstrapPubkey && !normalizeMembershipCommand(state.membershipCommand));
    if (!bootstrapMayEscape) {
      console.log(`AutoCluster: STOCK LOCKSTEP EXECUTION fence at LCL ${Number(hpContext.lclSeqNo)||'?'} candidatePresent=${stockLockstepCandidatePresent} membershipIntent=${!!normalizeMembershipCommand(state.membershipCommand)}; A and non-UNL observers stop before node-specific recovery/signer/tick work.`);
      return { ctx, state, hpContext, xrplContext, evernodeContext, clusterContext, submissionProbe, localIsUnl, bootstrapLockstepFence:true, deferTickOnce:true, closed:false };
    }
    console.log(`AutoCluster: LOCKSTEP MAINTENANCE ESCAPE at LCL ${Number(hpContext.lclSeqNo)||'?'} mode=${maintenanceMode.type} candidate=${cleanString(maintenanceMode.pubkey,24)} age=${Math.floor(Number(maintenanceMode.age||0)/1000)}s${maintenanceMode.headLag!=null?` headLag=${maintenanceMode.headLag}`:''}; READY/SYNC evidence was cleared before this A-only maintenance ledger.`);
  }

  // Repair alpha.18/stock-EverPocket state where a completed lease was removed
  // from cluster.pendingNodes after liveness failures. This runs before growth
  // decisions so the same host/refId cannot accidentally be acquired twice.
  if (localIsUnl) recoverCompletedAcquisitions({ state, hpContext, evernodeContext, clusterContext });
  if (bootstrapSignerExpected) {
    const localSigner = xrplContext.multiSigner && typeof xrplContext.multiSigner.getSigner === 'function' ? xrplContext.multiSigner.getSigner() : null;
    if (!localSigner || localSigner.account !== state.bootstrapSignerAddress) {
      throw new Error(`BOOTSTRAP_SIGNER_KEY_NOT_LOADED: validated ../${state.clusterAddress}.key for ${state.bootstrapSignerAddress || 'unknown'}, but EverPocket did not load that signer after XrplContext initialization.`);
    }
  }
  return { ctx, state, hpContext, xrplContext, evernodeContext, clusterContext, submissionProbe, localIsUnl,
    bootstrapMaintenanceMode: maintenanceMode || null,
    deferTickOnce: !!(hpContext.__everSmartNodeConfigTransitionThisExecution || hpContext.__everSmartNodeMembershipIntentThisExecution), closed: false };
}

async function feedUserMessage(run, user, raw) {
  if (!run || !run.clusterContext) return false;
  try {
    const text = Buffer.from(raw).toString('utf8').trim();
    if (!text.startsWith('{')) return false;
    const parsed = JSON.parse(text);

    // Membership changes are deliberately driven by an authenticated HotPocket
    // USER command, never directly by the autonomous lifecycle tick. Bootstrap A's
    // root control plane owns the user key stored as readyControllerPublicKey. The
    // command itself is a normal HotPocket input, so once A+B exist both validators
    // receive and execute exactly the same ADD_UNL/REMOVE_UNL decision.
    if (parsed && parsed.type === 'autocluster_unl_command') {
      const controller = hotPocketUserPubkey(user);
      const expectedController = cleanString(run.state.readyControllerPublicKey || '', 80).toLowerCase();
      let intent = normalizeMembershipCommand(run.state.membershipCommand);
      const operation = cleanString(parsed.operation || parsed.op || '', 32).toLowerCase();
      const pubkey = cleanString(parsed.pubkey || parsed.publicKey || '', 256).toLowerCase();
      const currentLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      if (!controller || controller !== expectedController) {
        console.log(`AutoCluster: ignored UNL COMMAND from unauthorized HotPocket user=${cleanString(controller || 'missing',80)} expected=${cleanString(expectedController || 'missing',80)}.`);
        return true;
      }

      // Recovery path for the newest validator only. Bootstrap A's authenticated
      // controller may remove the most recently added managed validator when every
      // older validator remains on Bootstrap A's recent canonical history within a
      // bounded lag and the newest member is the sole unreachable/divergent outlier.
      // This is intentionally unavailable for a 2-node UNL: at 60%, 2/2 votes are
      // still required, so there is no healthy majority capable of safely removing B.
      if (operation === 'remove-managed') {
        if (run.state.phase !== 'growing') throw new Error(`REMOVE_MANAGED is valid only during growing phase, current=${run.state.phase}.`);
        const cfg = await run.ctx.getConfig();
        const currentUnl = readContractUnlFromConfig(cfg);
        if (!currentUnl.includes(pubkey) || pubkey === cleanString(run.state.bootstrapPubkey || '',256).toLowerCase()) {
          throw new Error('REMOVE_MANAGED target must be the currently-added managed validator in the committed UNL.');
        }
        if (currentUnl.length < 3) throw new Error('REMOVE_MANAGED refused: fewer than 3 validators leaves no independent healthy majority for automatic recovery.');
        const stab = normalizeStabilization(run.state.stabilization);
        const newest = stab && Array.isArray(stab.addedPubkeys) && stab.addedPubkeys.length === 1 ? String(stab.addedPubkeys[0]).toLowerCase() : null;
        if (!newest || newest !== pubkey) throw new Error(`REMOVE_MANAGED refused: ${pubkey} is not the most recently added validator.`);
        const ageLcl = currentLcl && stab.startedAtLcl ? Math.max(0, currentLcl - Number(stab.startedAtLcl)) : 0;
        if (ageLcl < 6) throw new Error(`REMOVE_MANAGED refused: newest validator has had only ${ageLcl}/6 committed-ledger opportunities to converge.`);
        const proof = parsed && parsed.convergenceProof && typeof parsed.convergenceProof === 'object' ? parsed.convergenceProof : null;
        const proofUnl = normalizePubkeyList(proof && proof.currentUnl);
        const healthy = normalizePubkeyList(proof && proof.healthyPubkeys);
        const expectedHealthy = currentUnl.filter(k => k !== pubkey);
        const canonicalHeadLcl = Number(proof && proof.canonicalHeadLcl) || 0;
        const canonicalHeadHash = cleanString(proof && proof.canonicalHeadHash || '',256).toLowerCase();
        const rawHealthyRows = Array.isArray(proof && proof.healthyRows) ? proof.healthyRows : [];
        const rawHistory = Array.isArray(proof && proof.canonicalHistory) ? proof.canonicalHistory : [];
        const healthyRows = rawHealthyRows.map(row => ({
          pubkey: cleanString(row && row.pubkey || '',256).toLowerCase(),
          lcl: Number(row && row.lcl) || 0,
          hash: cleanString(row && row.hash || '',256).toLowerCase(),
          lag: Number(row && row.lag),
          canonical: row && row.canonical === true,
          converged: row && row.converged === true
        })).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
        const historyRows = rawHistory.map(row => ({
          lcl: Number(row && row.lcl) || 0,
          hash: cleanString(row && row.hash || '',256).toLowerCase()
        })).filter(row => row.lcl > 0 && /^[0-9a-f]{64}$/.test(row.hash));
        const historyMap = new Map(historyRows.map(row => [row.lcl,row.hash]));
        const bootstrapPubkey = cleanString(run.state.bootstrapPubkey || '',256).toLowerCase();
        if (!proof || proof.outlierPubkey !== pubkey || proof.outlierMatchesCanonical !== false ||
            JSON.stringify(proofUnl) !== JSON.stringify(currentUnl) ||
            JSON.stringify(healthy) !== JSON.stringify(expectedHealthy) ||
            !canonicalHeadLcl || !/^[0-9a-f]{64}$/.test(canonicalHeadHash) ||
            historyMap.get(canonicalHeadLcl) !== canonicalHeadHash ||
            historyRows.length < 1 || historyRows.length > (RECOVERY_CANONICAL_MAX_LAG_LCLS + 1) ||
            historyMap.size !== historyRows.length ||
            historyRows.some(row => row.lcl > canonicalHeadLcl || row.lcl < canonicalHeadLcl - RECOVERY_CANONICAL_MAX_LAG_LCLS) ||
            healthyRows.length !== expectedHealthy.length ||
            JSON.stringify(healthyRows.map(r=>r.pubkey)) !== JSON.stringify(expectedHealthy)) {
          throw new Error('REMOVE_MANAGED refused: authenticated convergence proof does not contain the complete older-validator canonical-history quorum with the newest validator as the sole outlier.');
        }
        for (const row of healthyRows) {
          const lag = canonicalHeadLcl - row.lcl;
          if (!row.lcl || !/^[0-9a-f]{64}$/.test(row.hash) || row.canonical !== true || row.converged !== true ||
              !Number.isInteger(row.lag) || row.lag !== lag || lag < 0 || lag > RECOVERY_CANONICAL_MAX_LAG_LCLS || historyMap.get(row.lcl) !== row.hash) {
            throw new Error(`REMOVE_MANAGED refused: older validator ${cleanString(row.pubkey,24)} is not proven on Bootstrap canonical history within ${RECOVERY_CANONICAL_MAX_LAG_LCLS} ledgers.`);
          }
        }
        const bootstrapRow = healthyRows.find(row => row.pubkey === bootstrapPubkey);
        if (!bootstrapRow || bootstrapRow.lcl !== canonicalHeadLcl || bootstrapRow.hash !== canonicalHeadHash || bootstrapRow.lag !== 0) {
          throw new Error('REMOVE_MANAGED refused: Bootstrap A is not the canonical-head anchor of the recovery proof.');
        }
        const threshold = signerMatchedBootstrapThreshold(run.state);
        const votesRequired = requiredVotesForThreshold(currentUnl.length, threshold);
        if (healthy.length < votesRequired) throw new Error(`REMOVE_MANAGED refused: only ${healthy.length} healthy validators, but ${votesRequired} votes are required at ${threshold}%.`);
        setConsensusThreshold(cfg, threshold);
        setContractUnl(cfg, expectedHealthy);
        await applyFullUnlPeerMesh(run, expectedHealthy, `REMOVE_MANAGED ${cleanString(pubkey,24)}`);
        const removedDomain = normalizeEndpointHost((run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === pubkey) || {}).domain);
        const removedPort = validPort((run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === pubkey) || {}).peerPort);
        if (removedDomain && removedPort && run.hpContext && typeof run.hpContext.updatePeers === 'function') {
          await run.hpContext.updatePeers([], [`${removedDomain}:${removedPort}`]);
        }
        run.hpContext.__everSmartNodeConfigTransitionThisExecution = true;
        run.deferTickOnce = true;
        run.state.membershipCommand = null;
        run.state.promotionBatch = null;
        run.state.bootstrapMeshOverride = null;
        let watches = normalizeCandidateWatchdogs(run.state.candidateWatchdogs);
        let watch = watches.find(w => String(w.pubkey || '').toLowerCase() === pubkey) || { pubkey, host:null, refId:null, firstSeenAt:null, firstSeenLcl:null };
        watch.stalledAt = consensusNowMs(run); watch.stalledAtLcl = currentLcl || null; watch.kickedAt = watch.stalledAt;
        watches = watches.filter(w => String(w.pubkey || '').toLowerCase() !== pubkey); watches.push(watch);
        run.state.candidateWatchdogs = normalizeCandidateWatchdogs(watches);
        saveState(run.state);
        console.log(`AutoCluster: AUTO-RECOVERY REMOVE_MANAGED submitted at LCL ${currentLcl || '?'} for newest outlier ${cleanString(pubkey,24)}. Every older validator is on Bootstrap canonical history within ${RECOVERY_CANONICAL_MAX_LAG_LCLS} ledgers; canonicalHead=L${canonicalHeadLcl}/${canonicalHeadHash.slice(0,12)} and signer-matched quorum ${healthy.length}/${votesRequired} holds at ${threshold}%.`);
        return true;
      }

      // Frozen stock-clone bootstrap deliberately has NO replicated ADD pre-intent.
      // The root controller samples FINAL proof first and sends proof + ADD_UNL in
      // this one authenticated consensus input. Other membership operations retain
      // the legacy replicated-intent requirement.
      const directAtomicStockAdd = !!(STOCK_CLONE_BOOTSTRAP && operation === 'add' && !intent && run.state.phase === 'growing');
      if (directAtomicStockAdd) {
        const sampledAt = Number(parsed && parsed.finalProof && parsed.finalProof.bootstrapLcl) || currentLcl || 0;
        intent = { active:true, operation:'add', pubkey, requestedAtLcl:sampledAt || null, submittedAtLcl:null, reason:'atomic-final-proof-direct-add' };
      }
      if (!intent || operation !== intent.operation || pubkey !== intent.pubkey) {
        console.log(`AutoCluster: ignored UNL COMMAND ${operation || 'missing'}:${cleanString(pubkey || 'missing',80)} because replicated intent is ${intent ? `${intent.operation}:${intent.pubkey}` : 'none'} and no atomic stock-bootstrap ADD exemption applies.`);
        return true;
      }
      if (intent.submittedAtLcl) {
        console.log(`AutoCluster: duplicate UNL COMMAND ${operation}:${cleanString(pubkey,24)} ignored; config patch was already submitted at LCL ${intent.submittedAtLcl}.`);
        return true;
      }

      const cfg = await run.ctx.getConfig();
      const currentUnl = readContractUnlFromConfig(cfg);
      if (directAtomicStockAdd) {
        const bootstrap = cleanString(run.state.bootstrapPubkey || '',256).toLowerCase();
        const stab = normalizeStabilization(run.state.stabilization);
        if (!currentUnl.includes(bootstrap)) {
          console.log(`AutoCluster: ATOMIC ADD_UNL rejected for ${cleanString(pubkey,24)} because Bootstrap A is not in committed UNL.`);
          return true;
        }
        if (stab && stab.active) {
          console.log(`AutoCluster: ATOMIC ADD_UNL deferred for ${cleanString(pubkey,24)} because validator-set stabilization is still active (${stab.cleanLedgers}/${stab.requiredCleanLedgers}).`);
          return true;
        }
        if (currentUnl.length === 1) {
          const frozen = bootstrapFreezeQualificationSnapshot(run.state, run.hpContext, currentUnl);
          if (!frozen.ready) {
            console.log(`AutoCluster: ATOMIC ADD_UNL rejected for ${cleanString(pubkey,24)} because hard fleet freeze is not armed (${frozen.qualified}/${frozen.target} durably qualified, ${frozen.usable}/${frozen.target} usable).`);
            return true;
          }
        }
      }
      if (operation === 'demote-managed') {
        const bootstrap = cleanString(run.state.bootstrapPubkey || '',256).toLowerCase();
        const target = finalManagedTarget(run.state);
        if (!['signing','growing'].includes(run.state.phase)) throw new Error(`DEMOTE_MANAGED invalid during phase=${run.state.phase}.`);
        if (!currentUnl.includes(bootstrap) || !currentUnl.includes(pubkey) || pubkey === bootstrap) throw new Error('DEMOTE_MANAGED requires Bootstrap A and the selected managed validator in current UNL.');
        if (currentUnl.length !== target + 1) throw new Error(`DEMOTE_MANAGED is only for legacy target+1 bridge repair; current=${currentUnl.length}, expected=${target + 1}.`);
        const nextUnl = normalizePubkeyList(currentUnl.filter(pk => pk !== pubkey));
        await applyFullUnlPeerMesh(run, nextUnl, `LEGACY BRIDGE DEMOTE ${cleanString(pubkey,24)}`);
        const manager = run.clusterContext && run.clusterContext.clusterManager;
        if (manager && typeof manager.getNode === 'function') {
          const n = manager.getNode(pubkey);
          if (n) { n.isUnl = false; n.status = { status:3, onLcl:currentLcl || 0 }; }
        }
        const clusterFile = path.resolve(process.cwd(), 'cluster.json');
        const disk = readJson(clusterFile, null);
        if (disk && Array.isArray(disk.nodes)) {
          const n = disk.nodes.find(x => x && cleanString(x.pubkey || '',256).toLowerCase() === pubkey);
          if (n) { n.isUnl = false; n.status = { status:3, onLcl:currentLcl || 0 }; writeJson(clusterFile, disk); }
        }
        run.hpContext.__everSmartNodeConfigTransitionThisExecution = true;
        run.deferTickOnce = true;
        run.state.phase = 'growing';
        run.state.handoverSignerPubkeys = [];
        run.state.handoverPreparedAtLcl = null;
        intent.submittedAtLcl = currentLcl || null;
        run.state.membershipCommand = intent;
        saveState(run.state);
        console.log(`AutoCluster: LEGACY TARGET+1 BRIDGE REPAIRED at LCL ${currentLcl || '?'}: ${currentUnl.length}->${nextUnl.length}; managed ${cleanString(pubkey,24)} returned to pre-UNL qualification. Fixed-size handover will continue without ever re-growing above target.`);
        return true;
      }
      if (operation === 'add' || operation === 'swap-bootstrap') {
        const swappingBootstrap = operation === 'swap-bootstrap';
        const opLabel = swappingBootstrap ? 'SWAP_BOOTSTRAP' : 'ADD_UNL';
        if ((!swappingBootstrap && run.state.phase !== 'growing') || (swappingBootstrap && run.state.phase !== 'ready-to-handover')) {
          throw new Error(`${opLabel} command is invalid during phase=${run.state.phase}.`);
        }
        const bootstrap = cleanString(run.state.bootstrapPubkey || '',256).toLowerCase();
        if (!currentUnl.includes(bootstrap)) {
          if (swappingBootstrap && currentUnl.includes(pubkey)) {
            intent.submittedAtLcl = currentLcl || intent.requestedAtLcl || null;
            run.state.membershipCommand = intent;
            saveState(run.state);
            return true;
          }
          throw new Error(`${opLabel} requires Bootstrap A to remain in the committed UNL.`);
        }
        if (currentUnl.includes(pubkey)) {
          intent.submittedAtLcl = currentLcl || intent.requestedAtLcl || null;
          run.state.membershipCommand = intent;
          saveState(run.state);
          console.log(`AutoCluster: ${opLabel} target ${cleanString(pubkey,24)} is already committed; marked command submitted idempotently.`);
          return true;
        }
        const targetSize = bootstrapBridgeUnlTarget(run.state);
        if (!swappingBootstrap && currentUnl.length >= targetSize) throw new Error(`ADD_UNL refused: temporary bootstrap bridge already has ${currentUnl.length}/${targetSize} validators.`);
        if (swappingBootstrap && currentUnl.length !== finalManagedTarget(run.state)) throw new Error(`SWAP_BOOTSTRAP refused: legacy swap mode requires the old target-sized bridge.`);
        const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === pubkey) || null;
        if (!node || node.isUnl) throw new Error(`${opLabel} refused: ${pubkey} is not a materialized non-UNL managed candidate.`);
        if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(node.signerAddress || ''))) throw new Error(`${opLabel} refused: ${pubkey} has not committed its signed public managed signer identity yet.`);
        const forceOverride = normalizeBootstrapMeshOverride(run.state.bootstrapMeshOverride);
        const forceAll = !!(forceOverride && forceOverride.forcedPubkey === pubkey && forceOverride.bypassAll === true);
        const maturityStable = nodeMaturityStability(node, run.state, currentLcl);
        if (!maturityStable.ready) {
          throw new Error(`ADD_UNL refused: ${pubkey} has only ${maturityStable.age}/${maturityStable.required} committed old-UNL ledgers since authenticated MATURED/ACKNOWLEDGED.`);
        }
        const commandAge = intent.requestedAtLcl && currentLcl ? Math.max(0, currentLcl - intent.requestedAtLcl) : 0;
        const finalProofRaw = parsed && parsed.finalProof && typeof parsed.finalProof === 'object' ? parsed.finalProof : null;
        const finalProof = finalProofRaw ? {
          candidateLcl:Number(finalProofRaw.candidateLcl) || 0,
          candidateHash:cleanString(finalProofRaw.candidateHash || '',256).toLowerCase(),
          bootstrapLcl:Number(finalProofRaw.bootstrapLcl) || 0,
          bootstrapHash:cleanString(finalProofRaw.bootstrapHash || '',256).toLowerCase(),
          candidateLag:Number(finalProofRaw.candidateLag),
          peerCount:Math.max(0, Number(finalProofRaw.peerCount) || 0),
          contractExecutionEnabled:finalProofRaw.contractExecutionEnabled === true,
          weaklyConnected:finalProofRaw.weaklyConnected === true,
          currentUnl:normalizePubkeyList(finalProofRaw.currentUnl),
          canonicalMatched:finalProofRaw.canonicalMatched === true,
          voteStatus:cleanString(finalProofRaw.voteStatus || '',32).toLowerCase() || null,
          firstAddSyncStreak:finalProofRaw.firstAddSyncStreak && typeof finalProofRaw.firstAddSyncStreak === 'object' ? {
            required:Math.max(0, Number(finalProofRaw.firstAddSyncStreak.required) || 0),
            observations:Array.isArray(finalProofRaw.firstAddSyncStreak.observations) ? finalProofRaw.firstAddSyncStreak.observations.slice(0, FIRST_ADD_SYNC_STREAK_REQUIRED + 2).map(o => ({
              lcl:Math.max(0, Number(o && o.lcl) || 0),
              hash:cleanString(o && o.hash || '',256).toLowerCase(),
              voteStatus:cleanString(o && o.voteStatus || '',32).toLowerCase(),
              peerCount:Math.max(0, Number(o && o.peerCount) || 0)
            })) : []
          } : null
        } : null;
        if (!STOCK_CLONE_BOOTSTRAP && !forceAll && intent.requestedAtLcl && currentLcl && commandAge > BOOTSTRAP_MEMBERSHIP_COMMAND_MAX_AGE_LCLS) {
          run.state.membershipCommand = null;
          if (run.state.promotionBatch && run.state.promotionBatch.active) {
            run.state.promotionBatch.submittedAtLcl = null;
            run.state.promotionBatch.submittedPubkey = null;
            run.state.promotionBatch.reason = `expired ADD_UNL intent for ${pubkey}; requalify ACKNOWLEDGED + current READY before retry`;
          }
          saveState(run.state);
          console.log(`AutoCluster: ${opLabel} intent EXPIRED for ${cleanString(pubkey,24)} requestLcl=${intent.requestedAtLcl} executeLcl=${currentLcl} age=${commandAge}/${BOOTSTRAP_MEMBERSHIP_COMMAND_MAX_AGE_LCLS}. No config patch written; candidate must be requalified.`);
          return true;
        }
        const maturityStatus = diskNodeStatus(node);
        if (maturityStatus !== 'acknowledged' && !forceAll) {
          run.state.membershipCommand = null;
          saveState(run.state);
          console.log(`AutoCluster: ${opLabel} intent CANCELLED for ${cleanString(pubkey,24)} at LCL ${currentLcl || '?'} because native EverPocket status=${maturityStatus || 'unknown'}; ACKNOWLEDGED is mandatory. No config patch written.`);
          return true;
        }
        const proof = promotionProofStatus(run.state, pubkey, currentLcl, run.state.promotionBatch, {
          proofFreshLcl:ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL,
          observationFreshLcl:ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL,
          atomicBootstrap:true
        });
        const syncNow = syncQuiescenceStatus(run.state, pubkey, currentLcl);
        const forcedAdmission = forceAll;
        const latestReady = normalizeCandidateReadiness(run.state.candidateReadiness).find(r => String(r.pubkey || '').toLowerCase() === pubkey) || null;
        const stableQualification = !!(latestReady &&
          Number(latestReady.readyHeartbeats || 0) >= CANDIDATE_READY_REQUIRED_HEARTBEATS &&
          Number(latestReady.syncHeartbeats || 0) >= SYNC_QUIESCENT_REQUIRED_EXECUTIONS);
        const requiredPeers = requiredAdmissionPeers(currentUnl.length);

        if (STOCK_CLONE_BOOTSTRAP) {
          // The replicated READY record is deliberately only a qualification history.
          // The actual membership boundary is authorized by a FINAL live proof collected
          // immediately before this user input was submitted by Bootstrap A's isolated
          // controller. This avoids using an observation that was current several
          // ledgers earlier but stale by the membership execution.
          // Transport age is measured from Bootstrap A's sampled head, not from the
          // candidate LCL. A network LCL/hash alone is NOT sufficient evidence that
          // the candidate's local primary/raw shards are ready: hpcore may advertise
          // the consensus ledger while history sync is still catching up. Therefore
          // every stock-clone ADD requires voteStatus=synced at FINAL proof time. The
          // zero-fault-tolerance 1->2 transition additionally requires five advancing
          // exact-tip + synced observations and a tighter two-ledger dispatch window.
          const firstAdd = !swappingBootstrap && currentUnl.length === 1;
          const finalAgeLimit = firstAdd ? FIRST_ADD_FINAL_PROOF_MAX_AGE_LCLS : LOCKSTEP_FINAL_PROOF_MAX_AGE_LCLS;
          const finalAge = finalProof && currentLcl && finalProof.bootstrapLcl ? currentLcl - finalProof.bootstrapLcl : Number.POSITIVE_INFINITY;
          const finalLag = finalProof ? Number(finalProof.candidateLag) : Number.POSITIVE_INFINITY;
          const finalTupleMatches = !!(finalProof && finalProof.canonicalMatched === true &&
            finalProof.candidateLcl > 0 && finalProof.bootstrapLcl === finalProof.candidateLcl &&
            /^[0-9a-f]{64}$/.test(finalProof.candidateHash) && /^[0-9a-f]{64}$/.test(finalProof.bootstrapHash) &&
            finalProof.candidateHash === finalProof.bootstrapHash &&
            Number.isFinite(finalLag) && finalLag === 0);
          const finalUnlMatches = !!(finalProof && samePubkeySet(finalProof.currentUnl, currentUnl));
          const finalVoteSynced = !!(finalProof && finalProof.voteStatus === 'synced');
          const finalCurrent = !!(finalProof && finalTupleMatches && finalAge >= 0 && finalAge <= finalAgeLimit);
          const finalHealthy = !!(finalProof && finalProof.contractExecutionEnabled && !finalProof.weaklyConnected && finalVoteSynced);
          const finalMesh = !!(finalProof && finalProof.peerCount >= requiredPeers);
          let firstAddStreakOk = !firstAdd;
          if (firstAdd && finalProof && finalProof.firstAddSyncStreak) {
            const streak = finalProof.firstAddSyncStreak;
            const observations = Array.isArray(streak.observations) ? streak.observations : [];
            firstAddStreakOk = Number(streak.required) === FIRST_ADD_SYNC_STREAK_REQUIRED && observations.length === FIRST_ADD_SYNC_STREAK_REQUIRED;
            if (firstAddStreakOk) {
              for (let i = 0; i < observations.length; i++) {
                const o = observations[i] || {};
                if (!(o.lcl > 0) || !/^[0-9a-f]{64}$/.test(o.hash || '') || o.voteStatus !== 'synced' || Number(o.peerCount) < requiredPeers) {
                  firstAddStreakOk = false; break;
                }
                if (i > 0 && Number(o.lcl) <= Number(observations[i-1].lcl)) { firstAddStreakOk = false; break; }
              }
            }
            const first = observations.length ? observations[0] : null;
            const last = observations.length ? observations[observations.length - 1] : null;
            if (firstAddStreakOk && (!first || !last || Number(last.lcl) - Number(first.lcl) < FIRST_ADD_SYNC_STREAK_REQUIRED - 1 || Number(last.lcl) !== finalProof.candidateLcl || cleanString(last.hash || '',256).toLowerCase() !== finalProof.candidateHash)) firstAddStreakOk = false;
          }
          const healthyBoundedFinal = !!(stableQualification && finalTupleMatches && finalUnlMatches && finalCurrent && finalHealthy && finalMesh && firstAddStreakOk);
          if (healthyBoundedFinal && run.state.promotionBatch && run.state.promotionBatch.active) {
            // The controller proved this pre-UNL candidate was at A's exact canonical tip
            // before dispatch. Protect it from the absolute hard timeout while a
            // bounded consensus-transport retry is in flight; this never bypasses
            // CURRENT READY/SYNC/mesh checks on the next retry.
            run.state.promotionBatch.lastFinalProofAtLcl = currentLcl || finalProof.candidateLcl || null;
            run.state.promotionBatch.admissionGraceUntilLcl = (currentLcl || finalProof.candidateLcl || 0) + LOCKSTEP_FINAL_ADMISSION_RETRY_GRACE_LCLS;
          }
          if (!stableQualification || !finalTupleMatches || !finalUnlMatches || !finalCurrent || !finalHealthy || !finalMesh || !firstAddStreakOk) {
            // Fail closed WITHOUT throwing after the input reached consensus. For the
            // direct atomic stock-bootstrap path, rejection is deliberately state-NOOP:
            // the root sidecar rotates/retries candidates locally so /state remains
            // frozen. Legacy intent mode retains its replicated retry bookkeeping.
            if (directAtomicStockAdd) {
              console.log(`AutoCluster: ATOMIC ADD_UNL FINAL-PROOF REJECTED pubkey=${cleanString(pubkey,24)} executeLcl=${currentLcl || '?'} stable=${stableQualification} tuple=${finalTupleMatches} current=${finalCurrent} age=${Number.isFinite(finalAge)?finalAge:'unknown'}/${finalAgeLimit} lag=${finalProof?finalProof.candidateLag:'missing'} unl=${finalUnlMatches} vote=${finalProof&&finalProof.voteStatus||'missing'} streak=${firstAdd?firstAddStreakOk:'n/a'} exec=${!!(finalProof&&finalProof.contractExecutionEnabled)} weak=${!!(finalProof&&finalProof.weaklyConnected)} peers=${finalProof?finalProof.peerCount:'?'} / ${requiredPeers}. Replicated state is unchanged; root controller may immediately try another qualified candidate.`);
              return true;
            }
            run.state.membershipCommand = null;
            if (run.state.promotionBatch && run.state.promotionBatch.active) {
              run.state.promotionBatch.submittedAtLcl = null;
              run.state.promotionBatch.submittedPubkey = null;
              run.state.promotionBatch.skipPubkey = pubkey;
              run.state.promotionBatch.skipUntilLcl = currentLcl + LOCKSTEP_FINAL_CANDIDATE_COOLDOWN_LCLS;
              run.state.promotionBatch.reason = healthyBoundedFinal
                ? `lockstep ADD_UNL final proof transport-age retry for ${pubkey}; temporarily rotate behind other qualified candidates`
                : `lockstep ADD_UNL final proof rejected for ${pubkey}; temporarily rotate behind other qualified candidates`;
            }
            saveState(run.state);
            console.log(`AutoCluster: LOCKSTEP ADD_UNL FINAL-PROOF REJECTED pubkey=${cleanString(pubkey,24)} executeLcl=${currentLcl || '?'} stable=${stableQualification} tuple=${finalTupleMatches} current=${finalCurrent} age=${Number.isFinite(finalAge)?finalAge:'unknown'}/${finalAgeLimit} lag=${finalProof?finalProof.candidateLag:'missing'} unl=${finalUnlMatches} vote=${finalProof&&finalProof.voteStatus||'missing'} streak=${firstAdd?firstAddStreakOk:'n/a'} exec=${!!(finalProof&&finalProof.contractExecutionEnabled)} weak=${!!(finalProof&&finalProof.weaklyConnected)} peers=${finalProof?finalProof.peerCount:'?'} / ${requiredPeers}. No config patch written; intent cleared for deterministic retry${healthyBoundedFinal ? ' and hard-timeout protection refreshed' : ''}.`);
            return true;
          }
          console.log(`AutoCluster: LOCKSTEP ADD_UNL FINAL-PROOF ACCEPTED pubkey=${cleanString(pubkey,24)} candidateLcl=${finalProof.candidateLcl} executeLcl=${currentLcl} age=${finalAge}/${finalAgeLimit} hash=${cleanString(finalProof.candidateHash,16)} vote=${finalProof.voteStatus} peers=${finalProof.peerCount}/${requiredPeers}; candidate matched Bootstrap A's exact LCL/hash with voteStatus=synced before dispatch${firstAdd?' across the required five advancing exact/synced observations':''} and remained within the bounded immutable-freeze transport window with the expected old UNL, healthy execution and live peer mesh; no replicated pre-intent existed.`);
        } else {
          if (!syncNow.ready) throw new Error(`ADD_UNL refused: runtime SYNC for ${pubkey} is missing/stale.`);
          if (!proof.ready) throw new Error(`ADD_UNL refused: canonical READY proof for ${pubkey} is no longer CURRENT.`);
          if (Number(proof.peerCount || 0) < requiredPeers) throw new Error(`ADD_UNL refused: candidate reports ${Number(proof.peerCount || 0)}/${requiredPeers} live peer connection(s).`);
        }
        console.log(`AutoCluster: ${opLabel} QUALIFICATION FINAL pubkey=${cleanString(pubkey,24)} maturity=${maturityStatus} mode=${STOCK_CLONE_BOOTSTRAP?'lockstep-final-live-proof':'canonical-sync-gated'} candidateLcl=${STOCK_CLONE_BOOTSTRAP&&finalProof?finalProof.candidateLcl:(Number(latestReady && latestReady.candidateLcl)||'?')} requestLcl=${intent.requestedAtLcl || '?'} executeLcl=${currentLcl || '?'} commandAge=${commandAge} peers=${STOCK_CLONE_BOOTSTRAP&&finalProof?finalProof.peerCount:Number(proof.peerCount||0)}/${requiredPeers} forcedPolicy=${forcedAdmission}.`);
        const nextUnl = swappingBootstrap
          ? normalizePubkeyList([...currentUnl.filter(pk => pk !== bootstrap), pubkey])
          : normalizePubkeyList([...currentUnl, pubkey]);
        if ((!swappingBootstrap && nextUnl.length !== currentUnl.length + 1) || (swappingBootstrap && nextUnl.length !== currentUnl.length)) throw new Error(`${opLabel} size invariant failed.`);
        const unchangedThreshold = readConsensusThreshold(cfg);
        const configBeforeUnlOnly = JSON.parse(JSON.stringify(cfg));
        setContractUnl(cfg, nextUnl);
        const configDiff = jsonDiffPaths(configBeforeUnlOnly, cfg);
        const illegalConfigDiff = configDiff.filter(p => p !== 'contract.unl' && p !== 'unl');
        if (illegalConfigDiff.length) throw new Error(`${opLabel} config purity invariant failed: unexpected config mutation(s) ${illegalConfigDiff.join(',')}`);
        console.log(`AutoCluster: ${opLabel} CONFIG-PURITY AUDIT pubkey=${cleanString(pubkey,24)} changedPaths=[${configDiff.join(',')||'none'}] thresholdBeforeAfter=${unchangedThreshold}/${readConsensusThreshold(cfg)}. No unrelated HotPocket config field is submitted by this command.`);
        if (!swappingBootstrap && STOCK_CLONE_BOOTSTRAP && run.clusterContext && typeof run.clusterContext.addToUnl === 'function') {
          // Use EverPocket's stock membership primitive, matching its one-at-a-time
          // promotion flow. Immediately afterward, mirror the reference cluster
          // manager's critical v1.3.0 behavior: persist and live-apply the COMPLETE
          // expanded UNL peer mesh so a config reload/restart cannot strand the new voter.
          await run.clusterContext.addToUnl(pubkey);
          console.log(`AutoCluster: STOCK EVERPOCKET addToUnl(${cleanString(pubkey,24)}) executed from authenticated HotPocket user input.`);
          markClusterNodesUnl(run.clusterContext, [pubkey]);
          await applyFullUnlPeerMesh(run, nextUnl, `ADD_UNL ${cleanString(pubkey,24)}`);
        } else if (swappingBootstrap) {
          await applyFullUnlPeerMesh(run, nextUnl, `SWAP_BOOTSTRAP A->${cleanString(pubkey,24)}`);
          const manager = run.clusterContext && run.clusterContext.clusterManager;
          if (manager && typeof manager.markAsQuorum === 'function') manager.markAsQuorum(bootstrap, null);
          if (manager && typeof manager.removeNode === 'function') manager.removeNode(bootstrap);
        } else {
          if (!cfg.mesh || typeof cfg.mesh !== 'object') cfg.mesh = {};
          cfg.mesh.known_peers = fullUnlPeerListFromNodes(run, nextUnl);
          await run.ctx.updateConfig(cfg);
          if (run.hpContext && typeof run.hpContext.updatePeers === 'function') await run.hpContext.updatePeers(cfg.mesh.known_peers);
        }
        run.hpContext.__everSmartNodeConfigTransitionThisExecution = true;
        run.deferTickOnce = true;
        run.hpContext.__everSmartNodeBatchUnlPubkeys = [pubkey];
        markClusterNodesUnl(run.clusterContext, [pubkey]);
        run.state.promotionTransition = null;
        run.state.bootstrapMeshOverride = null;
        if (swappingBootstrap) {
          run.state.phase = 'handover';
          run.state.handoverObservedAtLcl = currentLcl || null;
        }
        run.state.candidateSyncQuiescence = normalizeCandidateSyncQuiescence(run.state.candidateSyncQuiescence).filter(r => r.pubkey !== pubkey);
        if (directAtomicStockAdd) {
          run.state.membershipCommand = null;
        } else {
          intent.submittedAtLcl = currentLcl || null;
          run.state.membershipCommand = intent;
        }
        if (run.state.promotionBatch && run.state.promotionBatch.active) {
          run.state.promotionBatch.submittedAtLcl = currentLcl || null;
          run.state.promotionBatch.submittedPubkey = pubkey;
          run.state.promotionBatch.reason = `HotPocket user-command ADD_UNL submitted for ${pubkey}; waiting for committed expanded set`;
        }
        saveState(run.state);
        console.log(`AutoCluster: HOTPOCKET USER COMMAND ${opLabel} EXECUTED at LCL ${currentLcl || '?'}: ${currentUnl.length}->${nextUnl.length}, added=${cleanString(pubkey,24)}${swappingBootstrap ? ` removedBootstrap=${cleanString(bootstrap,24)}` : ''}, threshold unchanged=${unchangedThreshold}%. Every current validator executed this same command input.`);
        return true;
      }

      if (operation === 'remove-bootstrap') {
        const bootstrap = cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase();
        if (pubkey !== bootstrap) throw new Error('REMOVE_UNL command may remove only Bootstrap A during handover.');
        if (!Number(run.state.handoverPreparedAtLcl)) throw new Error('REMOVE_UNL refused: treasury signer/reward handover has not been prepared through consensus yet.');
        if (!['ready-to-handover','handover'].includes(run.state.phase)) throw new Error(`REMOVE_UNL refused from phase ${run.state.phase || 'unknown'}.`);
        if (!currentUnl.includes(bootstrap)) {
          intent.submittedAtLcl = currentLcl || intent.requestedAtLcl || null;
          run.state.membershipCommand = intent;
          saveState(run.state);
          return true;
        }
        const target = Math.max(1, Number(run.state.targetManagedNodes) || 1);
        const managed = currentUnl.filter(pk => pk !== bootstrap);
        if (currentUnl.length !== target + 1 || managed.length !== target) {
          throw new Error(`REMOVE_UNL refused: expected Bootstrap A + exactly ${target} managed validators, got ${currentUnl.length} total.`);
        }
        const nextUnl = normalizePubkeyList(managed);
        setContractUnl(cfg, nextUnl);
        await applyFullUnlPeerMesh(run, nextUnl, 'REMOVE_UNL bootstrap handover');
        const b = run.state.bootstrapEndpoint || {};
        const bootstrapPeer = normalizeEndpointHost(b.domain) && validPort(b.peerPort) ? `${normalizeEndpointHost(b.domain)}:${validPort(b.peerPort)}` : null;
        if (bootstrapPeer && run.hpContext && typeof run.hpContext.updatePeers === 'function') {
          await run.hpContext.updatePeers([], [bootstrapPeer]);
        }
        run.hpContext.__everSmartNodeConfigTransitionThisExecution = true;
        run.deferTickOnce = true;
        const manager = run.clusterContext && run.clusterContext.clusterManager;
        if (manager && typeof manager.markAsQuorum === 'function') manager.markAsQuorum(bootstrap, null);
        if (manager && typeof manager.removeNode === 'function') manager.removeNode(bootstrap);
        run.state.phase = 'handover';
        run.state.handoverObservedAtLcl = currentLcl || null;
        run.state.promotionBatch = null;
        intent.submittedAtLcl = currentLcl || null;
        run.state.membershipCommand = intent;
        saveState(run.state);
        console.log(`AutoCluster: HOTPOCKET USER COMMAND REMOVE_UNL(A) EXECUTED at LCL ${currentLcl || '?'}: ${currentUnl.length}->${nextUnl.length}. Bootstrap A leaves consensus BEFORE DisableMaster.`);
        return true;
      }
      return true;
    }

    // SYNC is a node-authenticated, node-local HPFS caught-up proof from a
    // managed candidate. It proves the latest observed HPFS targets were achieved; It is deliberately separate from READY: Bootstrap A's
    // controller proves canonical ledger identity, while the candidate itself
    // proves its latest /primary,/raw,/state targets have all been achieved. The state
    // target may legitimately advance every ledger; no wall-clock idle window is required.
    // The proof is short-lived for admission. Emergency operator Force-add may bypass policy gates, but never this canonical HPFS safety proof.
    if (parsed && parsed.type === 'autocluster_sync_quiescent') {
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      const observedAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      // EverPocket 0.1.6 HotPocketContext.sendMessage() is hard-wired to finish
      // only after it receives the same response shape used by MATURED. Our
      // custom SYNC proof is still a normal authenticated HotPocket user input,
      // but without this compatibility ACK the candidate blocks inside
      // sendMessage() for up to 60 seconds after the input was already accepted.
      // That stall alone can make a perfectly synced observer fall many ledgers
      // behind. Always answer promptly; this response is user output only and is
      // never written into replicated state.
      const replySync = async (status) => {
        if (user && typeof user.send === 'function') {
          await user.send(JSON.stringify({ type:'maturity_ack', status:status === 'ok' ? 'ok' : 'fail' }));
        }
      };
      if (!claimed || !actual || claimed !== actual) {
        console.log(`AutoCluster: ignored SYNC-QUIESCENT identity mismatch claimed=${cleanString(claimed||'missing',80)} actual=${cleanString(actual||'missing',80)}.`);
        await replySync('fail');
        return true;
      }
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log(`AutoCluster: deferred SYNC-QUIESCENT from ${cleanString(claimed,24)} because a membership transition is already armed; transition ledger stays control-plane quiet.`);
        await replySync('fail');
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
      if (!node || node.isUnl) {
        console.log(`AutoCluster: ignored SYNC-QUIESCENT from ${cleanString(claimed,24)} because sender is ${node && node.isUnl ? 'already UNL' : 'not a materialized candidate'}.`);
        await replySync('fail');
        return true;
      }
      const candidateLcl = Number(parsed.lcl) || 0;
      const candidateHash = cleanString(parsed.lclHash || '', 256).toLowerCase();
      const streak = Math.max(0, Number(parsed.streak) || 0);
      const idleMs = Math.max(0, Number(parsed.idleMs) || 0); // diagnostic only
      const primaryHash = cleanString(parsed.primaryHash || '',128).toLowerCase();
      const rawHash = cleanString(parsed.rawHash || '',128).toLowerCase();
      const stateHash = cleanString(parsed.stateHash || '',128).toLowerCase();
      const hpfsHashesValid = [primaryHash, rawHash, stateHash].every(h => /^[0-9a-f]+$/.test(h));
      if (!candidateLcl || !/^[0-9a-f]{64}$/.test(candidateHash) || streak < SYNC_QUIESCENT_REQUIRED_EXECUTIONS || !hpfsHashesValid) {
        console.log(`AutoCluster: ignored malformed/insufficient SYNC proof from ${cleanString(claimed,24)} lcl=${candidateLcl||'?'} streak=${streak}/${SYNC_QUIESCENT_REQUIRED_EXECUTIONS} hpfsHashesValid=${hpfsHashesValid}. Wall-clock HPFS idle is intentionally NOT an admission requirement because EverPocket advances cluster.json state every execution.`);
        await replySync('fail');
        return true;
      }
      const list = normalizeCandidateSyncQuiescence(run.state.candidateSyncQuiescence).filter(r => r.pubkey !== claimed);
      list.push({
        pubkey:claimed, candidateLcl, candidateHash, observedAtLcl:observedAtLcl || null, streak, idleMs,
        primaryHash:primaryHash || null,
        rawHash:rawHash || null,
        stateHash:stateHash || null,
        patchHash:cleanString(parsed.patchHash || '',128).toLowerCase() || null
      });
      run.state.candidateSyncQuiescence = normalizeCandidateSyncQuiescence(list);
      saveState(run.state);
      console.log(`AutoCluster: VERIFIED SYNC recorded for ${cleanString(claimed,24)} candidateLcl=${candidateLcl} observedAtBootstrapLcl=${observedAtLcl||'?'} streak=${streak}; latest HPFS targets achieved primary=${cleanString(primaryHash,12)} raw=${cleanString(rawHash,12)} state=${cleanString(stateHash,12)} activityAge=${idleMs}ms diagnostic-only.`);
      await replySync('ok');
      return true;
    }

    // MANAGED NODE-SIGNED SIDECAR REPORT. Production HotPocket NPL is a validator
    // party line; a candidate outside UNL can write to its local NPL fd but that
    // does not make it an NPL participant of the current validator set. Instead
    // the candidate contract signs its own LCL/HPFS-target/maturity into a node-local
    // file with the HotPocket validator key. server.js submits that signed
    // envelope through the candidate's own local user.port after contract
    // execution. The ordinary HotPocket input is then consensused by the current
    // UNL, and this handler verifies the inner node signature deterministically.
    if (parsed && parsed.type === AUTOCLUSTER_CANDIDATE_ATTESTATION_TYPE) {
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      if (!verifySignedCandidateAttestation(parsed)) {
        console.log(`AutoCluster: ignored candidate signed-attestation with invalid node signature claimed=${cleanString(claimed || 'missing',80)}.`);
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
      if (!node || claimed === cleanString(run.state.bootstrapPubkey || '',256).toLowerCase()) {
        console.log(`AutoCluster: ignored managed signed-attestation ${cleanString(claimed,80)} because it is ${!node ? 'not a materialized managed node' : 'Bootstrap A'}.`);
        return true;
      }
      const expectedUnl = currentUnlPubkeys(run);
      const reportedUnl = normalizePubkeyList(parsed.currentUnl);
      if (JSON.stringify(expectedUnl) !== JSON.stringify(reportedUnl)) {
        console.log(`AutoCluster: ignored candidate signed-attestation ${cleanString(claimed,24)} due UNL mismatch reported=[${reportedUnl.join(',')}] expected=[${expectedUnl.join(',')}].`);
        return true;
      }
      const bootstrapLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const candidateLcl = Number(parsed.lcl) || 0;
      const candidateHash = cleanString(parsed.lclHash || '', 256).toLowerCase();
      const candidateLag = bootstrapLcl && candidateLcl ? bootstrapLcl - candidateLcl : Number.POSITIVE_INFINITY;
      const hpfsReady = parsed.hpfsReady === true;
      const primaryHash = cleanString(parsed.primaryHash || '',128).toLowerCase();
      const rawHash = cleanString(parsed.rawHash || '',128).toLowerCase();
      const stateHash = cleanString(parsed.stateHash || '',128).toLowerCase();
      const patchHash = cleanString(parsed.patchHash || '',128).toLowerCase() || null;
      const hpfsHashesValid = [primaryHash, rawHash, stateHash].every(h => /^[0-9a-f]+$/.test(h));

      // MATURITY IS INDEPENDENT OF HPFS READINESS. A candidate can legitimately
      // complete EverPocket CONFIGURED -> MATURED while HPFS is still catching up
      // from the consensus input that carried the maturity relay. The old ordering
      // rejected the whole signed envelope when hpfsReady=false, so shared
      // cluster.json never reached ACKNOWLEDGED and promotion could never begin.
      // Commit this one-shot semantic transition first; readiness is gated below.
      let maturityNote = 'not-ready';
      let maturityChanged = false;
      let signerChanged = false;
      const attestedSigner = cleanString(parsed.signerAddress || '', 96);
      if (attestedSigner) {
        if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(attestedSigner)) {
          console.log(`AutoCluster: ignored invalid pre-UNL signer address from ${cleanString(claimed,24)}: ${cleanString(attestedSigner,80)}.`);
        } else {
          const markedSigner = markSharedSignerAddress(run.clusterContext, claimed, attestedSigner);
          if (markedSigner.conflict) {
            console.log(`AutoCluster: ignored pre-UNL signer change for ${cleanString(claimed,24)} shared=${cleanString(markedSigner.signerAddress,80)} attested=${cleanString(attestedSigner,80)}.`);
          } else {
            signerChanged = !!markedSigner.changed;
          }
        }
      }
      if (parsed.maturityReady === true && /^(?:acknowledged|added_to_unl|unl)$/.test(cleanString(parsed.privateStatus || '',64).toLowerCase())) {
        const marked = markSharedMaturityAcknowledged(run.clusterContext, claimed, bootstrapLcl);
        maturityNote = `${marked.status}${marked.changed ? '-written' : ''}`;
        maturityChanged = !!marked.changed;
        const signals = normalizeMaturitySignals(run.state.maturitySignals);
        const priorSignal = signals.find(x => String(x.pubkey || '').toLowerCase() === claimed) || null;
        if (!priorSignal || marked.changed) {
          const nextSignals = signals.filter(x => String(x.pubkey || '').toLowerCase() !== claimed);
          nextSignals.push({
            pubkey:node.pubkey,
            host:node.host || null,
            firstReceivedAtLcl:priorSignal && priorSignal.firstReceivedAtLcl || bootstrapLcl || null,
            lastReceivedAtLcl:bootstrapLcl || null,
            count:Math.max(1, Number(priorSignal && priorSignal.count || 0)),
            sharedStatusAtLastReceive:marked.status || diskNodeStatus(node)
          });
          run.state.maturitySignals = normalizeMaturitySignals(nextSignals);
          maturityChanged = true;
        }
      }

      // IMPORTANT CONSENSUS BOUNDARY: the signed candidate envelope is allowed to
      // carry only deterministic maturity here. Canonical LCL/hash validation is
      // deliberately NOT performed inside replicated contract execution because
      // ../autocluster-local/recent-ledgers.json is node-local and can differ by
      // one or more observations across validators during HPFS catch-up. Reading
      // that file here caused validators to make different READY decisions after
      // the first UNL expansion. Bootstrap A's root-side controller now performs
      // the local canonical comparison and submits a separate authenticated
      // autocluster_ready_observation that every validator processes identically.
      if (maturityChanged || signerChanged) saveState(run.state);
      console.log(`AutoCluster: SIGNED CANDIDATE ATTESTATION accepted sender=${cleanString(claimed,24)} candidateLcl=${candidateLcl||'?'} bootstrapLcl=${bootstrapLcl||'?'} lag=${Number.isFinite(candidateLag)?candidateLag:'?'} maturity=${maturityNote} signer=${attestedSigner || 'missing'} signerWrite=${signerChanged?'yes':'no'} stateWrite=${(maturityChanged||signerChanged)?'yes':'no'}; READY is controller-validated outside consensus.`);
      return true;
    }

    // NPL maturity bridge. The candidate's MATURED envelope is authenticated by
    // HotPocket NPL sender identity and cached outside consensus state. Bootstrap
    // A's authorized controller then submits this deterministic observation as a
    // normal HotPocket input; no candidate user WebSocket is opened.
    if (parsed && parsed.type === 'autocluster_npl_maturity_observation') {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: NPL MATURED observation deferred because a membership transition is armed.');
        return true;
      }
      const controller = hotPocketUserPubkey(user);
      const expectedController = cleanString(run.state.readyControllerPublicKey || '', 80).toLowerCase();
      if (!controller || controller !== expectedController) {
        console.log(`AutoCluster: ignored NPL MATURED observation from unauthorized controller=${cleanString(controller || 'missing',80)}.`);
        return true;
      }
      const claimed = cleanString(parsed.candidatePubkey || '', 256).toLowerCase();
      const observedAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
      if (!claimed || !node || node.isUnl) return true;
      const sharedStatus = diskNodeStatus(node);
      const signals = normalizeMaturitySignals(run.state.maturitySignals);
      const prior = signals.find(x => String(x.pubkey).toLowerCase() === claimed) || null;
      const next = signals.filter(x => String(x.pubkey).toLowerCase() !== claimed);
      next.push({
        pubkey:node.pubkey,
        host:node.host || null,
        firstReceivedAtLcl:prior && prior.firstReceivedAtLcl || observedAtLcl || null,
        lastReceivedAtLcl:observedAtLcl || null,
        count:Number(prior && prior.count || 0)+1,
        sharedStatusAtLastReceive:sharedStatus
      });
      run.state.maturitySignals = normalizeMaturitySignals(next);
      const marked = markSharedMaturityAcknowledged(run.clusterContext, claimed, observedAtLcl);
      saveState(run.state);
      console.log(`AutoCluster: NPL MATURED COMMITTED for ${cleanString(claimed,80)} at LCL ${observedAtLcl || '?'}; shared ${sharedStatus} -> ${marked.status}${marked.changed ? ' (written)' : ''}.`);
      return true;
    }

    // MATURED is native EverPocket maturity signalling, not a sync proof by itself.
    // Its authenticated handler must move the shared node row to ACKNOWLEDGED.
    // Admission then requires BOTH that shared ACKNOWLEDGED state and a fresh
    // canonical READY/mesh proof, so neither signal is trusted alone.
    if (parsed && parsed.type === 'maturity_ack') {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: MATURED deferred because a membership transition is armed; transition ledger stays state-quiet and candidate will retry.');
        if (user && typeof user.send === 'function') await user.send(JSON.stringify({ type:'maturity_ack', status:'fail' }));
        return true;
      }
      const claimed = cleanString(parsed.data || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      const observedAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      let responseStatus = 'fail';

      if (claimed && actual && claimed !== actual) {
        console.log(`AutoCluster: ignored MATURED with identity mismatch claimed=${cleanString(claimed,80)} actual=${cleanString(actual,80)}.`);
      } else if (claimed && actual && claimed === actual) {
        const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
        const sharedStatus = node ? diskNodeStatus(node) : 'missing';
        const signals = normalizeMaturitySignals(run.state.maturitySignals);
        const prior = signals.find(x => String(x.pubkey).toLowerCase() === claimed) || null;
        const next = signals.filter(x => String(x.pubkey).toLowerCase() !== claimed);
        next.push({pubkey:node && node.pubkey || claimed,host:node && node.host || null,
          firstReceivedAtLcl:prior && prior.firstReceivedAtLcl || observedAtLcl || null,
          lastReceivedAtLcl:observedAtLcl || null,count:Number(prior && prior.count || 0)+1,
          sharedStatusAtLastReceive:sharedStatus});
        run.state.maturitySignals = normalizeMaturitySignals(next);
        saveState(run.state);

        // Handle the tiny deterministic state transition directly. This remains
        // available even when bootstrap growth uses createSigningClusterView(),
        // whose EverPocket lifecycle handler is intentionally disabled.
        const marked = markSharedMaturityAcknowledged(run.clusterContext, claimed, observedAtLcl);
        if (marked.found) responseStatus = 'ok';
        console.log(`AutoCluster: REAL MATURED input RECEIVED from ${cleanString(claimed,80)} host=${node && node.host || 'unknown'} at LCL ${observedAtLcl || '?'}; shared ${sharedStatus} -> ${marked.status}${marked.changed ? ' (written)' : ''} via=${marked.via || 'none'}.`);
      }

      // EverPocket HotPocketContext.sendMessage() does not resolve merely because
      // the input was accepted. It waits for this exact contract output:
      // {type:'maturity_ack',status:'ok'}. Mirror stock ClusterContext.feedUserMessage
      // so the candidate can finish its private CONFIGURED -> ACKNOWLEDGED step.
      if (user && typeof user.send === 'function') {
        await user.send(JSON.stringify({ type:'maturity_ack', status:responseStatus }));
      }
      return true;
    }

    // Initial bootstrap signer provisioning deliberately does NOT use
    // EverPocket 0.1.6 addXrplSigner(pubkey,...). That helper can legally receive
    // an empty targeted vote result and then dereference signer.account before any
    // NPL message or Xahau submission exists. Instead each managed validator owns
    // its signer key locally and announces only the public Xahau account through
    // an authenticated HotPocket user input. The root-side final handover still
    // uses the treasury master seed to install the complete managed signer list in
    // one transaction, then disables the master key.
    if (parsed && parsed.type === 'autocluster_signer_ready') {
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      const signerAddress = cleanString(parsed.signerAddress || '', 96);
      if (!claimed || !actual || claimed !== actual) {
        console.log(`AutoCluster: ignored MANAGED_SIGNER_READY with identity mismatch claimed=${cleanString(claimed,80)} actual=${cleanString(actual,80)}.`);
        return true;
      }
      if (!['signing','ready-to-handover','handover','autonomous'].includes(run.state.phase)) {
        console.log(`AutoCluster: ignored MANAGED_SIGNER_READY from ${cleanString(claimed,80)} because phase=${run.state.phase || 'unknown'} does not accept managed signer identities.`);
        return true;
      }
      if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(signerAddress)) {
        console.log(`AutoCluster: ignored MANAGED_SIGNER_READY from ${cleanString(claimed,80)} with invalid Xahau signer address ${cleanString(signerAddress,80) || 'empty'}.`);
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
      if (!node || !node.isUnl || node.pubkey === run.state.bootstrapPubkey) {
        console.log(`AutoCluster: ignored MANAGED_SIGNER_READY from ${cleanString(claimed,80)} because sender is not a managed committed-UNL validator.`);
        return true;
      }
      if (node.signerAddress && node.signerAddress !== signerAddress) {
        console.log(`AutoCluster: ignored MANAGED_SIGNER_READY signer change for ${cleanString(node.pubkey,80)}: shared=${cleanString(node.signerAddress,80)} announced=${cleanString(signerAddress,80)}.`);
        return true;
      }
      const manager = run.clusterContext.clusterManager;
      if (!manager || typeof manager.markAsQuorum !== 'function') throw new Error('EverPocket ClusterManager internals changed; markAsQuorum is unavailable.');
      manager.markAsQuorum(node.pubkey, signerAddress);
      clearBlocker(run.state, null, 'managed-signer');
      saveState(run.state);
      console.log(`AutoCluster: MANAGED_SIGNER_READY COMMITTED for ${cleanString(node.pubkey,80)} signer=${signerAddress}. No interim SignerListSet was submitted; the quorum-${run.state.signerQuorum} handover set is frozen from the signer identities that are actually live.`);
      return true;
    }

    if (parsed && parsed.type === 'autocluster_candidate_diag') {
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      if (!claimed || !actual || claimed !== actual) {
        console.log(`AutoCluster: ignored CANDIDATE_DIAG with identity mismatch claimed=${cleanString(claimed,80)} actual=${cleanString(actual,80)}.`);
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed) || null;
      const observedAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const candidateLcl = Number(parsed.lcl) || 0;
      const candidateHash = cleanString(parsed.lclHash || '', 256).toLowerCase();
      const canonical = !!(candidateLcl && candidateHash && verifiedSharedRecentLedger(run.state, candidateLcl, candidateHash));
      const list = normalizeCandidateDiagnostics(run.state.candidateDiagnostics).filter(x => String(x.pubkey).toLowerCase() !== claimed);
      list.push({pubkey:node && node.pubkey || claimed,host:node && node.host || null,observedAtLcl:observedAtLcl || null,
        candidateLcl:candidateLcl || null,candidateHash:candidateHash || null,canonicalAtObservation:canonical,
        localNodePresent:!!parsed.localNodePresent,localIsUnl:!!parsed.localIsUnl,
        localSharedStatus:cleanString(parsed.localSharedStatus || '',64) || null,privateStatus:cleanString(parsed.privateStatus || '',64) || null,
        nodeRole:cleanString(parsed.nodeRole || '',32).toLowerCase() || null,
        bootstrapSharedStatus:node ? diskNodeStatus(node) : 'missing',bootstrapIsUnl:!!(node && node.isUnl),
        buildFingerprint:cleanString(parsed.buildFingerprint || '',256) || null});
      run.state.candidateDiagnostics = normalizeCandidateDiagnostics(list);
      saveState(run.state);
      const watch = normalizeCandidateWatchdogs(run.state.candidateWatchdogs).find(w => String(w.pubkey).toLowerCase() === claimed);
      console.log(`AutoCluster: CANDIDATE_DIAG received ${cleanString(claimed,80)} host=${node && node.host || 'unknown'} role=${cleanString(parsed.nodeRole || 'unknown',32)} localShared=${cleanString(parsed.localSharedStatus || 'unknown',64)} private=${cleanString(parsed.privateStatus || 'unknown',64)} bootstrapShared=${node ? diskNodeStatus(node) : 'missing'} candidateLcl=${candidateLcl || '?'} canonical=${canonical} watchdog=${watch && watch.stalledAt ? 'STALLED' : 'running'}. Diagnostic only; this does not satisfy maturity/admission.`);
      return true;
    }

    // Post-promotion synchronization proof. The sender must be exactly the validator
    // currently being transitioned, must already be in the committed UNL, and must
    // echo a fresh canonical ledger/hash from after the membership change. Only then
    // may AutoCluster restore the normal consensus threshold.
    if (parsed && parsed.type === 'autocluster_validator_active') {
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      const transition = normalizePromotionTransition(run.state.promotionTransition);
      if (!transition || transition.phase !== 'awaiting-active' || String(transition.pubkey).toLowerCase() !== claimed) {
        console.log(`AutoCluster: ignored VALIDATOR_ACTIVE from ${cleanString(claimed,80)} because no matching promotion transition is awaiting proof.`);
        return true;
      }
      if (!claimed || !actual || claimed !== actual) {
        console.log(`AutoCluster: ignored VALIDATOR_ACTIVE with identity mismatch claimed=${cleanString(claimed,80)} actual=${cleanString(actual,80)}.`);
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed);
      if (!node || !node.isUnl) {
        console.log(`AutoCluster: ignored VALIDATOR_ACTIVE from ${cleanString(claimed,80)} because the sender is not in the committed UNL.`);
        return true;
      }
      const observedAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const candidateLcl = Number(parsed.lcl) || 0;
      const candidateHash = cleanString(parsed.lclHash || '', 256).toLowerCase();
      const minimumPostStitchLcl = Number(transition.membershipObservedAtLcl || transition.membershipSubmittedAtLcl) || 0;
      if (!candidateLcl || candidateLcl <= minimumPostStitchLcl || !candidateHash || !verifiedSharedRecentLedger(run.state, candidateLcl, candidateHash)) {
        console.log(`AutoCluster: ignored non-canonical/pre-stitch VALIDATOR_ACTIVE from ${cleanString(claimed,80)} candidateLcl=${candidateLcl || '?'} required>${minimumPostStitchLcl}.`);
        return true;
      }
      if (observedAtLcl && candidateLcl < observedAtLcl - PROMOTED_ACTIVE_FRESH_LCL) {
        console.log(`AutoCluster: ignored stale VALIDATOR_ACTIVE from ${cleanString(claimed,80)} candidateLcl=${candidateLcl} clusterLcl=${observedAtLcl}.`);
        return true;
      }
      transition.phase = 'active-confirmed';
      transition.activeObservedAtLcl = observedAtLcl || candidateLcl;
      run.state.promotionTransition = transition;
      saveState(run.state);
      console.log(`AutoCluster: VERIFIED VALIDATOR_ACTIVE for ${cleanString(node.pubkey,80)} at candidateLcl=${candidateLcl}, observedAtLcl=${observedAtLcl || '?'}. Legacy/autonomous post-join proof is committed. Fresh bootstrap does not use this path.`);
      return true;
    }

    // Bootstrap A may also report a continuously unreachable candidate after the
    // configured external WSS timeout. This is a reversible pre-UNL quarantine:
    // a later fresh canonical READY immediately clears it. The report is accepted
    // only from the same authenticated READY controller used for positive proofs.
    if (parsed && parsed.type === 'autocluster_ready_unreachable_observation') {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: READY UNREACHABLE observation ignored during membership-transition quiet window.');
        return true;
      }
      const controller = hotPocketUserPubkey(user);
      const expectedController = cleanString(run.state.readyControllerPublicKey || '', 80).toLowerCase();
      if (run.state.phase !== 'growing' || !controller || controller !== expectedController) {
        console.log(`AutoCluster: ignored READY UNREACHABLE observation from unauthorized controller=${cleanString(controller || 'missing',80)}.`);
        return true;
      }
      const claimed = cleanString(parsed.candidatePubkey || '', 256).toLowerCase();
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed);
      if (!claimed || !node || node.isUnl) return true;
      let watches = normalizeCandidateWatchdogs(run.state.candidateWatchdogs);
      let watch = watches.find(w => String(w.pubkey).toLowerCase() === claimed);
      const now = consensusNowMs(run);
      const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      if (!watch) {
        watch = { pubkey:node.pubkey, host:normalizeHostAddress(node.host), refId:null, firstSeenAt:now, firstSeenLcl:lcl || null, staleSinceAt:null, staleSinceLcl:null, stalledAt:null, stalledAtLcl:null, kickedAt:null };
        watches.push(watch);
      }
      if (!watch.stalledAt) {
        watch.stalledAt = now;
        watch.stalledAtLcl = lcl || null;
        const host = normalizeHostAddress(node.host);
        const item = host ? hostEntry(run.state, host) : null;
        if (item) {
          item.status = 'readiness-stalled';
          item.lastError = `Quarantined after Bootstrap A could not establish the candidate HotPocket WSS/stat connection for the configured ${Math.round((Number(run.state.readyProbeUnreachableTimeoutMs) || DEFAULT_READY_PROBE_UNREACHABLE_TIMEOUT_MS)/1000)}s unreachable timeout. Quarantine is reversible if fresh canonical READY later arrives.`;
          if (run.state.activeHostAttempt === item.address) run.state.activeHostAttempt = null;
        }
        run.state.waitingForHosts = false;
        console.log(`AutoCluster: QUARANTINED WSS-unreachable pre-UNL candidate ${cleanString(node.pubkey,80)} host=${node.host || 'unknown'} at LCL ${lcl || '?'} after authenticated Bootstrap A candidate timeout; fresh canonical READY can recover it.`);
      }
      run.state.candidateWatchdogs = normalizeCandidateWatchdogs(watches);
      saveState(run.state);
      return true;
    }

    // Atomic bootstrap FINAL proof bundle. Bootstrap A samples BOTH selected
    // non-UNL followers from node-local HotPocket STAT, validates both exact LCL/hash
    // tuples against A's private canonical history, then submits them in ONE
    // lightweight consensus input. Recording both rows at the same observedAtLcl
    // eliminates the impossible freshness race where B's one-shot final proof was
    // already stale by the time C's independently serialized proof landed.
    if (parsed && parsed.type === AUTOCLUSTER_ATOMIC_READY_BUNDLE_TYPE) {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: ATOMIC READY bundle ignored during membership-transition quiet window.');
        return true;
      }
      const controller = hotPocketUserPubkey(user);
      const expectedController = cleanString(run.state.readyControllerPublicKey || '', 80).toLowerCase();
      const bootstrapLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const currentUnl = currentUnlPubkeys(run);
      const bootstrapPubkey = cleanString(run.state.bootstrapPubkey || '',256).toLowerCase();
      const warm = run.state && run.state.promotionPeerWarmup && typeof run.state.promotionPeerWarmup === 'object'
        ? run.state.promotionPeerWarmup : null;
      const warmPubkeys = warm && warm.mode === 'atomic-bootstrap-1to3' ? normalizePubkeyList(warm.pubkeys) : [];
      const observations = Array.isArray(parsed.observations) ? parsed.observations : [];
      const observedPubkeys = normalizePubkeyList(observations.map(o => o && o.candidatePubkey));
      if (run.state.phase !== 'growing' || !controller || controller !== expectedController || !bootstrapLcl ||
          currentUnl.length !== 1 || currentUnl[0] !== bootstrapPubkey || warmPubkeys.length !== 2 ||
          observations.length !== 2 || !samePubkeySet(warmPubkeys, observedPubkeys)) {
        console.log(`AutoCluster: ignored ATOMIC READY bundle controller=${cleanString(controller || 'missing',80)} expected=${cleanString(expectedController || 'missing',80)} lcl=${bootstrapLcl || '?'} unl=[${currentUnl.join(',')}] warm=[${warmPubkeys.join(',')}] observed=[${observedPubkeys.join(',')}].`);
        return true;
      }
      const expectedUnl = currentUnl.slice();
      const normalized = normalizeCandidateReadiness(run.state.candidateReadiness);
      const replacements = new Map();
      for (const obs of observations) {
        const claimed = cleanString(obs && obs.candidatePubkey || '',256).toLowerCase();
        const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed);
        const prior = normalized.find(r => String(r.pubkey || '').toLowerCase() === claimed) || null;
        const candidateLcl = Number(obs && obs.candidateLcl) || 0;
        const candidateHash = cleanString(obs && obs.candidateHash || '',256).toLowerCase();
        const candidateLag = obs && obs.candidateLag != null ? Math.max(0, Number(obs.candidateLag) || 0) : null;
        const weaklyConnected = !!(obs && obs.weaklyConnected);
        const contractExecutionEnabled = !(obs && obs.contractExecutionEnabled === false);
        const obsUnl = normalizePubkeyList(obs && obs.currentUnl);
        if (!claimed || !node || node.isUnl || !prior || Number(prior.readyHeartbeats || 0) < CANDIDATE_READY_REQUIRED_HEARTBEATS ||
            !candidateLcl || !/^[0-9a-f]{64}$/.test(candidateHash) || candidateLcl <= Number(prior.candidateLcl || 0) ||
            candidateLag == null || candidateLag > SIGNED_PREUNL_REPORT_MAX_LAG_LCLS || weaklyConnected || !contractExecutionEnabled ||
            JSON.stringify(obsUnl) !== JSON.stringify(expectedUnl)) {
          console.log(`AutoCluster: ignored ATOMIC READY bundle member=${cleanString(claimed || 'missing',80)} priorReady=${Number(prior && prior.readyHeartbeats || 0)}/${CANDIDATE_READY_REQUIRED_HEARTBEATS} candidateLcl=${candidateLcl || '?'} priorLcl=${Number(prior && prior.candidateLcl || 0) || '?'} lag=${candidateLag == null ? '?' : candidateLag}/${SIGNED_PREUNL_REPORT_MAX_LAG_LCLS} weak=${weaklyConnected} exec=${contractExecutionEnabled} unl=[${obsUnl.join(',')}].`);
          return true;
        }
        const proofHistory = [...(Array.isArray(prior.proofHistory) ? prior.proofHistory : []),
          { candidateLcl, candidateHash, observedAtLcl:bootstrapLcl, candidateLag }]
          .filter(p => p && Number(p.candidateLcl) > 0 && /^[0-9a-f]{64}$/.test(cleanString(p.candidateHash || '',256).toLowerCase()))
          .slice(-12);
        replacements.set(claimed, {
          ...prior,
          pubkey:node.pubkey,
          candidateLcl,
          observedAtLcl:bootstrapLcl,
          candidateHash,
          peerCount:obs && obs.peers != null ? Math.max(0, Number(obs.peers) || 0) : prior.peerCount,
          candidateLag,
          transport:'bootstrap-canonical-controller',
          syncHeartbeats:Math.max(SYNC_QUIESCENT_REQUIRED_EXECUTIONS, Number(prior.syncHeartbeats || 0)),
          readyHeartbeats:Math.max(CANDIDATE_READY_REQUIRED_HEARTBEATS, Number(prior.readyHeartbeats || 0)),
          finalReadyAtLcl:bootstrapLcl,
          proofHistory
        });
      }
      const list = normalized.map(r => replacements.get(String(r.pubkey || '').toLowerCase()) || r);
      run.state.candidateReadiness = normalizeCandidateReadiness(list);
      saveState(run.state);
      console.log(`AutoCluster: ATOMIC READY BUNDLE recorded at LCL ${bootstrapLcl}: candidates=${warmPubkeys.map(k=>cleanString(k,24)).join(',')} share one current canonical observation; atomic 1->3 gate may release on the next execution without recurring READY writes.`);
      return true;
    }

    // Bootstrap READY observation. In NPL mode the candidate reports its own LCL/hash
    // over HotPocket Node Party Line; Bootstrap A's node-local bridge verifies that
    // tuple against A's canonical history and submits this normal local user input.
    // No candidate WebSocket/stat probe occurs in contract execution.
    if (parsed && parsed.type === AUTOCLUSTER_READY_OBSERVATION_TYPE) {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: READY observation ignored during membership-transition quiet window.');
        return true;
      }
      const controller = hotPocketUserPubkey(user);
      const expectedController = cleanString(run.state.readyControllerPublicKey || '', 80).toLowerCase();
      const candidatePhases = ['growing','signing','ready-to-handover'];
      if (!candidatePhases.includes(run.state.phase) || !controller || controller !== expectedController) {
        console.log(`AutoCluster: ignored READY observation from unauthorized controller=${cleanString(controller || 'missing',80)} expected=${cleanString(expectedController || 'missing',80)} phase=${run.state.phase || 'unknown'}.`);
        return true;
      }
      const claimed = cleanString(parsed.candidatePubkey || '', 256).toLowerCase();
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed);
      if (!claimed || !node || node.isUnl) {
        console.log(`AutoCluster: ignored READY observation candidate=${cleanString(claimed || 'missing',80)} because it is ${node && node.isUnl ? 'already UNL' : 'not a materialized managed node'}.`);
        return true;
      }
      const voteStatus = cleanString(parsed.voteStatus || '', 32).toLowerCase();
      const weaklyConnected = !!parsed.weaklyConnected;
      const contractExecutionEnabled = parsed.contractExecutionEnabled !== false;
      const currentUnl = normalizePubkeyList(parsed.currentUnl);
      const expectedUnl = currentUnlPubkeys(run);
      // A non-UNL follower that reports a canonical ledger has synchronized that
      // ledger. voteStatus can transiently say desync/unreliable while the node is
      // between voting rounds, so it is diagnostic-only during candidate READY.
      // Connectivity, execution, and the expected follower UNL remain hard gates.
      if (weaklyConnected || !contractExecutionEnabled || JSON.stringify(currentUnl) !== JSON.stringify(expectedUnl)) {
        console.log(`AutoCluster: ignored READY observation candidate=${cleanString(claimed,80)} vote=${voteStatus || 'missing'}(diagnostic) weak=${weaklyConnected} exec=${contractExecutionEnabled} currentUnl=[${currentUnl.join(',')}].`);
        return true;
      }
      const bootstrapLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const candidateLcl = Number(parsed.candidateLcl) || 0;
      const candidateHash = cleanString(parsed.candidateHash || '', 256).toLowerCase();
      const candidateLag = parsed.candidateLag == null ? null : Math.max(0, Number(parsed.candidateLag) || 0);
      // The authorized root-side READY controller has already compared this exact
      // candidate LCL/hash against Bootstrap A's node-local recent-ledger witness
      // (../autocluster-local/recent-ledgers.json). Re-checking a node-local ring
      // here would make replicated execution depend on which physical node is
      // running the contract. From this point onward the candidate's authenticated
      // input is the deterministic canonical attestation.
      if (!candidateLcl || !/^[0-9a-f]{64}$/.test(candidateHash)) {
        console.log(`AutoCluster: ignored malformed READY observation candidate=${cleanString(claimed,80)} candidateLcl=${candidateLcl || '?'} hash=${candidateHash ? 'present' : 'missing'}.`);
        return true;
      }
      // Do not reject an advancing canonical candidate merely because the WSS/stat
      // sample is several ledgers behind A. Recording that progress keeps the
      // health watchdog honest. The final promotion gate below the READY layer
      // still requires a CURRENT proof before changing the validator set.
      const normalized = normalizeCandidateReadiness(run.state.candidateReadiness);
      const prior = normalized.find(r => r.pubkey.toLowerCase() === claimed) || null;
      if (prior && candidateLcl && prior.candidateLcl && candidateLcl <= prior.candidateLcl) return true;

      const priorCandidateLcl = Number(prior && prior.candidateLcl) || 0;
      const priorReady = Math.max(0, Number(prior && prior.readyHeartbeats) || 0);
      const priorAdmissionSync = Math.max(0, Number(prior && prior.admissionSyncHeartbeats) || 0);
      const priorObservedAt = Number(prior && prior.observedAtLcl) || 0;
      const warm = run.state && run.state.promotionPeerWarmup && typeof run.state.promotionPeerWarmup === 'object'
        ? run.state.promotionPeerWarmup : null;
      const warmSelected = !!(warm && (
        cleanString(warm.pubkey || '',256).toLowerCase() === claimed ||
        (warm.mode === 'atomic-bootstrap-1to3' && Array.isArray(warm.pubkeys) && normalizePubkeyList(warm.pubkeys).includes(claimed))
      ));
      const warmStartedLcl = Number(warm && warm.startedAtLcl) || 0;
      const warmAgeLcls = warmSelected && warmStartedLcl ? Math.max(0, bootstrapLcl - warmStartedLcl) : 0;
      const warmDone = warmSelected && warmAgeLcls >= PROMOTION_FINAL_PROOF_DELAY_LCLS;
      const advancing = candidateLcl > priorCandidateLcl;
      const needInitialMilestone = !prior || priorReady < CANDIDATE_READY_REQUIRED_HEARTBEATS;
      const priorFinalReadyAt = Number(prior && prior.finalReadyAtLcl) || 0;
      const finalProofStale = !prior ||
        (bootstrapLcl && priorObservedAt ? bootstrapLcl - priorObservedAt > ATOMIC_BOOTSTRAP_OBSERVATION_FRESH_LCL : true) ||
        (bootstrapLcl && priorCandidateLcl ? bootstrapLcl - priorCandidateLcl > ATOMIC_BOOTSTRAP_PROMOTION_FRESH_LCL : true);
      const finalRetryDue = !!(priorFinalReadyAt && bootstrapLcl - priorFinalReadyAt >= SIGNED_RELAY_FINAL_RETRY_LCLS);
      const needFinalMilestone = warmDone && finalProofStale && (!priorFinalReadyAt || finalRetryDue);
      const exactAdmissionSample = warmDone && voteStatus === 'synced' && candidateLag === 0;
      const needAdmissionMilestone = advancing && exactAdmissionSample && priorAdmissionSync < ADMISSION_SYNC_REQUIRED_HEARTBEATS;

      if (!advancing || (!needInitialMilestone && !needFinalMilestone && !needAdmissionMilestone)) {
        console.log(`AutoCluster: VERIFIED READY quiescent for ${cleanString(node.pubkey,80)} candidateLcl=${candidateLcl} bootstrapLcl=${bootstrapLcl}; canonical controller proof accepted but no replicated milestone is due.`);
        return true;
      }

      const readyHeartbeats = needInitialMilestone
        ? Math.min(CANDIDATE_READY_REQUIRED_HEARTBEATS, priorReady + 1)
        : Math.max(CANDIDATE_READY_REQUIRED_HEARTBEATS, priorReady);
      const syncLagOk = candidateLag != null && candidateLag >= 0 && candidateLag <= BOOTSTRAP_ADMISSION_MAX_LAG_LCLS;
      const priorSyncLagOk = !!(prior && prior.candidateLag != null && Number(prior.candidateLag) >= 0 && Number(prior.candidateLag) <= BOOTSTRAP_ADMISSION_MAX_LAG_LCLS);
      const syncHeartbeats = syncLagOk
        ? Math.max(1, needInitialMilestone
          ? (priorSyncLagOk ? Number(prior && prior.syncHeartbeats || 0) + 1 : 1)
          : Number(prior && prior.syncHeartbeats || 0))
        : 0;
      // Admission proof is intentionally independent of ordinary READY/SYNC. It
      // begins only after the selected candidate has completed peer warmup and it
      // increments only on advancing status samples where hpcore itself reports
      // voteStatus=synced while Bootstrap A measures the candidate at exact lag 0.
      const admissionSyncHeartbeats = exactAdmissionSample
        ? Math.min(ADMISSION_SYNC_REQUIRED_HEARTBEATS, priorAdmissionSync + 1)
        : priorAdmissionSync;
      const admissionSyncFirstAtLcl = admissionSyncHeartbeats > 0
        ? (priorAdmissionSync > 0 ? (prior && prior.admissionSyncFirstAtLcl || bootstrapLcl || null) : (bootstrapLcl || null))
        : null;
      const list = normalized.filter(r => r.pubkey.toLowerCase() !== claimed);
      const peerCount = parsed.peers == null ? null : Math.max(0, Number(parsed.peers) || 0);
      const proofHistory = [...(prior && Array.isArray(prior.proofHistory) ? prior.proofHistory : []),
        { candidateLcl, candidateHash, observedAtLcl:bootstrapLcl || null, candidateLag }]
        .filter(p => p && Number(p.candidateLcl) > 0 && /^[0-9a-f]{64}$/.test(cleanString(p.candidateHash || '',256).toLowerCase()))
        .slice(-4);
      const transport = cleanString(parsed.transport || '', 64).toLowerCase() === 'npl' ? 'npl' : 'bootstrap-canonical-controller';
      list.push({
        pubkey:node.pubkey,
        candidateLcl,
        observedAtLcl:bootstrapLcl || null,
        candidateHash,
        buildFingerprint:null,
        peerCount,
        candidateLag,
        voteStatus,
        admissionSyncHeartbeats,
        admissionSyncFirstAtLcl,
        transport,
        syncHeartbeats,
        readyHeartbeats,
        firstReadyAtLcl:prior ? (prior.firstReadyAtLcl || prior.observedAtLcl || bootstrapLcl || null) : (bootstrapLcl || null),
        finalReadyAtLcl:(needFinalMilestone || admissionSyncHeartbeats >= ADMISSION_SYNC_REQUIRED_HEARTBEATS) ? (bootstrapLcl || null) : (prior && prior.finalReadyAtLcl || null),
        proofHistory
      });
      run.state.candidateReadiness = normalizeCandidateReadiness(list);
      saveState(run.state);
      console.log(`AutoCluster: VERIFIED READY recorded for ${cleanString(node.pubkey,80)} heartbeat=${readyHeartbeats}/${CANDIDATE_READY_REQUIRED_HEARTBEATS} runtimeSync=${syncHeartbeats}/${SYNC_QUIESCENT_REQUIRED_EXECUTIONS} admissionSync=${admissionSyncHeartbeats}/${ADMISSION_SYNC_REQUIRED_HEARTBEATS} vote=${voteStatus||'missing'} candidateLcl=${candidateLcl} hash=${candidateHash.slice(0,12)} measuredLag=${candidateLag == null ? '?' : candidateLag} peers=${peerCount == null ? 'unknown' : peerCount} milestone=${needAdmissionMilestone?'admission-exact-tip':(needFinalMilestone?'final':'initial')} transport=${transport}. Canonical comparison was performed by Bootstrap-A sidecar before this controller input; replicated execution reads no node-local ledger witness.`);
      return true;
    }

    // Authoritative readiness proof. Bootstrap accepts it only from an acquired,
    // materialized managed node that is still outside UNL, then verifies the sender
    // identity plus an exact canonical LCL/hash no more than 4 ledgers behind.
    // Build fingerprint and reported node.role are diagnostics only.
    if (parsed && parsed.type === 'autocluster_validator_ready') {
      if (normalizeMembershipCommand(run.state.membershipCommand)) {
        console.log('AutoCluster: VALIDATOR_READY heartbeat ignored during membership-transition quiet window.');
        return true;
      }
      const claimed = cleanString(parsed.pubkey || '', 256).toLowerCase();
      const actual = hotPocketUserPubkey(user);
      if (!claimed || !actual || claimed !== actual) {
        console.log(`AutoCluster: ignored VALIDATOR_READY with identity mismatch claimed=${cleanString(claimed,80)} actual=${cleanString(actual,80)}.`);
        return true;
      }
      const node = run.clusterContext.getClusterNodes().find(n => n && String(n.pubkey).toLowerCase() === claimed);
      if (!node || node.isUnl) {
        console.log(`AutoCluster: ignored VALIDATOR_READY from ${cleanString(claimed,80)} because sender is ${node && node.isUnl ? 'already UNL' : 'not a materialized managed node'}.`);
        return true;
      }
      const bootstrapLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const candidateLcl = Number(parsed.lcl) || 0;
      const candidateHash = cleanString(parsed.lclHash || '', 256).toLowerCase();
      const candidateBuild = cleanString(parsed.buildFingerprint || '', 256).toLowerCase(); // diagnostic only
      if (!candidateLcl || !candidateHash || !verifiedSharedRecentLedger(run.state, candidateLcl, candidateHash)) {
        console.log(`AutoCluster: ignored UNSYNCED VALIDATOR_READY from ${cleanString(claimed,80)} candidateLcl=${candidateLcl || '?'}; candidate LCL/hash is not in the replicated canonical ledger ring; Bootstrap-controller READY is required during growth.`);
        return true;
      }
      const readyFreshLimit = run.state.phase === 'growing'
        ? ATOMIC_BOOTSTRAP_READY_FRESH_LCL
        : CANDIDATE_READY_FRESH_LCL;
      if (bootstrapLcl && candidateLcl < bootstrapLcl - readyFreshLimit) {
        console.log(`AutoCluster: ignored stale VALIDATOR_READY from ${cleanString(claimed,80)} candidateLcl=${candidateLcl} bootstrapLcl=${bootstrapLcl} lag=${bootstrapLcl-candidateLcl}/${readyFreshLimit}; candidate will retry.`);
        return true;
      }
      const normalized = normalizeCandidateReadiness(run.state.candidateReadiness);
      const prior = normalized.find(r => r.pubkey.toLowerCase() === claimed) || null;
      if (prior && candidateLcl && prior.candidateLcl && candidateLcl <= prior.candidateLcl) {
        console.log(`AutoCluster: ignored duplicate/non-advancing VALIDATOR_READY from ${cleanString(claimed,80)} candidateLcl=${candidateLcl} previousCandidateLcl=${prior.candidateLcl}.`);
        return true;
      }
      // Count independently verified, advancing canonical sync proofs. Build and
      // node.role do not reset or gate readiness.
      const readyHeartbeats = prior ? Number(prior.readyHeartbeats || 0) + 1 : 1;
      const list = normalized.filter(r => r.pubkey.toLowerCase() !== claimed);
      const proofHistory = [...(prior && Array.isArray(prior.proofHistory) ? prior.proofHistory : []),
        { candidateLcl:candidateLcl || null, candidateHash:candidateHash || null, observedAtLcl:bootstrapLcl || null }]
        .filter(p => p && Number(p.candidateLcl) > 0 && /^[0-9a-f]{64}$/.test(cleanString(p.candidateHash || '',256).toLowerCase()))
        .slice(-12);
      list.push({
        pubkey:node.pubkey,
        candidateLcl:candidateLcl || null,
        observedAtLcl:bootstrapLcl || null,
        candidateHash:candidateHash || null,
        buildFingerprint:candidateBuild,
        readyHeartbeats,
        firstReadyAtLcl:prior ? (prior.firstReadyAtLcl || prior.observedAtLcl || bootstrapLcl || null) : (bootstrapLcl || null),
        proofHistory
      });
      run.state.candidateReadiness = normalizeCandidateReadiness(list);
      saveState(run.state);
      console.log(`AutoCluster: VERIFIED VALIDATOR_READY recorded for ${cleanString(node.pubkey,80)} heartbeat=${readyHeartbeats}/${CANDIDATE_READY_REQUIRED_HEARTBEATS} candidateLcl=${candidateLcl} hash=${candidateHash.slice(0,12)} lag=${bootstrapLcl && candidateLcl ? bootstrapLcl-candidateLcl : '?'} / ${readyFreshLimit} observedAtBootstrapLcl=${bootstrapLcl || '?'}. Build/role are diagnostic only.`);
      return true;
    }
    // EverPocket currently defines cluster messages by a `type` property.
    if (!parsed || typeof parsed.type === 'undefined') return false;
    const response = await run.clusterContext.feedUserMessage(user, Buffer.from(raw));
    // UNHANDLED is currently represented by EverPocket's enum. We don't depend
    // on its numeric/string representation; a recognized JSON cluster message
    // is reserved for EverPocket and should not be BSON-decoded by EverAdmin.
    return !!response;
  } catch {
    return false;
  }
}

async function reconcilePromotionTransition(run) {
  const transition = normalizePromotionTransition(run && run.state && run.state.promotionTransition);
  if (!transition) return false;
  const cfg = await run.ctx.getConfig();
  const currentThreshold = readConsensusThreshold(cfg);
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  const currentUnlSize = Math.max(1, currentUnlPubkeys(run).length || 1);
  let bootstrapThreshold = Number(run.state.bootstrapGrowthConsensusThreshold) || null;
  let bootstrapNormal = Number(run.state.bootstrapNormalConsensusThreshold) || null;
  const bootstrapTarget = Math.max(1, Number(run.state.targetManagedNodes) || 1);

  // Compatibility cleanup for alpha.37.99. Fresh bootstrap no longer creates
  // promotionTransition at all: HotPocket's next committed ledger after a UNL-only
  // patch is the post-add proof. Clear an old bootstrap marker without fencing.
  if (run.state.phase === 'growing' && transition.mode === 'bootstrap-membership-proof') {
    const proven = transition.pubkey;
    run.state.promotionTransition = null;
    if (run.state.promotionBatch && run.state.promotionBatch.active) {
      run.state.promotionBatch.submittedAtLcl = null;
      run.state.promotionBatch.reason = `legacy post-join marker cleared for ${proven}; HotPocket committed-ledger progress now gates the next addition`;
    }
    saveState(run.state);
    console.log(`AutoCluster: removed legacy bootstrap candidate transition for ${cleanString(proven,80)} at LCL ${lcl || '?'}. No post-join callback is required.`);
    return false;
  }

  // Migration guard for alpha.37.33: if a growing cluster upgrades while an old
  // 50/66/75 per-stitch transition is still in flight, immediately convert it to
  // the persistent majority-safe bootstrap quorum before doing anything else.
  if (run.state.phase === 'growing' && (!bootstrapThreshold || !bootstrapNormal)) {
    bootstrapNormal = Number(transition.normalThreshold) >= MIN_BOOTSTRAP_GROWTH_THRESHOLD
      ? Number(transition.normalThreshold) : DEFAULT_CONSENSUS_THRESHOLD;
    bootstrapThreshold = bootstrapGrowthThreshold(bootstrapTarget, bootstrapNormal);
    run.state.bootstrapNormalConsensusThreshold = bootstrapNormal;
    run.state.bootstrapGrowthConsensusThreshold = bootstrapThreshold;
    transition.normalThreshold = bootstrapNormal;
    transition.transitionThreshold = bootstrapThreshold;
    run.state.promotionTransition = transition;
    saveState(run.state);
    if (currentThreshold !== bootstrapThreshold) {
      setConsensusThreshold(cfg, bootstrapThreshold);
      await run.ctx.updateConfig(cfg);
      console.log(`AutoCluster: migrated in-flight bootstrap transition to majority-safe quorum at LCL ${lcl || '?'}: ${currentThreshold}% -> ${bootstrapThreshold}%. This removes the old <=50% split-brain window before any further membership work.`);
      return true;
    }
  }
  const bootstrapTransition = !!(bootstrapThreshold && bootstrapNormal);

  if (transition.phase === 'active-confirmed') {
    if (bootstrapTransition && currentUnlSize < bootstrapTarget) {
      // Keep the SAME majority-safe quorum across the whole bootstrap. Restoring
      // 80% after every stitch can increase the integer vote requirement before
      // the just-added validator is actually proposing. Worse, the old 50% scheme
      // allowed two singleton quorums at N=2. Clear only this per-node transition;
      // the bootstrap quorum remains committed for the next stitch.
      run.state.promotionTransition = null;
      saveState(run.state);
      console.log(`AutoCluster: promotion transition COMPLETE at LCL ${lcl || '?'} for ${cleanString(transition.pubkey,80)}; retaining majority-safe bootstrap quorum ${currentThreshold}% while UNL grows ${currentUnlSize}/${bootstrapTarget}. Normal ${bootstrapNormal}% is intentionally deferred until target size.`);
      return true;
    }

    const desiredNormal = bootstrapTransition ? bootstrapNormal : transition.normalThreshold;
    if (bootstrapTransition) {
      const beforeVotes = requiredVotesForThreshold(currentUnlSize, currentThreshold);
      const afterVotes = requiredVotesForThreshold(currentUnlSize, desiredNormal);
      if (beforeVotes !== afterVotes) {
        // Consensus safety invariant: never raise the effective vote count as part
        // of an automatic threshold restore. If this fires, keep the safe growth
        // quorum rather than risking another irreversible stall/fork.
        console.log(`AutoCluster: QUORUM RESTORE DEFERRED at LCL ${lcl || '?'}: ${currentThreshold}% requires ${beforeVotes}/${currentUnlSize} votes but normal ${desiredNormal}% would require ${afterVotes}/${currentUnlSize}. Bootstrap quorum remains active; no lifecycle work will run until a vote-count-equivalent restore is possible.`);
        return true;
      }
    }

    if (currentThreshold !== desiredNormal) {
      setConsensusThreshold(cfg, desiredNormal);
      await run.ctx.updateConfig(cfg);
      transition.phase = 'restoring-threshold';
      transition.normalThreshold = desiredNormal;
      transition.restoredAtLcl = lcl || null;
      run.state.promotionTransition = transition;
      saveState(run.state);
      console.log(`AutoCluster: FINAL quorum restore submitted at LCL ${lcl || '?'} for ${cleanString(transition.pubkey,80)}: ${currentThreshold}% -> ${desiredNormal}% with unchanged effective quorum ${requiredVotesForThreshold(currentUnlSize,currentThreshold)}/${currentUnlSize}. No further membership/lifecycle work will run in this execution.`);
      return true;
    }
    run.state.promotionTransition = null;
    if (bootstrapTransition && currentUnlSize >= bootstrapTarget) {
      run.state.bootstrapNormalConsensusThreshold = null;
      run.state.bootstrapGrowthConsensusThreshold = null;
    }
    saveState(run.state);
    console.log(`AutoCluster: promotion transition complete for ${cleanString(transition.pubkey,80)}; normal ${desiredNormal}% quorum already active.`);
    return true;
  }

  if (transition.phase === 'restoring-threshold') {
    if (currentThreshold === transition.normalThreshold) {
      run.state.promotionTransition = null;
      if (bootstrapTransition && currentUnlSize >= bootstrapTarget) {
        run.state.bootstrapNormalConsensusThreshold = null;
        run.state.bootstrapGrowthConsensusThreshold = null;
      }
      saveState(run.state);
      console.log(`AutoCluster: promotion transition FINALIZED at LCL ${lcl || '?'} for ${cleanString(transition.pubkey,80)}; normal ${transition.normalThreshold}% consensus quorum is committed.`);
    } else {
      console.log(`AutoCluster: waiting for normal consensus threshold ${transition.normalThreshold}% to commit (currently ${currentThreshold}%) after promotion of ${cleanString(transition.pubkey,80)}.`);
    }
    return true;
  }

  // Every other active transition phase is also membership-only. The bootstrap
  // growth quorum is a narrow consensus-safety mode, not permission to perform
  // unrelated Xahau/Evernode/signer work while the new validator is proving itself.
  console.log(`AutoCluster: promotion transition fence active at LCL ${lcl || '?'} for ${cleanString(transition.pubkey,80)} phase=${transition.phase}; external lifecycle work remains paused.`);
  return true;
}

async function reconcileQueuedSigner(run) {
  const queued = normalizeQueuedSigner(run.state.queuedSigner);
  if (!queued) {
    if (run.state.queuedSigner) { run.state.queuedSigner = null; saveState(run.state); }
    return false;
  }
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  queued.lastObservedAtLcl = lcl || queued.lastObservedAtLcl;
  run.state.queuedSigner = queued;

  // NEVER advance signer provisioning from the local return value of
  // addXrplSigner(). SignerListSet is an on-ledger state transition and different
  // validators can observe tesSUCCESS / tefPAST_SEQ / tefALREADY while the same
  // equivalent transaction is racing to validation. Refresh the authoritative
  // account signer list first; only validated signer-list visibility may commit
  // the node's signerAddress in cluster.json.
  try {
    if (typeof run.xrplContext.loadSignerList === 'function') await run.xrplContext.loadSignerList();
  } catch (e) {
    console.log(`AutoCluster: managed signer reconciliation could not refresh Xahau SignerList at LCL ${lcl || '?'}: ${cleanString(errText(e),180)}. Will retry next ledger without advancing.`);
    clearBlocker(run.state, null, 'managed-signer');
    saveState(run.state);
    return true;
  }
  const current = run.xrplContext.getSignerList();
  const visible = !!(current && Array.isArray(current.signerList) && current.signerList.some(s => s && s.account === queued.signerAddress));
  if (visible) {
    const manager = run.clusterContext.clusterManager;
    if (!manager || typeof manager.markAsQuorum !== 'function') throw new Error('EverPocket ClusterManager internals changed; markAsQuorum is unavailable.');
    manager.markAsQuorum(queued.nodePubkey, queued.signerAddress);
    run.state.queuedSigner = null;
    clearBlocker(run.state, null, 'managed-signer');
    saveState(run.state);
    console.log(`AutoCluster: VALIDATED managed signer ${queued.signerAddress} for ${queued.nodePubkey} is visible in Xahau SignerList; local quorum bookkeeping committed. Next signer may start on the NEXT ledger.`);
    return true;
  }

  const validated = queued.hash && typeof run.xrplContext.getValidatedTransaction === 'function'
    ? run.xrplContext.getValidatedTransaction(queued.hash) : null;
  const pendingTxs = typeof run.xrplContext.getPendingTransactions === 'function' ? run.xrplContext.getPendingTransactions() : [];
  const pending = queued.hash ? pendingTxs.find(t => t && t.hash === queued.hash) || null : null;
  const finalCode = cleanString(validated && validated.resultCode || '', 64) || null;

  if (finalCode && !['tesSUCCESS','tefPAST_SEQ','tefALREADY'].includes(finalCode)) {
    run.state.queuedSigner = null;
    saveState(run.state);
    const e = new Error(`Queued managed SignerListSet ${queued.hash || ''} finalized with ${finalCode}.`);
    e.code = finalCode;
    setBlocker(run.state, e, 'managed-signer', lcl, { nodePubkey: queued.nodePubkey });
    throw e;
  }

  // A past-sequence/already result is NOT proof that this exact signer made it
  // into the account. It only means an equivalent/competing transaction may have
  // won. Wait a short deterministic grace window for validated signer-list
  // visibility, then retry the SAME target. This prevents the controller from
  // locally counting signer #1 and launching signer #2 while Xahau is still on
  // the previous list -- the divergence that triggers EverPocket's undefined
  // `.account` election path.
  const age = queued.queuedAtLcl && lcl ? Math.max(0, lcl - queued.queuedAtLcl) : 0;
  if (pending || age < SIGNER_QUEUE_ORPHAN_GRACE_LCL) {
    clearBlocker(run.state, null, 'managed-signer');
    saveState(run.state);
    console.log(`AutoCluster: managed signer intent WAITING validation target=${queued.nodePubkey} signer=${queued.signerAddress} result=${finalCode || queued.resultCode || 'unobserved'} age=${age}/${SIGNER_QUEUE_ORPHAN_GRACE_LCL}${queued.hash ? ` hash=${queued.hash}` : ''}; no next signer will start yet.`);
    return true;
  }

  run.state.queuedSigner = null;
  clearBlocker(run.state, null, 'managed-signer');
  saveState(run.state);
  console.log(`AutoCluster: managed signer ${queued.signerAddress} for ${queued.nodePubkey} is still absent from validated Xahau SignerList after ${age} ledger(s) (result=${finalCode || queued.resultCode || 'unobserved'}); releasing ONLY this intent for a clean same-target retry next ledger.`);
  return true;
}

async function provisionBootstrapSignerIdentity(run) {
  // Initial bootstrap handover uses NPL for the real-time signer identity
  // exchange. This avoids the alpha.37.62 re-entrant localhost HPWS call. NPL
  // receipts never mutate replicated state directly. Bootstrap A only writes a
  // node-local complete proposal; the root control plane later commits the exact
  // mapping through autocluster-handover-confirm after the Xahau authorization
  // changes are validated.
  if (run.state.queuedSigner) {
    run.state.queuedSigner = null; // migration cleanup from alpha.37.49/37.50
    saveState(run.state);
  }

  let nodes = managedNodes(run, true);
  const required = run.state.phase === 'autonomous'
    ? Math.max(1, Number(run.state.targetManagedNodes) || 1)
    : bootstrapManagedUnlTarget(run.state);
  if (nodes.length < required) return false;
  nodes = nodes.slice(0, required);

  // Autonomous replacement/growth still needs a canonical user input to commit
  // one new pubkey->signer mapping. Keep the pre-37.62 doorway behavior there;
  // the NPL proposal path below is intentionally scoped to the initial bootstrap
  // handover where Bootstrap A's root control plane is present to commit the
  // complete set after on-ledger validation.
  if (run.state.phase === 'autonomous') {
    const local = cleanString(run.hpContext && run.hpContext.publicKey || '', 256).toLowerCase();
    const localNode = nodes.find(n => cleanString(n && n.pubkey || '',256).toLowerCase() === local) || null;
    if (!localNode || localNode.signerAddress) return false;
    const signer = ensureManagedSignerVault(run);
    if (!signer || !signer.account || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(signer.account))) {
      throw new Error(`MANAGED_SIGNER_LOCAL_GENERATION_FAILED: ${localNode.pubkey} could not create/load a valid durable local Xahau signer.`);
    }
    const msg = JSON.stringify({ type:'autocluster_signer_ready', pubkey:localNode.pubkey, signerAddress:String(signer.account) });
    try {
      await run.hpContext.sendMessage(msg, []);
      console.log(`AutoCluster: autonomous MANAGED_SIGNER_READY submitted by ${cleanString(localNode.pubkey,80)} signer=${cleanString(signer.account,80)} through an existing UNL doorway.`);
    } catch (e) {
      console.log(`AutoCluster: autonomous MANAGED_SIGNER_READY send failed for ${cleanString(localNode.pubkey,80)}: ${cleanString(errText(e),220)}. Durable signer vault is preserved; retrying next ledger.`);
    }
    return true;
  }

  if (run.state.phase !== 'signing') return false;
  if (!run.ctx || !run.ctx.unl || typeof run.ctx.unl.send !== 'function') {
    throw new Error('MANAGED_SIGNER_NPL_UNAVAILABLE: HotPocket NodePartyLine send() is unavailable during signer handover.');
  }

  const expectedManaged = normalizePubkeyList(nodes.map(n => n && n.pubkey));
  const expectedUnl = currentUnlPubkeys(run);
  const expectedSet = new Set(expectedManaged.map(x => String(x).toLowerCase()));
  const local = cleanString(run.hpContext && run.hpContext.publicKey || '', 256).toLowerCase();
  const localNode = nodes.find(n => cleanString(n && n.pubkey || '',256).toLowerCase() === local) || null;
  const roundId = signerNplRoundId(run.state, expectedManaged, expectedUnl);
  const announcements = run.hpContext.__autoClusterSignerNpl instanceof Map ? run.hpContext.__autoClusterSignerNpl : new Map();
  const cumulative = readNplSignerCache(run, roundId, expectedManaged, expectedUnl);

  if (localNode) {
    const signer = ensureManagedSignerVault(run);
    if (!signer || !signer.account || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(signer.account))) {
      throw new Error(`MANAGED_SIGNER_LOCAL_GENERATION_FAILED: ${localNode.pubkey} could not create/load a valid durable local Xahau signer.`);
    }
    const envelope = {
      type: AUTOCLUSTER_SIGNER_NPL_TYPE,
      roundId,
      pubkey: localNode.pubkey,
      signerAddress: String(signer.account)
    };
    // Seed our execution-local view immediately; HotPocket also loops NPL back to
    // self when self is part of UNL, but correctness should not depend on the
    // callback scheduling order.
    announcements.set(`${roundId}|${local}`, { pubkey:local, signerAddress:String(signer.account), roundId });
    cumulative.set(local, { pubkey:local, signerAddress:String(signer.account), roundId });
    await run.ctx.unl.send(JSON.stringify(envelope));
    console.log(`AutoCluster: MANAGED_SIGNER_READY NPL broadcast by ${cleanString(localNode.pubkey,80)} signer=${cleanString(signer.account,80)} round=${cleanString(roundId,120)}.`);
  }

  // Keep this execution alive briefly so currently executing UNL instances can
  // exchange real-time NPL envelopes. NPL delivery is intentionally NOT assumed
  // to be synchronized to one HotPocket ledger execution: merge authenticated
  // observations into a node-local handover cache keyed by a stable signing round.
  // This cache never enters replicated contract state.
  const deadline = Date.now() + AUTOCLUSTER_SIGNER_NPL_WAIT_MS;
  while (Date.now() < deadline) {
    for (const rec of announcements.values()) {
      if (!rec || rec.roundId !== roundId || !expectedSet.has(rec.pubkey) || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(rec.signerAddress)) continue;
      const prior = cumulative.get(rec.pubkey);
      if (prior && prior.signerAddress !== rec.signerAddress) {
        console.log(`AutoCluster: NPL SIGNER CONFLICT for ${cleanString(rec.pubkey,80)} in stable handover round ${cleanString(roundId,90)}: cached=${cleanString(prior.signerAddress,80)} observed=${cleanString(rec.signerAddress,80)}. Refusing to replace either identity.`);
        continue;
      }
      cumulative.set(rec.pubkey, rec);
    }
    const readyNow = expectedManaged.every(pk => cumulative.has(String(pk).toLowerCase()));
    const uniqueNow = new Set(expectedManaged.map(pk => cumulative.get(String(pk).toLowerCase())).filter(Boolean).map(x => x.signerAddress));
    if (readyNow && uniqueNow.size === expectedManaged.length) break;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  writeNplSignerCache(run, roundId, expectedManaged, expectedUnl, cumulative);

  const complete = expectedManaged.map(pk => cumulative.get(String(pk).toLowerCase())).filter(Boolean);
  const uniqueAccounts = new Set(complete.map(x => x.signerAddress));
  const allReady = complete.length === expectedManaged.length && uniqueAccounts.size === expectedManaged.length;
  if (local === cleanString(run.state.bootstrapPubkey || '',256).toLowerCase()) {
    if (allReady) {
      const mappings = complete.map(x => ({ pubkey:x.pubkey, signerAddress:x.signerAddress })).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
      if (writeNplHandoverProposal(run, roundId, mappings, expectedUnl)) {
        console.log(`AutoCluster: NPL HANDOVER PROPOSAL READY ${mappings.length}/${expectedManaged.length} authenticated managed signer identities at LCL ${run.hpContext.lclSeqNo || '?'}. No signer identity was committed from NPL directly; root handover will commit the exact mapping through HotPocket consensus after Xahau validation.`);
      }
    } else {
      const got = new Set(complete.map(x => x.pubkey));
      const missing = expectedManaged.filter(pk => !got.has(String(pk).toLowerCase()));
      console.log(`AutoCluster: NPL signer gather cumulative ${complete.length}/${expectedManaged.length} at LCL ${run.hpContext.lclSeqNo || '?'}; missing=[${missing.join(',')}]. Authenticated observations persist node-locally across signing ledgers; validators rebroadcast every ledger.`);
    }
  }
  return true;
}

async function provisionOneSigner(run) {
  // Initial handover and autonomous growth both use the same robust primitive:
  // each live managed validator publishes its own signer identity. We do not use
  // EverPocket's targeted addXrplSigner election here; that path can dereference
  // an empty vote result before any NPL message exists.
  if (run.state.phase === 'signing' || run.state.phase === 'autonomous') {
    return await provisionBootstrapSignerIdentity(run);
  }
  return false;
}

async function retireBootstrapDirect(run) {
  // alpha40 invariant: this helper is reconciliation ONLY. It is forbidden from
  // originating Bootstrap A's removal. REMOVE_UNL(A) must have already committed
  // through the authenticated HotPocket user-command path.
  const bootstrapPubkey = run.state.bootstrapPubkey;
  const manager = run.clusterContext && run.clusterContext.clusterManager;
  if (!manager || typeof manager.markAsQuorum !== 'function' || typeof manager.removeNode !== 'function')
    throw new Error('EverPocket ClusterManager internals changed; Bootstrap A reconciliation is unavailable.');

  const cfg = await run.ctx.getConfig();
  const currentUnl = readContractUnlFromConfig(cfg);
  if (currentUnl.includes(bootstrapPubkey)) {
    throw new Error('BOOTSTRAP_REMOVE_REQUIRES_HOTPOCKET_COMMAND: Bootstrap A is still in committed UNL; direct contract-tick removal is forbidden.');
  }

  manager.markAsQuorum(bootstrapPubkey, null);
  manager.removeNode(bootstrapPubkey);
  run.state.phase = 'handover';
  run.state.handoverObservedAtLcl = run.state.handoverObservedAtLcl || run.hpContext.lclSeqNo;
  saveState(run.state);
  console.log(`AutoCluster: Bootstrap A is absent from committed UNL; reconciled stale ClusterManager tracking at LCL ${run.hpContext.lclSeqNo || '?'}. No config write occurred.`);
  return true;
}


async function observeMasterHandover(run) {
  if (run.state.phase !== 'ready-to-handover') return false;
  if (!Number(run.state.handoverPreparedAtLcl)) {
    console.log('AutoCluster: final managed signer set is frozen, but Bootstrap A removal waits for the consensus handover-prepared confirmation (SignerList + reward tracking ready; master key still enabled).');
    return false;
  }
  const allManaged = managedNodes(run, false);
  const frozen = normalizePubkeyList(run.state.handoverSignerPubkeys);
  const byPubkey = new Map(allManaged.map(n => [n.pubkey, n]));
  const managed = frozen.map(pk => byPubkey.get(pk)).filter(Boolean);
  const expectedCount = finalManagedTarget(run.state);
  if (frozen.length !== expectedCount || managed.length !== expectedCount || managed.some(n => !n.signerAddress)) {
    console.log(`AutoCluster: handover preparation is committed, but the frozen final managed signer set is incomplete (${managed.length}/${expectedCount}).`);
    return false;
  }

  const currentUnl = currentUnlPubkeys(run);
  const bootstrap = cleanString(run.state.bootstrapPubkey || '', 256).toLowerCase();
  const outside = frozen.filter(pk => !currentUnl.includes(pk));
  if (!currentUnl.includes(bootstrap)) {
    if (!outside.length) return false;
    console.log(`AutoCluster: Bootstrap A is already absent but frozen managed set still has ${outside.length} member(s) outside UNL; refusing a second handover mutation.`);
    return false;
  }
  if (currentUnl.length !== expectedCount + 1 || outside.length !== 0) {
    console.log(`AutoCluster: handover waits for Bootstrap A + all ${expectedCount} managed validators in UNL: unl=${currentUnl.length}/${expectedCount + 1}, outsideFrozen=[${outside.join(',')}].`);
    return false;
  }

  const existing = normalizeMembershipCommand(run.state.membershipCommand);
  if (existing) {
    if (existing.operation === 'remove-bootstrap' && existing.pubkey === bootstrap) {
      console.log(`AutoCluster: waiting for Bootstrap A control plane to submit pending REMOVE_UNL(A) command requested at LCL ${existing.requestedAtLcl || '?'}.`);
      return true;
    }
    console.log(`AutoCluster: handover removal waiting because membership command ${existing.operation}:${cleanString(existing.pubkey,24)} is still active.`);
    return true;
  }

  run.state.membershipCommand = {
    active:true,
    operation:'remove-bootstrap',
    pubkey:bootstrap,
    requestedAtLcl:Number(run.hpContext && run.hpContext.lclSeqNo) || null,
    submittedAtLcl:null,
    reason:'final handover consensus operation: remove Bootstrap A after all target managed validators are already committed in UNL'
  };
  saveState(run.state);
  console.log(`AutoCluster: HOTPOCKET REMOVE_UNL(A) COMMAND REQUESTED at LCL ${run.hpContext.lclSeqNo || '?'}: temporary bridge ${currentUnl.length}->${expectedCount}; all managed validators remain. DisableMaster stays deferred until A is absent.`);
  return true;
}


function refreshAutonomousMaintenanceHealth(run) {
  const state = run.state;
  state.maintenance = normalizeMaintenance(state.maintenance, state.targetManagedNodes);
  const m = state.maintenance;
  if (state.phase !== 'autonomous' || !m.enabled) return { changed:false, dead:null };
  const now = consensusNowMs(run), lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  if (!now || !lcl) return { changed:false, dead:null };
  const managedUnl = managedNodes(run, true);
  const old = new Map((m.health || []).map(h => [h.pubkey, h]));
  const health = [];
  let changed = false, dead = null;
  for (const node of managedUnl) {
    const previous = old.get(node.pubkey) || {};
    const active = Number(node.activeOnLcl) || 0;
    const staleLedgers = active > 0 ? Math.max(0, lcl - active) : 0;
    let status = 'unknown', suspectSinceAt = Number(previous.suspectSinceAt) || null, deadSinceAt = Number(previous.deadSinceAt) || null;
    // Never declare a node dead if EverPocket has not supplied an activity LCL.
    // This prevents a migration/metadata gap from evicting a healthy validator.
    if (active > 0 && staleLedgers <= m.suspectAfterLcl) {
      status = 'healthy'; suspectSinceAt = null; deadSinceAt = null;
    } else if (active > 0) {
      if (!suspectSinceAt) suspectSinceAt = now;
      const age = Math.max(0, now - suspectSinceAt);
      status = age >= m.healthTimeoutMs ? 'dead' : 'suspect';
      if (status === 'dead' && !deadSinceAt) deadSinceAt = now;
    }
    const rec = { pubkey:node.pubkey, host:normalizeHostAddress(node.host), status, activeOnLcl:active || null, lastObservedLcl:lcl, suspectSinceAt, deadSinceAt };
    health.push(rec);
    if (JSON.stringify(rec) !== JSON.stringify(previous)) changed = true;
    if (!dead && status === 'dead') dead = rec;
  }
  if (health.length && health.every(h => h.status === 'healthy')) {
    if (m.lastHealthyLcl !== lcl) { m.lastHealthyLcl = lcl; m.lastHealthyAt = now; changed = true; }
  }
  m.health = health.sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
  if (changed) saveState(state);
  return { changed, dead };
}

function beginAutonomousRepair(run, dead) {
  const state = run.state;
  state.maintenance = normalizeMaintenance(state.maintenance, state.targetManagedNodes);
  const m = state.maintenance;
  if (!dead || m.repair) return false;
  const now = consensusNowMs(run), lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  m.repair = {
    active:true, phase:'replacement-needed', deadPubkey:dead.pubkey, deadHost:dead.host || null,
    startedAt:now || null, startedAtLcl:lcl || null,
    baselineUnlPubkeys:currentUnlPubkeys(run), replacementPubkey:null, replacementHost:null,
    lastUpdatedAt:now || null, lastError:null
  };
  m.lastAction = `Validator ${dead.pubkey} exceeded the ${Math.round(m.healthTimeoutMs/60000)} minute health timeout; preparing a replacement before removal.`;
  saveState(state);
  console.log(`AutoCluster: AUTONOMOUS REPAIR armed for dead validator ${cleanString(dead.pubkey,80)} host=${dead.host || 'unknown'}. Dead member remains in UNL while a replacement is prepared.`);
  return true;
}

function autonomousRepairTarget(run) {
  const m = normalizeMaintenance(run.state.maintenance, run.state.targetManagedNodes);
  const r = m.repair;
  if (!r || !r.active) return run.state.targetManagedNodes;
  const deadStillUnl = managedNodes(run, true).some(n => n.pubkey === r.deadPubkey);
  return deadStillUnl ? run.state.targetManagedNodes + 1 : run.state.targetManagedNodes;
}

async function advanceAutonomousRepair(run) {
  const state = run.state;
  state.maintenance = normalizeMaintenance(state.maintenance, state.targetManagedNodes);
  const m = state.maintenance, r = m.repair;
  if (!r || !r.active) return false;
  const now = consensusNowMs(run), lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  const managed = managedNodes(run, false), unl = managed.filter(n => n.isUnl);
  const dead = managed.find(n => n.pubkey === r.deadPubkey) || null;
  const baseline = new Set(r.baselineUnlPubkeys || []);
  const replacements = managed.filter(n => n.pubkey !== r.deadPubkey && !baseline.has(n.pubkey));
  const replacement = (r.replacementPubkey && managed.find(n => n.pubkey === r.replacementPubkey)) || replacements.find(n => n.isUnl) || replacements[0] || null;
  if (replacement) {
    r.replacementPubkey = replacement.pubkey;
    r.replacementHost = normalizeHostAddress(replacement.host);
    if (!replacement.isUnl) r.phase = clusterNodeMaturityDone(replacement) ? 'replacement-ready-waiting-promotion' : 'replacement-syncing';
    else if (!replacement.signerAddress) r.phase = 'replacement-unl-waiting-signer';
    else r.phase = 'replacement-signed-ready-to-retire-dead';
  } else {
    r.phase = 'replacement-acquiring';
  }
  r.lastUpdatedAt = now || r.lastUpdatedAt;

  // Never retire the dead validator while a validator-set stabilization gate is active.
  const stab = normalizeStabilization(state.stabilization);
  if (replacement && replacement.isUnl && replacement.signerAddress && !(stab && stab.active) && dead && dead.isUnl) {
    console.log(`AutoCluster: replacement ${cleanString(replacement.pubkey,80)} is UNL + signed. Retiring dead validator ${cleanString(r.deadPubkey,80)} in a separate membership change.`);
    r.phase = 'retiring-dead-validator';
    m.lastAction = `Replacement ${replacement.pubkey} is ready; retiring dead validator ${r.deadPubkey}.`;
    saveState(state);
    await run.clusterContext.removeNode(r.deadPubkey, true);
    return true;
  }

  // After the dead validator has disappeared and the replacement set stabilized,
  // normalize the signer list back to target count/quorum, then declare repair complete.
  const deadGone = !unl.some(n => n.pubkey === r.deadPubkey);
  if (deadGone && !(stab && stab.active)) {
    r.phase = 'normalizing-signers';
    saveState(state);
    const changed = await normalizeAutonomousSignerList(run);
    if (changed) return true;
    const currentManagedUnl = managedNodes(run, true);
    if (currentManagedUnl.length === state.targetManagedNodes && currentManagedUnl.every(n => n.signerAddress)) {
      console.log(`AutoCluster: AUTONOMOUS REPAIR complete. Replaced ${cleanString(r.deadPubkey,80)} with ${cleanString(r.replacementPubkey || 'replacement',80)}; cluster restored to ${state.targetManagedNodes} managed validators.`);
      m.lastAction = `Repair complete: replaced ${r.deadPubkey} with ${r.replacementPubkey || 'replacement'}.`;
      m.repair = null;
      saveState(state);
      return true;
    }
  }
  saveState(state);
  return false;
}

async function normalizeAutonomousSignerList(run) {
  if (run.state.phase !== 'autonomous') return false;
  let all = managedNodes(run, true);
  const repair = run.state.maintenance && run.state.maintenance.repair;
  if (repair && repair.deadPubkey) all = all.filter(n => n.pubkey !== repair.deadPubkey);
  const nodes = all.slice(0, run.state.targetManagedNodes);
  if (nodes.length !== run.state.targetManagedNodes || nodes.some(n => !n.signerAddress)) return false;
  const desired = nodes.map(n => ({ account: n.signerAddress, weight: 1 }));
  const current = run.xrplContext.getSignerList();
  if (current && Number(current.signerQuorum) === run.state.signerQuorum && sameSignerList(current.signerList, desired)) return false;
  console.log('AutoCluster: normalizing autonomous signer list.');
  await run.xrplContext.setSignerList({ signerQuorum: run.state.signerQuorum, signerList: desired });
  return true;
}

function emitFinalClusterInventory(run) {
  if (!run || !run.state || run.state.phase !== 'autonomous') return false;
  const state = run.state;
  const nodes = managedNodes(run, true).slice(0, state.targetManagedNodes);
  if (nodes.length !== state.targetManagedNodes || nodes.some(n => !n.signerAddress)) return false;
  const repair = state.maintenance && state.maintenance.repair;
  if (repair && repair.active) return false;
  const desiredSignerList = nodes.map(n => ({ account:n.signerAddress, weight:1 }));
  const currentSignerList = run.xrplContext && typeof run.xrplContext.getSignerList === 'function' ? run.xrplContext.getSignerList() : null;
  if (!currentSignerList || Number(currentSignerList.signerQuorum) !== state.signerQuorum || !sameSignerList(currentSignerList.signerList, desiredSignerList)) return false;
  const records = new Map(normalizeValidatorRecords(state.validators).map(v => [v.publicKey, v]));
  const rows = nodes.map(node => {
    const r = records.get(node.pubkey) || {};
    return {
      pubkey: cleanString(node.pubkey || '', 256),
      host: normalizeHostAddress(node.host) || r.hostAddress || null,
      domain: normalizeEndpointHost(node.domain || r.domain),
      userPort: validPort(node.userPort || r.userPort),
      peerPort: validPort(node.peerPort || node.meshPort || r.peerPort),
      gpTcp1Port: validPort(node.gpTcp1Port || node.gpTcpPort || r.gpTcp1Port),
      gpUdp1Port: validPort(node.gpUdp1Port || node.gpUdpPort || r.gpUdp1Port),
      signerAddress: cleanString(node.signerAddress || r.signerAddress || '', 128) || null
    };
  }).sort((a,b)=>a.pubkey.localeCompare(b.pubkey));
  const fingerprint = crypto.createHash('sha256').update(JSON.stringify(rows)).digest('hex');
  if (state.finalInventoryFingerprint === fingerprint) return false;
  state.finalInventoryFingerprint = fingerprint;
  state.finalInventoryAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
  saveState(state);
  console.log(`AutoCluster: FINAL CLUSTER INVENTORY ${rows.length}/${state.targetManagedNodes} managed validators at LCL ${state.finalInventoryAtLcl || '?'}.`);
  rows.forEach((r,i) => console.log(`AutoCluster: FINAL NODE #${i+1} pubkey=${r.pubkey || 'missing'} host=${r.host || 'missing'} domain=${r.domain || 'missing'} user=${r.userPort || 'missing'} peer=${r.peerPort || 'missing'} gptcp=${r.gpTcp1Port || 'missing'} gpudp=${r.gpUdp1Port || 'missing'} signer=${r.signerAddress || 'missing'}.`));
  return true;
}

// Generic pruning is intentionally not performed by AutoCluster.
// Pre-UNL failures are handled by candidateReadinessWatchdog(); autonomous
// validator failures are handled by replacement-first maintenance/repair.
// Calling NomadContext.prune() here would create a second lifecycle owner and
// can remove a validator before a replacement is ready.

async function extendManagedOnly(run) {
  // Same lease-extension trigger as NomadContext.extend(), excluding bootstrap A.
  const momentSize = run.clusterContext.evernodeContext.getEvernodeConfig().momentSize;
  const curTimestamp = run.hpContext.timestamp;
  for (const node of managedNodes(run, false)) {
    if (!node.createdOnTimestamp || !Number.isFinite(Number(node.lifeMoments)) || !Number.isFinite(Number(node.targetLifeMoments))) continue;
    const nodeExpiryTs = node.createdOnTimestamp + (node.lifeMoments * momentSize * 1000);
    if (node.targetLifeMoments <= node.lifeMoments &&
        (!node.maxLifeMoments || node.targetLifeMoments < node.maxLifeMoments) &&
        curTimestamp > (nodeExpiryTs - (run.state.lifeIncrMomentMinLimit * momentSize * 500))) {
      const remainingLife = node.maxLifeMoments ? (node.maxLifeMoments - node.targetLifeMoments) : 48;
      // EverPocket's deterministic NumberHelpers is internal. Queue the minimum
      // requested increment here; ClusterContext performs the actual extension
      // transaction in consensus and enforces max life.
      const increment = Math.max(1, Math.min(run.state.lifeIncrMomentMinLimit, remainingLife));
      if (increment > 0) run.clusterContext.extendNode(node.pubkey, increment);
    }
  }
}


function clusterNodeStatusCode(node) {
  const raw = node && node.status;
  const v = raw && typeof raw === 'object' ? raw.status : raw;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function clusterNodeStatusName(node) {
  const raw = node && node.status;
  const v = raw && typeof raw === 'object' ? raw.status : raw;
  const code = Number(v);
  if (Number.isFinite(code)) return ({0:'none',1:'created',2:'configured',3:'acknowledged',4:'added_to_unl'})[code] || String(code);
  return cleanString(v || '', 64).toLowerCase();
}
function clusterNodeMaturityDone(node) {
  const status = clusterNodeStatusName(node);
  return !!(node && node.isUnl) || /^(?:acknowledged|added_to_unl|unl)$/.test(status);
}

function syncValidatorRecords(run) {
  if (!run || !run.state || !run.clusterContext) return false;
  const state = run.state;
  const now = consensusNowMs(run);
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
  const previous = normalizeValidatorRecords(state.validators);
  const old = new Map(previous.map(v => [v.publicKey, v]));
  const managed = managedNodes(run, false);
  const acquired = run.evernodeContext && typeof run.evernodeContext.getAcquiredNodes === 'function'
    ? (run.evernodeContext.getAcquiredNodes() || []) : [];
  const health = new Map(((state.maintenance && state.maintenance.health) || []).filter(Boolean).map(h => [h.pubkey, h]));
  const records = [];

  for (const node of managed) {
    if (!node || !node.pubkey) continue;
    const prior = old.get(node.pubkey) || {};
    const nodeHost = normalizeHostAddress(node.host);
    const acquire = acquired.find(a => a && (
      (a.pubkey && a.pubkey === node.pubkey) ||
      (nodeHost && a.host === nodeHost) ||
      (prior.refId && a.refId === prior.refId)
    )) || null;
    const hostAddress = nodeHost || normalizeHostAddress(acquire && acquire.host) || prior.hostAddress || null;
    const queueItem = hostAddress ? hostEntry(state, hostAddress) : null;
    const h = health.get(node.pubkey) || null;
    const record = {
      publicKey: cleanString(node.pubkey, 256),
      hostAddress,
      refId: cleanString((acquire && acquire.refId) || (queueItem && queueItem.refId) || prior.refId || '', 256) || null,
      domain: normalizeEndpointHost(node.domain || (acquire && acquire.domain) || prior.domain),
      peerPort: validPort(node.peerPort || node.meshPort || (acquire && (acquire.peerPort || acquire.meshPort)) || prior.peerPort),
      userPort: validPort(node.userPort || (acquire && (acquire.userPort || acquire.user_port)) || prior.userPort),
      gpTcp1Port: validPort(node.gpTcp1Port || node.gpTcpPort || node.gptcp1 || node.gp_tcp_port || (acquire && (acquire.gpTcp1Port || acquire.gpTcpPort || acquire.gptcp1 || acquire.gp_tcp_port || acquire.gp_tcp1_port)) || prior.gpTcp1Port),
      gpUdp1Port: validPort(node.gpUdp1Port || node.gpUdpPort || node.gpudp1 || node.gp_udp_port || (acquire && (acquire.gpUdp1Port || acquire.gpUdpPort || acquire.gpudp1 || acquire.gp_udp_port || acquire.gp_udp1_port)) || prior.gpUdp1Port),
      signerAddress: normalizeHostAddress(node.signerAddress) || prior.signerAddress || null,
      isUnl: !!node.isUnl,
      present: true,
      maturityStatus: clusterNodeStatusName(node) || prior.maturityStatus || null,
      health: h && ['healthy','suspect','dead','unknown'].includes(h.status) ? h.status : (node.isUnl ? (prior.health === 'dead' ? 'dead' : 'unknown') : 'candidate'),
      activeOnLcl: Number(node.activeOnLcl) || (h && Number(h.activeOnLcl)) || prior.activeOnLcl || null,
      createdOnTimestamp: Number(node.createdOnTimestamp) || prior.createdOnTimestamp || null,
      lifeMoments: Number.isFinite(Number(node.lifeMoments)) ? Number(node.lifeMoments) : (prior.lifeMoments ?? null),
      targetLifeMoments: Number.isFinite(Number(node.targetLifeMoments)) ? Number(node.targetLifeMoments) : (prior.targetLifeMoments ?? null),
      maxLifeMoments: Number.isFinite(Number(node.maxLifeMoments)) ? Number(node.maxLifeMoments) : (prior.maxLifeMoments ?? null),
      firstSeenAt: prior.firstSeenAt || now || null,
      firstSeenLcl: prior.firstSeenLcl || lcl || null,
      // These are mutation timestamps, not a per-ledger heartbeat. They are filled
      // below only when the semantic validator record actually changes.
      lastUpdatedAt: prior.lastUpdatedAt || null,
      lastUpdatedLcl: prior.lastUpdatedLcl || null,
      retiredAt: null,
      retiredAtLcl: null
    };
    const semanticPrior = normalizeValidatorRecords([prior])[0] || null;
    const semanticNext = normalizeValidatorRecords([record])[0] || null;
    if (semanticPrior) {
      semanticPrior.lastUpdatedAt = null;
      semanticPrior.lastUpdatedLcl = null;
    }
    if (semanticNext) {
      semanticNext.lastUpdatedAt = null;
      semanticNext.lastUpdatedLcl = null;
    }
    if (!semanticPrior || JSON.stringify(semanticNext) !== JSON.stringify(semanticPrior)) {
      record.lastUpdatedAt = now || prior.lastUpdatedAt || null;
      record.lastUpdatedLcl = lcl || prior.lastUpdatedLcl || null;
    }
    records.push(record);
    old.delete(node.pubkey);
  }

  // Preserve historical endpoint/acquisition linkage after a validator leaves
  // the active cluster. This is intentionally metadata-only history: retired
  // records are never used to decide consensus membership or acquisitions.
  for (const prior of old.values()) {
    const alreadyRetired = prior.present === false && prior.health === 'retired';
    records.push({
      ...prior,
      isUnl: false,
      present: false,
      health: 'retired',
      retiredAt: prior.retiredAt || now || null,
      retiredAtLcl: prior.retiredAtLcl || lcl || null,
      lastUpdatedAt: alreadyRetired ? (prior.lastUpdatedAt || null) : (now || prior.lastUpdatedAt || null),
      lastUpdatedLcl: alreadyRetired ? (prior.lastUpdatedLcl || null) : (lcl || prior.lastUpdatedLcl || null)
    });
  }

  records.sort((a,b) => (Number(b.present)-Number(a.present)) || String(a.publicKey).localeCompare(String(b.publicKey)));
  const normalized = normalizeValidatorRecords(records);
  if (JSON.stringify(normalized) === JSON.stringify(previous)) return false;
  state.validators = normalized;
  saveState(state);
  return true;
}

function availableUnlSyncPeers(run) {
  const peers = new Set();
  const add = (domain, port) => {
    const d = normalizeEndpointHost(domain), p = validPort(port);
    if (d && p) peers.add(`${d}:${p}`);
  };
  const unl = run.clusterContext && typeof run.clusterContext.getClusterUnlNodes === 'function'
    ? run.clusterContext.getClusterUnlNodes() : [];
  // Bootstrap A can be absent/incomplete in cluster.json, so use its explicitly
  // published endpoint as a fallback only while it is actually still in the UNL.
  const bootstrapInUnl = unl.some(n => n && n.pubkey === run.state.bootstrapPubkey);
  const b = run.state && run.state.bootstrapEndpoint;
  if (bootstrapInUnl && b) add(b.domain, b.peerPort);
  for (const node of unl) add(node && node.domain, node && node.peerPort);
  return [...peers].sort();
}


function nodeMaturityStability(node, state, lcl) {
  const status = diskNodeStatus(node);
  const statusObj = node && node.status && typeof node.status === 'object' ? node.status : {};
  const acknowledgedOnLcl = Number(statusObj.onLcl || node && node.acknowledgedOnLcl) || 0;
  const required = Math.max(REFERENCE_MATURITY_STABILITY_LCLS, Number(state && state.maturityLclThreshold) || 0);
  const age = acknowledgedOnLcl && lcl ? Math.max(0, Number(lcl) - acknowledgedOnLcl) : 0;
  return {
    ready: status === 'acknowledged' && acknowledgedOnLcl > 0 && age >= required,
    status, acknowledgedOnLcl, age, required
  };
}

function fullUnlPeerListFromNodes(run, unlPubkeys, extraPubkeys = []) {
  const wanted = new Set(normalizePubkeyList([...(unlPubkeys || []), ...(extraPubkeys || [])]));
  const peers = new Set();
  const nodes = run && run.clusterContext && typeof run.clusterContext.getClusterNodes === 'function'
    ? (run.clusterContext.getClusterNodes() || []) : [];
  const byKey = new Map(nodes.filter(Boolean).map(n => [String(n.pubkey || '').toLowerCase(), n]));
  for (const pubkey of wanted) {
    let node = byKey.get(pubkey) || null;
    if ((!node || !normalizeEndpointHost(node.domain) || !validPort(node.peerPort || node.meshPort)) &&
        run && run.state && pubkey === String(run.state.bootstrapPubkey || '').toLowerCase()) {
      const b = run.state.bootstrapEndpoint || {};
      node = { domain:b.domain, peerPort:b.peerPort };
    }
    const domain = normalizeEndpointHost(node && node.domain);
    const port = validPort(node && (node.peerPort || node.meshPort));
    if (domain && port) peers.add(`${domain}:${port}`);
  }
  return [...peers].sort();
}

async function applyFullUnlPeerMesh(run, unlPubkeys, label = 'membership') {
  const peers = fullUnlPeerListFromNodes(run, unlPubkeys);
  if (!peers.length) throw new Error(`FULL_UNL_MESH_EMPTY: ${label} cannot persist an empty peer list.`);
  const cfg = await run.ctx.getConfig();
  setContractUnl(cfg, normalizePubkeyList(unlPubkeys));
  if (!cfg.mesh || typeof cfg.mesh !== 'object') cfg.mesh = {};
  cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
  cfg.mesh.peer_discovery.enabled = false;
  cfg.mesh.known_peers = peers.slice();
  await run.ctx.updateConfig(cfg);
  if (run.hpContext && typeof run.hpContext.updatePeers === 'function') {
    await run.hpContext.updatePeers(peers);
  } else if (run.ctx && typeof run.ctx.updatePeers === 'function') {
    await run.ctx.updatePeers(peers);
  }
  console.log(`AutoCluster: FULL UNL PEER MESH applied after ${label}: unl=${normalizePubkeyList(unlPubkeys).length} peers=${peers.length} [${peers.join(', ')}]. patch.cfg mesh.known_peers and live hpcore peers now agree.`);
  return peers;
}

// Fresh bootstrap initially keeps contract.unl=[A], then grows the trusted UNL one validator at a time
// switch, but networking does not need to stay star-shaped. Seed each newly
// acquired follower with Bootstrap A plus already-materialized healthy managed
// candidates. Put the most useful candidates first because the final acquire-memo
// guard may need to trim the tail to remain under Xahau's 1 KiB memo ceiling.
function availableBootstrapAcquisitionPeers(run) {
  const bootstrapPeers = availableUnlSyncPeers(run);
  const seen = new Set(bootstrapPeers);
  const readiness = new Map(normalizeCandidateReadiness(run.state && run.state.candidateReadiness)
    .map(r => [String(r.pubkey || '').toLowerCase(), r]));
  const stalled = new Set(normalizeCandidateWatchdogs(run.state && run.state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => String(w.pubkey || '').toLowerCase()));
  const ranked = [];
  for (const node of managedNodes(run, false)) {
    const pubkey = String(node && node.pubkey || '').toLowerCase();
    if (!node || !pubkey || stalled.has(pubkey)) continue;
    const d = normalizeEndpointHost(node.domain), p = validPort(node.peerPort || node.meshPort);
    if (!d || !p) continue;
    const endpoint = `${d}:${p}`;
    if (seen.has(endpoint)) continue;
    const rec = readiness.get(pubkey) || null;
    ranked.push({
      endpoint,
      pubkey,
      acceptedReady: !!(rec && Number(rec.readyHeartbeats || 0) >= CANDIDATE_READY_REQUIRED_HEARTBEATS),
      peerCount: rec && rec.peerCount != null ? Math.max(0, Number(rec.peerCount) || 0) : -1,
      observedAtLcl: Number(rec && rec.observedAtLcl) || 0
    });
  }
  ranked.sort((a,b) =>
    Number(b.acceptedReady) - Number(a.acceptedReady) ||
    b.peerCount - a.peerCount ||
    b.observedAtLcl - a.observedAtLcl ||
    a.pubkey.localeCompare(b.pubkey) ||
    a.endpoint.localeCompare(b.endpoint));
  for (const item of ranked) {
    if (seen.has(item.endpoint)) continue;
    seen.add(item.endpoint);
    bootstrapPeers.push(item.endpoint);
  }
  return bootstrapPeers;
}

// Mirror EverPocket JSONHelpers.castFromModel() closely enough to measure the
// exact plaintext object that Evernode encrypts for prepareAcquireLeaseTransaction.
// Arrays are deliberately left intact, matching EverPocket 0.1.6 behavior.
function castFromModelForAcquireMemo(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return obj;
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    const snake = key.replace(/([A-Z])/g, g => `_${g.toLowerCase()}`);
    out[snake] = (value && typeof value === 'object' && !Array.isArray(value))
      ? castFromModelForAcquireMemo(value)
      : value;
  }
  return out;
}

// Evernode encrypts the requirement before placing it in MemoData. Hosts may use
// either key type, so calculate the larger secp256k1 envelope as a safe upper
// bound: 65-byte ephemeral key + 16-byte IV + 32-byte MAC + PKCS#7 AES payload,
// then Evernode prepends one byte and base64-encodes the whole blob.
function xrplVariableLengthPrefixBytes(length) {
  const n = Math.max(0, Number(length) || 0);
  if (n <= 192) return 1;
  if (n <= 12480) return 2;
  if (n <= 918744) return 3;
  return 4; // impossible for our acquire memo; keeps projection conservative.
}

function projectAcquireMemoUsage(instanceCfg, messageKey) {
  const requirement = {
    ...castFromModelForAcquireMemo(instanceCfg && typeof instanceCfg === 'object' ? instanceCfg : {}),
    messageKey: String(messageKey || '')
  };
  const plaintextBytes = Buffer.byteLength(JSON.stringify(requirement), 'utf8');
  const ciphertextBytes = 16 * (Math.floor(plaintextBytes / 16) + 1);
  const encryptedBytes = 65 + 16 + 32 + ciphertextBytes;
  const memoDataBytes = 4 * Math.ceil((1 + encryptedBytes) / 3);

  // Evernode submits one memo: type="evnAcquireLease", format="base64". XRPL's
  // limit applies to the serialized Memos array, so include field headers, VL
  // prefixes, the Memo object/end marker and the array/end marker. All three memo
  // fields use one-byte field IDs at these field numbers.
  const memoTypeBytes = Buffer.byteLength('evnAcquireLease', 'utf8');
  const memoFormatBytes = Buffer.byteLength('base64', 'utf8');
  const vlFieldBytes = n => 1 + xrplVariableLengthPrefixBytes(n) + n;
  const serializedMemoBytes =
    1 + // Memos array field header
    1 + // Memo object field header
    vlFieldBytes(memoTypeBytes) +
    vlFieldBytes(memoFormatBytes) +
    vlFieldBytes(memoDataBytes) +
    1 + // end-of-object marker
    1;  // end-of-array marker
  return { plaintextBytes, ciphertextBytes, encryptedBytes, memoDataBytes, serializedMemoBytes };
}

function bootstrapPeerEndpoint(state) {
  const b = state && state.bootstrapEndpoint;
  const d = normalizeEndpointHost(b && b.domain), p = validPort(b && b.peerPort);
  return d && p ? `${d}:${p}` : null;
}

// Final safety gate runs inside EvernodeContext.acquireSubmit(), after
// ClusterContext has added ownerPubkey/contractId/consensus fields and after the
// per-acquisition message key exists. This is the first point where the complete
// requirement can be measured accurately. Keep Bootstrap A first, then retain as
// many ranked progressive-mesh seeds as fit under the conservative memo target.
function fitAcquirePeersToMemo(options, messageKey, state) {
  const cfg = options && options.instanceCfg;
  const mesh = cfg && cfg.config && cfg.config.mesh;
  if (!mesh || typeof mesh !== 'object') {
    const usage = projectAcquireMemoUsage(cfg, messageKey);
    if (usage.serializedMemoBytes > XRPL_ACQUIRE_MEMO_TARGET_BYTES) throw new Error(`ACQUIRE_MEMO_TOO_LARGE_WITHOUT_TRIMMABLE_PEERS: projected serialized Memos ${usage.serializedMemoBytes}/${XRPL_ACQUIRE_MEMO_TARGET_BYTES} bytes.`);
    return { trimmed:false, originalPeers:[], peers:[], dropped:[], usage };
  }
  const prop = Array.isArray(mesh.known_peers) ? 'known_peers' : (Array.isArray(mesh.knownPeers) ? 'knownPeers' : null);
  if (!prop) {
    const usage = projectAcquireMemoUsage(cfg, messageKey);
    if (usage.serializedMemoBytes > XRPL_ACQUIRE_MEMO_TARGET_BYTES) throw new Error(`ACQUIRE_MEMO_TOO_LARGE_WITHOUT_TRIMMABLE_PEERS: projected serialized Memos ${usage.serializedMemoBytes}/${XRPL_ACQUIRE_MEMO_TARGET_BYTES} bytes.`);
    return { trimmed:false, originalPeers:[], peers:[], dropped:[], usage };
  }

  const originalPeers = [...new Set(mesh[prop].map(v => cleanString(v, 512)).filter(Boolean))];
  const bootstrap = bootstrapPeerEndpoint(state);
  let peers = originalPeers.slice();
  if (bootstrap && peers.includes(bootstrap)) peers = [bootstrap, ...peers.filter(p => p !== bootstrap)];
  mesh[prop] = peers;
  let usage = projectAcquireMemoUsage(cfg, messageKey);
  const dropped = [];
  while (usage.serializedMemoBytes > XRPL_ACQUIRE_MEMO_TARGET_BYTES && peers.length > 1) {
    dropped.unshift(peers.pop());
    mesh[prop] = peers.slice();
    usage = projectAcquireMemoUsage(cfg, messageKey);
  }
  if (usage.serializedMemoBytes > XRPL_ACQUIRE_MEMO_TARGET_BYTES) {
    throw new Error(`ACQUIRE_MEMO_TOO_LARGE_WITH_REQUIRED_SEED: projected serialized Memos ${usage.serializedMemoBytes}/${XRPL_ACQUIRE_MEMO_TARGET_BYTES} bytes (MemoData=${usage.memoDataBytes}B, plaintext=${usage.plaintextBytes}B) even after reducing known_peers to ${peers.length}.`);
  }
  return { trimmed:dropped.length > 0, originalPeers, peers:peers.slice(), dropped, usage };
}


function safeAcquireRecordSummary(record) {
  if (!record || typeof record !== 'object') return null;
  const nested = record.instance && typeof record.instance === 'object' ? record.instance
    : (record.instanceInfo && typeof record.instanceInfo === 'object' ? record.instanceInfo
      : (record.acquire && typeof record.acquire === 'object' ? record.acquire : null));
  const src = nested || record;
  return {
    refId: cleanString(record.refId || record.acquireRefId || src.refId || src.acquireRefId || '', 256) || null,
    host: normalizeHostAddress(record.host || src.host),
    pubkey: cleanString(src.pubkey || src.publicKey || record.pubkey || record.publicKey || '', 256) || null,
    domain: normalizeEndpointHost(src.domain || record.domain),
    userPort: validPort(src.userPort || src.user_port || record.userPort || record.user_port),
    peerPort: validPort(src.peerPort || src.peer_port || src.meshPort || record.peerPort || record.peer_port || record.meshPort),
    gpTcp1Port: validPort(src.gpTcp1Port || src.gpTcpPort || src.gptcp1 || src.gp_tcp_port || src.gp_tcp1_port || record.gpTcp1Port || record.gpTcpPort || record.gptcp1 || record.gp_tcp_port || record.gp_tcp1_port),
    gpUdp1Port: validPort(src.gpUdp1Port || src.gpUdpPort || src.gpudp1 || src.gp_udp_port || src.gp_udp1_port || record.gpUdp1Port || record.gpUdpPort || record.gpudp1 || record.gp_udp_port || record.gp_udp1_port),
    name: cleanString(src.name || record.name || '', 256) || null,
    contractId: cleanString(src.contract_id || src.contractId || record.contract_id || record.contractId || '', 256) || null,
    recordKeys: Object.keys(record).sort().slice(0, 32),
    instanceKeys: nested ? Object.keys(nested).sort().slice(0, 32) : []
  };
}

function recordNativeAcquireStage(state, item, stage, lcl, detail = {}) {
  if (!state || !item) return false;
  const summary = detail.completed ? safeAcquireRecordSummary(detail.completed) : null;
  const parts = [
    stage || 'unknown', item.refId || '',
    detail.txState || '', detail.txResult || '',
    detail.everPocketPending ? 'ep-pending' : 'no-ep-pending',
    detail.everPocketAcquired ? 'ep-acquired' : 'no-ep-acquired',
    detail.clusterPending ? 'cluster-pending' : 'no-cluster-pending',
    detail.materialized ? 'materialized' : 'not-materialized',
    summary && summary.pubkey || '', summary && summary.domain || '',
    summary && summary.userPort || '', summary && summary.peerPort || '',
    summary && summary.gpTcp1Port || '', summary && summary.gpUdp1Port || ''
  ];
  const fingerprint = cleanString(parts.join('|'), 512);

  // Pipeline trace is observability, not consensus state.  Older builds stored
  // nativeTraceFingerprint/nativeStageAtLcl in autocluster.state.json, so each
  // Xahau/EverPocket poll could manufacture a new HPFS /state hash even though
  // no admission decision changed. Keep the detailed trace node-local instead.
  let traceChanged = false;
  try {
    fs.mkdirSync(LOCAL_AUTOCLUSTER_ROOT, { recursive:true });
    const trace = readJson(LOCAL_NATIVE_ACQUIRE_TRACE_FILE, { schema:1, items:{} }) || { schema:1, items:{} };
    if (!trace.items || typeof trace.items !== 'object') trace.items = {};
    const key = normalizeHostAddress(item.address) || cleanString(item.refId || 'unknown', 256);
    const prev = trace.items[key];
    if (!prev || prev.fingerprint !== fingerprint) {
      trace.items[key] = { fingerprint, stage:cleanString(stage || 'unknown',64), lcl:Number(lcl)||0, refId:cleanString(item.refId||'',256)||null };
      trace.updatedAtLcl = Number(lcl) || trace.updatedAtLcl || 0;
      writeJson(LOCAL_NATIVE_ACQUIRE_TRACE_FILE, trace);
      traceChanged = true;
    }
  } catch (_) {}

  // AcquireSuccess instance identity is a true semantic milestone and is useful
  // for deterministic cleanup/recovery, so preserve it once in replicated state.
  // Intermediate tx/pending/cluster-pending trace transitions are deliberately
  // NOT copied into shared state.
  let replicatedChanged = false;
  if (summary) {
    const set = (k, v) => { if ((item[k] ?? null) !== (v ?? null)) { item[k] = v ?? null; replicatedChanged = true; } };
    if (!item.acquireSuccessAtLcl) { item.acquireSuccessAtLcl = Number(lcl) || null; replicatedChanged = true; }
    set('acquireSuccessPubkey', summary.pubkey);
    set('acquireSuccessDomain', summary.domain);
    set('acquireSuccessUserPort', summary.userPort);
    set('acquireSuccessPeerPort', summary.peerPort);
    set('acquireSuccessGpTcp1Port', summary.gpTcp1Port);
    set('acquireSuccessGpUdp1Port', summary.gpUdp1Port);
    set('acquireSuccessName', summary.name);
    set('acquireSuccessContractId', summary.contractId);
  }

  if (traceChanged || replicatedChanged) {
    const inst = summary ? ` instance(pubkey=${summary.pubkey || 'missing'},domain=${summary.domain || 'missing'},user=${summary.userPort || 'missing'},peer=${summary.peerPort || 'missing'},gpTcp1=${summary.gpTcp1Port || 'missing'},gpUdp1=${summary.gpUdp1Port || 'missing'},name=${summary.name || 'missing'},contract=${summary.contractId || 'missing'}) recordKeys=[${summary.recordKeys.join(',')}] instanceKeys=[${summary.instanceKeys.join(',')}]` : '';
    console.log(`AutoCluster: ACQUIRE_NATIVE_TRACE host=${item.address || 'unknown'} refId=${item.refId || 'unknown'} stage=${cleanString(stage || 'unknown',64)} tx=${detail.txState || 'unknown'}${detail.txResult ? `/${detail.txResult}` : ''} everPocketPending=${!!detail.everPocketPending} everPocketAcquireSuccess=${!!detail.everPocketAcquired} clusterPending=${!!detail.clusterPending} materialized=${!!detail.materialized} trace=${traceChanged ? 'local' : 'unchanged'} replicated=${replicatedChanged ? 'acquire-success-milestone' : 'no'}.${inst}`);
  }
  return replicatedChanged;
}

async function pendingAcquisitionWatchdog(run) {
  const state = run.state;
  const now = consensusNowMs(run);
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  if (!now && !lcl) return false; // Consensus time/LCL only; never Date.now().

  const nodes = run.clusterContext.getClusterNodes();
  const acquired = typeof run.evernodeContext.getAcquiredNodes === 'function' ? run.evernodeContext.getAcquiredNodes() : [];
  const pendingAcquires = typeof run.evernodeContext.getPendingAcquires === 'function' ? run.evernodeContext.getPendingAcquires() : [];
  const validatedTxs = typeof run.xrplContext.getValidatedTransactions === 'function' ? run.xrplContext.getValidatedTransactions() : [];
  const pendingTxs = typeof run.xrplContext.getPendingTransactions === 'function' ? run.xrplContext.getPendingTransactions() : [];
  const currentLedger = Number(run.xrplContext.xrplApi && run.xrplContext.xrplApi.ledgerIndex) || null;
  let changed = false;

  for (const item of state.hostQueue) {
    if (!item || !item.address || !['attempting','pending'].includes(item.status)) continue;

    // Once it is a real cluster node, the separate maturity watchdog owns it.
    if (nodes.some(n => n && n.host === item.address)) {
      if (item.pendingSinceAt || item.pendingSinceLcl) { item.pendingSinceAt = null; item.pendingSinceLcl = null; changed = true; }
      continue;
    }

    let watchdogStarted = false;
    if (!item.pendingSinceAt && now) { item.pendingSinceAt = now; changed = true; watchdogStarted = true; }
    if (!item.pendingSinceLcl && lcl) { item.pendingSinceLcl = Number(item.lastAttemptLcl) || lcl; changed = true; watchdogStarted = true; }
    if (watchdogStarted) {
      console.log(`AutoCluster: durable provisioning watchdog active for ${item.address}${item.refId ? ` refId=${item.refId}` : ''}; deadline=${PENDING_ACQUISITION_TIMEOUT_MS / 60000} minutes or ${PENDING_ACQUISITION_TIMEOUT_LCL} committed ledgers, whichever comes first. Late recovery remains enabled after quarantine.`);
    }

    let completed = acquired.find(a => a && ((item.refId && (a.refId === item.refId || a.acquireRefId === item.refId)) || a.host === item.address)) || null;
    let pendingAcquire = pendingAcquires.find(a => a && ((item.refId && (a.refId === item.refId || a.acquireRefId === item.refId)) || a.host === item.address)) || null;
    const refId = cleanString((completed && (completed.refId || completed.acquireRefId)) || (pendingAcquire && (pendingAcquire.refId || pendingAcquire.acquireRefId)) || item.refId || item.acquireRequestTxId || '', 256) || null;
    // Cross-check EverPocket's documented direct lookup API against its backing arrays.
    // If these disagree, that is an EverPocket state-management bug rather than a host failure.
    if (refId && typeof run.evernodeContext.getIfAcquired === 'function') {
      try {
        const direct = run.evernodeContext.getIfAcquired(refId);
        if (direct && !completed) { completed = direct; console.log(`AutoCluster: ACQUIRE_VIEW_MISMATCH refId=${refId}: getIfAcquired() returned a successful acquire while getAcquiredNodes() did not.`); }
        else if (!direct && completed) console.log(`AutoCluster: ACQUIRE_VIEW_MISMATCH refId=${refId}: getAcquiredNodes() contains a successful acquire while getIfAcquired() returned empty.`);
      } catch (e) { console.log(`AutoCluster: getIfAcquired(${refId}) diagnostic failed: ${errText(e)}`); }
    }
    if (refId && typeof run.evernodeContext.getIfPending === 'function') {
      try {
        const direct = run.evernodeContext.getIfPending(refId);
        if (direct && !pendingAcquire) { pendingAcquire = direct; console.log(`AutoCluster: ACQUIRE_VIEW_MISMATCH refId=${refId}: getIfPending() returned pending while getPendingAcquires() did not.`); }
      } catch (e) { console.log(`AutoCluster: getIfPending(${refId}) diagnostic failed: ${errText(e)}`); }
    }
    const validated = refId ? (
      (typeof run.xrplContext.getValidatedTransaction === 'function' ? run.xrplContext.getValidatedTransaction(refId) : null) ||
      validatedTxs.find(t => t && t.hash === refId) || null
    ) : null;
    const pendingTx = refId ? pendingTxs.find(t => t && t.hash === refId) || null : null;
    const clusterPending = run.clusterContext.getPendingNodes().find(n => n && ((refId && n.refId === refId) || n.host === item.address)) || null;
    const materialized = nodes.find(n => n && n.host === item.address) || null;
    const txState = validated ? 'validated' : (pendingTx ? 'pending' : (refId ? 'submitted-or-unknown' : 'missing'));
    const txResult = cleanString(validated && validated.resultCode || pendingTx && pendingTx.resultCode || '', 64) || null;
    const stage = materialized ? 'materialized' : clusterPending ? 'cluster-pending-candidate' : completed ? 'acquire-success-observed' : validated && txResult === 'tesSUCCESS' ? 'tx-validated-waiting-acquire-success' : pendingTx ? 'tx-pending' : 'waiting-acquire-success';
    if (recordNativeAcquireStage(state, item, stage, lcl, { txState, txResult, everPocketPending:!!pendingAcquire, everPocketAcquired:!!completed, clusterPending:!!clusterPending, materialized:!!materialized, completed })) changed = true;
    if (completed) continue; // Native AcquireSuccess is processed; deterministic candidate materialization owns it now.
    const resultCode = String(validated && validated.resultCode || '');
    // For acquisitions, only tesSUCCESS proves that THIS lease purchase landed.
    // tefPAST_SEQ/tefALREADY are not purchase success; if an acquired instance
    // already exists it was handled by the completed check above.
    const successLike = !!validated && resultCode === 'tesSUCCESS';
    const provenFailed = !!validated && !successLike;
    const txExpired = !!(pendingTx && currentLedger && Number(pendingTx.lastLedgerSequence) && Number(pendingTx.lastLedgerSequence) < currentLedger);

    // Only a proven ledger failure/expiry is allowed to discard an in-flight
    // acquisition automatically. A missing transient EverPocket pending entry is
    // not proof of failure.
    if (provenFailed || txExpired) {
      item.status = 'failed';
      item.pendingSinceAt = null;
      item.pendingSinceLcl = null;
      item.lastError = provenFailed
        ? `Acquisition transaction ${refId || ''} validated with ${resultCode}; safe to try another host.`
        : `Acquisition transaction ${refId || ''} expired before validation; safe to try another host.`;
      if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
      state.waitingForHosts = false;
      saveState(state);
      console.log(`AutoCluster: acquisition for ${item.address}${refId ? ` refId=${refId}` : ''} is PROVEN FAILED (${provenFailed ? resultCode : 'expired'}); moving to the next queued host.`);
      return true;
    }

    const age = now && item.pendingSinceAt ? Math.max(0, now - Number(item.pendingSinceAt)) : 0;
    const ageLcl = lcl && item.pendingSinceLcl ? Math.max(0, lcl - Number(item.pendingSinceLcl)) : 0;
    if (age < PENDING_ACQUISITION_TIMEOUT_MS && ageLcl < PENDING_ACQUISITION_TIMEOUT_LCL) continue;

    // A success/accepted/unknown submission may already represent a paid lease.
    // Do not delete the EverPocket pending record or message-key file: a late
    // acquire response still needs them for decryption/recovery. Quarantine this
    // provisioning attempt and let the queue continue with a different host.
    item.status = 'provisioning-stalled';
    item.nativeStage = 'acquire-response-timeout-late-watch';
    item.nativeStageAtLcl = lcl || null;
    item.refId = refId || item.refId;
    item.pendingSinceAt = null;
    item.pendingSinceLcl = null;
    state.nextAcquireAfterLcl = Math.max(Number(state.nextAcquireAfterLcl) || 0, lcl + ACQUISITION_SETTLE_CLEAN_LEDGERS);
    item.lastError = successLike
      ? `Lease transaction ${refId || ''} is tesSUCCESS, but EverPocket still has no successful-acquire record (native AcquireSuccess not observed/decoded) before the provisioning deadline (${PENDING_ACQUISITION_TIMEOUT_MS / 60000} minutes / ${PENDING_ACQUISITION_TIMEOUT_LCL} ledgers). Preserved for late recovery; this host will not be repurchased automatically.`
      : `No definitive acquisition failure was proven before the provisioning deadline (${PENDING_ACQUISITION_TIMEOUT_MS / 60000} minutes / ${PENDING_ACQUISITION_TIMEOUT_LCL} ledgers). Preserved for late recovery; AutoCluster may try another host without deleting the original pending/key material.`;
    if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
    if (state.blocker && state.blocker.host === item.address && ['acquire-node','acquisition-endpoint'].includes(state.blocker.stage)) state.blocker = null;
    state.waitingForHosts = false;
    saveState(state);
    console.log(`AutoCluster: PROVISIONING TIMEOUT for ${item.address}${refId ? ` refId=${refId}` : ''} after ${Math.floor(age/1000)}s / ${ageLcl} committed ledgers; moved to provisioning-stalled late-watch with lease/key material preserved. AutoCluster may try the next queued host on a later ledger.`);
    return true;
  }

  if (changed) saveState(state);
  return false;
}

async function terminateEvernodeLeaseForCandidate(run, node, item) {
  if (!run || !run.xrplContext || !run.evernodeContext) throw new Error('EverPocket/Xahau runtime is unavailable; cannot terminate this lease safely.');
  const acquired = typeof run.evernodeContext.getAcquiredNodes === 'function' ? (run.evernodeContext.getAcquiredNodes() || []) : [];
  const completed = acquired.find(a => {
    if (!a) return false;
    const summary = safeAcquireRecordSummary(a);
    return !!summary && ((item && item.refId && summary.refId === item.refId) || (node && node.host && summary.host === node.host) || (node && node.pubkey && summary.pubkey === node.pubkey));
  }) || null;
  const summary = safeAcquireRecordSummary(completed);
  const tokenId = cleanString((summary && summary.name) || (item && item.acquireSuccessName) || '', 256) || null;
  if (!tokenId) throw new Error('LEASE_TOKEN_ID_UNAVAILABLE: candidate has no recovered Evernode instance/URI-token name; refusing to delete bookkeeping without terminating the paid lease.');

  let token = null;
  if (run.xrplContext.xrplApi && typeof run.xrplContext.xrplApi.getURITokenByIndex === 'function') {
    token = await run.xrplContext.xrplApi.getURITokenByIndex(tokenId);
  } else if (run.xrplContext.xrplAcc && typeof run.xrplContext.xrplAcc.getURITokens === 'function') {
    const tokens = await run.xrplContext.xrplAcc.getURITokens();
    token = Array.isArray(tokens) ? tokens.find(t => t && (t.index === tokenId || t.index === String(tokenId).toUpperCase())) || null : null;
  }
  // Missing token means the lease has already been terminated/burned. It is safe
  // to finish local cleanup instead of trapping the candidate forever.
  if (!token) return { tokenId, alreadyTerminated:true, resultCode:'already-gone', hash:null };

  const owner = normalizeHostAddress(token.Owner || token.owner);
  const treasury = normalizeHostAddress(run.xrplContext.xrplAcc && run.xrplContext.xrplAcc.address);
  if (owner && treasury && owner !== treasury) throw new Error(`LEASE_TOKEN_NOT_OWNED: URI token ${tokenId} is owned by ${owner}, not cluster treasury ${treasury}.`);
  const issuer = normalizeHostAddress(token.Issuer || token.issuer);
  if (!issuer) throw new Error(`LEASE_TOKEN_ISSUER_MISSING: URI token ${tokenId} has no valid issuer.`);
  if (!run.xrplContext.xrplAcc || typeof run.xrplContext.xrplAcc.prepareMakePayment !== 'function' || typeof run.xrplContext.multiSignAndSubmitTransaction !== 'function') {
    throw new Error('EverPocket Xahau multisign payment runtime is unavailable; cannot terminate lease.');
  }

  // Mirror evernode-js-client TenantClient.terminateLease(), but submit through
  // EverPocket's clustered multisign path rather than a single treasury secret.
  const evernode = require('evernode-js-client');
  const payment = await run.xrplContext.xrplAcc.prepareMakePayment(
    issuer,
    evernode.XrplConstants.MIN_DROPS,
    null,
    null,
    null,
    { hookParams:[
      { name:evernode.HookParamKeys.PARAM_EVENT_TYPE_KEY, value:evernode.EventTypes.TERMINATE_LEASE },
      { name:evernode.HookParamKeys.PARAM_EVENT_DATA_KEY, value:tokenId }
    ] }
  );
  const result = await run.xrplContext.multiSignAndSubmitTransaction(payment);
  const resultCode = ledgerResultCode(result) || null;
  if (resultCode && !/^tesSUCCESS$/i.test(resultCode)) {
    throw new Error(`TERMINATE_LEASE_FAILED: Xahau returned ${resultCode} for URI token ${tokenId}. Candidate retained for retry.`);
  }
  return { tokenId, alreadyTerminated:false, resultCode:resultCode || 'submitted', hash:submissionHash(result, payment) || null };
}

async function lookupLeaseToken(run, tokenId) {
  if (!run || !run.xrplContext || !tokenId) return null;
  if (run.xrplContext.xrplApi && typeof run.xrplContext.xrplApi.getURITokenByIndex === 'function') {
    return await run.xrplContext.xrplApi.getURITokenByIndex(tokenId);
  }
  if (run.xrplContext.xrplAcc && typeof run.xrplContext.xrplAcc.getURITokens === 'function') {
    const tokens = await run.xrplContext.xrplAcc.getURITokens();
    return Array.isArray(tokens) ? tokens.find(t => t && (t.index === tokenId || t.index === String(tokenId).toUpperCase())) || null : null;
  }
  return null;
}

async function finalizePreUnlCandidateDrop(run, node, item, reason, termination) {
  const state = run.state;
  const wanted = cleanString(node && node.pubkey || '', 256);
  const host = normalizeHostAddress(node && node.host);
  const manager = run.clusterContext && run.clusterContext.clusterManager;
  if (!manager || typeof manager.removeNode !== 'function') throw new Error('ClusterManager.removeNode is unavailable after confirmed lease termination; refusing incomplete candidate cleanup.');
  manager.removeNode(wanted);

  const acquired = typeof run.evernodeContext.getAcquiredNodes === 'function' ? run.evernodeContext.getAcquiredNodes() : [];
  for (let i = acquired.length - 1; i >= 0; i--) {
    const summary = safeAcquireRecordSummary(acquired[i]);
    if (summary && ((item && item.refId && summary.refId === item.refId) || (host && summary.host === host) || summary.pubkey === wanted)) acquired.splice(i, 1);
  }
  persistEverPocketAcquireArrays(run);

  state.candidateReadiness = normalizeCandidateReadiness(state.candidateReadiness).filter(r => r.pubkey !== wanted);
  state.candidateSyncQuiescence = normalizeCandidateSyncQuiescence(state.candidateSyncQuiescence).filter(r => r.pubkey !== wanted);
  state.candidateWatchdogs = normalizeCandidateWatchdogs(state.candidateWatchdogs).filter(w => w.pubkey !== wanted);
  state.candidateDiagnostics = normalizeCandidateDiagnostics(state.candidateDiagnostics).filter(d => d.pubkey !== wanted);
  state.maturitySignals = normalizeMaturitySignals(state.maturitySignals).filter(m => m.pubkey !== wanted);
  const replacement = normalizeBootstrapReplacement(state.bootstrapReplacement);
  if (replacement && replacement.failedPubkey === wanted) state.bootstrapReplacement = null;
  if (item) {
    item.status = 'dropped';
    item.pendingSinceAt = null;
    item.pendingSinceLcl = null;
    item.lastError = `Instance dropped after confirmed lease termination: ${cleanString(reason, 300)}${termination && termination.alreadyTerminated ? ' (lease token was already gone)' : ''}.`;
    item.droppedAtLcl = Number(run.hpContext.lclSeqNo) || null;
    item.dropReason = cleanString(reason, 300);
    item.dropTokenId = termination && termination.tokenId || item.dropTokenId || null;
    item.dropTxHash = termination && termination.hash || item.dropTxHash || null;
    if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
  }
  state.waitingForHosts = false;
  state.nextAcquireAfterLcl = Math.max(Number(state.nextAcquireAfterLcl) || 0, (Number(run.hpContext.lclSeqNo) || 0) + 1);
  if (state.blocker && (state.blocker.pubkey === wanted || (host && state.blocker.host === host))) state.blocker = null;
  saveState(state);
  console.log(`AutoCluster: DROP INSTANCE FINALIZED for ${cleanString(wanted,80)} host=${host || 'unknown'} token=${cleanString((termination && termination.tokenId) || (item && item.dropTokenId) || '',32)||'already-gone'} validation=${termination && termination.resultCode || 'confirmed'}. Next queued host may start on the next ledger.`);
  return { dropped:true, pending:false, pubkey:wanted, host, reason:cleanString(reason,300), termination, nextAcquireAfterLcl:state.nextAcquireAfterLcl };
}

async function dropPreUnlCandidate(run, pubkey, reason = 'operator-drop') {
  if (!run || !run.state || !run.clusterContext || !run.hpContext) throw new Error('AutoCluster runtime is unavailable for candidate drop.');
  const state = run.state;
  const wanted = cleanString(pubkey || '', 256);
  if (!wanted) throw new Error('Candidate public key is required.');
  const nodes = run.clusterContext.getClusterNodes();
  const node = nodes.find(n => n && n.pubkey === wanted) || null;
  if (!node) throw new Error(`Candidate ${wanted} is no longer materialized.`);
  const committedUnl = (typeof run.clusterContext.getClusterUnlNodes === 'function' ? run.clusterContext.getClusterUnlNodes() : []).map(n => n && n.pubkey).filter(Boolean);
  if (node.isUnl || committedUnl.includes(wanted)) throw new Error(`REFUSE_DROP_UNL_VALIDATOR: ${wanted} is already in the UNL. Remove it through coordinated validator removal before terminating its lease.`);
  const bootstrapKey = cleanString(state.bootstrapPubkey || '',256);
  if (committedUnl.length !== 1 || !bootstrapKey || committedUnl[0] !== bootstrapKey) {
    throw new Error('REFUSE_DROP_AFTER_MEMBERSHIP_GROWTH: destructive lease termination is allowed only while Bootstrap A is the sole UNL validator. After growth begins, use candidate rotation or the signer-quorum REMOVE_MANAGED recovery path.');
  }

  const membership = normalizeMembershipCommand(state.membershipCommand);
  if (membership && membership.pubkey === wanted && Number(membership.submittedAtLcl) > 0) {
    throw new Error(`REFUSE_DROP_MEMBERSHIP_SUBMITTED: ADD_UNL for ${wanted} has already been submitted/applied. Wait for the membership result before any lease termination.`);
  }
  if (membership && membership.pubkey === wanted) state.membershipCommand = null;
  const override = normalizeBootstrapMeshOverride(state.bootstrapMeshOverride);
  if (override && override.forcedPubkey === wanted) state.bootstrapMeshOverride = null;

  const host = normalizeHostAddress(node.host);
  const item = host ? hostEntry(state, host) : null;
  if (!item) throw new Error(`DROP_HOST_RECORD_MISSING: ${wanted} has no AutoCluster host record.`);

  // A termination submission is only the first half of DROP. Never erase the
  // candidate until the exact Payment validates tesSUCCESS or the URI token is
  // authoritatively absent. This prevents tefPAST_SEQ/local-submit ambiguity from
  // being misreported as a completed drop.
  if (item.status === 'drop-termination-pending') {
    const tokenId = cleanString(item.dropTokenId || '', 256) || null;
    const hash = cleanString(item.dropTxHash || '', 256) || null;
    let validated = null;
    if (hash && run.xrplContext && typeof run.xrplContext.getValidatedTransaction === 'function') validated = run.xrplContext.getValidatedTransaction(hash);
    if (validated) {
      const code = ledgerResultCode(validated) || null;
      if (/^tesSUCCESS$/i.test(String(code || ''))) {
        return await finalizePreUnlCandidateDrop(run, node, item, item.dropReason || reason, { tokenId, hash, alreadyTerminated:false, resultCode:code });
      }
      item.status = 'acquired';
      item.lastError = `Lease termination transaction ${hash} validated with ${code || 'unknown'}; candidate retained for a clean retry.`;
      item.dropTxHash = null;
      item.dropRequestedAtLcl = null;
      saveState(state);
      throw new Error(`TERMINATE_LEASE_VALIDATION_FAILED: ${hash} validated with ${code || 'unknown'}. Candidate retained.`);
    }
    if (tokenId) {
      const token = await lookupLeaseToken(run, tokenId);
      if (!token) {
        return await finalizePreUnlCandidateDrop(run, node, item, item.dropReason || reason, { tokenId, hash, alreadyTerminated:true, resultCode:'token-gone' });
      }
    }
    console.log(`AutoCluster: DROP INSTANCE FINALITY WAIT for ${cleanString(wanted,80)} host=${host || 'unknown'} token=${cleanString(tokenId || '',32)||'unknown'} tx=${cleanString(hash || '',20)||'unknown'}. Candidate/bookkeeping are intentionally retained until ledger validation or token disappearance.`);
    return { dropped:false, pending:true, pubkey:wanted, host, reason:item.dropReason || cleanString(reason,300), termination:{ tokenId, hash, resultCode:'pending-validation' } };
  }

  console.log(`AutoCluster: DROP INSTANCE starting for pre-UNL candidate ${cleanString(wanted,80)} host=${host || 'unknown'} reason=${cleanString(reason,180)}.`);
  const termination = await terminateEvernodeLeaseForCandidate(run, node, item);
  if (termination.alreadyTerminated) return await finalizePreUnlCandidateDrop(run, node, item, reason, termination);

  item.status = 'drop-termination-pending';
  item.dropReason = cleanString(reason,300);
  item.dropTokenId = termination.tokenId || null;
  item.dropTxHash = termination.hash || null;
  item.dropRequestedAtLcl = Number(run.hpContext.lclSeqNo) || null;
  item.lastError = `Lease termination submitted${termination.hash ? ` tx=${termination.hash}` : ''}; candidate retained until validated tesSUCCESS or URI token disappearance.`;
  state.nextAcquireAfterLcl = Math.max(Number(state.nextAcquireAfterLcl) || 0, (Number(run.hpContext.lclSeqNo) || 0) + 1);
  saveState(state);
  console.log(`AutoCluster: DROP INSTANCE TERMINATION SUBMITTED for ${cleanString(wanted,80)} host=${host || 'unknown'} token=${cleanString(termination.tokenId || '',32)||'unknown'} tx=${cleanString(termination.hash || '',20)||'unknown'} result=${termination.resultCode || 'submitted'}. NOT marked dropped yet; waiting for ledger finality.`);
  return { dropped:false, pending:true, pubkey:wanted, host, reason:cleanString(reason,300), termination };
}

async function dropCandidateInstance(run, pubkey, reason = 'operator-drop') {
  return await dropPreUnlCandidate(run, pubkey, reason);
}

async function candidateReadinessWatchdog(run) {
  const state = run.state;
  const now = consensusNowMs(run);
  const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
  if (!now) return false; // Never fall back to Date.now() inside consensus.
  let watches = normalizeCandidateWatchdogs(state.candidateWatchdogs);
  const managed = managedNodes(run, false);
  const acceptedReady = acceptedReadyPubkeys(state);
  const currentFreshReady = ['growing','signing','ready-to-handover'].includes(state.phase)
    ? currentCanonicalBootstrapReportingPubkeys(state, lcl)
    : freshReadyPubkeys(state, lcl);
  let changed = false;

  // Keep a watch for every materialized non-UNL candidate, even after it has once
  // produced READY. A once-good node can freeze later; old READY must not grant
  // permanent health and deadlock the bootstrap sync barrier.
  const keep = [];
  for (const w of watches) {
    const node = managed.find(n => n && n.pubkey === w.pubkey);
    if (!node || node.isUnl) {
      changed = true;
      continue;
    }
    keep.push(w);
  }
  watches = keep;

  // A replacement acquisition intentionally leaves the quiet qualification path
  // for a short period so Bootstrap A can perform one Evernode purchase. During
  // that interval the pre-UNL followers remain passive and may transiently report
  // desync/unreliable while A writes lifecycle state. Do NOT charge that elapsed
  // time against every other candidate's READY watchdog. Once either the failed
  // candidate recovers or one new materialized candidate appears, return to quiet
  // qualification with fresh watchdog clocks for all unaffected candidates.
  const replacement = normalizeBootstrapReplacement(state.bootstrapReplacement);
  if (state.phase === 'growing' && replacement) {
    const baseline = new Set(replacement.baselinePubkeys || []);
    const newCandidate = managed.find(n => n && n.pubkey && !n.isUnl && !baseline.has(n.pubkey));
    const failedRecovered = !!(replacement.failedPubkey && currentFreshReady.has(replacement.failedPubkey));
    if (newCandidate || failedRecovered) {
      for (const w of watches) {
        if (!w || w.pubkey === replacement.failedPubkey || w.stalledAt) continue;
        w.firstSeenAt = now;
        w.firstSeenLcl = lcl || null;
        w.staleSinceAt = null;
        w.staleSinceLcl = null;
        changed = true;
      }
      if (failedRecovered) {
        const failedWatch = watches.find(w => w && w.pubkey === replacement.failedPubkey);
        if (failedWatch) {
          failedWatch.staleSinceAt = null;
          failedWatch.staleSinceLcl = null;
          failedWatch.stalledAt = null;
          failedWatch.stalledAtLcl = null;
          changed = true;
        }
        const failedItem = replacement.failedHost ? hostEntry(state, replacement.failedHost) : null;
        if (failedItem && failedItem.status === 'readiness-stalled') {
          failedItem.status = 'acquired';
          failedItem.lastError = null;
          changed = true;
        }
      }
      state.bootstrapReplacement = null;
      state.candidateWatchdogs = watches;
      saveState(state);
      console.log(`AutoCluster: BOOTSTRAP REPLACEMENT cycle complete at LCL ${lcl || '?'}; ${newCandidate ? `new candidate ${cleanString(newCandidate.pubkey,80)} materialized` : `stalled candidate ${cleanString(replacement.failedPubkey,80)} recovered`}. Unaffected READY watchdog clocks were reset so acquisition time cannot cascade into false quarantines.`);
      return true;
    }
  }

  const currentUnlCount = run.clusterContext.getClusterUnlNodes().length;
  const safeReplacementUnlCount = Math.max(1, Number(state.targetManagedNodes) || 1);

  for (const node of managed) {
    if (!node || !node.pubkey || node.isUnl) continue;
    const host = normalizeHostAddress(node.host);
    const item = host ? hostEntry(state, host) : null;
    let watch = watches.find(w => w.pubkey === node.pubkey);
    if (!watch) {
      watch = {
        pubkey:cleanString(node.pubkey,256), host,
        refId:cleanString(item && item.refId || '',256) || null,
        firstSeenAt:now, firstSeenLcl:lcl || null,
        materializedAt:now, materializedAtLcl:lcl || null,
        staleSinceAt:null, staleSinceLcl:null,
        stalledAt:null, stalledAtLcl:null, kickedAt:null
      };
      watches.push(watch);
      changed = true;
      console.log(`AutoCluster: readiness watchdog started for ${cleanString(node.pubkey,80)} host=${node.host || 'unknown'} at LCL ${lcl || '?'}; READY watchdog tracks canonical sync independently; ACKNOWLEDGED is also required at admission. Candidate READY window=${(Number(state.candidateReadyTimeoutMs) || DEFAULT_CANDIDATE_READY_TIMEOUT_MS) / 60000}m; absolute admission deadline=${(Number(state.candidateAdmissionTimeoutMs) || DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS) / 60000}m; bootstrap candidate pool=${Math.max(1, Math.min(MAX_CANDIDATE_POOL_SIZE, Number(state.candidatePoolSize) || DEFAULT_CANDIDATE_POOL_SIZE))}.`);
    }
    if (!watch.firstSeenAt) { watch.firstSeenAt = now; watch.firstSeenLcl = lcl || null; changed = true; }
    if (!watch.materializedAt) { watch.materializedAt = watch.firstSeenAt || now; watch.materializedAtLcl = watch.firstSeenLcl || lcl || null; changed = true; }

    const isFresh = currentFreshReady.has(node.pubkey);
    const wasAccepted = acceptedReady.has(node.pubkey);

    // Absolute candidate lifetime: partial READY/SYNC/peer progress never resets
    // this clock. A pre-UNL VM that cannot complete admission is disposable.
    const admissionTimeoutMs = Number(state.candidateAdmissionTimeoutMs) || DEFAULT_CANDIDATE_ADMISSION_TIMEOUT_MS;
    const admissionAge = Math.max(0, now - Number(watch.materializedAt || watch.firstSeenAt || now));
    const membershipForCandidate = normalizeMembershipCommand(state.membershipCommand);
    const membershipAlreadySubmitted = !!(membershipForCandidate && membershipForCandidate.pubkey === node.pubkey && Number(membershipForCandidate.submittedAtLcl) > 0);
    const committedUnlForFinalization = normalizePubkeyList(run.clusterContext.getClusterUnlNodes().map(n => n && n.pubkey).filter(Boolean));
    const finalizationProtection = candidateFinalizationProtectionStatus(state, node, watch, lcl, now, committedUnlForFinalization, admissionTimeoutMs);
    if (finalizationProtection.changed) {
      changed = true;
      console.log(`AutoCluster: FINALIZATION GRACE ARMED for ${cleanString(node.pubkey,80)} at LCL ${lcl || '?'}: ACK=${finalizationProtection.acknowledged} READY=true SYNC=true peers=${finalizationProtection.peerCount}/${finalizationProtection.requiredPeers}; graceUntil=${finalizationProtection.graceUntilAt}. This deadline is one-shot and will not slide on later heartbeats.`);
    }
    if (admissionAge >= admissionTimeoutMs && !membershipAlreadySubmitted && finalizationProtection.graceActive) {
      console.log(`AutoCluster: ADMISSION TIMEOUT DEFERRED for ${cleanString(node.pubkey,80)} age=${Math.floor(admissionAge/1000)}s: candidate already qualified for finalization; bounded grace remains until ${finalizationProtection.graceUntilAt}.`);
    }
    if (admissionAge >= admissionTimeoutMs && !membershipAlreadySubmitted && !finalizationProtection.graceActive) {
      try {
        const drop = await dropPreUnlCandidate(run, node.pubkey, `admission-timeout after ${Math.floor(admissionAge/1000)}s (limit ${Math.floor(admissionTimeoutMs/1000)}s)`);
        console.log(`AutoCluster: ADMISSION TIMEOUT dropped ${cleanString(node.pubkey,80)} after ${Math.floor(admissionAge/1000)}s; replacement acquisition is released for the next ledger.`);
        return !!drop.dropped;
      } catch (e) {
        console.log(`AutoCluster: ADMISSION TIMEOUT could not safely drop ${cleanString(node.pubkey,80)}: ${errText(e)}. Candidate remains outside UNL and termination will retry.`);
        state.candidateWatchdogs = watches;
        if (changed) saveState(state);
        return true;
      }
    }

    // A fresh canonical proof immediately recovers a quarantined candidate and
    // cancels any stale-proof grace timer. This keeps replacement reversible if
    // the paid lease starts advancing again before retirement.
    if (isFresh) {
      if (watch.staleSinceAt || watch.staleSinceLcl || watch.stalledAt || watch.stalledAtLcl) {
        watch.staleSinceAt = null;
        watch.staleSinceLcl = null;
        watch.stalledAt = null;
        watch.stalledAtLcl = null;
        changed = true;
      }
      if (item && item.status === 'readiness-stalled') {
        item.status = 'acquired';
        item.lastError = null;
        changed = true;
        console.log(`AutoCluster: RECOVERED pre-UNL candidate ${cleanString(node.pubkey,80)} host=${host || 'unknown'} with fresh canonical READY at LCL ${lcl || '?'}. Quarantine cleared immediately.`);
      }
      continue;
    }

    // READY freshness is an ADMISSION condition, not lease health. Once a
    // candidate has successfully produced an accepted canonical READY, later
    // staleness must never quarantine it, reduce physical-pool capacity or buy a
    // replacement. It simply becomes temporarily ineligible for normal ADD_UNL
    // until a fresh proof arrives (or the operator explicitly forces one stitch).
    if (wasAccepted) {
      if (!watch.staleSinceAt) {
        watch.staleSinceAt = now;
        watch.staleSinceLcl = lcl || null;
        changed = true;
        console.log(`AutoCluster: READY freshness expired for ${cleanString(node.pubkey,80)} host=${host || 'unknown'} at LCL ${lcl || '?'}. Candidate remains materialized/usable and will NOT be quarantined or replaced; pre-freeze qualification uses durable history only; live sync + peer mesh are checked by the atomic final ADD_UNL proof after freeze.`);
      }
      // alpha47 upgrade repair: a candidate previously quarantined *only* because
      // an accepted READY became stale is immediately restored to usable capacity.
      if (watch.stalledAt || watch.stalledAtLcl) {
        watch.stalledAt = null;
        watch.stalledAtLcl = null;
        changed = true;
      }
      if (item && item.status === 'readiness-stalled') {
        item.status = 'acquired';
        item.lastError = 'Canonical READY is historically accepted but currently stale. Candidate remains materialized and usable; freshness gates normal admission only.';
        changed = true;
      }
      const replacement = normalizeBootstrapReplacement(state.bootstrapReplacement);
      if (replacement && replacement.failedPubkey === node.pubkey && replacement.reason === 'readiness-stalled') {
        state.bootstrapReplacement = null;
        changed = true;
        console.log(`AutoCluster: cancelled obsolete replacement cycle for ${cleanString(node.pubkey,80)}; stale READY no longer constitutes candidate failure.`);
      }
      continue;
    }

    if (watch.staleSinceAt || watch.staleSinceLcl) {
      watch.staleSinceAt = null;
      watch.staleSinceLcl = null;
      changed = true;
    }
    const timeoutMs = Number(state.candidateReadyTimeoutMs) || DEFAULT_CANDIDATE_READY_TIMEOUT_MS;
    const age = Math.max(0, now - Number(watch.firstSeenAt || now));
    const failureReason = 'without ever producing an accepted canonical VALIDATOR_READY';

    if (age < timeoutMs) continue;

    if (state.phase === 'growing') {
      if (!watch.stalledAt) {
        watch.stalledAt = now;
        watch.stalledAtLcl = lcl || null;
        if (item) {
          item.status = 'readiness-stalled';
          item.lastError = `Quarantined after ${Math.floor(age/1000)}s without ever producing an accepted canonical VALIDATOR_READY. EverPocket ACKNOWLEDGED alone does not satisfy initial READY health. The paid materialized instance remains outside UNL and may recover when canonical READY arrives; admission still requires ACKNOWLEDGED + READY.`;
          if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
        }
        changed = true;
        console.log(`AutoCluster: QUARANTINED never-ready pre-UNL candidate ${cleanString(node.pubkey,80)} host=${host || 'unknown'} after ${Math.floor(age/1000)}s ${failureReason}. Historical READY staleness can never enter this path; any first/fresh canonical READY clears the quarantine, and admission still requires fresh live canonical sync before freeze plus the atomic exact-tip FINAL proof at ADD_UNL.`);

        // Open exactly ONE replacement cycle. Snapshot the currently materialized
        // managed pubkeys so completion is detected by one new candidate appearing.
        // Return immediately: no second candidate may be quarantined in this same
        // execution merely because several READY timestamps expired together.
        if (!normalizeBootstrapReplacement(state.bootstrapReplacement)) {
          state.bootstrapReplacement = {
            active:true,
            failedPubkey:cleanString(node.pubkey,256),
            failedHost:host || null,
            startedAtLcl:lcl || null,
            baselinePubkeys:normalizePubkeyList(managed.filter(n => n && n.pubkey).map(n => n.pubkey)),
            reason:'readiness-stalled'
          };
          console.log(`AutoCluster: BOOTSTRAP REPLACEMENT cycle opened for ${cleanString(node.pubkey,80)} at LCL ${lcl || '?'}. Exactly one replacement capacity slot may open; all other READY watchdog ages are frozen across acquisition until quiet qualification resumes.`);
        }
        state.candidateWatchdogs = watches;
        saveState(state);
        return true;
      }

      if (watch.stalledAt && currentUnlCount >= safeReplacementUnlCount && !watch.kickedAt) {
        try { await run.clusterContext.removeNode(node.pubkey, true); }
        catch (e) {
          console.log(`AutoCluster: readiness-stalled candidate ${cleanString(node.pubkey,80)} is safe to replace but removal failed: ${errText(e)}. Will retry without touching UNL.`);
          state.candidateWatchdogs = watches;
          if (changed) saveState(state);
          return true;
        }
        watch.kickedAt = now;
        if (item) {
          item.status = 'readiness-retired';
          item.lastError = `Retired after failing current canonical VALIDATOR_READY health because the bootstrap validator set already had ${currentUnlCount} validators. This paid host will not be reacquired automatically.`;
          if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
        }
        state.candidateReadiness = normalizeCandidateReadiness(state.candidateReadiness).filter(r => r.pubkey !== node.pubkey);
        state.candidateWatchdogs = watches;
        state.waitingForHosts = false;
        saveState(state);
        console.log(`AutoCluster: RETIRED readiness-stalled candidate ${cleanString(node.pubkey,80)} host=${host || 'unknown'} after safe bootstrap UNL reached ${currentUnlCount} validator(s).`);
        return true;
      }
      continue;
    }

    if (watch.kickedAt) continue;
    try { await run.clusterContext.removeNode(node.pubkey, true); }
    catch (e) {
      console.log(`AutoCluster: readiness watchdog could not remove ${cleanString(node.pubkey,80)} after ${Math.floor(age/1000)}s without current READY: ${errText(e)}. Will retry.`);
      state.candidateWatchdogs = watches;
      if (changed) saveState(state);
      return true;
    }
    watch.kickedAt = now;
    if (item) {
      item.status = 'auto-kicked';
      item.lastError = `Auto-kicked after ${Math.floor(age/1000)}s without current canonical VALIDATOR_READY during ${state.phase || 'maintenance'}. ACKNOWLEDGED remains required for admission, while this auto-kick was triggered by missing canonical READY.`;
      if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
    }
    state.candidateReadiness = normalizeCandidateReadiness(state.candidateReadiness).filter(r => r.pubkey !== node.pubkey);
    state.candidateWatchdogs = watches;
    state.waitingForHosts = false;
    saveState(state);
    console.log(`AutoCluster: AUTO-KICKED stalled pre-UNL candidate ${cleanString(node.pubkey,80)} host=${host || 'unknown'} after ${Math.floor(age/1000)}s without current canonical VALIDATOR_READY during ${state.phase || 'maintenance'}.`);
    return true;
  }

  state.candidateWatchdogs = normalizeCandidateWatchdogs(watches);
  if (changed) saveState(state);
  return false;
}

function recoverCompletedAcquisitions(run) {
  if (!run || !run.state || !run.clusterContext || !run.evernodeContext) return 0;
  const state = run.state;
  const manager = run.clusterContext.clusterManager;
  if (!manager || typeof manager.addPending !== 'function') return 0;
  const nodes = run.clusterContext.getClusterNodes();
  const pending = run.clusterContext.getPendingNodes();
  const acquired = typeof run.evernodeContext.getAcquiredNodes === 'function' ? run.evernodeContext.getAcquiredNodes() : [];
  let recovered = 0, stateChanged = false;
  for (const item of state.hostQueue) {
    // Pending-watchdog failures and safely retired maturity candidates are final.
    // Legacy maturity-only quarantine is reopened by normalizeHostQueue(); final
    // readiness-retired/auto-kicked records remain terminal.
    if (item && ['auto-kicked','maturity-retired','readiness-retired'].includes(item.status)) continue;
    if (!item || !item.address || nodes.some(n => n && n.host === item.address)) continue;
    const done = acquired.find(a => a && ((item.refId && a.refId === item.refId) || a.host === item.address));
    if (!done || !(done.refId || done.acquireRefId)) continue;
    if (!done.refId && done.acquireRefId) done.refId = done.acquireRefId;
    const nativeSummary = safeAcquireRecordSummary(done);
    if (item.nativeStage !== 'acquire-success-observed' && item.nativeStage !== 'cluster-pending-candidate' && item.nativeStage !== 'materialized') {
      item.nativeStage = 'acquire-success-observed';
      item.nativeStageAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
      item.acquireSuccessAtLcl = item.acquireSuccessAtLcl || item.nativeStageAtLcl;
      item.acquireSuccessPubkey = nativeSummary && nativeSummary.pubkey || null;
      item.acquireSuccessDomain = nativeSummary && nativeSummary.domain || null;
      item.acquireSuccessUserPort = nativeSummary && nativeSummary.userPort || null;
      item.acquireSuccessPeerPort = nativeSummary && nativeSummary.peerPort || null;
      item.acquireSuccessName = nativeSummary && nativeSummary.name || null;
      item.acquireSuccessContractId = nativeSummary && nativeSummary.contractId || null;
      stateChanged = true;
      console.log(`AutoCluster: ACQUIRE_SUCCESS_OBSERVED host=${item.address} refId=${done.refId} instance(pubkey=${nativeSummary && nativeSummary.pubkey || 'missing'},domain=${nativeSummary && nativeSummary.domain || 'missing'},user=${nativeSummary && nativeSummary.userPort || 'missing'},peer=${nativeSummary && nativeSummary.peerPort || 'missing'},name=${nativeSummary && nativeSummary.name || 'missing'},contract=${nativeSummary && nativeSummary.contractId || 'missing'}) recordKeys=[${nativeSummary ? nativeSummary.recordKeys.join(',') : ''}] instanceKeys=[${nativeSummary ? nativeSummary.instanceKeys.join(',') : ''}]. EverPocket has processed the native host response; contract-side endpoint liveness is NOT a gate. Candidate materialization and canonical READY are next.`);
    }
    const alreadyPending = pending.some(n => n && n.refId === done.refId);
    if (!alreadyPending) {
      manager.addPending({
        host: item.address,
        refId: done.refId,
        targetLifeMoments: Math.max(1, state.lifeIncrMomentMinLimit),
        maxLifeMoments: state.maxLifeMomentLimit || 0,
        aliveCheckCount: 0
      });
      recovered++;
      item.nativeStage = 'cluster-pending-candidate'; item.nativeStageAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
      console.log(`AutoCluster: recovered native AcquireSuccess ${done.refId} for ${item.address} into deterministic cluster pending state. Contract-side endpoint liveness is bypassed; canonical READY will prove the candidate actually runs before UNL admission.`);
    }
    if (item.status !== 'pending' || item.refId !== done.refId || item.lastError) {
      item.status = 'pending';
      item.pendingSinceAt = item.pendingSinceAt || consensusNowMs(run) || null;
      item.refId = cleanString(done.refId, 256);
      item.lastError = null;
      stateChanged = true;
    }
    if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; stateChanged = true; }
  }
  if (stateChanged) saveState(state);
  return recovered;
}

function reconcileHostQueue(run) {
  const state = run.state;
  const now = consensusNowMs(run);
  const nodes = run.clusterContext.getClusterNodes();
  const pending = run.clusterContext.getPendingNodes();
  const acquired = typeof run.evernodeContext.getAcquiredNodes === 'function' ? run.evernodeContext.getAcquiredNodes() : [];
  const queuedOps = run.clusterContext.addNodeQueueCount();
  let changed = false;
  for (const item of state.hostQueue) {
    // Pending-watchdog auto-kicks and safely retired maturity candidates are final.
    if (['auto-kicked','maturity-retired','readiness-retired'].includes(item.status)) {
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }
    const presentNode = nodes.find(n => n && n.host === item.address) || null;
    if (presentNode) {
      const stalledWatch = normalizeCandidateWatchdogs(state.candidateWatchdogs).find(w => w.pubkey === presentNode.pubkey && w.stalledAt && !w.kickedAt);
      const desiredStatus = stalledWatch ? 'readiness-stalled' : 'acquired';
      const firstMaterialized = !['acquired','readiness-stalled'].includes(item.status);
      if (item.status !== desiredStatus || item.pendingSinceAt || item.pendingSinceLcl) { item.status = desiredStatus; item.pendingSinceAt = null; item.pendingSinceLcl = null; if (!stalledWatch) item.lastError = null; changed = true; }
      if (firstMaterialized) {
        const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
        item.nativeStage = 'materialized'; item.nativeStageAtLcl = lcl || null;
        changed = true;
        if (state.phase === 'growing' && currentUnlPubkeys(run).length === 1 && currentUnlPubkeys(run).includes(state.bootstrapPubkey)) {
          state.nextAcquireAfterLcl = null;
          console.log(`AutoCluster: lease for ${item.address} materialized; singleton acquisition remains immediately open. Provisioning/READY does not pace the next lease purchase.`);
        } else {
          state.nextAcquireAfterLcl = Math.max(Number(state.nextAcquireAfterLcl) || 0, lcl + ACQUISITION_SETTLE_CLEAN_LEDGERS);
        }
      }
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }

    // provisioning-stalled is a durable quarantine state. EverPocket can keep
    // the original pending acquire in cluster.pendingNodes after our watchdog
    // deadline; that stale library row must NOT resurrect the hostQueue item to
    // `pending` every ledger or it will be quarantined again forever. A genuine
    // late instance response is still recovered by recoverCompletedAcquisitions()
    // in begin(), and a real cluster node above immediately becomes acquired.
    if (item.status === 'provisioning-stalled') {
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }

    if (pending.some(n => n && n.host === item.address)) {
      if (item.status !== 'pending') { item.status = 'pending'; changed = true; }
      if (!item.pendingSinceAt && now) { item.pendingSinceAt = now; changed = true; }
      if (!item.pendingSinceLcl) { item.pendingSinceLcl = Number(item.lastAttemptLcl) || Number(run.hpContext && run.hpContext.lclSeqNo) || null; changed = true; }
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }
    const completed = acquired.find(a => a && ((item.refId && a.refId === item.refId) || a.host === item.address));
    if (completed) {
      // A lease has already been purchased and decrypted. Never classify this
      // as an acquisition failure merely because EverPocket dropped its
      // cluster.pendingNodes entry after a liveness problem; recovery will put
      // the same refId back into pending instead of buying a second lease.
      if (item.status !== 'pending' || item.refId !== completed.refId) {
        item.status = 'pending'; item.pendingSinceAt = item.pendingSinceAt || now || null; item.pendingSinceLcl = item.pendingSinceLcl || Number(item.lastAttemptLcl) || Number(run.hpContext && run.hpContext.lclSeqNo) || null; item.refId = cleanString(completed.refId, 256); item.lastError = null; changed = true;
      }
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }
    if (item.status === 'provisioning-stalled') {
      // Late-recoverable paid/accepted lease. Do not repurchase it and do not
      // let it block another queued host. recoverCompletedAcquisitions() will
      // revive it if EverPocket later records the instance response.
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
      continue;
    }
    if (item.status === 'queued' && state.activeHostAttempt === item.address && item.nativeStage === 'operation-queued' && queuedOps === 0) {
      // This is NOT an acquisition attempt yet. It only means we asked
      // ClusterContext to enqueue one. If that queue entry disappears before
      // acquireNode() starts, safely release the scheduling token and enqueue the
      // same host again later. UI stays `queued`; `attempting` is reserved for the
      // actual awaited acquireNode() call below.
      const currentLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
      const queuedAt = Number(item.nativeStageAtLcl) || currentLcl;
      if (Math.max(0, currentLcl - queuedAt) >= ACQUIRE_OPERATION_QUEUE_RETRY_LCL) {
        state.activeHostAttempt = null;
        item.nativeStage = 'operation-queue-retry';
        item.nativeStageAtLcl = currentLcl || null;
        changed = true;
        console.log(`AutoCluster: acquisition operation queue entry for ${item.address} disappeared before acquireNode() started; safely re-queueing the SAME host. No acquisition attempt was counted and no purchase result was inferred.`);
      }
    } else if (item.status === 'attempting' && state.activeHostAttempt === item.address && queuedOps === 0) {
      // Do not infer anything from ledger age or transient queue visibility.
      // `attempting` means the real acquireNode() call started. Only that awaited
      // call's success/failure path may leave this state. If the process itself
      // dies mid-call, HotPocket rolls the execution back rather than committing
      // a synthetic queued/failed transition here.
      if (item.nativeStage !== 'acquire-call-in-flight') {
        item.nativeStage = 'acquire-call-in-flight';
        item.nativeStageAtLcl = Number(item.lastAttemptLcl) || Number(run.hpContext && run.hpContext.lclSeqNo) || null;
        changed = true;
      }
    } else if (item.status === 'pending' && !pending.some(n => n && n.host === item.address)) {
      // EverPocket's cluster pending view is ephemeral. Its disappearance is not
      // an error and is never a purchase/admission signal. The durable refId plus
      // Xahau finality and native AcquireSuccess/AcquireError own this lifecycle.
      if (item.lastError && /^EverPocket transient pending view is absent/i.test(String(item.lastError))) {
        item.lastError = null;
        changed = true;
      }
      if (state.activeHostAttempt === item.address) { state.activeHostAttempt = null; changed = true; }
    }
  }
  if (changed) saveState(state);
}

function bootstrapPaidLeaseRecoveryBudget(state, stalledManaged = []) {
  const target = Math.max(1, Number(state && state.targetManagedNodes) || 1);
  const poolBudget = Math.max(1, Math.min(MAX_CANDIDATE_POOL_SIZE, Number(state && state.candidatePoolSize) || DEFAULT_CANDIDATE_POOL_SIZE));
  const debtHosts = new Set();

  // Materialized pre-UNL candidates already quarantined by the READY watchdog are
  // paid capacity that cannot currently satisfy targetManagedNodes. Count them once.
  for (const n of Array.isArray(stalledManaged) ? stalledManaged : []) {
    if (!n) continue;
    const host = normalizeHostAddress(n.host);
    if (host) debtHosts.add(host);
    else if (n.pubkey) debtHosts.add(`pubkey:${String(n.pubkey).toLowerCase()}`);
  }

  // A provisioning-stalled row has a validated/possibly-paid acquisition but no
  // native AcquireSuccess yet. Keep its late-recovery identity, but immediately
  // open one bounded replacement slot. readiness-stalled is included as a durable
  // fallback in case the watchdog object and hostQueue are observed in different
  // reconciliation phases. The Set prevents double-counting the same host.
  for (const h of state && Array.isArray(state.hostQueue) ? state.hostQueue : []) {
    if (!h || !['provisioning-stalled','readiness-stalled'].includes(h.status)) continue;
    const host = normalizeHostAddress(h.address);
    if (host) debtHosts.add(host);
  }

  const recoveryDebt = debtHosts.size;
  const overflowAllowance = Math.min(poolBudget, recoveryDebt);
  return { target, poolBudget, recoveryDebt, overflowAllowance, hardLeaseCap:target + overflowAllowance };
}


function prepareDirectSingletonAcquireMode(run) {
  const state = run && run.state;
  const clusterContext = run && run.clusterContext;
  if (!state || !clusterContext || state.phase !== 'growing') return false;
  const committedUnl = currentUnlPubkeys(run);
  const singleton = committedUnl.length === 1 && committedUnl.includes(state.bootstrapPubkey);
  if (!singleton) return false;

  // EverPocket's addNewClusterNode() only appends an ADD_NODE operation. Its
  // private operation processor may postpone that operation whenever an older
  // pending node needs an aliveness check. During Bootstrap-A-only fleet fill
  // that creates a head-of-line deadlock: a later host sits "queued for acquire"
  // with attempts=0 even though purchasing the next lease is safe.
  //
  // In singleton bootstrap we execute the exact ADD_NODE body directly instead,
  // so no deferred ADD_NODE operation should survive in operations.json.
  const operationData = clusterContext.operationData;
  if (operationData && Array.isArray(operationData.operations)) {
    const before = operationData.operations.length;
    operationData.operations = operationData.operations.filter(op => !(op && op.data && op.data.acquireOptions));
    if (operationData.operations.length !== before) {
      clusterContext.updatedData = true;
      console.log(`AutoCluster: DIRECT BOOTSTRAP ACQUIRE cleared ${before - operationData.operations.length} deferred EverPocket ADD_NODE operation(s); singleton purchases execute acquireNode() inline instead of waiting behind pending-node liveness work.`);
    }
  }

  let changed = false;
  for (const item of state.hostQueue || []) {
    if (!item || item.status !== 'queued' || item.nativeStage !== 'operation-queued') continue;
    item.nativeStage = 'direct-bootstrap-ready';
    item.nativeStageAtLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || null;
    if (state.activeHostAttempt === item.address) state.activeHostAttempt = null;
    changed = true;
  }
  if (changed) saveState(state);
  return true;
}

async function directSingletonAcquireAndRecord(run, hostItem, lifeMoments, acquireOptions) {
  const clusterContext = run.clusterContext;
  const hpconfig = await clusterContext.hpContext.getContractConfig();
  const suppliedInstance = (acquireOptions && acquireOptions.instanceCfg) || {};
  const suppliedConfig = suppliedInstance.config || {};
  const suppliedContract = suppliedConfig.contract || {};
  const suppliedConsensus = suppliedContract.consensus || {};
  const suppliedMesh = suppliedConfig.mesh || {};
  const suppliedDiscovery = suppliedMesh.peer_discovery || {};
  const unl = Array.isArray(hpconfig && hpconfig.unl) ? hpconfig.unl.slice().sort().slice(0, 1) : [];

  // Mirror everpocket-nodejs-contract 0.1.6 ClusterContext.addNewClusterNode()
  // option normalization, then execute the body that its deferred ADD_NODE
  // processor would execute on a later ledger.
  const options = {
    ...(acquireOptions || {}),
    instanceCfg: {
      ...suppliedInstance,
      ownerPubkey: suppliedInstance.ownerPubkey || 'dummy_owner_pubkey',
      image: suppliedInstance.image || 'evernodedev/sashimono:hp.0.6.4-ubt.20.04-njs.20',
      contractId: clusterContext.hpContext.contractId,
      config: {
        ...suppliedConfig,
        contract: {
          ...suppliedContract,
          unl,
          consensus: {
            ...suppliedConsensus,
            roundtime: hpconfig && hpconfig.consensus && hpconfig.consensus.roundtime,
            stage_slice: hpconfig && hpconfig.consensus && hpconfig.consensus.stage_slice
          }
        },
        mesh: {
          ...suppliedMesh,
          peer_discovery: {
            enabled: false,
            interval: suppliedDiscovery.interval || 30000
          },
          // Preserve stock EverPocket ADD_NODE normalization. Explicit known_peers
          // remain present; AutoCluster's later peer reconciliation builds the mesh.
          msg_forwarding: false
        }
      }
    }
  };

  const acquire = await run.evernodeContext.acquireNode(options);
  if (!acquire || !acquire.refId) throw new Error(`DIRECT_BOOTSTRAP_ACQUIRE_NO_REF: acquireNode(${hostItem && hostItem.address || 'unknown'}) returned no pending reference.`);
  acquire.targetLifeMoments = lifeMoments;
  acquire.maxLifeMoments = Number(run.state.maxLifeMomentLimit) || 0;
  acquire.aliveCheckCount = 0;

  // TypeScript `private` compiles to a normal property in the pinned EverPocket
  // package. Use the same ClusterManager.addPending() call as #processOperations().
  const manager = clusterContext.clusterManager;
  if (!manager || typeof manager.addPending !== 'function') {
    throw new Error('DIRECT_BOOTSTRAP_CLUSTER_MANAGER_UNAVAILABLE: purchased lease cannot be recorded safely.');
  }
  manager.addPending(acquire);
  console.log(`AutoCluster: DIRECT BOOTSTRAP ACQUIRE RECORDED host=${hostItem.address} refId=${cleanString(acquire.refId,256)}; ClusterManager.pendingNodes now owns provisioning while the next purchase may start on a later ledger.`);
  return acquire;
}

async function growFromHostQueue(run, targetCount) {
  const state = run.state;
  const singletonDirectAcquire = prepareDirectSingletonAcquireMode(run);
  reconcileHostQueue(run);
  const totalCount = run.clusterContext.totalCount();
  const queueCount = run.clusterContext.addNodeQueueCount();
  // Only queue operations that still have an active durable hostQueue attempt are
  // allowed to reserve growth capacity. A stale EverPocket add-node queue entry
  // left behind by a quarantined acquisition must not block replacement forever.
  const activeAttemptCount = state.hostQueue.filter(h => h && (
    h.status === 'attempting' ||
    (h.status === 'queued' && h.nativeStage === 'operation-queued' && state.activeHostAttempt === h.address)
  )).length;
  const effectiveQueueCount = Math.min(Math.max(0, Number(queueCount) || 0), activeAttemptCount);
  const stalledPubkeys = new Set(normalizeCandidateWatchdogs(state.candidateWatchdogs)
    .filter(w => w && w.stalledAt && !w.kickedAt)
    .map(w => w.pubkey));
  const stalledManaged = managedNodes(run, false).filter(n => n && !n.isUnl && stalledPubkeys.has(n.pubkey));
  const clusterHosts = new Set(run.clusterContext.getClusterNodes().filter(Boolean).map(n => n.host).filter(Boolean));
  const quarantinedPendingHosts = new Set(state.hostQueue
    .filter(h => h && h.status === 'provisioning-stalled')
    .map(h => h.address));
  const pendingNodes = run.clusterContext.getPendingNodes().filter(Boolean);
  const quarantinedPendingCount = pendingNodes
    .filter(n => n && n.host && quarantinedPendingHosts.has(n.host) && !clusterHosts.has(n.host)).length;
  const activeBootstrapPending = state.phase === 'growing'
    ? pendingNodes.filter(n => n && n.host && !quarantinedPendingHosts.has(n.host) && !clusterHosts.has(n.host)).length
    : 0;
  // BOUNDED PAID-LEASE RECOVERY CAP. The final healthy target is still
  // targetManagedNodes, but a quarantined paid lease must not permanently consume
  // the very capacity needed to replace it. Open one temporary paid slot per known
  // provisioning/readiness failure, bounded by candidatePoolSize. This is NOT a
  // speculative spare pool: with zero recovery debt the hard cap remains exactly
  // targetManagedNodes. Late AcquireSuccess/READY recovery shrinks the allowance
  // automatically, and surplus materialized candidates are retired before handover.
  if (state.phase === 'growing') {
    const paidManagedHosts = new Set();
    for (const n of managedNodes(run, false)) {
      const host = normalizeHostAddress(n && n.host);
      if (host) paidManagedHosts.add(host);
      else if (n && n.pubkey) paidManagedHosts.add(`pubkey:${String(n.pubkey).toLowerCase()}`);
    }
    for (const h of state.hostQueue || []) {
      if (!h || !['attempting','pending','provisioning-stalled','acquired'].includes(h.status)) continue;
      const host = normalizeHostAddress(h.address);
      if (host) paidManagedHosts.add(host);
    }
    const recoveryBudget = bootstrapPaidLeaseRecoveryBudget(state, stalledManaged);
    if (paidManagedHosts.size >= recoveryBudget.hardLeaseCap) {
      console.log(`AutoCluster: BOUNDED MANAGED LEASE CAP ${paidManagedHosts.size}/${recoveryBudget.hardLeaseCap} (target=${recoveryBudget.target}, recoveryDebt=${recoveryBudget.recoveryDebt}, overflow=${recoveryBudget.overflowAllowance}/${recoveryBudget.poolBudget}); no further Evernode purchase is permitted until a quarantined lease recovers/retires or another paid slot is released.`);
      return false;
    }
    if (recoveryBudget.overflowAllowance > 0 && paidManagedHosts.size >= recoveryBudget.target) {
      console.log(`AutoCluster: RECOVERY LEASE OVERFLOW ${paidManagedHosts.size}/${recoveryBudget.hardLeaseCap}: ${recoveryBudget.recoveryDebt} quarantined paid lease(s) open ${recoveryBudget.overflowAllowance} bounded replacement slot(s) beyond healthy target ${recoveryBudget.target}. Late recovery remains tracked and any surplus materialized candidate will be retired before handover.`);
    }
  }
  // ClusterContext.totalCount() includes both cluster nodes and pending nodes.
  // During fresh bootstrap, unresolved provisioning does NOT satisfy capacity:
  // only materialized instances count toward the managed acquisition target.
  // We still bound unresolved paid acquisitions separately below so one slow host
  // cannot freeze the queue and a burst cannot create unlimited paid extras.
  // Two-stage bootstrap capacity model:
  //   1) ACQUIRE the full physical managed pool first. READY never blocks these
  //      initial purchases; even a materialized candidate already marked
  //      readiness-stalled still counts as one of the initially acquired leases.
  //   2) QUALIFY the acquired pool. Once the initial physical pool exists,
  //      readiness-stalled/provisioning-stalled candidates stop counting toward
  //      effective capacity, so replacement leases are purchased until enough
  //      healthy candidates remain.
  // This deliberately decouples Evernode acquisition from HotPocket readiness.
  const materializedManagedCount = managedNodes(run, false).length;
  const initialManagedTarget = state.phase === 'growing'
    ? Math.max(1, Number(state.targetManagedNodes) || 1)
    : 0;
  const initialPhysicalPoolComplete = state.phase === 'growing' && materializedManagedCount >= initialManagedTarget;
  const stalledCapacityPenalty = (state.phase === 'growing' && !initialPhysicalPoolComplete) ? 0 : stalledManaged.length;
  const effectiveTotalCount = Math.max(0, totalCount - stalledCapacityPenalty - quarantinedPendingCount - activeBootstrapPending);
  if (targetCount <= (effectiveTotalCount + effectiveQueueCount)) return false;

  if (state.phase === 'growing' && !initialPhysicalPoolComplete) {
    console.log(`AutoCluster: BOOTSTRAP ACQUIRE phase ${materializedManagedCount}/${initialManagedTarget} managed lease(s) materialized; READY does not gate initial lease purchases. ${stalledManaged.length} candidate(s) may already be marked bad, but replacements and later purchases continue independently; validator admission begins only after the full healthy upfront fleet exists.`);
  } else if (stalledManaged.length || quarantinedPendingCount) {
    const replacement = normalizeBootstrapReplacement(state.bootstrapReplacement);
    console.log(`AutoCluster: BOOTSTRAP REPLACE capacity open: ${totalCount} raw node/pending slot(s), ${stalledManaged.length} readiness-stalled, ${quarantinedPendingCount} provisioning-stalled pending, ${activeBootstrapPending} unresolved bootstrap pending excluded from capacity, ${effectiveTotalCount}/${targetCount} effective instance(s). ${replacement ? `Controlled replacement cycle active for ${cleanString(replacement.failedPubkey,80)}; READY watchdog ages for unaffected candidates are frozen until one replacement materializes.` : 'Bad candidates no longer consume qualified capacity.'}`);
  }

  const currentLcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;

  const nextAcquireAfterLcl = Number(state.nextAcquireAfterLcl) || 0;
  if (nextAcquireAfterLcl && currentLcl < nextAcquireAfterLcl) {
    console.log(`AutoCluster: acquisition pacing fence active at LCL ${currentLcl}; next lease purchase allowed at LCL ${nextAcquireAfterLcl}. Existing candidates continue READY synchronization in parallel.`);
    return false;
  }
  if (nextAcquireAfterLcl && currentLcl >= nextAcquireAfterLcl) {
    state.nextAcquireAfterLcl = null;
    saveState(state);
  }

  if (state.phase === 'growing') {
    const materializedHostsForTxFence = new Set(run.clusterContext.getClusterNodes().filter(Boolean).map(n => normalizeHostAddress(n.host)).filter(Boolean));
    const unresolvedNativeResponses = unresolvedNativeAcquireResponses(state, run.xrplContext, run.evernodeContext, materializedHostsForTxFence);
    if (unresolvedNativeResponses.length > 0) {
      console.log(`AutoCluster: BOOTSTRAP ACQUIRE TX FINALITY at LCL ${currentLcl || '?'}: previous Xahau acquisition transaction has not reached ledger finality yet (${unresolvedNativeResponses.map(h=>`${cleanString(h.address,48)}:${h.nativeStage||h.status}`).join(',')}). This is the only purchase-serialization fence; native Evernode provisioning is asynchronous after validation.`);
      return false;
    }
  }

  if (state.phase === 'growing' || !state.parallelGrow) {
    // Serialize only the irreversible Xahau acquisition transaction until it reaches
    // ledger finality. Native host provisioning then overlaps with later purchases;
    // bootstrap does NOT serialize initial growth on candidate READY. Bootstrap first
    // fills the bounded physical lease pool; readiness then classifies candidates as
    // qualified or replaceable. EverPocket maturity does not block continued lease acquisition, but UNL admission
    // requires shared ACKNOWLEDGED plus canonical READY proof in prepareCandidatePromotionGate().
    //
    // IMPORTANT: EverPocket may retain a pendingNodes row indefinitely after a
    // provisioning attempt has been quarantined as provisioning-stalled. Ignore
    // only those explicitly quarantined rows here; otherwise one dead host can
    // permanently serialize the queue even though our durable hostQueue has
    // already opened a replacement slot.
    const blockingPendingNodes = pendingNodes
      .filter(n => n && !quarantinedPendingHosts.has(n.host));
    if (state.phase === 'growing') {
      // The transaction-finality fence above prevents sequence races. Once the prior
      // purchase validates, its native AcquireSuccess may arrive minutes later without
      // blocking this pipeline. During A-only fleet fill, candidatePoolSize must not
      // stop purchase #5 when the configured speculative pool is only 4: the physical
      // managed target itself is the minimum provisioning concurrency budget.
      if (effectiveQueueCount > 0 || state.hostQueue.some(h => h && h.status === 'attempting')) return false;
      const durablePendingCount = state.hostQueue.filter(h => h && h.status === 'pending').length;
      const unresolvedPendingCount = Math.max(blockingPendingNodes.length, durablePendingCount);
      const configuredPool = Number(state.candidatePoolSize) || DEFAULT_CANDIDATE_POOL_SIZE;
      const singletonFleetTarget = singletonDirectAcquire ? Math.max(1, Number(state.targetManagedNodes) || 1) : 1;
      const pendingCap = Math.max(1, Math.min(BOOTSTRAP_MAX_CONCURRENT_PENDING, Math.max(configuredPool, singletonFleetTarget)));
      if (unresolvedPendingCount >= pendingCap) {
        console.log(`AutoCluster: bootstrap provisioning pool cap ${unresolvedPendingCount}/${pendingCap}; purchase submission pauses while those leases provision. In singleton fleet-fill this cap is never below targetManagedNodes, so candidatePoolSize cannot block the fifth purchase.`);
        return false;
      }
    } else {
      if (blockingPendingNodes.length > 0 || effectiveQueueCount > 0) return false;
      // Outside fresh bootstrap, preserve conservative serialization.
      if (state.hostQueue.some(h => h && ['attempting','pending'].includes(h.status))) return false;
    }
    // Do not wait for EverPocket ACKNOWLEDGED before purchasing later leases. The bounded
    // physical pool keeps building while candidates independently complete native
    // maturity and canonical READY; both are required only at UNL admission.
    const quarantined = managedNodes(run, false).filter(n => n && !n.isUnl && stalledPubkeys.has(n.pubkey));
    if (quarantined.length) console.log(`AutoCluster: ${quarantined.length} readiness-stalled candidate(s) are quarantined outside UNL and do not block acquiring the remaining target leases.`);
  }
  if (state.hostQueue.some(h => h.status === 'attempting')) return false;
  // A ClusterContext add-node operation may be scheduled one ledger before the
  // real acquireNode() call starts. Keep that scheduling token serialized too;
  // reconcileHostQueue() safely releases it only if the operation queue entry
  // truly disappears before acquireNode() begins.
  if (state.hostQueue.some(h => h && h.status === 'queued' && h.nativeStage === 'operation-queued' && state.activeHostAttempt === h.address)) return false;

  // Funding errors are global treasury failures, not host failures. Do not
  // burn through the rest of the queue while the wallet is underfunded; retry
  // the same host periodically so topping up can resume without a button click.
  const fundingWait = state.hostQueue.find(h => h.status === 'funding-wait');
  let next = null;
  if (fundingWait) {
    const last = Number(fundingWait.lastAttemptLcl || 0);
    if (run.hpContext.lclSeqNo - last < 3) return false;
    next = fundingWait;
  } else {
    const queued = state.hostQueue.filter(h => h && h.status === 'queued');
    // A host gets a burst of real acquireNode() attempts before rotation. A burst
    // retry outranks untouched hosts, so a momentary RPC failure gets a fair chance.
    // Only after ACQUIRE_TRANSIENT_BURST_ATTEMPTS genuine failures do untouched
    // hosts move ahead; the failed host remains queued and comes back after cooldown.
    const burstRetry = queued.find(h => h.nativeStage === 'transient-retry' && currentLcl >= Number(h.retryAfterLcl || 0));
    const burstWaiting = queued.find(h => h.nativeStage === 'transient-retry' && currentLcl < Number(h.retryAfterLcl || 0));
    if (burstWaiting && !burstRetry) {
      console.log(`AutoCluster: patient acquire retry for ${burstWaiting.address}; waiting until LCL ${Number(burstWaiting.retryAfterLcl)||'?'} before the next REAL acquireNode() call (${Number(burstWaiting.transientFailureStreak||0)}/${ACQUIRE_TRANSIENT_BURST_ATTEMPTS} transient failures in this burst).`);
      return false;
    }
    const untouched = queued.find(h => Number(h.attempts || 0) === 0 && h.nativeStage !== 'operation-queued');
    const ordinary = queued.find(h => !['transient-retry','transient-rotated','operation-queued'].includes(h.nativeStage));
    const cooledRetry = queued.find(h => h.nativeStage === 'transient-rotated' && currentLcl >= Number(h.retryAfterLcl || 0));
    next = burstRetry || untouched || ordinary || cooledRetry || null;
    if (!next && queued.some(h => h.nativeStage === 'transient-rotated')) {
      const waits = queued.filter(h => h.nativeStage === 'transient-rotated').map(h => Math.max(0, Number(h.retryAfterLcl || currentLcl) - currentLcl));
      const waitLcl = waits.length ? Math.min(...waits) : ACQUIRE_TRANSIENT_ROTATE_COOLDOWN_LCL;
      console.log(`AutoCluster: all currently eligible hosts have had a fair acquisition chance; oldest rotated transient failure retries in about ${waitLcl} committed ledger(s).`);
      return false;
    }
  }
  if (!next) {
    if (!state.waitingForHosts) {
      state.waitingForHosts = true;
      saveState(state);
      console.log(`AutoCluster: target ${targetCount} has not been reached and the host queue is empty. Add more Evernode host r-addresses.`);
    }
    return false;
  }

  // Crucial: pass `host` explicitly. EverPocket's acquireNode() then skips
  // decideHost()/getActiveHostsFromLedger() and freshly queries this exact
  // host's lease offers before preparing the acquisition transaction. The
  // discovery API is never trusted for lease availability or transaction data.
  const lifeMoments = Math.max(1, state.lifeIncrMomentMinLimit);
  const committedUnl = currentUnlPubkeys(run);
  const singletonFollowerBootstrap = state.phase === 'growing' && committedUnl.length === 1 && committedUnl.includes(state.bootstrapPubkey);
  const syncUnl = singletonFollowerBootstrap ? [state.bootstrapPubkey] : committedUnl;
  const syncPeers = availableUnlSyncPeers(run);
  const acquireOptions = {
    host: next.address,
    instanceCfg: {
      image: state.managedImage,
      config: {
        node: { role: 'validator' },
        contract: syncUnl.length ? { unl: syncUnl, npl: { mode: 'public' }, consensus: { mode: 'public' } } : { npl: { mode: 'public' }, consensus: { mode: 'public' } },
        mesh: {
          peer_discovery: { enabled: false, interval: 10000 },
          msg_forwarding: true,
          ...(syncPeers.length ? { known_peers: syncPeers } : {})
        }
      }
    }
  };

  state.waitingForHosts = false;
  next.lastError = null;
  if (singletonDirectAcquire) {
    // Do NOT queue ClusterContext.ADD_NODE during Bootstrap-A-only fleet fill.
    // Its processor intentionally skips operations on ledgers where a pending
    // node needed an aliveness check, which can leave the next host at
    // "queued for acquire / attempts 0" indefinitely. Execute the exact stock
    // ADD_NODE body now: acquireNode() -> ClusterManager.addPending(). The
    // acquireNode wrapper is still the only code that marks ATTEMPTING/counts
    // a real attempt, and its return releases the next purchase for a later ledger.
    next.status = 'queued';
    next.nativeStage = 'direct-bootstrap-ready';
    next.nativeStageAtLcl = run.hpContext.lclSeqNo;
    state.activeHostAttempt = null;
    saveState(state);
    console.log(`AutoCluster: DIRECT BOOTSTRAP ACQUIRE host=${next.address}; invoking the real acquireNode() now instead of enqueueing EverPocket ADD_NODE. attempts remains ${Number(next.attempts||0)} until the wrapper enters the actual call.`);
    try {
      await directSingletonAcquireAndRecord(run, next, lifeMoments, acquireOptions);
    } catch (e) {
      // The acquireNode wrapper already classified/requeued/failed the durable
      // host item. Do not abort the contract ledger just because this host failed.
      console.log(`AutoCluster: DIRECT BOOTSTRAP ACQUIRE host=${next.address} completed with failure classification=${next.status}: ${errText(e)}`);
      return false;
    }
  } else {
    // Outside singleton fleet fill preserve stock EverPocket's deferred operation
    // queue semantics.
    next.status = 'queued';
    next.nativeStage = 'operation-queued';
    next.nativeStageAtLcl = run.hpContext.lclSeqNo;
    state.activeHostAttempt = next.address;
    saveState(state);
    console.log(`AutoCluster: scheduling EverPocket acquisition operation for explicit host ${next.address}; actual attempt count remains ${Number(next.attempts||0)} until acquireNode() really starts.`);
    await run.clusterContext.addNewClusterNode(state.maxLifeMomentLimit || 0, lifeMoments, acquireOptions);
  }
  if (syncPeers.length) console.log(`AutoCluster: acquisition config seeded ${syncPeers.length} trusted UNL endpoint(s), trusted UNL=[${syncUnl.join(',')}] for ${next.address}: ${syncPeers.join(', ')}. Full-mesh reconciliation occurs before MATURED and after membership changes.`);
  else console.log(`AutoCluster: WARNING no UNL peer endpoint was available to seed for ${next.address}; readiness watchdog will quarantine the candidate if it cannot synchronize; healthy candidates may continue clustering.`);
  return true;
}

async function tick(run) {
  if (!run) return;
  // Autonomous/legacy transitions may still own an execution. Streaming bootstrap
  // transitions are membership-only proof markers: reconcilePromotionTransition()
  // returns false for them so lifecycle/acquisition/admin work keeps running.
  if (await reconcilePromotionTransition(run)) return;
  const state = run.state;

  // Read requests never enter AutoCluster.begin(). Keep this guard as a safety
  // boundary: shared lifecycle changes only happen in normal consensus executions.
  if (run.ctx.readonly) return;

  // alpha53.34 SLIM IDLE FENCE: processInputs() has already had a chance to run.
  // This execution deliberately owns no EverPocket/Xahau lifecycle context and
  // therefore performs zero lifecycle/state work in tick().
  if (run.lightweightIdleFence) return;

  // LOCKSTEP MAINTENANCE ESCAPE. This branch is reachable only on Bootstrap A
  // after every copy deterministically cleared pre-maintenance READY/SYNC evidence
  // in begin(). Do exactly ONE external lifecycle action, then stop. The non-UNL
  // observers remain fenced and will HPFS-catch A before qualification resumes.
  if (run.bootstrapMaintenanceMode) {
    const mode = run.bootstrapMaintenanceMode;
    if (!run.localIsUnl || run.hpContext.publicKey !== state.bootstrapPubkey) return;
    if (mode.type === 'drop') {
      try {
        const out = await dropPreUnlCandidate(run, mode.pubkey, `hard-admission-timeout after ${Math.floor(Number(mode.age||0)/1000)}s`);
        console.log(`AutoCluster: LOCKSTEP MAINTENANCE DROP ${out && out.dropped ? 'complete' : 'no-op'} for ${cleanString(mode.pubkey,80)} at LCL ${run.hpContext.lclSeqNo || '?'}. Qualification will restart from fresh proofs.`);
      } catch (e) {
        console.log(`AutoCluster: LOCKSTEP MAINTENANCE DROP failed for ${cleanString(mode.pubkey,80)}: ${errText(e)}. It will retry on a later ledger; candidate stays outside UNL.`);
      }
      return;
    }
    if (mode.type === 'pool-fill') {
      const targetCount = Math.max(1, Number(mode.targetCount) || 1);
      try {
        const queued = await growFromHostQueue(run, targetCount);
        console.log(`AutoCluster: LOCKSTEP CANDIDATE POOL ${queued ? 'purchase queued' : 'checked'} at LCL ${run.hpContext.lclSeqNo || '?'} occupancy=${Number(mode.poolOccupancy||0)}/${Number(mode.desiredPool||mode.poolSize||0)} pending=${Number(mode.pendingCount||0)}. Each new purchase waits only for the previous Xahau transaction to reach ledger finality; native host provisioning overlaps up to the pool cap; admission remains one-at-a-time.`);
      } catch (e) {
        console.log(`AutoCluster: LOCKSTEP CANDIDATE POOL purchase failed: ${errText(e)}. Existing candidates keep qualifying; pool fill may retry on a later ledger.`);
      }
      return;
    }
  }

  // LOCKSTEP MEMBERSHIP INTENT FENCE. Once replicated state contains an ADD_UNL
  // intent, every clone stays out of autonomous lifecycle/tick mutations while the
  // Bootstrap-A controller obtains the final proof and submits the membership input.
  // processInputs() still runs before tick(), so the exact membership command can
  // execute normally on every synchronized copy.
  if (normalizeMembershipCommand(state.membershipCommand)) {
    console.log(`AutoCluster: LOCKSTEP membership-intent tick fence at LCL ${run.hpContext && run.hpContext.lclSeqNo || '?'}; no autonomous lifecycle mutation until the user-input membership command commits or is cancelled.`);
    return;
  }

  // During bootstrap qualification both Bootstrap A and pre-UNL followers run
  // this same deterministic lightweight watchdog path. No EverPocket/Xahau
  // lifecycle code is initialized in begin(), so the only replicated writes are
  // READY/watchdog state derived from the same consensus timestamp and files.
  if (run.bootstrapQualificationFence) {
    await candidateReadinessWatchdog(run);
    return;
  }

  // Outside the quiet qualification window, non-UNL candidates never drive
  // acquisition, replacement, signer provisioning, or validator membership.
  if (!run.localIsUnl) return;

  if (run.membershipTransitionQuietFence) {
    console.log(`AutoCluster: MEMBERSHIP-TRANSITION QUIET tick fence at LCL ${run.hpContext && run.hpContext.lclSeqNo || '?'}; only the authenticated membership input is allowed to mutate consensus state.`);
    return;
  }

  // alpha41 post-join bridge is intentionally state-machine-only. User inputs
  // (READY and ADD_UNL) have already been processed before tick(); there is
  // nothing else this execution is allowed to do until the full bridge exists.
  if (run.postJoinConsensusPurityFence) {
    console.log(`AutoCluster: CONSENSUS-PURITY tick fence at LCL ${run.hpContext && run.hpContext.lclSeqNo || '?'}; no acquisition, extension, external RPC, signer, watchdog or lifecycle mutation will run.`);
    return;
  }

  // HANDOVER FENCE: all target managed validators are already committed in UNL
  // beside Bootstrap A. No lifecycle work may disturb this temporary target+1
  // bridge while the root control plane installs the final signer list and reward
  // tracking. The next membership command removes Bootstrap A only.
  if (state.phase === 'signing') {
    const target = finalManagedTarget(state);
    const currentUnl = currentUnlPubkeys(run);
    const frozen = normalizePubkeyList(state.handoverSignerPubkeys);
    console.log(`AutoCluster: SIGNING FENCE active; frozen final managed signer set=${frozen.length}/${target}. Temporary UNL=${currentUnl.length}/${target + 1} (Bootstrap A + managed fleet). Waiting for root handover preparation.`);
    return;
  }


  // Persist the validator identity -> Evernode endpoint/acquisition mapping in
  // consensus state. Existing alpha.36 clusters are backfilled automatically
  // from cluster.json + acquires.json on the first successful ledger.
  syncValidatorRecords(run);

  // Expose Evernode moment size in consensus state for lease-expiry UI.
  try {
    const momentSize = Number(run.clusterContext.evernodeContext.getEvernodeConfig().momentSize);
    if (Number.isFinite(momentSize) && momentSize > 0 && momentSize !== Number(state.evernodeMomentSizeSeconds || 0)) { state.evernodeMomentSizeSeconds = momentSize; saveState(state); }
  } catch {}

  // alpha.29 incorrectly persisted terQUEUED as a hard managed-signer blocker.
  // On upgrade we do not know the signer address/hash of that old provisional
  // transaction, so wait a short ledger window before releasing it for a clean
  // retry. New alpha.30 terQUEUED submissions use queuedSigner and are fully
  // reconciled without duplicate submission.
  if (state.blocker && state.blocker.stage === 'managed-signer' && /\bterQUEUED\b/i.test(state.blocker.message || '')) {
    const lcl = Number(run.hpContext && run.hpContext.lclSeqNo) || 0;
    const at = Number(state.blocker.atLcl) || lcl;
    const age = Math.max(0, lcl - at);
    if (age < LEGACY_TERQUEUED_BLOCKER_HOLD_LCL) {
      console.log(`AutoCluster: legacy alpha.29 terQUEUED signer blocker is provisional; holding ${age}/${LEGACY_TERQUEUED_BLOCKER_HOLD_LCL} HotPocket ledgers before a clean retry.`);
      return;
    }
    clearBlocker(state, null, 'managed-signer');
    console.log('AutoCluster: released legacy alpha.29 terQUEUED managed-signer blocker after hold window; signer provisioning may retry on the next ledger.');
    return;
  }

  // Older builds could persist EverPocket's empty addSigner election / generic
  // vote-collection timeout as a fatal managed-signer blocker. There is no
  // concrete Xahau engine result in these cases, so release and retry.
  if (state.blocker && state.blocker.stage === 'managed-signer' && (
      /Cannot read properties of undefined \(reading ['"]account['"]\)/i.test(state.blocker.message || '') ||
      /Could not consider as a valid submission/i.test(state.blocker.message || '') ||
      /Could not consider as a valid transaction/i.test(state.blocker.message || '') ||
      /No enough signatures/i.test(state.blocker.message || '')
    )) {
    clearBlocker(state, null, 'managed-signer');
    console.log('AutoCluster: released retryable legacy managed-signer vote/election blocker; signer provisioning will retry with the extended vote timeout.');
    return;
  }

  // CRITICAL SAME-EXECUTION MEMBERSHIP FENCE: direct addToUnl() runs in begin().
  // The resulting hp.cfg patch is not necessarily visible through every
  // ClusterContext getter until the execution commits/reloads. Do absolutely no
  // pruning, growth, extension, or signer work in the execution that submitted
  // a validator stitch. The next committed execution will detect the UNL delta
  // and arm the normal five-ledger stabilization gate.
  const submittedPromotion = normalizePromotionBatch(state.promotionBatch);
  if (state.phase !== 'growing' && submittedPromotion && submittedPromotion.active && submittedPromotion.submittedAtLcl &&
      Number(submittedPromotion.submittedAtLcl) === Number(run.hpContext.lclSeqNo || 0)) {
    console.log(`AutoCluster: membership-change fence active at LCL ${run.hpContext.lclSeqNo || '?'} after direct validator stitch; deferring all remaining lifecycle work until the committed UNL is observed.`);
    return;
  }

  // CRITICAL CONSENSUS SAFETY GATE: ClusterContext.init() can promote a matured
  // node into the UNL before tick() runs. Detect that membership change here and
  // end this execution before any acquisition, extension, or signer transaction.
  // Subsequent executions are also paused until the new set closes several
  // deterministic ledgers successfully.
  if (!STOCK_CLONE_BOOTSTRAP && validatorStabilizationGate(run)) return;

  // STREAMING BOOTSTRAP MODE: a promotion batch no longer suppresses unrelated
  // lifecycle work. It only sequences one validator admission at a time.
  if (state.phase === 'growing') {
    const promotion = normalizePromotionBatch(state.promotionBatch);
    const nodesNow = run.clusterContext.getClusterNodes();
    const unlNow = nodesNow.filter(n => n && n.isUnl);
    const safeBootstrapTarget = finalManagedTarget(state);
    if (promotion && promotion.active && unlNow.length < safeBootstrapTarget) {
      console.log(`AutoCluster: STREAMING bootstrap membership active (${unlNow.length}/${safeBootstrapTarget} validators). Admission and normal Xahau/Evernode lifecycle work are running concurrently.`);
    }
  }

  // Hard cap the pre-cluster pending stage as well. Whether EverPocket is still
  // waiting for the host response or the paid instance endpoint never becomes
  // usable, a missing transient EverPocket pending view is not treated as failure; durable provisioning is bounded by consensus time and committed-ledger count.
  if (await pendingAcquisitionWatchdog(run)) return;

  // Keep readiness classification live during streaming bootstrap too. During
  // growth, watchdog state changes do not pause the rest of lifecycle processing;
  // acquisition/replacement and validator admission are intentionally concurrent.
  if (state.phase === 'growing') {
    await candidateReadinessWatchdog(run);
  } else if (await candidateReadinessWatchdog(run)) return;

  if (state.phase === 'ready-to-handover') {
    if (await observeMasterHandover(run)) return;
  }

  // Phase changes after a queued remove are observed from consensus state.
  if (state.phase === 'handover') {
    const bootstrapStillTracked = run.clusterContext.getClusterNodes().some(n => n.pubkey === state.bootstrapPubkey);
    if (bootstrapStillTracked && Number(state.handoverPreparedAtLcl)) {
      // Reconcile stale EverPocket cluster.json tracking only AFTER the HotPocket
      // REMOVE_UNL(A) command has moved us into handover. retireBootstrapDirect()
      // sees A absent from committed config and removes only stale local manager
      // tracking; it must not originate a new membership change here.
      if (await retireBootstrapDirect(run)) return;
    }
    if (!bootstrapStillTracked) {
      state.phase = 'autonomous';
      state.autonomousAtLcl = run.hpContext.lclSeqNo;
      saveState(state);
      console.log('AutoCluster: bootstrap instance has left the managed cluster; autonomous mode is active.');
    }
  }

  // Handover readiness: all target managed validators join first, so bootstrap
  // temporarily runs target+1 validators (A + the complete managed fleet).
  // Once all managed signer identities are present, freeze that managed set and
  // enter signer preparation. Final membership later removes A only.
  if (state.phase === 'growing') {
    const handover = fixedSizeBootstrapHandoverSet(run);
    if (handover.bridgeReady) {
      if (!handover.ready) {
        const signed = handover.unlManaged.filter(n => /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(String(n.signerAddress || ''))).length;
        console.log(`AutoCluster: HANDOVER waiting for managed signer identities ${signed}/${handover.target}; temporary UNL already has Bootstrap A + all ${handover.bridgeManagedTarget} managed validators (${handover.currentUnl.length}/${handover.bridgeTarget}).`);
      } else {
        const keep = new Set(handover.pubkeys);
        const currentSet = new Set(handover.currentUnl);
        const surplusPreUnl = handover.all.filter(n => {
          const pk = cleanString(n && n.pubkey || '',256).toLowerCase();
          return pk && !currentSet.has(pk) && !keep.has(pk);
        });
        if (surplusPreUnl.length) console.log(`AutoCluster: retaining ${surplusPreUnl.length} surplus pre-UNL candidate(s) through handover; external lease mutation remains frozen.`);
        state.promotionBatch = null;
        state.handoverSignerPubkeys = handover.pubkeys;
        state.phase = 'signing';
        saveState(state);
        console.log(`AutoCluster: HANDOVER READY at LCL ${run.hpContext.lclSeqNo || '?'}: temporary UNL=${handover.currentUnl.length}/${handover.bridgeTarget} (Bootstrap A + ${handover.bridgeManagedTarget} managed), signer identities=${handover.pubkeys.length}/${handover.target}. Entering signer preparation; final membership step removes Bootstrap A only.`);
        return;
      }
    }
  }


  const target = (state.phase === 'autonomous' || state.phase === 'handover')
    ? state.targetManagedNodes
    : state.targetManagedNodes + 1; // include bootstrap A until handover.

  // AutoCluster owns lifecycle sequencing. We deliberately do not invoke
  // NomadContext.init()/prune()/grow(): stock Nomad pruning can remove a validator
  // before our replacement-first repair has a healthy substitute ready, while
  // stock growth bypasses the consensus host queue. EverPocket remains the
  // authoritative implementation for cluster operations (acquire/add/remove/extend).
  if (state.phase === 'autonomous') {
    const health = refreshAutonomousMaintenanceHealth(run);
    syncValidatorRecords(run);
    if (!state.maintenance.repair && health.dead) { beginAutonomousRepair(run, health.dead); return; }
    const repairTarget = autonomousRepairTarget(run);
    // Never call stock Nomad.prune() here: removing a dead 5th validator before
    // a replacement is ready would turn 4/5 fault tolerance into a fragile 4/4 set.
    await growFromHostQueue(run, repairTarget);
    await extendManagedOnly(run);
    if (await advanceAutonomousRepair(run)) return;
  } else if (state.phase === 'growing') {
    if (STOCK_CLONE_BOOTSTRAP) {
      // BOUNDED CANDIDATE POOL: provisioning and admission are separate lanes.
      // Keep up to candidatePoolSize pre-UNL slots warm while ADD_UNL remains
      // strictly one-at-a-time. The lockstep maintenance planner owns pool refill
      // whenever materialized candidates exist; this fallback handles the initial
      // all-pending phase before the first candidate materializes.
      const poolSize = Math.max(1, Math.min(MAX_CANDIDATE_POOL_SIZE, Number(state.candidatePoolSize) || DEFAULT_CANDIDATE_POOL_SIZE));
      const committedUnl = currentUnlPubkeys(run);
      const managedUnlCount = committedUnl.filter(k => k !== state.bootstrapPubkey).length;
      const remainingManaged = Math.max(0, (Number(state.targetManagedNodes) || 1) - managedUnlCount);
      const singletonPhysicalBuild = committedUnl.length === 1 && committedUnl.includes(state.bootstrapPubkey) && managedUnlCount === 0;
      const desiredPool = singletonPhysicalBuild ? bootstrapInitialPhysicalManagedGoal(state) : Math.min(poolSize, remainingManaged);
      const poolTargetCount = committedUnl.length + desiredPool;
      console.log(`AutoCluster: BOOTSTRAP CANDIDATE POOL target=${desiredPool} pre-UNL slot(s), managedUnl=${managedUnlCount}/${Number(state.targetManagedNodes)||1}; lease purchases serialize only until the previous Xahau acquisition transaction reaches ledger finality. Native provisioning is asynchronous; transient EverPocket pending-view disappearance never marks a host failed.`);
      await growFromHostQueue(run, poolTargetCount);
    } else {
      // Legacy streaming mode.
      await growFromHostQueue(run, target);
      await extendManagedOnly(run);
    }
  } else if (['signing','ready-to-handover','handover'].includes(state.phase)) {
    console.log(`AutoCluster: pre-handover quiet mode (${state.phase}); routine acquisition/extension is paused while signer/master handover completes.`);
  }

  if (state.phase === 'autonomous') {
    const changed = await provisionOneSigner(run);
    if (changed) return; // one Xahau signer transaction per execution.
    await normalizeAutonomousSignerList(run);
    emitFinalClusterInventory(run);
  }
}

function recordRuntimeError(stage, error, lcl = null) {
  const state = loadState();
  if (!state || !state.enabled) return null;
  let effectiveStage = cleanString(stage || 'autocluster', 96);
  if (effectiveStage === 'tick') {
    if (state.phase === 'signing') effectiveStage = 'managed-signer';
    else if (state.phase === 'growing') effectiveStage = 'cluster-growth';
    else if (state.phase === 'autonomous') effectiveStage = 'autonomous-maintenance';
  }
  return setBlocker(state, error, effectiveStage, lcl);
}

async function end(run) {
  if (!run || run.closed) return;
  // This is node-local evidence only (outside consensus state). Every managed
  // non-bootstrap node signs its own LCL/hash/maturity/public-signer identity with
  // the HotPocket node key. This also repairs signer identity after upgrading from
  // a target+1 bootstrap bridge. The root sidecar relays it only after execution.
  writeSignedCandidateAttestation(run);
  run.closed = true;
  if (run.clusterContext && typeof run.clusterContext.deinit === 'function') await run.clusterContext.deinit();
  const batch = run.hpContext && Array.isArray(run.hpContext.__everSmartNodeBatchUnlPubkeys)
    ? run.hpContext.__everSmartNodeBatchUnlPubkeys : [];
  if (batch.length) markClusterNodesUnl(null, batch);
}

function acquisitionDiagnosticsSnapshot(state, cluster, acquires) {
  const nodes = cluster && Array.isArray(cluster.nodes) ? cluster.nodes : [];
  const pending = cluster && Array.isArray(cluster.pendingNodes) ? cluster.pendingNodes : [];
  const acquired = acquires && Array.isArray(acquires.acquiredNodes) ? acquires.acquiredNodes : [];
  const watches = normalizeCandidateWatchdogs(state && state.candidateWatchdogs);
  const readiness = normalizeCandidateReadiness(state && state.candidateReadiness);
  const candidateDiags = normalizeCandidateDiagnostics(state && state.candidateDiagnostics);
  const maturitySignals = normalizeMaturitySignals(state && state.maturitySignals);
  const bootstrap = state && state.bootstrapPubkey;
  const managedDisk = nodes.filter(n => n && (!bootstrap || n.pubkey !== bootstrap));
  const stalledPubkeys = new Set(watches.filter(w => w && w.stalledAt && !w.kickedAt).map(w => w.pubkey));
  const acceptedReady = acceptedReadyPubkeys(state);
  const queue = state && Array.isArray(state.hostQueue) ? state.hostQueue : [];
  const quarantinedPendingHosts = new Set(queue.filter(h => h && h.status === 'provisioning-stalled').map(h => h.address));
  const clusterHosts = new Set(nodes.filter(Boolean).map(n => n.host).filter(Boolean));
  const quarantinedPendingCount = pending.filter(n => n && n.host && quarantinedPendingHosts.has(n.host) && !clusterHosts.has(n.host)).length;
  const stalledManaged = managedDisk.filter(n => n && !n.isUnl && stalledPubkeys.has(n.pubkey));
  const rawTotalCount = nodes.length + pending.length;
  const effectiveInstanceCount = Math.max(0, rawTotalCount - stalledManaged.length - quarantinedPendingCount);
  const acquisitionTarget = state ? ((state.phase === 'autonomous' || state.phase === 'handover') ? state.targetManagedNodes : state.targetManagedNodes + 1) : null;
  const hosts = queue.map(item => {
    const node = nodes.find(n => n && item.address && n.host === item.address) || null;
    const pendingNode = pending.find(n => n && ((item.address && n.host === item.address) || (item.refId && n.refId === item.refId))) || null;
    const acquiredNode = acquired.find(n => n && ((item.address && n.host === item.address) || (item.refId && n.refId === item.refId))) || null;
    const watch = node ? watches.find(w => w.pubkey === node.pubkey) || null : null;
    const ready = node ? readiness.find(r => r.pubkey === node.pubkey) || null : null;
    const remote = node ? candidateDiags.find(d => d.pubkey === node.pubkey) || null : null;
    const maturity = node ? maturitySignals.find(m => m.pubkey === node.pubkey) || null : null;
    const sharedStatus = node ? diskNodeStatus(node) : null;
    const maturityDone = !!(node && clusterNodeMaturityDone(node));
    const readyAccepted = !!(node && acceptedReady.has(node.pubkey));
    let classification = item.status || 'unknown', reason = null;
    if (node) {
      if (node.isUnl) { classification='validator-unl'; reason='Materialized and already in committed UNL.'; }
      else if (watch && watch.stalledAt) {
        classification = 'candidate-readiness-stalled';
        reason = readyAccepted
          ? 'Materialized candidate had canonical READY previously, but the proof became stale and was not refreshed before the grace deadline.'
          : (remote ? `Materialized but no canonical VALIDATOR_READY before deadline. Remote reported localShared=${remote.localSharedStatus || 'unknown'} private=${remote.privateStatus || 'unknown'}; shared ACKNOWLEDGED will also be required at admission.` : 'Materialized but no canonical VALIDATOR_READY before the readiness deadline.');
      }
      else if (readyAccepted) { classification='candidate-ready-stale'; reason=`Canonical VALIDATOR_READY was accepted historically. Candidate remains materialized/usable and is never quarantined merely because freshness expired; admission waits for refreshed READY. The candidate remains outside UNL until fresh live canonical sync and the final exact-tip admission proof are both satisfied. EverPocket shared maturity status=${sharedStatus || 'unknown'}.`; }
      else { classification='candidate-awaiting-ready'; reason=`Materialized and waiting for canonical VALIDATOR_READY; maturity status=${sharedStatus || 'unknown'}; admission requires ACKNOWLEDGED plus fresh READY, fresh runtime SYNC, and mesh.`; }
    } else if (pendingNode) { classification=quarantinedPendingHosts.has(item.address)?'pending-quarantined':'pending-provisioning'; reason='EverPocket pending node has not materialized into cluster.nodes.'; }
    else if (acquiredNode) { classification='acquired-awaiting-candidate-materialization'; reason='Native AcquireSuccess is recorded, but no cluster node is materialized yet. Contract-side WSS liveness is intentionally bypassed.'; }
    return {host:item.address||null,queueStatus:item.status||null,attempts:Number(item.attempts||0),refId:item.refId||null,classification,reason,
      clusterNode:node?{pubkey:node.pubkey||null,domain:node.domain||null,userPort:node.userPort||null,peerPort:node.peerPort||null,gpTcp1Port:validPort(node.gpTcp1Port||node.gpTcpPort||node.gptcp1||node.gp_tcp_port||node.gp_tcp1_port),gpUdp1Port:validPort(node.gpUdp1Port||node.gpUdpPort||node.gpudp1||node.gp_udp_port||node.gp_udp1_port),isUnl:!!node.isUnl,sharedStatus}:null,
      pendingNode:pendingNode?{refId:pendingNode.refId||null,aliveCheckCount:Number(pendingNode.aliveCheckCount||0),acquireSentOnLcl:Number(pendingNode.acquireSentOnLcl||0)||null}:null,
      acquiredRecord:acquiredNode?safeAcquireRecordSummary(acquiredNode):null,
      nativeAcquisition:{stage:item.nativeStage||null,stageAtLcl:item.nativeStageAtLcl||null,requestTxId:item.acquireRequestTxId||null,requestCode:item.acquireRequestCode||null,requestLedgerIndex:item.acquireRequestLedgerIndex||null,acquireSuccessAtLcl:item.acquireSuccessAtLcl||null,acquireSuccessInstance:{pubkey:item.acquireSuccessPubkey||null,domain:item.acquireSuccessDomain||null,userPort:item.acquireSuccessUserPort||null,peerPort:item.acquireSuccessPeerPort||null,gpTcp1Port:item.acquireSuccessGpTcp1Port||null,gpUdp1Port:item.acquireSuccessGpUdp1Port||null,name:item.acquireSuccessName||null,contractId:item.acquireSuccessContractId||null}},
      maturityWatch:watch,maturitySignal:maturity,candidateDiagnostic:remote,readiness:ready,
      usableForBootstrap:!!(node && (node.isUnl || readyAccepted))};
  });
  return {summary:{phase:state&&state.phase||null,targetManagedNodes:state&&state.targetManagedNodes||null,candidatePoolSize:state?Math.max(1,Math.min(MAX_CANDIDATE_POOL_SIZE,Number(state.candidatePoolSize)||DEFAULT_CANDIDATE_POOL_SIZE)):DEFAULT_CANDIDATE_POOL_SIZE,acquisitionTarget,
    clusterNodes:nodes.length,pendingNodes:pending.length,rawTotalCount,readinessStalledManaged:stalledManaged.length,
    quarantinedPending:quarantinedPendingCount,effectiveInstanceCount,managedMaterialized:managedDisk.length,
    managedReadyAccepted:managedDisk.filter(n=>!n.isUnl&&acceptedReady.has(n.pubkey)).length,
    managedAcknowledgedInformational:managedDisk.filter(n=>!n.isUnl&&clusterNodeMaturityDone(n)).length,managedUnl:managedDisk.filter(n=>n.isUnl).length,
    candidateDiagnosticsReceived:candidateDiags.length,maturitySignalsReceived:maturitySignals.reduce((a,m)=>a+Number(m.count||0),0),contractEndpointLiveness:'disabled-consensus-neutral'},
    countFormula:'effectiveInstanceCount = clusterNodes + pendingNodes - readinessStalledManaged - provisioningStalledPending',
    nativeStages:'tx-submitted -> tx-validated-waiting-acquire-success -> (async AcquireSuccess OR provisioning-timeout late-watch) -> cluster-pending-candidate -> materialized -> canonical READY',
    note:'Native Evernode AcquireSuccess is the provisioning boundary. Contract-side DNS/TLS/WSS liveness is deliberately bypassed because validator-local network results must not mutate replicated state. Canonical VALIDATOR_READY proves a bootstrap candidate has reached Bootstrap A\'s canonical history. Once READY has been accepted, later proof staleness is admission-only and never quarantines/replaces the paid candidate. Normal admission requires shared ACKNOWLEDGED plus fresh READY, fresh runtime SYNC, and mesh. Bootstrap admission remains automatic: pre-freeze qualification uses durable ACK/signer/maturity/READY-SYNC history only; live exact-tip sync and peer mesh are enforced by the atomic final membership proof. Stock-clone ADD_UNL is then submitted as a normal HotPocket user input so the synchronized observer executes the same membership decision before becoming trusted.',hosts};
}

function publicStatus() {
  const state = loadState();
  const cluster = readJson(path.resolve(process.cwd(), 'cluster.json'), null);
  const operations = readJson(path.resolve(process.cwd(), 'operations.json'), null);
  const acquires = readJson(path.resolve(process.cwd(), 'acquires.json'), null);
  return { state, cluster, operations, acquires, acquisitionDiagnostics: acquisitionDiagnosticsSnapshot(state, cluster, acquires) };
}

module.exports = { isConfigured, loadState, prepareBootstrap, activateBootstrap, setBootstrapEndpoint, confirmMasterHandover, addHosts, removeHost, retryFailedHosts, retryFundingWait, skipPendingAttempt, dropCandidateInstance, setMaxLeaseAmount, armBootstrapMeshOverride, setRuntimeSettings, setRpcPools, retryRpcPool, addValidatorViaEverPocket, validatorStabilizationPreflight, begin, tick, end, feedUserMessage, publicStatus, recordRuntimeError };
