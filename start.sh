#!/bin/bash
set -euo pipefail

if [ -f /contract/env.vars ]; then
  set -a
  # shellcheck disable=SC1091
  source /contract/env.vars
  set +a
fi

WEB_PORT="${EXTERNAL_GPTCP1_PORT:-}"
TLS_CERT="/contract/cfg/tlscert.pem"
TLS_KEY="/contract/cfg/tlskey.pem"
HP_CFG="/contract/cfg/hp.cfg"
DATA_DIR="${EVERSMARTNODE_DATA_DIR:-/var/lib/eversmartnode}"
SECRET_DIR="${EVERSMARTNODE_SECRET_DIR:-$DATA_DIR/secrets}"
SUPERVISOR_CONF="${EVERSMARTNODE_SUPERVISOR_CONF:-/etc/eversmartnode/supervisord.conf}"
PACKAGED_CONTRACT="/opt/eversmartnode/contract"
SEED_STATE="/contract/contract_fs/seed/state"

if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
  echo "EverSmartNode: EXTERNAL_GPTCP1_PORT is missing or invalid." >&2
  exit 1
fi
if [ ! -f "$TLS_CERT" ] || [ ! -f "$TLS_KEY" ]; then
  echo "EverSmartNode: Evernode TLS files are required: $TLS_CERT and $TLS_KEY" >&2
  exit 1
fi
if [ ! -f "$HP_CFG" ]; then
  echo "EverSmartNode: HotPocket config is missing: $HP_CFG" >&2
  exit 1
fi

install -d -m 0755 "$DATA_DIR" /var/log/supervisor
install -d -m 0700 "$SECRET_DIR"

# The Docker image contains the packaged bootstrap copy, but HotPocket executes
# the smart contract from its contract/state working directory. Keep bin_args
# relative so index.js (and its sibling contract files) resolve from that state.

# Keep consensus rounds long enough for a geographically distributed validator
# set to exchange proposals reliably. Existing Evernode instances may retain a
# 2000 ms value in /contract/cfg/hp.cfg even though contract.deploy.json uses
# 4000 ms, so force the live HotPocket config on every container start.
sed -i -E 's/"roundtime"[[:space:]]*:[[:space:]]*[0-9]+/"roundtime": 4000/g' "$HP_CFG"

node <<'NODE'
const fs = require('fs');
const file = '/contract/cfg/hp.cfg';
const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
cfg.contract = cfg.contract && typeof cfg.contract === 'object' ? cfg.contract : {};
cfg.contract.bin_path = '/usr/bin/node';
cfg.contract.bin_args = 'index.js';
cfg.contract.execute = true;
cfg.consensus = cfg.consensus && typeof cfg.consensus === 'object' ? cfg.consensus : {};
cfg.consensus.roundtime = 4000;
// Use deterministic explicit peers. HotPocket 0.6.4 rejects peer_changeset
// control messages while peer discovery is enabled, but AutoCluster relies on
// updatePeers() to install the full current-UNL mesh before promotion. Keep
// discovery OFF so known_peers + peer_changeset are authoritative.
cfg.mesh = cfg.mesh && typeof cfg.mesh === 'object' ? cfg.mesh : {};
cfg.mesh.peer_discovery = cfg.mesh.peer_discovery && typeof cfg.mesh.peer_discovery === 'object' ? cfg.mesh.peer_discovery : {};
cfg.mesh.peer_discovery.enabled = false;
if (!Number.isInteger(Number(cfg.mesh.peer_discovery.interval)) || Number(cfg.mesh.peer_discovery.interval) < 1) cfg.mesh.peer_discovery.interval = 10000;
cfg.mesh.msg_forwarding = true;
const tmp = file + '.eversmartnode-' + process.pid + '.tmp';
fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + '\n');
fs.renameSync(tmp, file);
const userPort = Number(cfg.user && cfg.user.port);
const meshPort = Number(cfg.mesh && cfg.mesh.port);
console.log(`EverSmartNode: HotPocket executable -> ${cfg.contract.bin_path} ${cfg.contract.bin_args}`);
console.log(`EverSmartNode: HotPocket local ports -> user=${Number.isInteger(userPort)?userPort:'unknown'} mesh=${Number.isInteger(meshPort)?meshPort:'unknown'} peerDiscovery=off explicitPeers=on msgForwarding=on`);
console.log(`EverSmartNode: HotPocket consensus roundtime -> ${cfg.consensus.roundtime} ms`);
NODE

# Populate the seed only as initial application content. This is deliberately
# non-destructive; existing or synchronized HotPocket state remains authoritative.
if [ -d /contract/contract_fs/seed ]; then
  mkdir -p "$SEED_STATE"
  cp -an "$PACKAGED_CONTRACT"/. "$SEED_STATE"/ 2>/dev/null || true
fi

export EVERSMARTNODE_DATA_DIR="$DATA_DIR"
export EVERSMARTNODE_SECRET_DIR="$SECRET_DIR"
export EVERSMARTNODE_SUPERVISOR_CONF="$SUPERVISOR_CONF"
export EVERSMARTNODE_PORT="$WEB_PORT"
export EVERSMARTNODE_HOST="0.0.0.0"
export EVERSMARTNODE_TLS_CERT="$TLS_CERT"
export EVERSMARTNODE_TLS_KEY="$TLS_KEY"
export NODE_PATH="/opt/eversmartnode/node_modules${NODE_PATH:+:$NODE_PATH}"
export LD_LIBRARY_PATH="/usr/local/lib:/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Restart mailboxes are strictly ephemeral operator commands. Never carry a stale
# request across a container/control-plane start; doing so can SIGTERM a healthy
# HotPocket instance for no current operational reason.
rm -f \
  /contract/contract_fs/mnt/rw/restart-hotpocket.request \
  /contract/contract_fs/seed/restart-hotpocket.request \
  /contract/contract_fs/restart-hotpocket.request 2>/dev/null || true
for q in /contract/contract_fs/mnt/rw/restart-hotpocket.queue /contract/contract_fs/seed/restart-hotpocket.queue; do
  [ -d "$q" ] && find "$q" -maxdepth 1 -type f -name '*.json' -delete 2>/dev/null || true
done

for q in \
  /contract/contract_fs/mnt/rw/restart-hotpocket.queue \
  /contract/contract_fs/seed/restart-hotpocket.queue; do
  parent="$(dirname "$q")"
  if [ -d "$parent" ]; then
    mkdir -p "$q" 2>/dev/null || true
    chmod 0700 "$q" 2>/dev/null || true
  fi
done

echo "EverSmartNode v1.7.0-alpha.53.95-purity-fence-handover"
echo "  Ubuntu base: 24.04"
echo "  Web + API: https://<host>:${WEB_PORT}/"
echo "  HotPocket admin: https://<host>:${WEB_PORT}/evernode"
echo "  HotPocket WSS: direct on hp.cfg user.port (wss://<host>:<user.port>)"
echo "  Runtime: Node.js + HotPocket + Supervisor"
echo "  HotPocket: /usr/local/bin/hotpocket/hpcore run /contract"

exec /usr/bin/supervisord -c "$SUPERVISOR_CONF"
