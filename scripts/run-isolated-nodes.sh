#!/usr/bin/env bash
# Spin up a 2-node fully isolated local Freenet network for E2E tests.
#
# - Gateway on 7510 (network 31338)
# - Peer on 7511 (network 31339), connected only to local gateway
# - HOME override per node so neither reads ~/Library/.../gateways.toml
#   (which would pull in public Freenet bootstrap gateways and break
#   the "isolated" guarantee — see freenet/freenet-core#3980).
#
# Usage:
#   scripts/run-isolated-nodes.sh up      # start both
#   scripts/run-isolated-nodes.sh down    # stop both, keep data
#   scripts/run-isolated-nodes.sh wipe    # stop + delete data dirs
#   scripts/run-isolated-nodes.sh status  # show running pids + ports
#
# Environment overrides:
#   FREENET_E2E_ROOT  base dir for HOME + data + logs (default: ~/freenet-mail-iso)

set -euo pipefail

ROOT="${FREENET_E2E_ROOT:-$HOME/freenet-mail-iso}"
GW_HOME="$ROOT/HOME-gw"
PEER_HOME="$ROOT/HOME-peer"
GW_DATA="$ROOT/gw/data"
GW_LOGS="$ROOT/gw/logs"
PEER_DATA="$ROOT/peer/data"
PEER_LOGS="$ROOT/peer/logs"

GW_PORT_NET=31338
GW_PORT_WS=7510
PEER_PORT_NET=31339
PEER_PORT_WS=7511

GW_PIDFILE="$ROOT/gw.pid"
PEER_PIDFILE="$ROOT/peer.pid"
GW_PUBKEY_FILE="$ROOT/gw.pubkey"

setup_dirs() {
    mkdir -p "$GW_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet"
    mkdir -p "$PEER_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet"
    mkdir -p "$GW_DATA" "$GW_LOGS" "$PEER_DATA" "$PEER_LOGS"
    # Empty `gateways = []` so freenet doesn't load real public bootstraps
    # from the global config dir. Empty file ('') errors out with
    # "missing field `gateways`" — must be the explicit array form.
    printf 'gateways = []\n' > "$GW_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet/gateways.toml"
    printf 'gateways = []\n' > "$PEER_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet/gateways.toml"
}

derive_pubkey() {
    # Derive X25519 public key from the gateway's transport keypair.
    # The keypair file holds the 32-byte private key as hex.
    local priv_hex
    priv_hex=$(cat "$GW_DATA/secrets/transport_keypair")
    # ASN.1 prefix for a raw X25519 PrivateKey + 32-byte key, fed to openssl.
    { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20'; \
      echo -n "$priv_hex" | xxd -r -p; } | \
        openssl pkey -inform DER -pubout -outform DER 2>/dev/null | \
        xxd -p -c 64 | tail -1 | sed 's/^.*032100//'
}

up() {
    setup_dirs

    if lsof -i :$GW_PORT_WS -P -sTCP:LISTEN > /dev/null 2>&1; then
        echo "gateway already listening on :$GW_PORT_WS"
    else
        echo "starting gateway on ws://127.0.0.1:$GW_PORT_WS (net :$GW_PORT_NET)"
        HOME="$GW_HOME" nohup freenet network \
            --network-port $GW_PORT_NET \
            --ws-api-port $GW_PORT_WS \
            --ws-api-address 0.0.0.0 \
            --is-gateway \
            --skip-load-from-network \
            --data-dir "$GW_DATA" \
            --public-network-address 127.0.0.1 \
            --log-dir "$GW_LOGS" \
            --log-level info \
            > "$GW_LOGS/stdout.log" 2>&1 &
        echo $! > "$GW_PIDFILE"
        # Wait for gateway to bind ws port + write transport_keypair.
        for _ in $(seq 1 30); do
            if [ -f "$GW_DATA/secrets/transport_keypair" ] && \
               curl -sf -o /dev/null "http://127.0.0.1:$GW_PORT_WS/" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
    fi

    GW_PUBKEY=$(derive_pubkey)
    echo "$GW_PUBKEY" > "$GW_PUBKEY_FILE"
    echo "gateway pubkey: $GW_PUBKEY"

    if lsof -i :$PEER_PORT_WS -P -sTCP:LISTEN > /dev/null 2>&1; then
        echo "peer already listening on :$PEER_PORT_WS"
    else
        echo "starting peer on ws://127.0.0.1:$PEER_PORT_WS (net :$PEER_PORT_NET) → gateway 127.0.0.1:$GW_PORT_NET"
        HOME="$PEER_HOME" nohup freenet network \
            --network-port $PEER_PORT_NET \
            --ws-api-port $PEER_PORT_WS \
            --ws-api-address 0.0.0.0 \
            --gateway "127.0.0.1:$GW_PORT_NET,$GW_PUBKEY" \
            --skip-load-from-network \
            --data-dir "$PEER_DATA" \
            --log-dir "$PEER_LOGS" \
            --log-level info \
            > "$PEER_LOGS/stdout.log" 2>&1 &
        echo $! > "$PEER_PIDFILE"
        for _ in $(seq 1 30); do
            if curl -sf -o /dev/null "http://127.0.0.1:$PEER_PORT_WS/" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
    fi

    # Confirm only the local gateway shows up in the peer's bootstrap list.
    sleep 2
    local n
    n=$(grep -c "Attempting connection to gateway" "$PEER_LOGS"/freenet.*.log 2>/dev/null | tail -1 || echo 0)
    if [ "${n:-0}" -gt 1 ]; then
        echo "WARNING: peer is dialing $n gateways — isolation broken (check HOME override)"
    fi

    status
}

down() {
    if [ -f "$GW_PIDFILE" ]; then
        kill "$(cat "$GW_PIDFILE")" 2>/dev/null || true
        rm -f "$GW_PIDFILE"
    fi
    if [ -f "$PEER_PIDFILE" ]; then
        kill "$(cat "$PEER_PIDFILE")" 2>/dev/null || true
        rm -f "$PEER_PIDFILE"
    fi
    # Belt-and-suspenders: kill anything still bound to the iso WS
    # ports. macOS `ps` truncates argv beyond ~32 chars, so the
    # data-dir-based pkill from earlier versions silently missed
    # processes whose argv had been trimmed.
    for port in $GW_PORT_WS $PEER_PORT_WS; do
        for pid in $(lsof -ti :"$port" -sTCP:LISTEN 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
    done
    # Final pass: any freenet process whose argv mentions the iso
    # root, regardless of which leg it ran.
    pkill -f "freenet network.*$ROOT" 2>/dev/null || true
    # macOS truncates argv visible via pgrep in some cases (re-exec /
    # fork patterns), so additionally kill any pid that holds an open
    # file under the iso data tree. `lsof +D` recurses; safe because
    # only freenet writes there.
    if [ -d "$ROOT" ]; then
        for pid in $(lsof -t +D "$ROOT" 2>/dev/null | sort -u); do
            kill "$pid" 2>/dev/null || true
        done
    fi
    # Wait for ports to drain so a back-to-back up doesn't race the
    # bind. SIGKILL after a grace period.
    for _ in $(seq 1 10); do
        if ! lsof -i :$GW_PORT_WS -i :$PEER_PORT_WS -P -sTCP:LISTEN >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    if lsof -i :$GW_PORT_WS -i :$PEER_PORT_WS -P -sTCP:LISTEN >/dev/null 2>&1; then
        for port in $GW_PORT_WS $PEER_PORT_WS; do
            for pid in $(lsof -ti :"$port" -sTCP:LISTEN 2>/dev/null); do
                kill -9 "$pid" 2>/dev/null || true
            done
        done
    fi
    echo "stopped"
}

wipe() {
    down
    rm -rf "$ROOT"
    echo "wiped $ROOT"
}

status() {
    echo "--- ports ---"
    lsof -i :$GW_PORT_WS -i :$PEER_PORT_WS -P 2>/dev/null | grep LISTEN || echo "no node listening"
    echo "--- pids ---"
    pgrep -lf "freenet network" || echo "no freenet processes"
}

case "${1:-}" in
    up)     up ;;
    down)   down ;;
    wipe)   wipe ;;
    status) status ;;
    *)      echo "usage: $0 {up|down|wipe|status}"; exit 1 ;;
esac
