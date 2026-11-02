#!/usr/bin/env bash
# Spin up a 2-node fully isolated local Freenet network for E2E tests.
#
# - Gateway on 7510 (network 31338)
# - Peer on 7511 (network 31339), connected only to local gateway
# - HOME override per node so neither reads ~/Library/.../gateways.toml
#   (which would pull in public Freenet bootstrap gateways and break
#   the "isolated" guarantee — see freenet/freenet-core#3980).
# - --config-dir per node so gw and peer never share a config.toml.
#   freenet-core's ConfigArgs::build persists a config.toml on first run
#   (containing secrets.transport_keypair = ...). On hosts where
#   XDG_CONFIG_HOME is set (ubicloud runners), HOME override is bypassed
#   for config resolution and both nodes resolve to the same dir, so the
#   second node loads the first's transport keypair and fails its
#   "same public key as self" check (#124).
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
GW_CONFIG="$ROOT/gw/config"
PEER_DATA="$ROOT/peer/data"
PEER_LOGS="$ROOT/peer/logs"
PEER_CONFIG="$ROOT/peer/config"

# Overridable so the harness can run beside another node using the defaults
# (live-node.spec.ts and publish-email-iso read the same WS port variables).
GW_PORT_NET="${FREENET_ISO_GW_NET_PORT:-31338}"
GW_PORT_WS="${FREENET_ISO_GW_PORT:-7510}"
PEER_PORT_NET="${FREENET_ISO_PEER_NET_PORT:-31339}"
PEER_PORT_WS="${FREENET_ISO_PEER_PORT:-7511}"

GW_PIDFILE="$ROOT/gw.pid"
PEER_PIDFILE="$ROOT/peer.pid"
GW_PGIDFILE="$ROOT/gw.pgid"
PEER_PGIDFILE="$ROOT/peer.pgid"
GW_PUBKEY_FILE="$ROOT/gw.pubkey"

# Block freenet's startup auto-update probe.
#
# At boot freenet (a clean release build) hits
# https://api.github.com/repos/freenet/freenet-core/releases/latest and,
# if a newer release exists, gracefully shuts itself down to auto-update
# (crates/core/src/bin/freenet.rs — gated only on a dirty git build, with
# no env knob to disable). That self-shutdown kills the iso gateway
# mid-E2E whenever the local binary trails the latest freenet-core
# release, which broke a production release run (the gw on :7510 died
# seconds after bind → publish hit connection-refused).
#
# The update check uses `reqwest::Client` with no `.no_proxy()`, so it
# honors HTTPS_PROXY. Point it at a dead local port: the probe's
# `send()` errors, `startup_update_check` returns None, and the node
# fails-open and stays up. The P2P transport is raw UDP (no reqwest) and
# the public-gateway-index fetch is already suppressed by
# `gateways = []` + `--skip-load-from-network`, so nothing load-bearing
# routes through this proxy. CI achieves the same effect by routing
# api.github.com → 127.0.0.1 in /etc/hosts (e2e-real-node.yml), which
# needs sudo; the proxy approach keeps this harness root-free.
NO_AUTOUPDATE_ENV=(HTTPS_PROXY=http://127.0.0.1:1 HTTP_PROXY=http://127.0.0.1:1 NO_PROXY=)

# spawn_setsid <pidfile> <pgidfile> <stdout-log> <env-prefix> <cmd...>
#
# Spawns cmd in its own POSIX session via perl, so the entire process
# group can be killed regardless of how freenet re-execs / forks
# internally. macOS has no /usr/bin/setsid; perl POSIX::setsid does
# the same thing.
spawn_setsid() {
    local pidfile="$1" pgidfile="$2" outlog="$3"
    shift 3
    ISO_OUTLOG="$outlog" perl -e '
        use POSIX;
        POSIX::setsid() or die "setsid: $!";
        open STDIN,  "<", "/dev/null";
        open STDOUT, ">>", $ENV{ISO_OUTLOG} or die $!;
        open STDERR, ">&STDOUT";
        exec { $ARGV[0] } @ARGV or die "exec: $!";
    ' "$@" &
    local pid=$!
    echo "$pid" > "$pidfile"
    # In a setsid-spawned process the pid IS the pgid.
    echo "$pid" > "$pgidfile"
}

setup_dirs() {
    # macOS layout: dirs::config_dir() / dirs::data_local_dir() both
    # resolve under "Library/Application Support/<APPLICATION>".
    mkdir -p "$GW_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet"
    mkdir -p "$PEER_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet"
    # Linux layout: dirs::config_dir() = $XDG_CONFIG_HOME or $HOME/.config;
    # dirs::data_local_dir() = $XDG_DATA_HOME or $HOME/.local/share.
    # Pre-create both so freenet never falls back to a host-default path
    # outside our HOME override (which would let gw + peer share state).
    mkdir -p "$GW_HOME/.config/freenet" "$GW_HOME/.local/share/freenet"
    mkdir -p "$PEER_HOME/.config/freenet" "$PEER_HOME/.local/share/freenet"
    mkdir -p "$GW_DATA" "$GW_LOGS" "$GW_CONFIG" "$PEER_DATA" "$PEER_LOGS" "$PEER_CONFIG"
    # Empty `gateways = []` so freenet doesn't load real public bootstraps
    # from the global config dir. Empty file ('') errors out with
    # "missing field `gateways`" — must be the explicit array form.
    for cfg in \
        "$GW_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet/gateways.toml" \
        "$PEER_HOME/Library/Application Support/The-Freenet-Project-Inc.Freenet/gateways.toml" \
        "$GW_HOME/.config/freenet/gateways.toml" \
        "$PEER_HOME/.config/freenet/gateways.toml"; do
        printf 'gateways = []\n' > "$cfg"
    done
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
        HOME="$GW_HOME" spawn_setsid "$GW_PIDFILE" "$GW_PGIDFILE" "$GW_LOGS/stdout.log" \
            env "${NO_AUTOUPDATE_ENV[@]}" \
            freenet network \
            --network-port "$GW_PORT_NET" \
            --ws-api-port "$GW_PORT_WS" \
            --ws-api-address 0.0.0.0 \
            --is-gateway \
            --skip-load-from-network \
            --config-dir "$GW_CONFIG" \
            --data-dir "$GW_DATA" \
            --public-network-address 127.0.0.1 \
            --public-network-port "$GW_PORT_NET" \
            --log-dir "$GW_LOGS" \
            --log-level info
        # Wait for gateway to bind ws port + write transport_keypair.
        gw_ready=0
        for _ in $(seq 1 30); do
            if [ -f "$GW_DATA/secrets/transport_keypair" ] && \
               curl -sf -o /dev/null "http://127.0.0.1:$GW_PORT_WS/" 2>/dev/null; then
                gw_ready=1
                break
            fi
            sleep 0.5
        done
        if [ "$gw_ready" != 1 ]; then
            if [ -f "$GW_DATA/secrets/transport_keypair" ]; then
                echo "error: the gateway wrote its keypair but is not answering on :$GW_PORT_WS after 15 s:" >&2
            else
                echo "error: the gateway wrote no $GW_DATA/secrets/transport_keypair within 15 s; it most likely exited at startup:" >&2
            fi
            tail -20 "$GW_LOGS/stdout.log" >&2 || true
            exit 1
        fi
    fi

    if [ ! -f "$GW_DATA/secrets/transport_keypair" ]; then
        # Only reachable when :$GW_PORT_WS was already taken above.
        echo "error: something is already listening on :$GW_PORT_WS, but $GW_DATA has no transport keypair," >&2
        echo "       so it is not this harness's gateway. Stop it, or choose other ports" >&2
        echo "       (FREENET_ISO_GW_PORT and friends)." >&2
        exit 1
    fi
    GW_PUBKEY=$(derive_pubkey)
    echo "$GW_PUBKEY" > "$GW_PUBKEY_FILE"
    echo "gateway pubkey: $GW_PUBKEY"
    # Diagnostic for the CI flake where peer bails with
    # "Skipping gateway with same public key as self" — print the first
    # 16 bytes of gw's transport_keypair so a follow-up CI run can
    # compare against peer's keypair head and confirm whether they
    # actually collide on Linux.
    if [ -f "$GW_DATA/secrets/transport_keypair" ]; then
        echo "gw transport_keypair head: $(head -c 32 "$GW_DATA/secrets/transport_keypair")"
    fi

    if lsof -i :$PEER_PORT_WS -P -sTCP:LISTEN > /dev/null 2>&1; then
        echo "peer already listening on :$PEER_PORT_WS"
    else
        echo "starting peer on ws://127.0.0.1:$PEER_PORT_WS (net :$PEER_PORT_NET) → gateway 127.0.0.1:$GW_PORT_NET"
        HOME="$PEER_HOME" spawn_setsid "$PEER_PIDFILE" "$PEER_PGIDFILE" "$PEER_LOGS/stdout.log" \
            env "${NO_AUTOUPDATE_ENV[@]}" \
            freenet network \
            --network-port "$PEER_PORT_NET" \
            --ws-api-port "$PEER_PORT_WS" \
            --ws-api-address 0.0.0.0 \
            --gateway "127.0.0.1:$GW_PORT_NET,$GW_PUBKEY" \
            --skip-load-from-network \
            --config-dir "$PEER_CONFIG" \
            --data-dir "$PEER_DATA" \
            --log-dir "$PEER_LOGS" \
            --log-level info
        for _ in $(seq 1 30); do
            if curl -sf -o /dev/null "http://127.0.0.1:$PEER_PORT_WS/" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
    fi

    # Confirm only the local gateway shows up in the peer's bootstrap list.
    sleep 2
    if [ -f "$PEER_DATA/secrets/transport_keypair" ]; then
        echo "peer transport_keypair head: $(head -c 32 "$PEER_DATA/secrets/transport_keypair")"
    else
        echo "peer transport_keypair: NOT WRITTEN (peer likely crashed during init — see $PEER_LOGS)"
    fi
    # Use shopt nullglob so the freenet.*.log glob doesn't pass a
    # literal pattern to grep when the peer crashed before producing
    # any rolled log file. `set -e + pipefail` would abort the whole
    # `up()` call on grep's exit-2 in that case.
    local n=0
    shopt -s nullglob
    local peer_logs=( "$PEER_LOGS"/freenet.*.log )
    shopt -u nullglob
    if (( ${#peer_logs[@]} > 0 )); then
        n=$(grep -c "Attempting connection to gateway" "${peer_logs[@]}" 2>/dev/null \
            | awk -F: '{ sum += $NF } END { print sum + 0 }')
    fi
    if [ "${n:-0}" -gt 1 ]; then
        echo "WARNING: peer is dialing $n gateways — isolation broken (check HOME override)"
    fi

    status
}

# Whether process `$1` was started under the iso root. The nodes' command
# lines carry `--data-dir <root>/...`, so a pid reused by anything else does
# not match.
is_ours() {
    local cmd
    cmd=$(tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null || true)
    [ -n "$cmd" ] || cmd=$(ps -o command= -p "$1" 2>/dev/null || true)
    case "$cmd" in *"$ROOT/"*) return 0 ;; esac
    return 1
}

# Whether the recorded id still names a process group of ours. The group is
# tested, not only its leader: a child can outlive the leader. A live leader
# must also be ours, or the id was reused. A group with no leader cannot be a
# reuse, since a pid is not handed out while it still names a group.
still_running() {
    local id="$1"
    if kill -0 -- "-$id" 2>/dev/null; then
        if kill -0 "$id" 2>/dev/null && ! is_ours "$id"; then
            return 1
        fi
        return 0
    fi
    kill -0 "$id" 2>/dev/null && is_ours "$id"
}

# Signal the group, and the leader, of a recorded id that is still ours.
signal_recorded() {
    local sig="$1" id="$2"
    still_running "$id" || return 0
    kill "-$sig" -- "-$id" 2>/dev/null || true
    kill "-$sig" "$id" 2>/dev/null || true
}

down() {
    # Kill by the PIDs recorded at startup, never by matching a command line
    # across the machine: a prefix match on the iso root once killed a sibling
    # test run. Each recorded id is checked against the iso root first, so a
    # pid reused since is left alone, and the whole process group is signalled
    # (spawn_setsid puts each freenet under its own session, so this takes any
    # daemonized re-exec, child, or grandchild with it). Then check that what
    # we recorded is gone.
    local recorded=()
    for idfile in "$GW_PGIDFILE" "$PEER_PGIDFILE" "$GW_PIDFILE" "$PEER_PIDFILE"; do
        if [ -f "$idfile" ]; then
            local id
            id=$(cat "$idfile")
            if [ -n "$id" ]; then
                signal_recorded TERM "$id"
                recorded+=("$id")
            fi
            rm -f "$idfile"
        fi
    done
    # Verify the recorded groups died. One that survives the grace period gets
    # SIGKILL, and one that survives that is an error, not a quiet success:
    # the next `up` would race it for the ports.
    local alive=()
    for id in ${recorded[@]+"${recorded[@]}"}; do
        for _ in $(seq 1 20); do
            still_running "$id" || break
            sleep 0.25
        done
        if still_running "$id"; then
            signal_recorded KILL "$id"
            sleep 0.5
            if still_running "$id"; then
                alive+=("$id")
            fi
        fi
    done
    if [ "${#alive[@]}" -ne 0 ]; then
        echo "error: recorded iso node processes still running after SIGKILL: ${alive[*]}" >&2
        return 1
    fi
    # Nothing is killed by port, by open file or by command line: those reach
    # processes that are not ours. If something else still holds a port, say
    # so, and let `up` fail on the bind.
    if lsof -i :$GW_PORT_WS -i :$PEER_PORT_WS -P -sTCP:LISTEN >/dev/null 2>&1; then
        echo "warning: something not started by this script still listens on $GW_PORT_WS or $PEER_PORT_WS; not touching it" >&2
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
