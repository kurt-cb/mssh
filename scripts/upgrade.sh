#!/bin/sh
# msshd — host upgrade / install / verify / rollback.
#
# POSIX sh (works under ash, busybox sh, bash). Run as root on the
# target host:
#
#   scp upgrade.sh root@target-host:/root/
#   ssh root@target-host
#   chmod +x upgrade.sh
#   ./upgrade.sh install     # phase 1 — fallback-mode msshd alongside sshd
#   ./upgrade.sh verify-1    # confirm SSH still works through msshd
#   ./upgrade.sh enforce     # phase 2 — switch msshd to CA-enforced
#   ./upgrade.sh verify-2    # confirm CA-mediated auth works
#   ./upgrade.sh cutover     # phase 3 — move msshd to port 22
#   ./upgrade.sh verify-3    # confirm port 22 still works
#   ./upgrade.sh rollback    # at any point: restore original sshd state
#
# DESIGN PRINCIPLES
# - **Never lock out the operator.** Each phase keeps the previous
#   path open until the operator explicitly cuts over. The original
#   system sshd on port 22 is untouched in phases 1 and 2.
# - **Fallback-by-default.** msshd installs in transparent-proxy
#   mode (no CA call, no cert mint — just byte-forward to system sshd).
#   This proves msshd is wired up without changing auth behavior.
# - **Operator verifies every phase from a SECOND terminal.** The
#   script prompts; the operator confirms before the next phase. If a
#   phase breaks something, the operator's current SSH session (in the
#   first terminal) is the rollback escape.
# - **Idempotent where possible.** Re-running a completed phase should
#   be a no-op or a clean re-install.
#
# This script is **provisioning glue**, not a full installer. It assumes
# the msshd package has been delivered to the host (e.g.,
# distro package, tarball under /opt, or a binary copied alongside this
# script). The actual binary names / paths are configurable below.

set -eu

# ---------------------------------------------------------------------------
# Configuration — operator may override these via env vars before running.
# ---------------------------------------------------------------------------

MSSHD_BIN="${MSSHD_BIN:-/usr/local/bin/msshd}"
MSSHD_ADMIN_BIN="${MSSHD_ADMIN_BIN:-/usr/sbin/msshd-admin}"
MSSHD_PKG="${MSSHD_PKG:-/root/msshd.tar.gz}"
                # tarball or .deb/.rpm path; install logic below picks
                # the right tool based on what's present.

MSSHD_CONFIG_DIR="${MSSHD_CONFIG_DIR:-/etc/mssh}"
MSSHD_STATE_DIR="${MSSHD_STATE_DIR:-/var/lib/mssh}"
MSSHD_CONFIG="${MSSHD_CONFIG:-${MSSHD_CONFIG_DIR}/msshd.yaml}"

# Phase 1 port: msshd lives here in fallback mode, doesn't disrupt
# the system sshd on 22.
MSSHD_PORT_INITIAL="${MSSHD_PORT_INITIAL:-2200}"

# Phase 3 cutover port (typically 22; can be overridden if the operator
# wants to keep system sshd on a non-22 port permanently).
MSSHD_PORT_FINAL="${MSSHD_PORT_FINAL:-22}"

# CA endpoint — required for phase 2 (enforce). Will be prompted for
# if not pre-set in env or in msshd.yaml already.
CA_ENDPOINTS="${CA_ENDPOINTS:-}"

# Backup directory for files we change; restored by rollback.
BACKUP_DIR="${BACKUP_DIR:-/var/backups/mssh-upgrade}"

# State file tracks which phase we're at — rollback uses it to know what
# to undo.
STATE_FILE="${STATE_FILE:-${BACKUP_DIR}/phase.state}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

confirm() {
    # $1 = prompt; returns 0 if user says yes, 1 otherwise.
    printf '%s [y/N]: ' "$1" >&2
    read -r ans || return 1
    case "$ans" in
        y|Y|yes|YES) return 0 ;;
        *)           return 1 ;;
    esac
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "must be run as root"
}

backup() {
    # $1 = absolute path to back up. Idempotent — won't overwrite an
    # existing backup if one already exists for this path.
    src="$1"
    [ -e "$src" ] || return 0
    mkdir -p "$BACKUP_DIR"
    # Replace / with __ in the backup filename so we can flatten the tree.
    dst="${BACKUP_DIR}/$(printf '%s' "$src" | sed 's|/|__|g').orig"
    if [ ! -e "$dst" ]; then
        cp -p "$src" "$dst"
        log "backed up $src → $dst"
    else
        log "backup of $src already exists at $dst (skipping)"
    fi
}

restore() {
    # $1 = absolute path to restore from the backup dir.
    src="$1"
    dst="${BACKUP_DIR}/$(printf '%s' "$src" | sed 's|/|__|g').orig"
    if [ -e "$dst" ]; then
        cp -p "$dst" "$src"
        log "restored $src from $dst"
    fi
}

set_phase() {
    mkdir -p "$BACKUP_DIR"
    printf '%s\n' "$1" > "$STATE_FILE"
}

get_phase() {
    if [ -r "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "none"; fi
}

is_systemd() {
    [ -d /run/systemd/system ]
}

service_running() {
    # Returns 0 if a service is active. Tries systemd first, then
    # falls back to rc-service (OpenRC) and finally to a process check.
    name="$1"
    if is_systemd; then
        systemctl is-active --quiet "$name" 2>/dev/null && return 0
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$name" status >/dev/null 2>&1 && return 0
    else
        pgrep -x "$name" >/dev/null 2>&1 && return 0
    fi
    return 1
}

service_action() {
    # $1 = action (start/stop/restart/enable/disable)
    # $2 = service name
    action="$1"; name="$2"
    if is_systemd; then
        systemctl "$action" "$name"
    elif command -v rc-service >/dev/null 2>&1; then
        case "$action" in
            enable)  rc-update add "$name" default ;;
            disable) rc-update del "$name" default ;;
            *)       rc-service "$name" "$action" ;;
        esac
    else
        warn "no service manager detected — '$action $name' must be done manually"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

cmd_install() {
    require_root
    log "Phase 1: installing msshd in FALLBACK mode (system sshd untouched)"

    # 1. Sanity: ensure system sshd is up and reachable. We're about to
    #    install something that will forward to it.
    if ! service_running sshd && ! service_running ssh; then
        die "system sshd not running — refusing to proceed. msshd " \
            "in fallback mode forwards to the system sshd; if it's down, " \
            "you'd lock yourself out."
    fi

    # 2. Install msshd package if not present.
    if [ ! -x "$MSSHD_BIN" ]; then
        log "msshd binary not at $MSSHD_BIN; attempting install"
        if [ -e "$MSSHD_PKG" ]; then
            case "$MSSHD_PKG" in
                *.deb) dpkg -i "$MSSHD_PKG" || apt-get install -f -y ;;
                *.rpm) rpm -i --replacepkgs "$MSSHD_PKG" || \
                       (command -v dnf >/dev/null && dnf install -y "$MSSHD_PKG") || \
                       (command -v yum >/dev/null && yum install -y "$MSSHD_PKG") ;;
                *.tar.gz|*.tgz)
                       tar -C / -xzf "$MSSHD_PKG" ;;
                *.apk) apk add --allow-untrusted "$MSSHD_PKG" ;;
                *)     die "unknown package format: $MSSHD_PKG" ;;
            esac
        else
            die "msshd not installed and no package at $MSSHD_PKG. " \
                "Set MSSHD_PKG=... or install msshd package first."
        fi
    fi
    [ -x "$MSSHD_BIN" ] || die "msshd still not installed at $MSSHD_BIN"

    # 3. Create config + state dirs.
    mkdir -p "$MSSHD_CONFIG_DIR" "$MSSHD_STATE_DIR"
    chmod 0750 "$MSSHD_CONFIG_DIR" "$MSSHD_STATE_DIR"

    # 4. Write a minimal fallback-mode config.
    backup "$MSSHD_CONFIG"
    cat > "$MSSHD_CONFIG" <<EOF
# Generated by upgrade.sh — phase 1 (fallback mode).
# Edit /etc/mssh/msshd.yaml to customise.
mode: fallback
fallback:
  host: 127.0.0.1
  port: 22
listen:
  external_address: 0.0.0.0
  external_port: ${MSSHD_PORT_INITIAL}
  interfaces: []
# Other sections (tls, ca, users, ...) populated in phase 2 (enforce).
EOF
    chmod 0640 "$MSSHD_CONFIG"
    log "wrote $MSSHD_CONFIG (fallback mode, port $MSSHD_PORT_INITIAL)"

    # 5. Enable + start msshd service.
    if is_systemd; then
        service_action enable msshd
        service_action start  msshd
    elif command -v rc-service >/dev/null 2>&1; then
        service_action enable msshd
        service_action start  msshd
    else
        warn "no service manager detected — please start msshd manually:"
        warn "  $MSSHD_BIN --config $MSSHD_CONFIG &"
    fi

    set_phase 'installed-fallback'

    cat <<EOF

================================================================
Phase 1 complete. msshd is running in FALLBACK mode on port
${MSSHD_PORT_INITIAL}, transparently proxying to system sshd on
127.0.0.1:22. System sshd remains the actual auth surface.

NEXT STEP — verify from a SECOND terminal (keep this one open):

  ssh -p ${MSSHD_PORT_INITIAL} <your-user>@<this-host>

You should land in a normal shell, authenticated by the system sshd
exactly as before. If that works, run:

  ./upgrade.sh verify-1

If it doesn't, run:

  ./upgrade.sh rollback

================================================================
EOF
}

cmd_verify_1() {
    require_root
    [ "$(get_phase)" = 'installed-fallback' ] || \
        warn "current phase is '$(get_phase)', expected 'installed-fallback'"

    log "verify-1: msshd health-checks (fallback mode)"

    if ! service_running msshd; then
        die "msshd is not running"
    fi

    if ! ss -ltn 2>/dev/null | grep -q ":${MSSHD_PORT_INITIAL}\b" && \
       ! netstat -ltn 2>/dev/null | grep -q ":${MSSHD_PORT_INITIAL}\b"; then
        die "nothing listening on port $MSSHD_PORT_INITIAL"
    fi

    log "msshd is running and bound to port $MSSHD_PORT_INITIAL"
    log "verify access via:  ssh -p $MSSHD_PORT_INITIAL <user>@<this-host>"

    set_phase 'verified-fallback'
    cat <<EOF

Phase 1 verification complete. Next step (when ready):

  ./upgrade.sh enforce

EOF
}

cmd_enforce() {
    require_root

    # Require phase 1 verified — defensive, not absolute.
    case "$(get_phase)" in
        verified-fallback|installed-fallback) ;;
        *) warn "unexpected current phase '$(get_phase)' — proceeding anyway" ;;
    esac

    log "Phase 2: switching msshd to ENFORCE mode (CA-mediated auth)"

    # Need CA endpoint + mTLS material.
    if [ -z "$CA_ENDPOINTS" ]; then
        printf 'CA endpoint URL (e.g. https://ca.internal:8443): ' >&2
        read -r CA_ENDPOINTS
        [ -n "$CA_ENDPOINTS" ] || die "CA endpoint required for enforce mode"
    fi

    for f in "$MSSHD_CONFIG_DIR/msshd-server.crt" \
             "$MSSHD_CONFIG_DIR/msshd-server.key" \
             "$MSSHD_CONFIG_DIR/user-ca.pub" \
             "$MSSHD_CONFIG_DIR/msshd-mtls.crt" \
             "$MSSHD_CONFIG_DIR/msshd-mtls.key" \
             "$MSSHD_CONFIG_DIR/server-mtls-ca.pub"; do
        [ -r "$f" ] || die "missing required cert/key file: $f " \
                          "(provision via mssh-admin server add + copy)"
    done

    # Rewrite config with enforce mode.
    backup "$MSSHD_CONFIG"
    cat > "$MSSHD_CONFIG" <<EOF
# Generated by upgrade.sh — phase 2 (enforce mode).
mode: enforce

listen:
  external_address: 0.0.0.0
  external_port: ${MSSHD_PORT_INITIAL}
  interfaces: []

tls:
  server_cert: ${MSSHD_CONFIG_DIR}/msshd-server.crt
  server_key:  ${MSSHD_CONFIG_DIR}/msshd-server.key
  user_ca_pubkey: ${MSSHD_CONFIG_DIR}/user-ca.pub

ca:
  endpoints:
    - ${CA_ENDPOINTS}
  client_cert: ${MSSHD_CONFIG_DIR}/msshd-mtls.crt
  client_key:  ${MSSHD_CONFIG_DIR}/msshd-mtls.key
  ca_pubkey:   ${MSSHD_CONFIG_DIR}/server-mtls-ca.pub
  timeout_seconds: 5

inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]

users:
  # POPULATE THIS — msshd will deny connections for usernames not listed.
  allowed: []

logging:
  level: info
  destination: syslog
  audit_destination: file:/var/log/mssh/msshd-audit.jsonl
EOF
    chmod 0640 "$MSSHD_CONFIG"

    # Initialise the local user-CA if it doesn't exist yet.
    if [ -x "$MSSHD_ADMIN_BIN" ] && \
       [ ! -e "${MSSHD_STATE_DIR}/msshd-user-ca" ]; then
        log "initialising local user-CA via $MSSHD_ADMIN_BIN init"
        "$MSSHD_ADMIN_BIN" init
    fi

    # Pre-flight: lint the config + check CA reachability.
    if [ -x "$MSSHD_ADMIN_BIN" ]; then
        log "running $MSSHD_ADMIN_BIN lint"
        if ! "$MSSHD_ADMIN_BIN" lint; then
            die "msshd lint failed — refusing to restart. Fix issues and re-run."
        fi
    else
        warn "$MSSHD_ADMIN_BIN not present; skipping pre-flight lint"
    fi

    service_action restart msshd

    set_phase 'enforced'

    cat <<EOF

================================================================
Phase 2 complete. msshd is now in ENFORCE mode on port
${MSSHD_PORT_INITIAL}. System sshd on port 22 is STILL RUNNING
as the rollback escape.

NEXT STEP — verify CA-mediated auth from a SECOND terminal:

  mssh -p ${MSSHD_PORT_INITIAL} <enrolled-user>@<this-host>

The user must be enrolled at the CA with a policy granting access.
If verification succeeds, run:

  ./upgrade.sh verify-2

If it fails:

  ./upgrade.sh rollback

(rollback returns msshd to fallback mode; system sshd was
never touched, so port 22 still works regardless.)

================================================================
EOF
}

cmd_verify_2() {
    require_root
    [ "$(get_phase)" = 'enforced' ] || \
        warn "current phase is '$(get_phase)', expected 'enforced'"

    log "verify-2: confirming CA-enforcing msshd is healthy"
    if ! service_running msshd; then
        die "msshd is not running"
    fi
    if [ -x "$MSSHD_ADMIN_BIN" ]; then
        "$MSSHD_ADMIN_BIN" lint || die "lint failed in enforce mode"
    fi
    log "OK — msshd is enforcing"

    set_phase 'verified-enforced'
    cat <<EOF

Phase 2 verification complete. Next step (when ready):

  ./upgrade.sh cutover

This moves msshd to port ${MSSHD_PORT_FINAL} and stops the
system sshd. AFTER cutover, your only SSH entry point is msshd —
make sure you have a working enrollment and a way back in.
EOF
}

cmd_cutover() {
    require_root

    log "Phase 3: cutover — moving msshd to port $MSSHD_PORT_FINAL"

    case "$(get_phase)" in
        verified-enforced) ;;
        *) confirm "Current phase is '$(get_phase)', not 'verified-enforced'. Cut over anyway?" || \
               die "aborting cutover" ;;
    esac

    confirm "FINAL CONFIRMATION. After cutover, port $MSSHD_PORT_FINAL is msshd, system sshd is stopped. Continue?" || \
        die "aborting cutover"

    # 1. Stop the system sshd. (Note: this disconnects no existing sessions —
    #    they survive sshd restarts.)
    if service_running sshd; then
        service_action stop sshd
    elif service_running ssh; then
        service_action stop ssh
    fi

    # 2. Rewrite msshd.yaml with port $MSSHD_PORT_FINAL.
    sed -i.bak \
        "s|external_port: ${MSSHD_PORT_INITIAL}|external_port: ${MSSHD_PORT_FINAL}|" \
        "$MSSHD_CONFIG"

    # 3. Restart msshd.
    service_action restart msshd

    # 4. Disable system sshd from autostart.
    if service_running sshd 2>/dev/null; then service_action disable sshd || true; fi
    if service_running ssh  2>/dev/null; then service_action disable ssh  || true; fi

    set_phase 'cutover'

    cat <<EOF

================================================================
Phase 3 (cutover) complete. msshd is now on port
${MSSHD_PORT_FINAL}. System sshd is stopped and disabled.

NEXT STEP — verify from a SECOND terminal:

  mssh <enrolled-user>@<this-host>

If this works, you're done — run:

  ./upgrade.sh verify-3

If it doesn't:

  ./upgrade.sh rollback

(rollback re-enables and starts system sshd, returns msshd to
fallback mode on port ${MSSHD_PORT_INITIAL}.)

================================================================
EOF
}

cmd_verify_3() {
    require_root
    [ "$(get_phase)" = 'cutover' ] || \
        warn "current phase is '$(get_phase)', expected 'cutover'"

    log "verify-3: confirming msshd is healthy on port $MSSHD_PORT_FINAL"
    if ! service_running msshd; then
        die "msshd is not running"
    fi
    if ! ss -ltn 2>/dev/null | grep -q ":${MSSHD_PORT_FINAL}\b" && \
       ! netstat -ltn 2>/dev/null | grep -q ":${MSSHD_PORT_FINAL}\b"; then
        die "msshd not listening on $MSSHD_PORT_FINAL"
    fi
    log "OK — msshd is on port $MSSHD_PORT_FINAL"

    set_phase 'verified-cutover'
    cat <<EOF

================================================================
Upgrade complete. msshd is the SSH entry point for
this host. System sshd is stopped and disabled.

Periodic verification (e.g. via cron, monitoring):

  $MSSHD_ADMIN_BIN lint
  systemctl is-active msshd

To roll back at any time: ./upgrade.sh rollback

================================================================
EOF
}

cmd_rollback() {
    require_root
    phase="$(get_phase)"
    log "Rolling back from phase '$phase'"

    # 1. Make sure system sshd is up first — it's the safety net.
    if ! service_running sshd && ! service_running ssh; then
        # Re-enable + start.
        if is_systemd; then
            systemctl enable sshd 2>/dev/null || systemctl enable ssh 2>/dev/null || true
            systemctl start  sshd 2>/dev/null || systemctl start  ssh 2>/dev/null || true
        elif command -v rc-service >/dev/null 2>&1; then
            rc-update add sshd default 2>/dev/null || \
                rc-update add ssh default 2>/dev/null || true
            rc-service sshd start 2>/dev/null || rc-service ssh start 2>/dev/null || true
        fi
    fi

    # 2. Stop msshd.
    if service_running msshd; then
        service_action stop msshd
    fi

    # 3. If we're past phase 1, restore the original msshd config (the
    #    one we backed up). If we're at phase 1, just remove ours.
    case "$phase" in
        installed-fallback|verified-fallback)
            # We installed msshd but never went to enforce.
            # Disable the service; leave the config behind for inspection.
            service_action disable msshd || true
            ;;
        enforced|verified-enforced|cutover|verified-cutover)
            # Restore the fallback-mode msshd config from backup, or
            # just rewrite it.
            restore "$MSSHD_CONFIG"
            # Make sure mode is fallback.
            if [ -e "$MSSHD_CONFIG" ]; then
                sed -i.bak 's|^mode:.*|mode: fallback|' "$MSSHD_CONFIG"
            fi
            service_action disable msshd || true
            ;;
        *)
            log "no msshd state to roll back from phase '$phase'"
            ;;
    esac

    log "rollback complete. System sshd should be operational on its " \
        "original port. Verify by SSHing in normally."
    set_phase 'rolled-back'
}

cmd_uninstall() {
    require_root
    log "Uninstalling msshd entirely"

    cmd_rollback || true

    # Remove config / state.
    if [ -d "$MSSHD_CONFIG_DIR" ]; then
        confirm "Remove $MSSHD_CONFIG_DIR (config + keys)?" && \
            rm -rf "$MSSHD_CONFIG_DIR"
    fi
    if [ -d "$MSSHD_STATE_DIR" ]; then
        confirm "Remove $MSSHD_STATE_DIR (state, user-CA key)?" && \
            rm -rf "$MSSHD_STATE_DIR"
    fi
    log "uninstall complete. System sshd untouched."
}

cmd_status() {
    require_root
    cat <<EOF
upgrade.sh status
  current phase:       $(get_phase)
  msshd binary:      $MSSHD_BIN $([ -x "$MSSHD_BIN" ] && echo '(present)' || echo '(MISSING)')
  msshd service:     $(service_running msshd && echo 'running' || echo 'not running')
  system sshd:         $(service_running sshd && echo 'running' || service_running ssh && echo 'running' || echo 'not running')
  msshd config:      $MSSHD_CONFIG
  backup dir:          $BACKUP_DIR
EOF
}

cmd_help() {
    cat <<'EOF'
msshd — host upgrade tool

Usage:
  upgrade.sh install     Phase 1: install msshd in FALLBACK mode
  upgrade.sh verify-1    Phase 1 health check
  upgrade.sh enforce     Phase 2: switch to CA-mediated auth (still on alt port)
  upgrade.sh verify-2    Phase 2 health check
  upgrade.sh cutover     Phase 3: move msshd to port 22; stop system sshd
  upgrade.sh verify-3    Phase 3 health check
  upgrade.sh rollback    Restore system sshd; disable msshd (works from any phase)
  upgrade.sh uninstall   Remove msshd entirely
  upgrade.sh status      Show current phase + service status

Environment overrides (run with `VAR=value ./upgrade.sh ...`):
  MSSHD_BIN, MSSHD_PKG, MSSHD_CONFIG_DIR, MSSHD_STATE_DIR,
  MSSHD_PORT_INITIAL (default 2200), MSSHD_PORT_FINAL (default 22),
  CA_ENDPOINTS

Phase summary:
  install → verify-1 → enforce → verify-2 → cutover → verify-3
                                  ↑                        ↓
                                  rollback ←——————— rollback
EOF
}

# ---------------------------------------------------------------------------
# Entry
# ---------------------------------------------------------------------------

cmd="${1:-help}"
case "$cmd" in
    install)    cmd_install ;;
    verify-1)   cmd_verify_1 ;;
    enforce)    cmd_enforce ;;
    verify-2)   cmd_verify_2 ;;
    cutover)    cmd_cutover ;;
    verify-3)   cmd_verify_3 ;;
    rollback)   cmd_rollback ;;
    uninstall)  cmd_uninstall ;;
    status)     cmd_status ;;
    help|-h|--help) cmd_help ;;
    *) die "unknown command: $cmd (try './upgrade.sh help')" ;;
esac
