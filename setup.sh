#!/usr/bin/env bash
# RALF — pre-execution command firewall for AI coding agents.
# One-command installer for Linux and macOS.
#
# Usage:
#   ./setup.sh                          interactive install
#   ./setup.sh --agent claude           install + wire Claude only
#   ./setup.sh --agent gemini           install + wire Gemini only
#   ./setup.sh --agent claude,gemini    install + wire both
#   ./setup.sh --agent all              install + wire every supported agent
#   ./setup.sh --agent none             install only, skip hook wiring
#   ./setup.sh --uninstall              remove hook from every wired agent
#   ./setup.sh --uninstall --agent X    remove hook from one agent only
#
# Environment:
#   RALF_AGENT=claude,gemini   same as --agent flag
#   RALF_AUTO_YES=1            accept all confirmations (non-interactive)
set -euo pipefail

# ─── colors ───────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m')
    RED=$(printf '\033[31m'); GREEN=$(printf '\033[32m')
    YELLOW=$(printf '\033[33m'); BLUE=$(printf '\033[34m')
    RESET=$(printf '\033[0m')
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; BLUE=""; RESET=""
fi

step()  { printf '%s==>%s %s\n' "$BLUE" "$RESET" "$*"; }
ok()    { printf '%s ✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '%s !%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail()  { printf '%s ✗%s %s\n' "$RED"   "$RESET" "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Supported agents. Keep in sync with ralf/scripts/install_hook.py::_AGENTS.
SUPPORTED_AGENTS=(claude gemini codex)
SELECTED_AGENTS=()

# Populated by resolve_pip() — may be "pip3", "pip", or "python3 -m pip".
PIP_CMD=""

# ─── OS detection ─────────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux*)   OS=linux ;;
        Darwin*)  OS=macos ;;
        *)        fail "Unsupported OS: $(uname -s). RALF supports Linux and macOS only." ;;
    esac
    ok "OS: $OS"
}

# ─── Python check ─────────────────────────────────────────────────────
check_python() {
    command -v python3 >/dev/null 2>&1 || fail "python3 not found in PATH"
    local v
    v="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
    local major minor
    major="${v%.*}"
    minor="${v#*.}"
    if (( major < 3 || (major == 3 && minor < 10) )); then
        fail "Python $v is too old. RALF requires 3.10+."
    fi
    ok "Python: $v"
}

# ─── pip resolver ─────────────────────────────────────────────────────
# macOS (Python 3.13+, Homebrew) ships pip3 but no ``pip`` symlink;
# some Linux distros ship neither and require ``python3 -m pip``. Try
# all three in order of preference and export PIP_CMD for every pip
# call below.
resolve_pip() {
    if command -v pip3 >/dev/null 2>&1; then
        PIP_CMD="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP_CMD="pip"
    elif python3 -m pip --version >/dev/null 2>&1; then
        PIP_CMD="python3 -m pip"
    else
        fail "No working pip found. Install pip for Python 3: 'python3 -m ensurepip --user'"
    fi
    ok "pip: $PIP_CMD"
}

# ─── pip install ──────────────────────────────────────────────────────
install_package() {
    step "Installing the ralf-free package into your user pip"
    # --no-build-isolation works around older system pip variants that
    # try to bootstrap setuptools into a system path under --user.
    if $PIP_CMD install --user -e "$REPO_ROOT" --no-build-isolation \
            >/tmp/ralf-free-pip.log 2>&1; then
        ok "Package installed (see ~/.local/lib/python*/site-packages/ralf*)"
    else
        warn "pip install failed. Tail of /tmp/ralf-free-pip.log:"
        tail -20 /tmp/ralf-free-pip.log
        fail "pip install failed — see log above"
    fi
}

uninstall_package() {
    step "Uninstalling the ralf-free package"
    $PIP_CMD uninstall -y ralf-free >/dev/null 2>&1 || true
    ok "Package removed"
}

# ─── compile rules ────────────────────────────────────────────────────
compile_rules() {
    step "Compiling the rule cache"
    if python3 -m ralf.shared.cli compile-rules >/dev/null 2>&1; then
        ok "Rules compiled to ~/.cache/ralf-free/rules.pkl"
    else
        warn "Rule compilation reported a non-zero exit (cache may still be usable)"
    fi
}

clear_cache() {
    rm -rf "${HOME}/.cache/ralf-free" 2>/dev/null || true
    ok "Cache cleared"
}

# ─── agent selection ──────────────────────────────────────────────────
# Populates the SELECTED_AGENTS array based on --agent flag, RALF_AGENT
# env var, or an interactive prompt.
select_agents() {
    if [[ ${#SELECTED_AGENTS[@]} -gt 0 ]]; then
        return  # already set via --agent flag
    fi
    if [[ -n "${RALF_AGENT:-}" ]]; then
        parse_agents_arg "$RALF_AGENT"
        return
    fi
    if [[ "${RALF_AUTO_YES:-}" == "1" ]]; then
        SELECTED_AGENTS=(claude)  # non-interactive default
        return
    fi
    cat <<EOF

${BOLD}Which agents should RALF wire up?${RESET}

  1) Claude Code only           (~/.claude/settings.json)
  2) Gemini CLI only            (~/.gemini/settings.json)
  3) Codex CLI only             (~/.codex/settings.json)
  4) All agents (Claude + Gemini + Codex)
  5) Skip hooks — pip install only

EOF
    local reply
    read -r -p "Select [1-5, default 1]: " reply
    case "${reply:-1}" in
        1) SELECTED_AGENTS=(claude) ;;
        2) SELECTED_AGENTS=(gemini) ;;
        3) SELECTED_AGENTS=(codex) ;;
        4) SELECTED_AGENTS=(claude gemini codex) ;;
        5) SELECTED_AGENTS=() ;;
        *) warn "unknown choice, defaulting to claude"; SELECTED_AGENTS=(claude) ;;
    esac
}

# Parse a comma-separated agent list (claude,gemini or "all" or "none").
parse_agents_arg() {
    local arg="$1"
    case "$arg" in
        all)  SELECTED_AGENTS=("${SUPPORTED_AGENTS[@]}"); return ;;
        none) SELECTED_AGENTS=(); return ;;
    esac
    SELECTED_AGENTS=()
    local IFS=,
    for a in $arg; do
        local matched=0
        for s in "${SUPPORTED_AGENTS[@]}"; do
            if [[ "$a" == "$s" ]]; then
                SELECTED_AGENTS+=("$a")
                matched=1
                break
            fi
        done
        if [[ $matched -eq 0 ]]; then
            fail "unknown agent: $a (supported: ${SUPPORTED_AGENTS[*]}, or 'all' / 'none')"
        fi
    done
}

# ─── settings.json edit — delegates to ralf.scripts.install_hook ──────
# The Python module handles backups, JSON merge, and the 'hook already
# present' check for every supported agent. We pass RALF_AUTO_YES
# through so the user is only prompted once (at select_agents time).
install_hook_for_agent() {
    local agent="$1"
    step "Wiring the hook for ${BOLD}${agent}${RESET}"
    if RALF_AUTO_YES="${RALF_AUTO_YES:-1}" \
       python3 -m ralf.shared.cli install-agent --agent "$agent"; then
        ok "${agent}: hook installed"
    else
        warn "${agent}: install failed (see error above)"
    fi
}

uninstall_hook_for_agent() {
    local agent="$1"
    step "Removing the hook for ${BOLD}${agent}${RESET}"
    python3 - "$agent" <<'PY' || true
import sys
from ralf.scripts.install_hook import uninstall_for_agent
sys.exit(uninstall_for_agent(sys.argv[1]))
PY
}

install_hooks() {
    if [[ ${#SELECTED_AGENTS[@]} -eq 0 ]]; then
        warn "No agents selected — skipping hook wiring"
        warn "Run 'ralf-free install-agent --agent claude|gemini' later"
        return
    fi
    for agent in "${SELECTED_AGENTS[@]}"; do
        install_hook_for_agent "$agent"
    done
}

uninstall_hooks() {
    # When uninstalling, default to removing from every supported agent
    # unless the user narrowed it with --agent.
    if [[ ${#SELECTED_AGENTS[@]} -eq 0 ]]; then
        SELECTED_AGENTS=("${SUPPORTED_AGENTS[@]}")
    fi
    for agent in "${SELECTED_AGENTS[@]}"; do
        uninstall_hook_for_agent "$agent"
    done
}

# ─── smoke test ───────────────────────────────────────────────────────
smoke_test() {
    step "Smoke test"
    local out

    # Case 1 — benign command should allow (exit 0).
    if out=$(python3 -m ralf.shared.cli test "ls /tmp" 2>&1); then
        ok "ls /tmp → allow"
    else
        warn "Smoke test 1 failed: $out"
    fi

    # Case 2 — malicious pattern should block. ``ralf-free test``
    # returns a non-zero exit code on a block verdict, so we cannot
    # gate on ``if ... then``. Capture stdout unconditionally with
    # ``|| true`` and inspect the output text.
    out=$(python3 -m ralf.shared.cli test "echo bad | crontab -" 2>&1 || true)
    if grep -qi "block" <<<"$out"; then
        ok "Malicious pattern → block"
    else
        warn "Malicious pattern unexpectedly allowed: $out"
    fi
}

# ─── summary ──────────────────────────────────────────────────────────
print_summary() {
    cat <<EOF

${BOLD}Install complete.${RESET}

  Status:    ralf-free status
  Test:      ralf-free test "<command>"
  Logs:      ralf-free logs -n 20
  Diagnose:  ralf-free doctor
  Pause:     ralf-free pause  /  ralf-free resume
  Dashboard: $PIP_CMD install --user -e '.[dashboard]' && ralf-free dashboard
             (quote '.[dashboard]' — zsh globs the [...] otherwise)
  Uninstall: ./setup.sh --uninstall

EOF
    if [[ ${#SELECTED_AGENTS[@]} -gt 0 ]]; then
        echo "Hooks wired for: ${SELECTED_AGENTS[*]}"
        echo "Restart the agent(s) for changes to take effect."
    else
        echo "No hooks wired. Run 'ralf-free install-agent --agent claude|gemini' when ready."
    fi
    echo
}

# ─── main ─────────────────────────────────────────────────────────────
parse_args() {
    local action=install
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall)
                action=uninstall ;;
            --agent)
                [[ $# -ge 2 ]] || fail "--agent requires an argument"
                parse_agents_arg "$2"
                shift ;;
            --agent=*)
                parse_agents_arg "${1#*=}" ;;
            --yes|-y)
                export RALF_AUTO_YES=1 ;;
            -h|--help)
                # Print the contiguous comment block at the top of this
                # script (after the shebang, before the first `set` line).
                awk 'NR==1{next} /^#/{sub(/^# ?/, ""); print; next} {exit}' "$0"
                exit 0 ;;
            *)
                fail "unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
    ACTION="$action"
}

main() {
    ACTION=install
    parse_args "$@"

    if [[ "$ACTION" == "uninstall" ]]; then
        printf '%sRALF — uninstall%s\n' "$BOLD" "$RESET"
        detect_os
        check_python
        resolve_pip
        uninstall_hooks
        uninstall_package
        clear_cache
        printf '\n%sUninstall complete.%s Audit logs and overrides preserved.\n\n' "$BOLD" "$RESET"
        return
    fi

    printf '%sRALF — pre-execution command firewall%s\n\n' "$BOLD" "$RESET"
    detect_os
    check_python
    resolve_pip
    install_package
    compile_rules
    select_agents
    install_hooks
    smoke_test
    print_summary
}

main "$@"
