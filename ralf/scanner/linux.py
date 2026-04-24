"""Linux hardening checks — 55 checks covering firewall, encryption, SSH, etc.

Lightweight state scanners.
Each check is registered via :func:`ralf.scanner.checks.register`.
CIS Ubuntu 22.04 LTS benchmark cross-references included where applicable.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from ralf.scanner import CheckResult
from ralf.scanner.checks import register

log = logging.getLogger(__name__)

_PLAT = ("linux",)
_CAT = "host_hardening"


def _run_cmd(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="command not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr="timeout")


def _read_file(path: str) -> str:
    """Read a file, return empty string on error."""
    try:
        return Path(path).read_text()
    except (OSError, PermissionError):
        return ""


def _sysctl_val(key: str) -> str:
    """Read a sysctl value, return empty string on error."""
    r = _run_cmd(["sysctl", "-n", key])
    return r.stdout.strip() if r.returncode == 0 else ""


def _file_perms(path: str) -> int | None:
    """Return octal permission bits, or None if unreadable."""
    try:
        return os.stat(path).st_mode & 0o777
    except OSError:
        return None


def _ssh_config_value(key: str) -> str | None:
    """Return the first non-commented value for *key* in sshd_config, or None."""
    content = _read_file("/etc/ssh/sshd_config")
    if not content:
        return None
    needle = key.lower()
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0].lower() == needle:
            return tokens[1]
    return None


def _service_active(name: str) -> bool:
    """Return True if systemd unit *name* is currently active."""
    r = _run_cmd(["systemctl", "is-active", name])
    return r.returncode == 0 and r.stdout.strip() == "active"


# ── 1. Firewall ────────────────────────────────────────────────────────
# Lightweight port of FirewallScanner: just check if a firewall is active.


@register(
    id="linux_firewall",
    name="Linux Firewall Active",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_linux_firewall() -> CheckResult:
    # Try ufw first
    r = _run_cmd(["ufw", "status"])
    if r.returncode == 0 and "active" in r.stdout.lower():
        return CheckResult(
            check_id="linux_firewall",
            name="Linux Firewall Active",
            category=_CAT,
            status="pass",
            detail="ufw firewall is active",
            remediation="",
            severity="high",
            score_delta=0,
        )

    # Try nftables
    r = _run_cmd(["nft", "list", "ruleset"])
    if r.returncode == 0 and r.stdout.strip():
        return CheckResult(
            check_id="linux_firewall",
            name="Linux Firewall Active",
            category=_CAT,
            status="pass",
            detail="nftables rules are loaded",
            remediation="",
            severity="high",
            score_delta=0,
        )

    # Try iptables — check if default INPUT policy is DROP/REJECT
    r = _run_cmd(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
    if r.returncode == 0 and ("DROP" in r.stdout or "REJECT" in r.stdout):
        return CheckResult(
            check_id="linux_firewall",
            name="Linux Firewall Active",
            category=_CAT,
            status="pass",
            detail="iptables has DROP/REJECT rules",
            remediation="",
            severity="high",
            score_delta=0,
        )

    return CheckResult(
        check_id="linux_firewall",
        name="Linux Firewall Active",
        category=_CAT,
        status="fail",
        detail="No active firewall detected (ufw/nftables/iptables)",
        remediation="Run: sudo ufw enable",
        severity="high",
        score_delta=-10,
    )


# ── 2. Disk Encryption ────────────────────────────────────────────────


@register(
    id="linux_disk_encryption",
    name="LUKS Disk Encryption",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_linux_disk_encryption() -> CheckResult:
    r = _run_cmd(["lsblk", "-o", "NAME,FSTYPE", "--noheadings"])
    has_luks = "crypto_LUKS" in r.stdout
    return CheckResult(
        check_id="linux_disk_encryption",
        name="LUKS Disk Encryption",
        category=_CAT,
        status="pass" if has_luks else "fail",
        detail="LUKS encryption detected" if has_luks else "No LUKS encryption found on any partition",
        remediation="Encrypt disk with LUKS at install time or migrate with cryptsetup",
        severity="high",
        score_delta=0 if has_luks else -10,
    )


# ── 3. SSH PermitRootLogin ─────────────────────────────────────────────


@register(
    id="linux_ssh_root",
    name="SSH PermitRootLogin Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_linux_ssh_root() -> CheckResult:
    content = _read_file("/etc/ssh/sshd_config")
    if not content:
        return CheckResult(
            check_id="linux_ssh_root",
            name="SSH PermitRootLogin Disabled",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/ssh/sshd_config",
            remediation="",
            severity="high",
            score_delta=0,
        )
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0].lower() == "permitrootlogin":
            val = tokens[1].lower()
            if val == "no" or val == "prohibit-password":
                return CheckResult(
                    check_id="linux_ssh_root",
                    name="SSH PermitRootLogin Disabled",
                    category=_CAT,
                    status="pass",
                    detail=f"PermitRootLogin = {tokens[1]}",
                    remediation="",
                    severity="high",
                    score_delta=0,
                )
            return CheckResult(
                check_id="linux_ssh_root",
                name="SSH PermitRootLogin Disabled",
                category=_CAT,
                status="fail",
                detail=f"PermitRootLogin = {tokens[1]}",
                remediation=(
                    "Edit /etc/ssh/sshd_config: set PermitRootLogin no, "
                    "then: sudo systemctl restart sshd"
                ),
                severity="high",
                score_delta=-8,
            )
    # Default (no explicit setting): depends on distro, treat as warn
    return CheckResult(
        check_id="linux_ssh_root",
        name="SSH PermitRootLogin Disabled",
        category=_CAT,
        status="warn",
        detail="PermitRootLogin not explicitly set (default varies by distro)",
        remediation=(
            "Explicitly set PermitRootLogin no in /etc/ssh/sshd_config, "
            "then: sudo systemctl restart sshd"
        ),
        severity="high",
        score_delta=-4,
    )


# ── 4. SSH PasswordAuthentication ──────────────────────────────────────


@register(
    id="linux_ssh_password",
    name="SSH PasswordAuthentication Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_ssh_password() -> CheckResult:
    content = _read_file("/etc/ssh/sshd_config")
    if not content:
        return CheckResult(
            check_id="linux_ssh_password",
            name="SSH PasswordAuthentication Disabled",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/ssh/sshd_config",
            remediation="",
            severity="medium",
            score_delta=0,
        )
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0].lower() == "passwordauthentication":
            val = tokens[1].lower()
            disabled = val == "no"
            return CheckResult(
                check_id="linux_ssh_password",
                name="SSH PasswordAuthentication Disabled",
                category=_CAT,
                status="pass" if disabled else "warn",
                detail=f"PasswordAuthentication = {tokens[1]}",
                remediation=(
                    "" if disabled else
                    "Edit /etc/ssh/sshd_config: set PasswordAuthentication no, "
                    "then: sudo systemctl restart sshd"
                ),
                severity="medium",
                score_delta=0 if disabled else -5,
            )
    return CheckResult(
        check_id="linux_ssh_password",
        name="SSH PasswordAuthentication Disabled",
        category=_CAT,
        status="warn",
        detail="PasswordAuthentication not explicitly set",
        remediation=(
            "Set PasswordAuthentication no in /etc/ssh/sshd_config, "
            "then: sudo systemctl restart sshd"
        ),
        severity="medium",
        score_delta=-3,
    )


# ── 5. AppArmor / SELinux ──────────────────────────────────────────────


@register(
    id="linux_apparmor",
    name="AppArmor/SELinux Enforcing",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_apparmor() -> CheckResult:
    # Try SELinux
    r = _run_cmd(["getenforce"])
    if r.returncode == 0:
        mode = r.stdout.strip().lower()
        if mode == "enforcing":
            return CheckResult(
                check_id="linux_apparmor",
                name="AppArmor/SELinux Enforcing",
                category=_CAT,
                status="pass",
                detail="SELinux is in Enforcing mode",
                remediation="",
                severity="medium",
                score_delta=0,
            )
        return CheckResult(
            check_id="linux_apparmor",
            name="AppArmor/SELinux Enforcing",
            category=_CAT,
            status="warn",
            detail=f"SELinux is {r.stdout.strip()} (not Enforcing)",
            remediation="Run: sudo setenforce 1; edit /etc/selinux/config SELINUX=enforcing",
            severity="medium",
            score_delta=-5,
        )

    # Try AppArmor
    r = _run_cmd(["aa-status", "--json"])
    if r.returncode == 0:
        return CheckResult(
            check_id="linux_apparmor",
            name="AppArmor/SELinux Enforcing",
            category=_CAT,
            status="pass",
            detail="AppArmor is active",
            remediation="",
            severity="medium",
            score_delta=0,
        )

    # Check if AppArmor module is loaded via /sys
    if Path("/sys/module/apparmor").exists():
        return CheckResult(
            check_id="linux_apparmor",
            name="AppArmor/SELinux Enforcing",
            category=_CAT,
            status="pass",
            detail="AppArmor kernel module is loaded",
            remediation="",
            severity="medium",
            score_delta=0,
        )

    return CheckResult(
        check_id="linux_apparmor",
        name="AppArmor/SELinux Enforcing",
        category=_CAT,
        status="warn",
        detail="Neither AppArmor nor SELinux detected",
        remediation="Install and enable AppArmor: sudo apt install apparmor apparmor-utils && sudo systemctl enable --now apparmor",
        severity="medium",
        score_delta=-5,
    )


# ── 6. Non-Root User ──────────────────────────────────────────────────


@register(
    id="linux_nonroot_user",
    name="Not Running as Root",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_linux_nonroot_user() -> CheckResult:
    is_root = os.geteuid() == 0
    return CheckResult(
        check_id="linux_nonroot_user",
        name="Not Running as Root",
        category=_CAT,
        status="pass" if not is_root else "fail",
        detail="Running as non-root user" if not is_root else "Running as root (UID 0)",
        remediation="Create a non-root user and run agents as that user",
        severity="high",
        score_delta=0 if not is_root else -10,
    )


# ── 7. /etc/shadow Permissions ─────────────────────────────────────────


@register(
    id="linux_shadow_perms",
    name="/etc/shadow Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_linux_shadow_perms() -> CheckResult:
    perms = _file_perms("/etc/shadow")
    if perms is None:
        return CheckResult(
            check_id="linux_shadow_perms",
            name="/etc/shadow Permissions",
            category=_CAT,
            status="skip",
            detail="Cannot stat /etc/shadow",
            remediation="",
            severity="high",
            score_delta=0,
        )
    ok = perms <= 0o640
    return CheckResult(
        check_id="linux_shadow_perms",
        name="/etc/shadow Permissions",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"/etc/shadow permissions: {oct(perms)}",
        remediation="Run: sudo chmod 640 /etc/shadow",
        severity="high",
        score_delta=0 if ok else -8,
    )


# ── 8. /etc/sudoers Permissions ────────────────────────────────────────


@register(
    id="linux_sudoers_perms",
    name="/etc/sudoers Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_sudoers_perms() -> CheckResult:
    perms = _file_perms("/etc/sudoers")
    if perms is None:
        return CheckResult(
            check_id="linux_sudoers_perms",
            name="/etc/sudoers Permissions",
            category=_CAT,
            status="skip",
            detail="Cannot stat /etc/sudoers",
            remediation="",
            severity="medium",
            score_delta=0,
        )
    ok = perms <= 0o440
    return CheckResult(
        check_id="linux_sudoers_perms",
        name="/etc/sudoers Permissions",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"/etc/sudoers permissions: {oct(perms)}",
        remediation="Run: sudo chmod 440 /etc/sudoers",
        severity="medium",
        score_delta=0 if ok else -5,
    )


# ── 9. SUID Binaries ──────────────────────────────────────────────────


@register(
    id="linux_suid_binaries",
    name="SUID Binary Count",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_suid_binaries() -> CheckResult:
    # Scan common system paths instead of full filesystem
    search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
    count = 0
    for sp in search_paths:
        r = _run_cmd(
            ["find", sp, "-perm", "-4000", "-type", "f"],
            timeout=15,
        )
        if r.returncode == 0:
            count += len([l for l in r.stdout.strip().splitlines() if l])

    ok = count <= 30
    return CheckResult(
        check_id="linux_suid_binaries",
        name="SUID Binary Count",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"{count} SUID binaries found" + ("" if ok else " (high count — audit recommended)"),
        remediation="Audit SUID binaries: find / -perm -4000 -type f -ls",
        severity="medium",
        score_delta=0 if ok else -3,
    )


# ── 10. IP Forwarding ─────────────────────────────────────────────────


@register(
    id="linux_kernel_forwarding",
    name="IP Forwarding Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_kernel_forwarding() -> CheckResult:
    val = _sysctl_val("net.ipv4.ip_forward")
    disabled = val == "0"
    return CheckResult(
        check_id="linux_kernel_forwarding",
        name="IP Forwarding Disabled",
        category=_CAT,
        status="pass" if disabled else "warn",
        detail="IP forwarding is disabled" if disabled else f"IP forwarding is enabled (net.ipv4.ip_forward = {val})",
        remediation="Run: sudo sysctl -w net.ipv4.ip_forward=0; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if disabled else -5,
    )


# ── 11. Core Dumps ────────────────────────────────────────────────────


@register(
    id="linux_core_dumps",
    name="Core Dumps Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_core_dumps() -> CheckResult:
    val = _sysctl_val("fs.suid_dumpable")
    disabled = val == "0"
    return CheckResult(
        check_id="linux_core_dumps",
        name="Core Dumps Disabled",
        category=_CAT,
        status="pass" if disabled else "warn",
        detail="SUID core dumps disabled" if disabled else f"fs.suid_dumpable = {val} (should be 0)",
        remediation="Run: sudo sysctl -w fs.suid_dumpable=0; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if disabled else -3,
    )


# ── 12. TCP SYN Cookies ───────────────────────────────────────────────


@register(
    id="linux_syn_cookies",
    name="TCP SYN Cookies Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_syn_cookies() -> CheckResult:
    val = _sysctl_val("net.ipv4.tcp_syncookies")
    enabled = val == "1"
    return CheckResult(
        check_id="linux_syn_cookies",
        name="TCP SYN Cookies Enabled",
        category=_CAT,
        status="pass" if enabled else "warn",
        detail="SYN cookies are enabled" if enabled else f"SYN cookies disabled (tcp_syncookies = {val})",
        remediation="Run: sudo sysctl -w net.ipv4.tcp_syncookies=1; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if enabled else -3,
    )


# ── 13. Unattended Upgrades ───────────────────────────────────────────


@register(
    id="linux_unattended_upgrades",
    name="Automatic Security Updates",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_unattended_upgrades() -> CheckResult:
    # Debian/Ubuntu: check apt conf
    apt_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if apt_conf.exists():
        content = _read_file(str(apt_conf))
        if 'Unattended-Upgrade "1"' in content or "Unattended-Upgrade \"1\"" in content:
            return CheckResult(
                check_id="linux_unattended_upgrades",
                name="Automatic Security Updates",
                category=_CAT,
                status="pass",
                detail="Unattended upgrades enabled via apt",
                remediation="",
                severity="medium",
                score_delta=0,
            )

    # Fallback: check if unattended-upgrades package is installed
    r = _run_cmd(["dpkg", "-l", "unattended-upgrades"])
    if r.returncode == 0 and "ii" in r.stdout:
        return CheckResult(
            check_id="linux_unattended_upgrades",
            name="Automatic Security Updates",
            category=_CAT,
            status="pass",
            detail="unattended-upgrades package is installed",
            remediation="",
            severity="medium",
            score_delta=0,
        )

    # RHEL/Fedora: check dnf-automatic
    r = _run_cmd(["systemctl", "is-active", "dnf-automatic.timer"])
    if r.returncode == 0 and "active" in r.stdout:
        return CheckResult(
            check_id="linux_unattended_upgrades",
            name="Automatic Security Updates",
            category=_CAT,
            status="pass",
            detail="dnf-automatic timer is active",
            remediation="",
            severity="medium",
            score_delta=0,
        )

    return CheckResult(
        check_id="linux_unattended_upgrades",
        name="Automatic Security Updates",
        category=_CAT,
        status="warn",
        detail="No automatic security update mechanism detected",
        remediation="Run: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades",
        severity="medium",
        score_delta=-5,
    )


# ── 14. Failed Logins ─────────────────────────────────────────────────


@register(
    id="linux_failed_logins",
    name="Excessive Failed Logins",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_failed_logins() -> CheckResult:
    # journalctl is more portable than lastb
    r = _run_cmd([
        "journalctl", "-u", "sshd", "--since", "24 hours ago",
        "--no-pager", "-q",
    ], timeout=15)
    if r.returncode != 0:
        # Fallback to lastb
        r = _run_cmd(["lastb", "-n", "100"])
        if r.returncode != 0:
            return CheckResult(
                check_id="linux_failed_logins",
                name="Excessive Failed Logins",
                category=_CAT,
                status="skip",
                detail="Cannot read login failure logs",
                remediation="",
                severity="medium",
                score_delta=0,
            )

    failed_count = r.stdout.lower().count("failed") + r.stdout.lower().count("invalid user")
    ok = failed_count <= 50
    return CheckResult(
        check_id="linux_failed_logins",
        name="Excessive Failed Logins",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"{failed_count} failed login indicators in last 24h",
        remediation="Install fail2ban: sudo apt install fail2ban && sudo systemctl enable --now fail2ban",
        severity="medium",
        score_delta=0 if ok else -3,
    )


# ── 15. Dangerous Kernel Capabilities ─────────────────────────────────
# Lightweight port of KernelCapScanner: check for non-system processes
# holding CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, etc.


_DANGEROUS_CAPS = frozenset({
    "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
    "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
})

_CAP_NAMES = {
    0: "CAP_CHOWN", 1: "CAP_DAC_OVERRIDE", 2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER", 5: "CAP_KILL", 6: "CAP_SETGID", 7: "CAP_SETUID",
    12: "CAP_NET_ADMIN", 13: "CAP_NET_RAW", 16: "CAP_SYS_MODULE",
    19: "CAP_SYS_PTRACE", 21: "CAP_SYS_ADMIN", 22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE", 24: "CAP_SYS_RESOURCE", 25: "CAP_SYS_TIME",
}


def _decode_caps(bitmask: int) -> set[str]:
    caps: set[str] = set()
    for bit, name in _CAP_NAMES.items():
        if bitmask & (1 << bit):
            caps.add(name)
    return caps


@register(
    id="linux_dangerous_caps",
    name="Dangerous Kernel Capabilities",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_linux_dangerous_caps() -> CheckResult:
    flagged: list[str] = []
    try:
        pids = [e for e in os.listdir("/proc") if e.isdigit()]
    except OSError:
        return CheckResult(
            check_id="linux_dangerous_caps",
            name="Dangerous Kernel Capabilities",
            category=_CAT,
            status="skip",
            detail="Cannot read /proc",
            remediation="",
            severity="medium",
            score_delta=0,
        )

    for pid_s in pids[:500]:  # cap scan to avoid slowness
        pid = int(pid_s)
        # Skip kernel threads and root-owned system processes
        try:
            status = Path(f"/proc/{pid}/status").read_text()
        except (OSError, PermissionError):
            continue

        cap_eff = 0
        uid_line = ""
        comm = ""
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                try:
                    cap_eff = int(line.split(":", 1)[1].strip(), 16)
                except ValueError:
                    pass
            elif line.startswith("Uid:"):
                uid_line = line
            elif line.startswith("Name:"):
                comm = line.split(":", 1)[1].strip()

        if cap_eff == 0:
            continue

        # Skip UID 0 processes (expected to have caps)
        if uid_line:
            uids = uid_line.split(":", 1)[1].strip().split()
            if uids and uids[0] == "0":
                continue

        caps = _decode_caps(cap_eff)
        dangerous = caps & _DANGEROUS_CAPS
        if dangerous:
            flagged.append(f"PID {pid} ({comm}): {', '.join(sorted(dangerous))}")
            if len(flagged) >= 5:
                break

    ok = len(flagged) == 0
    detail = "No non-root processes with dangerous capabilities" if ok else f"{len(flagged)} process(es) with dangerous caps"
    if flagged:
        detail += "\n" + "\n".join(f"  - {f}" for f in flagged)

    return CheckResult(
        check_id="linux_dangerous_caps",
        name="Dangerous Kernel Capabilities",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=detail,
        remediation="Audit processes with: getpcaps <PID>; remove unneeded caps from service units",
        severity="medium",
        score_delta=0 if ok else -5,
    )


# ── 16. SSH MaxAuthTries ─────────────────────────────────────────────


@register(
    id="linux_ssh_max_auth_tries",
    name="SSH MaxAuthTries",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.5",
    section="SSH Server Configuration",
)
def check_linux_ssh_max_auth_tries() -> CheckResult:
    val = _ssh_config_value("MaxAuthTries")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_max_auth_tries",
            name="SSH MaxAuthTries",
            category=_CAT,
            status="warn",
            detail="MaxAuthTries not set (default 6)",
            remediation="Set MaxAuthTries 4 in /etc/ssh/sshd_config",
            severity="medium",
            score_delta=-3,
            benchmark_id="CIS-5.2.5",
            section="SSH Server Configuration",
        )
    try:
        n = int(val)
    except ValueError:
        n = 99
    ok = n <= 4
    return CheckResult(
        check_id="linux_ssh_max_auth_tries",
        name="SSH MaxAuthTries",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"MaxAuthTries = {val}",
        remediation="" if ok else "Set MaxAuthTries 4 in /etc/ssh/sshd_config",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.2.5",
        section="SSH Server Configuration",
    )


# ── 17. SSH ClientAlive ──────────────────────────────────────────────


@register(
    id="linux_ssh_client_alive",
    name="SSH ClientAlive Settings",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.16",
    section="SSH Server Configuration",
)
def check_linux_ssh_client_alive() -> CheckResult:
    interval = _ssh_config_value("ClientAliveInterval")
    count_max = _ssh_config_value("ClientAliveCountMax")
    if interval is None and count_max is None:
        return CheckResult(
            check_id="linux_ssh_client_alive",
            name="SSH ClientAlive Settings",
            category=_CAT,
            status="warn",
            detail="ClientAliveInterval/ClientAliveCountMax not configured",
            remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 3 in sshd_config",
            severity="medium",
            score_delta=-3,
            benchmark_id="CIS-5.2.16",
            section="SSH Server Configuration",
        )
    try:
        iv = int(interval) if interval else 0
    except ValueError:
        iv = 9999
    try:
        cm = int(count_max) if count_max else 3
    except ValueError:
        cm = 99
    ok = 0 < iv <= 300 and cm <= 3
    return CheckResult(
        check_id="linux_ssh_client_alive",
        name="SSH ClientAlive Settings",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"ClientAliveInterval={interval}, ClientAliveCountMax={count_max}",
        remediation="" if ok else "Set ClientAliveInterval 300, ClientAliveCountMax 3 in sshd_config",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.2.16",
        section="SSH Server Configuration",
    )


# ── 18. SSH X11Forwarding ───────────────────────────────────────────


@register(
    id="linux_ssh_x11_forwarding",
    name="SSH X11Forwarding Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.6",
    section="SSH Server Configuration",
)
def check_linux_ssh_x11_forwarding() -> CheckResult:
    val = _ssh_config_value("X11Forwarding")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_x11_forwarding",
            name="SSH X11Forwarding Disabled",
            category=_CAT,
            status="warn",
            detail="X11Forwarding not explicitly set",
            remediation="Set X11Forwarding no in /etc/ssh/sshd_config",
            severity="medium",
            score_delta=-2,
            benchmark_id="CIS-5.2.6",
            section="SSH Server Configuration",
        )
    ok = val.lower() == "no"
    return CheckResult(
        check_id="linux_ssh_x11_forwarding",
        name="SSH X11Forwarding Disabled",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"X11Forwarding = {val}",
        remediation="" if ok else "Set X11Forwarding no in /etc/ssh/sshd_config",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.2.6",
        section="SSH Server Configuration",
    )


# ── 19. SSH Banner ───────────────────────────────────────────────────


@register(
    id="linux_ssh_banner",
    name="SSH Login Banner",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-5.2.17",
    section="SSH Server Configuration",
)
def check_linux_ssh_banner() -> CheckResult:
    val = _ssh_config_value("Banner")
    ok = val is not None and val.lower() != "none"
    return CheckResult(
        check_id="linux_ssh_banner",
        name="SSH Login Banner",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"Banner = {val}" if val else "SSH Banner not configured",
        remediation="" if ok else "Set Banner /etc/issue.net in /etc/ssh/sshd_config",
        severity="low",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-5.2.17",
        section="SSH Server Configuration",
    )


# ── 20. SSH TCP Forwarding ──────────────────────────────────────────


@register(
    id="linux_ssh_tcp_forwarding",
    name="SSH TCP Forwarding Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.18",
    section="SSH Server Configuration",
)
def check_linux_ssh_tcp_forwarding() -> CheckResult:
    val = _ssh_config_value("AllowTcpForwarding")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_tcp_forwarding",
            name="SSH TCP Forwarding Disabled",
            category=_CAT,
            status="warn",
            detail="AllowTcpForwarding not explicitly set (default yes)",
            remediation="Set AllowTcpForwarding no in /etc/ssh/sshd_config",
            severity="medium",
            score_delta=-3,
            benchmark_id="CIS-5.2.18",
            section="SSH Server Configuration",
        )
    ok = val.lower() == "no"
    return CheckResult(
        check_id="linux_ssh_tcp_forwarding",
        name="SSH TCP Forwarding Disabled",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"AllowTcpForwarding = {val}",
        remediation="" if ok else "Set AllowTcpForwarding no in /etc/ssh/sshd_config",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.2.18",
        section="SSH Server Configuration",
    )


# ── 21. SSH LogLevel ────────────────────────────────────────────────


@register(
    id="linux_ssh_log_level",
    name="SSH LogLevel",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-5.2.3",
    section="SSH Server Configuration",
)
def check_linux_ssh_log_level() -> CheckResult:
    val = _ssh_config_value("LogLevel")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_log_level",
            name="SSH LogLevel",
            category=_CAT,
            status="pass",
            detail="LogLevel not set (default INFO — acceptable)",
            remediation="",
            severity="low",
            score_delta=0,
            benchmark_id="CIS-5.2.3",
            section="SSH Server Configuration",
        )
    ok = val.upper() in ("VERBOSE", "INFO")
    return CheckResult(
        check_id="linux_ssh_log_level",
        name="SSH LogLevel",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"LogLevel = {val}",
        remediation="" if ok else "Set LogLevel VERBOSE in /etc/ssh/sshd_config",
        severity="low",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-5.2.3",
        section="SSH Server Configuration",
    )


# ── 22. SSH Weak Ciphers ────────────────────────────────────────────


_WEAK_CIPHERS = {"3des-cbc", "blowfish-cbc", "cast128-cbc"}


@register(
    id="linux_ssh_ciphers",
    name="SSH No Weak Ciphers",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.2.13",
    section="SSH Server Configuration",
)
def check_linux_ssh_ciphers() -> CheckResult:
    val = _ssh_config_value("Ciphers")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_ciphers",
            name="SSH No Weak Ciphers",
            category=_CAT,
            status="pass",
            detail="Ciphers not explicitly set (modern defaults exclude weak ciphers)",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-5.2.13",
            section="SSH Server Configuration",
        )
    found = _WEAK_CIPHERS & {c.strip() for c in val.split(",")}
    ok = len(found) == 0
    return CheckResult(
        check_id="linux_ssh_ciphers",
        name="SSH No Weak Ciphers",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No weak ciphers configured" if ok else f"Weak ciphers found: {', '.join(sorted(found))}",
        remediation="" if ok else "Remove weak ciphers from Ciphers line in /etc/ssh/sshd_config",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-5.2.13",
        section="SSH Server Configuration",
    )


# ── 23. SSH Weak MACs ───────────────────────────────────────────────


_WEAK_MACS = {"hmac-md5", "hmac-sha1", "umac-64@openssh.com", "hmac-md5-96", "hmac-sha1-96"}


@register(
    id="linux_ssh_macs",
    name="SSH No Weak MACs",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.2.14",
    section="SSH Server Configuration",
)
def check_linux_ssh_macs() -> CheckResult:
    val = _ssh_config_value("MACs")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_macs",
            name="SSH No Weak MACs",
            category=_CAT,
            status="pass",
            detail="MACs not explicitly set (modern defaults exclude weak MACs)",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-5.2.14",
            section="SSH Server Configuration",
        )
    found = _WEAK_MACS & {m.strip() for m in val.split(",")}
    ok = len(found) == 0
    return CheckResult(
        check_id="linux_ssh_macs",
        name="SSH No Weak MACs",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No weak MACs configured" if ok else f"Weak MACs found: {', '.join(sorted(found))}",
        remediation="" if ok else "Remove weak MACs from MACs line in /etc/ssh/sshd_config",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-5.2.14",
        section="SSH Server Configuration",
    )


# ── 24. SSH Weak KEX ────────────────────────────────────────────────


_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}


@register(
    id="linux_ssh_kex",
    name="SSH No Weak Key Exchange",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.2.15",
    section="SSH Server Configuration",
)
def check_linux_ssh_kex() -> CheckResult:
    val = _ssh_config_value("KexAlgorithms")
    if val is None:
        return CheckResult(
            check_id="linux_ssh_kex",
            name="SSH No Weak Key Exchange",
            category=_CAT,
            status="pass",
            detail="KexAlgorithms not explicitly set (modern defaults are safe)",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-5.2.15",
            section="SSH Server Configuration",
        )
    found = _WEAK_KEX & {k.strip() for k in val.split(",")}
    ok = len(found) == 0
    return CheckResult(
        check_id="linux_ssh_kex",
        name="SSH No Weak Key Exchange",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="No weak KEX configured" if ok else f"Weak KEX found: {', '.join(sorted(found))}",
        remediation="" if ok else "Remove weak algorithms from KexAlgorithms in /etc/ssh/sshd_config",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-5.2.15",
        section="SSH Server Configuration",
    )


# ── 25. ASLR ────────────────────────────────────────────────────────


@register(
    id="linux_aslr",
    name="ASLR Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-1.5.2",
    section="Sysctl / Network Configuration",
)
def check_linux_aslr() -> CheckResult:
    val = _sysctl_val("kernel.randomize_va_space")
    ok = val == "2"
    return CheckResult(
        check_id="linux_aslr",
        name="ASLR Enabled",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"kernel.randomize_va_space = {val}" if val else "Cannot read ASLR sysctl",
        remediation="" if ok else "Run: sudo sysctl -w kernel.randomize_va_space=2; persist in /etc/sysctl.conf",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-1.5.2",
        section="Sysctl / Network Configuration",
    )


# ── 26. Reverse Path Filtering ──────────────────────────────────────


@register(
    id="linux_rp_filter",
    name="Reverse Path Filtering Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-3.3.7",
    section="Sysctl / Network Configuration",
)
def check_linux_rp_filter() -> CheckResult:
    val = _sysctl_val("net.ipv4.conf.all.rp_filter")
    ok = val == "1"
    return CheckResult(
        check_id="linux_rp_filter",
        name="Reverse Path Filtering Enabled",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"net.ipv4.conf.all.rp_filter = {val}" if val else "Cannot read rp_filter sysctl",
        remediation="" if ok else "Run: sudo sysctl -w net.ipv4.conf.all.rp_filter=1; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-3.3.7",
        section="Sysctl / Network Configuration",
    )


# ── 27. IPv6 Router Advertisements ──────────────────────────────────


@register(
    id="linux_accept_ra",
    name="IPv6 Router Advertisements Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-3.3.9",
    section="Sysctl / Network Configuration",
)
def check_linux_accept_ra() -> CheckResult:
    val = _sysctl_val("net.ipv6.conf.all.accept_ra")
    ok = val == "0"
    return CheckResult(
        check_id="linux_accept_ra",
        name="IPv6 Router Advertisements Disabled",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"net.ipv6.conf.all.accept_ra = {val}" if val else "Cannot read accept_ra sysctl",
        remediation="" if ok else "Run: sudo sysctl -w net.ipv6.conf.all.accept_ra=0; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-3.3.9",
        section="Sysctl / Network Configuration",
    )


# ── 28. Yama ptrace_scope ───────────────────────────────────────────


@register(
    id="linux_yama_ptrace",
    name="Yama ptrace Scope Restricted",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.5.4",
    section="Sysctl / Network Configuration",
)
def check_linux_yama_ptrace() -> CheckResult:
    val = _sysctl_val("kernel.yama.ptrace_scope")
    if not val:
        return CheckResult(
            check_id="linux_yama_ptrace",
            name="Yama ptrace Scope Restricted",
            category=_CAT,
            status="skip",
            detail="Yama LSM not available",
            remediation="Enable Yama LSM in kernel config",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-1.5.4",
            section="Sysctl / Network Configuration",
        )
    try:
        n = int(val)
    except ValueError:
        n = 0
    ok = n >= 1
    return CheckResult(
        check_id="linux_yama_ptrace",
        name="Yama ptrace Scope Restricted",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"kernel.yama.ptrace_scope = {val}",
        remediation="" if ok else "Run: sudo sysctl -w kernel.yama.ptrace_scope=1; persist in /etc/sysctl.conf",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-1.5.4",
        section="Sysctl / Network Configuration",
    )


# ── 29. journald Persistent Storage ─────────────────────────────────


@register(
    id="linux_journald_persistent",
    name="journald Persistent Storage",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-4.2.2.3",
    section="Logging and Auditing",
)
def check_linux_journald_persistent() -> CheckResult:
    content = _read_file("/etc/systemd/journald.conf")
    if not content:
        return CheckResult(
            check_id="linux_journald_persistent",
            name="journald Persistent Storage",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/systemd/journald.conf",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-4.2.2.3",
            section="Logging and Auditing",
        )
    ok = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.lower().startswith("storage=") and "persistent" in stripped.lower():
            ok = True
            break
    return CheckResult(
        check_id="linux_journald_persistent",
        name="journald Persistent Storage",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Storage=persistent in journald.conf" if ok else "journald not set to persistent storage",
        remediation="" if ok else "Set Storage=persistent in /etc/systemd/journald.conf",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-4.2.2.3",
        section="Logging and Auditing",
    )


# ── 30. rsyslog Installed ───────────────────────────────────────────


@register(
    id="linux_rsyslog_installed",
    name="Syslog Service Installed",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-4.2.1.1",
    section="Logging and Auditing",
)
def check_linux_rsyslog_installed() -> CheckResult:
    for svc in ("rsyslog", "syslog-ng"):
        if _service_active(svc):
            return CheckResult(
                check_id="linux_rsyslog_installed",
                name="Syslog Service Installed",
                category=_CAT,
                status="pass",
                detail=f"{svc} is active",
                remediation="",
                severity="medium",
                score_delta=0,
                benchmark_id="CIS-4.2.1.1",
                section="Logging and Auditing",
            )
    r = _run_cmd(["dpkg", "-l", "rsyslog"])
    if r.returncode == 0 and "ii" in r.stdout:
        return CheckResult(
            check_id="linux_rsyslog_installed",
            name="Syslog Service Installed",
            category=_CAT,
            status="warn",
            detail="rsyslog installed but not active",
            remediation="Run: sudo systemctl enable --now rsyslog",
            severity="medium",
            score_delta=-2,
            benchmark_id="CIS-4.2.1.1",
            section="Logging and Auditing",
        )
    return CheckResult(
        check_id="linux_rsyslog_installed",
        name="Syslog Service Installed",
        category=_CAT,
        status="fail",
        detail="No syslog service (rsyslog/syslog-ng) detected",
        remediation="Run: sudo apt install rsyslog && sudo systemctl enable --now rsyslog",
        severity="medium",
        score_delta=-5,
        benchmark_id="CIS-4.2.1.1",
        section="Logging and Auditing",
    )


# ── 31. Audit Rules ─────────────────────────────────────────────────


@register(
    id="linux_audit_rules",
    name="Audit Rules Configured",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-4.1.x",
    section="Logging and Auditing",
)
def check_linux_audit_rules() -> CheckResult:
    rules_dir = Path("/etc/audit/rules.d")
    if not rules_dir.is_dir():
        return CheckResult(
            check_id="linux_audit_rules",
            name="Audit Rules Configured",
            category=_CAT,
            status="fail",
            detail="/etc/audit/rules.d/ does not exist",
            remediation="Install auditd: sudo apt install auditd && configure rules in /etc/audit/rules.d/",
            severity="medium",
            score_delta=-5,
            benchmark_id="CIS-4.1.x",
            section="Logging and Auditing",
        )
    rule_files = list(rules_dir.glob("*.rules"))
    ok = len(rule_files) > 0
    return CheckResult(
        check_id="linux_audit_rules",
        name="Audit Rules Configured",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"{len(rule_files)} audit rule file(s) found" if ok else "No .rules files in /etc/audit/rules.d/",
        remediation="" if ok else "Add audit rules to /etc/audit/rules.d/",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-4.1.x",
        section="Logging and Auditing",
    )


# ── 32. /tmp noexec ─────────────────────────────────────────────────


@register(
    id="linux_tmp_noexec",
    name="/tmp Mounted with noexec",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.1.8.2",
    section="Filesystem",
)
def check_linux_tmp_noexec() -> CheckResult:
    r = _run_cmd(["findmnt", "-n", "-o", "OPTIONS", "/tmp"])
    if r.returncode != 0:
        return CheckResult(
            check_id="linux_tmp_noexec",
            name="/tmp Mounted with noexec",
            category=_CAT,
            status="skip",
            detail="/tmp not a separate mount or findmnt unavailable",
            remediation="Mount /tmp as separate partition with noexec",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-1.1.8.2",
            section="Filesystem",
        )
    ok = "noexec" in r.stdout
    return CheckResult(
        check_id="linux_tmp_noexec",
        name="/tmp Mounted with noexec",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="/tmp has noexec" if ok else "/tmp missing noexec mount option",
        remediation="" if ok else "Add noexec to /tmp mount options in /etc/fstab",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-1.1.8.2",
        section="Filesystem",
    )


# ── 33. /tmp nosuid ─────────────────────────────────────────────────


@register(
    id="linux_tmp_nosuid",
    name="/tmp Mounted with nosuid",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.1.8.3",
    section="Filesystem",
)
def check_linux_tmp_nosuid() -> CheckResult:
    r = _run_cmd(["findmnt", "-n", "-o", "OPTIONS", "/tmp"])
    if r.returncode != 0:
        return CheckResult(
            check_id="linux_tmp_nosuid",
            name="/tmp Mounted with nosuid",
            category=_CAT,
            status="skip",
            detail="/tmp not a separate mount or findmnt unavailable",
            remediation="Mount /tmp as separate partition with nosuid",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-1.1.8.3",
            section="Filesystem",
        )
    ok = "nosuid" in r.stdout
    return CheckResult(
        check_id="linux_tmp_nosuid",
        name="/tmp Mounted with nosuid",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="/tmp has nosuid" if ok else "/tmp missing nosuid mount option",
        remediation="" if ok else "Add nosuid to /tmp mount options in /etc/fstab",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-1.1.8.3",
        section="Filesystem",
    )


# ── 34. /home Permissions ───────────────────────────────────────────


@register(
    id="linux_home_perms",
    name="/home Directories Not World-Readable",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-6.2.7",
    section="Filesystem",
)
def check_linux_home_perms() -> CheckResult:
    home = Path("/home")
    if not home.is_dir():
        return CheckResult(
            check_id="linux_home_perms",
            name="/home Directories Not World-Readable",
            category=_CAT,
            status="skip",
            detail="/home does not exist",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-6.2.7",
            section="Filesystem",
        )
    world_readable: list[str] = []
    try:
        for d in home.iterdir():
            if d.is_dir() and not d.name.startswith("."):
                perms = _file_perms(str(d))
                if perms is not None and perms & 0o004:
                    world_readable.append(d.name)
    except PermissionError:
        pass
    ok = len(world_readable) == 0
    return CheckResult(
        check_id="linux_home_perms",
        name="/home Directories Not World-Readable",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="No world-readable home dirs" if ok else f"World-readable: {', '.join(world_readable[:5])}",
        remediation="" if ok else "Run: chmod 750 /home/*",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-6.2.7",
        section="Filesystem",
    )


# ── 35. umask ────────────────────────────────────────────────────────


@register(
    id="linux_umask",
    name="Default umask Restrictive",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.5.5",
    section="Access, Auth, and Authorization",
)
def check_linux_umask() -> CheckResult:
    content = _read_file("/etc/login.defs")
    if not content:
        return CheckResult(
            check_id="linux_umask",
            name="Default umask Restrictive",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/login.defs",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.5.5",
            section="Access, Auth, and Authorization",
        )
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0] == "UMASK":
            try:
                val = int(tokens[1], 8)
            except ValueError:
                continue
            ok = val >= 0o027
            return CheckResult(
                check_id="linux_umask",
                name="Default umask Restrictive",
                category=_CAT,
                status="pass" if ok else "fail",
                detail=f"UMASK = {tokens[1]}",
                remediation="" if ok else "Set UMASK 027 in /etc/login.defs",
                severity="medium",
                score_delta=0 if ok else -5,
                benchmark_id="CIS-5.5.5",
                section="Access, Auth, and Authorization",
            )
    return CheckResult(
        check_id="linux_umask",
        name="Default umask Restrictive",
        category=_CAT,
        status="warn",
        detail="UMASK not set in /etc/login.defs",
        remediation="Set UMASK 027 in /etc/login.defs",
        severity="medium",
        score_delta=-3,
        benchmark_id="CIS-5.5.5",
        section="Access, Auth, and Authorization",
    )


# ── 36. /etc/shadow Strict Mode ─────────────────────────────────────


@register(
    id="linux_shadow_mode",
    name="/etc/shadow Strict Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-6.1.3",
    section="Access, Auth, and Authorization",
)
def check_linux_shadow_mode() -> CheckResult:
    perms = _file_perms("/etc/shadow")
    if perms is None:
        return CheckResult(
            check_id="linux_shadow_mode",
            name="/etc/shadow Strict Permissions",
            category=_CAT,
            status="skip",
            detail="Cannot stat /etc/shadow",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-6.1.3",
            section="Access, Auth, and Authorization",
        )
    ok = perms <= 0o600
    return CheckResult(
        check_id="linux_shadow_mode",
        name="/etc/shadow Strict Permissions",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"/etc/shadow permissions: {oct(perms)}",
        remediation="" if ok else "Run: sudo chmod 600 /etc/shadow",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-6.1.3",
        section="Access, Auth, and Authorization",
    )


# ── 37. /etc/crontab Permissions ────────────────────────────────────


@register(
    id="linux_cron_perms",
    name="/etc/crontab Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.1.2",
    section="Access, Auth, and Authorization",
)
def check_linux_cron_perms() -> CheckResult:
    perms = _file_perms("/etc/crontab")
    if perms is None:
        return CheckResult(
            check_id="linux_cron_perms",
            name="/etc/crontab Permissions",
            category=_CAT,
            status="skip",
            detail="Cannot stat /etc/crontab",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.1.2",
            section="Access, Auth, and Authorization",
        )
    ok = perms <= 0o600
    return CheckResult(
        check_id="linux_cron_perms",
        name="/etc/crontab Permissions",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"/etc/crontab permissions: {oct(perms)}",
        remediation="" if ok else "Run: sudo chmod 600 /etc/crontab",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.1.2",
        section="Access, Auth, and Authorization",
    )


# ── 38. /etc/cron.allow ─────────────────────────────────────────────


@register(
    id="linux_cron_allow",
    name="cron.allow Exists",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.1.8",
    section="Access, Auth, and Authorization",
)
def check_linux_cron_allow() -> CheckResult:
    ok = Path("/etc/cron.allow").is_file()
    return CheckResult(
        check_id="linux_cron_allow",
        name="cron.allow Exists",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="/etc/cron.allow exists" if ok else "/etc/cron.allow not found",
        remediation="" if ok else "Create /etc/cron.allow with authorized users",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-5.1.8",
        section="Access, Auth, and Authorization",
    )


# ── 39. PAM Password Quality ────────────────────────────────────────


@register(
    id="linux_pam_pwquality",
    name="PAM Password Quality (minlen >= 14)",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.4.1",
    section="Access, Auth, and Authorization",
)
def check_linux_pam_pwquality() -> CheckResult:
    content = _read_file("/etc/security/pwquality.conf")
    if not content:
        return CheckResult(
            check_id="linux_pam_pwquality",
            name="PAM Password Quality (minlen >= 14)",
            category=_CAT,
            status="warn",
            detail="Cannot read /etc/security/pwquality.conf",
            remediation="Install libpam-pwquality and set minlen = 14 in /etc/security/pwquality.conf",
            severity="medium",
            score_delta=-3,
            benchmark_id="CIS-5.4.1",
            section="Access, Auth, and Authorization",
        )
    minlen = 0
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "minlen" in stripped.lower():
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                try:
                    minlen = int(parts[1].strip())
                except ValueError:
                    pass
    ok = minlen >= 14
    return CheckResult(
        check_id="linux_pam_pwquality",
        name="PAM Password Quality (minlen >= 14)",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"minlen = {minlen}" if minlen else "minlen not configured",
        remediation="" if ok else "Set minlen = 14 in /etc/security/pwquality.conf",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.4.1",
        section="Access, Auth, and Authorization",
    )


# ── 40. PASS_MAX_DAYS ───────────────────────────────────────────────


@register(
    id="linux_pass_max_days",
    name="Password Maximum Age (PASS_MAX_DAYS)",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.5.1.1",
    section="Access, Auth, and Authorization",
)
def check_linux_pass_max_days() -> CheckResult:
    content = _read_file("/etc/login.defs")
    if not content:
        return CheckResult(
            check_id="linux_pass_max_days",
            name="Password Maximum Age (PASS_MAX_DAYS)",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/login.defs",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.5.1.1",
            section="Access, Auth, and Authorization",
        )
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0] == "PASS_MAX_DAYS":
            try:
                days = int(tokens[1])
            except ValueError:
                continue
            ok = days <= 365
            return CheckResult(
                check_id="linux_pass_max_days",
                name="Password Maximum Age (PASS_MAX_DAYS)",
                category=_CAT,
                status="pass" if ok else "fail",
                detail=f"PASS_MAX_DAYS = {days}",
                remediation="" if ok else "Set PASS_MAX_DAYS 365 in /etc/login.defs",
                severity="medium",
                score_delta=0 if ok else -5,
                benchmark_id="CIS-5.5.1.1",
                section="Access, Auth, and Authorization",
            )
    return CheckResult(
        check_id="linux_pass_max_days",
        name="Password Maximum Age (PASS_MAX_DAYS)",
        category=_CAT,
        status="warn",
        detail="PASS_MAX_DAYS not set in /etc/login.defs",
        remediation="Set PASS_MAX_DAYS 365 in /etc/login.defs",
        severity="medium",
        score_delta=-3,
        benchmark_id="CIS-5.5.1.1",
        section="Access, Auth, and Authorization",
    )


# ── 41. /etc/motd Permissions ───────────────────────────────────────


@register(
    id="linux_motd_perms",
    name="/etc/motd Permissions",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-1.7.4",
    section="Access, Auth, and Authorization",
)
def check_linux_motd_perms() -> CheckResult:
    perms = _file_perms("/etc/motd")
    if perms is None:
        return CheckResult(
            check_id="linux_motd_perms",
            name="/etc/motd Permissions",
            category=_CAT,
            status="pass",
            detail="/etc/motd does not exist (acceptable)",
            remediation="",
            severity="low",
            score_delta=0,
            benchmark_id="CIS-1.7.4",
            section="Access, Auth, and Authorization",
        )
    ok = perms <= 0o644
    return CheckResult(
        check_id="linux_motd_perms",
        name="/etc/motd Permissions",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"/etc/motd permissions: {oct(perms)}",
        remediation="" if ok else "Run: sudo chmod 644 /etc/motd",
        severity="low",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-1.7.4",
        section="Access, Auth, and Authorization",
    )


# ── 42. sudo Logging ────────────────────────────────────────────────


@register(
    id="linux_sudo_log",
    name="sudo Logging Configured",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.3.5",
    section="Access, Auth, and Authorization",
)
def check_linux_sudo_log() -> CheckResult:
    content = _read_file("/etc/sudoers")
    if not content:
        r = _run_cmd(["sudo", "-n", "cat", "/etc/sudoers"])
        content = r.stdout if r.returncode == 0 else ""
    if not content:
        return CheckResult(
            check_id="linux_sudo_log",
            name="sudo Logging Configured",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/sudoers",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.3.5",
            section="Access, Auth, and Authorization",
        )
    ok = "logfile" in content.lower()
    return CheckResult(
        check_id="linux_sudo_log",
        name="sudo Logging Configured",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Defaults logfile configured in sudoers" if ok else "No logfile configured in sudoers",
        remediation="" if ok else 'Add: Defaults logfile="/var/log/sudo.log" via visudo',
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-5.3.5",
        section="Access, Auth, and Authorization",
    )


# ── 43. sudo use_pty ────────────────────────────────────────────────


@register(
    id="linux_sudo_use_pty",
    name="sudo use_pty Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.3.6",
    section="Access, Auth, and Authorization",
)
def check_linux_sudo_use_pty() -> CheckResult:
    content = _read_file("/etc/sudoers")
    if not content:
        r = _run_cmd(["sudo", "-n", "cat", "/etc/sudoers"])
        content = r.stdout if r.returncode == 0 else ""
    if not content:
        return CheckResult(
            check_id="linux_sudo_use_pty",
            name="sudo use_pty Enabled",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/sudoers",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.3.6",
            section="Access, Auth, and Authorization",
        )
    ok = "use_pty" in content
    return CheckResult(
        check_id="linux_sudo_use_pty",
        name="sudo use_pty Enabled",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Defaults use_pty configured" if ok else "use_pty not configured in sudoers",
        remediation="" if ok else "Add: Defaults use_pty via visudo",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-5.3.6",
        section="Access, Auth, and Authorization",
    )


# ── 44. sudo timestamp_timeout ──────────────────────────────────────


@register(
    id="linux_sudo_timeout",
    name="sudo Timeout Configured",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.3.7",
    section="Access, Auth, and Authorization",
)
def check_linux_sudo_timeout() -> CheckResult:
    content = _read_file("/etc/sudoers")
    if not content:
        r = _run_cmd(["sudo", "-n", "cat", "/etc/sudoers"])
        content = r.stdout if r.returncode == 0 else ""
    if not content:
        return CheckResult(
            check_id="linux_sudo_timeout",
            name="sudo Timeout Configured",
            category=_CAT,
            status="skip",
            detail="Cannot read /etc/sudoers",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-5.3.7",
            section="Access, Auth, and Authorization",
        )
    ok = "timestamp_timeout" in content
    return CheckResult(
        check_id="linux_sudo_timeout",
        name="sudo Timeout Configured",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="timestamp_timeout configured in sudoers" if ok else "timestamp_timeout not set (default 15 min)",
        remediation="" if ok else "Add: Defaults timestamp_timeout=5 via visudo",
        severity="medium",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-5.3.7",
        section="Access, Auth, and Authorization",
    )


# ── 45. Single-User Mode Auth ───────────────────────────────────────


@register(
    id="linux_single_user_auth",
    name="Single-User Mode Requires Auth",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-1.4.3",
    section="System Maintenance",
)
def check_linux_single_user_auth() -> CheckResult:
    for unit in ("rescue.service", "emergency.service"):
        content = _read_file(f"/usr/lib/systemd/system/{unit}")
        if not content:
            content = _read_file(f"/lib/systemd/system/{unit}")
        if content and "sulogin" in content:
            continue
        if content:
            return CheckResult(
                check_id="linux_single_user_auth",
                name="Single-User Mode Requires Auth",
                category=_CAT,
                status="fail",
                detail=f"{unit} does not invoke sulogin",
                remediation=f"Ensure ExecStart contains sulogin in {unit}",
                severity="high",
                score_delta=-8,
                benchmark_id="CIS-1.4.3",
                section="System Maintenance",
            )
    return CheckResult(
        check_id="linux_single_user_auth",
        name="Single-User Mode Requires Auth",
        category=_CAT,
        status="pass",
        detail="rescue.service and emergency.service require sulogin",
        remediation="",
        severity="high",
        score_delta=0,
        benchmark_id="CIS-1.4.3",
        section="System Maintenance",
    )


# ── 46. No Avahi Daemon ─────────────────────────────────────────────


@register(
    id="linux_no_avahi",
    name="Avahi Daemon Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.3",
    section="System Maintenance",
)
def check_linux_no_avahi() -> CheckResult:
    running = _service_active("avahi-daemon")
    return CheckResult(
        check_id="linux_no_avahi",
        name="Avahi Daemon Not Running",
        category=_CAT,
        status="pass" if not running else "warn",
        detail="avahi-daemon is not active" if not running else "avahi-daemon is active",
        remediation="" if not running else "Run: sudo systemctl stop avahi-daemon && sudo systemctl disable avahi-daemon",
        severity="medium",
        score_delta=0 if not running else -3,
        benchmark_id="CIS-2.2.3",
        section="System Maintenance",
    )


# ── 47. No CUPS ─────────────────────────────────────────────────────


@register(
    id="linux_no_cups",
    name="CUPS Not Running (Unless Required)",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.2.4",
    section="System Maintenance",
)
def check_linux_no_cups() -> CheckResult:
    running = _service_active("cups")
    return CheckResult(
        check_id="linux_no_cups",
        name="CUPS Not Running (Unless Required)",
        category=_CAT,
        status="pass" if not running else "warn",
        detail="cups is not active" if not running else "cups is active (disable if printing not needed)",
        remediation="" if not running else "Run: sudo systemctl stop cups && sudo systemctl disable cups",
        severity="low",
        score_delta=0 if not running else -2,
        benchmark_id="CIS-2.2.4",
        section="System Maintenance",
    )


# ── 48. No DHCP Server ──────────────────────────────────────────────


@register(
    id="linux_no_dhcp_server",
    name="DHCP Server Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.5",
    section="System Maintenance",
)
def check_linux_no_dhcp_server() -> CheckResult:
    running = _service_active("isc-dhcp-server") or _service_active("dhcpd")
    return CheckResult(
        check_id="linux_no_dhcp_server",
        name="DHCP Server Not Running",
        category=_CAT,
        status="pass" if not running else "fail",
        detail="DHCP server is not active" if not running else "DHCP server is active",
        remediation="" if not running else "Run: sudo systemctl stop isc-dhcp-server && sudo systemctl disable isc-dhcp-server",
        severity="medium",
        score_delta=0 if not running else -5,
        benchmark_id="CIS-2.2.5",
        section="System Maintenance",
    )


# ── 49. No slapd ────────────────────────────────────────────────────


@register(
    id="linux_no_slapd",
    name="LDAP Server (slapd) Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.6",
    section="System Maintenance",
)
def check_linux_no_slapd() -> CheckResult:
    running = _service_active("slapd")
    return CheckResult(
        check_id="linux_no_slapd",
        name="LDAP Server (slapd) Not Running",
        category=_CAT,
        status="pass" if not running else "fail",
        detail="slapd is not active" if not running else "slapd is active",
        remediation="" if not running else "Run: sudo systemctl stop slapd && sudo systemctl disable slapd",
        severity="medium",
        score_delta=0 if not running else -5,
        benchmark_id="CIS-2.2.6",
        section="System Maintenance",
    )


# ── 50. No NFS ──────────────────────────────────────────────────────


@register(
    id="linux_no_nfs",
    name="NFS Server Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.7",
    section="System Maintenance",
)
def check_linux_no_nfs() -> CheckResult:
    running = _service_active("nfs-kernel-server") or _service_active("nfs-server")
    return CheckResult(
        check_id="linux_no_nfs",
        name="NFS Server Not Running",
        category=_CAT,
        status="pass" if not running else "fail",
        detail="NFS server is not active" if not running else "NFS server is active",
        remediation="" if not running else "Run: sudo systemctl stop nfs-kernel-server && sudo systemctl disable nfs-kernel-server",
        severity="medium",
        score_delta=0 if not running else -5,
        benchmark_id="CIS-2.2.7",
        section="System Maintenance",
    )


# ── 51. No SMB ──────────────────────────────────────────────────────


@register(
    id="linux_no_smb",
    name="Samba (smbd) Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.12",
    section="System Maintenance",
)
def check_linux_no_smb() -> CheckResult:
    running = _service_active("smbd")
    return CheckResult(
        check_id="linux_no_smb",
        name="Samba (smbd) Not Running",
        category=_CAT,
        status="pass" if not running else "warn",
        detail="smbd is not active" if not running else "smbd is active",
        remediation="" if not running else "Run: sudo systemctl stop smbd && sudo systemctl disable smbd",
        severity="medium",
        score_delta=0 if not running else -3,
        benchmark_id="CIS-2.2.12",
        section="System Maintenance",
    )


# ── 52. No Squid ────────────────────────────────────────────────────


@register(
    id="linux_no_squid",
    name="Squid Proxy Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.13",
    section="System Maintenance",
)
def check_linux_no_squid() -> CheckResult:
    running = _service_active("squid")
    return CheckResult(
        check_id="linux_no_squid",
        name="Squid Proxy Not Running",
        category=_CAT,
        status="pass" if not running else "warn",
        detail="squid is not active" if not running else "squid is active",
        remediation="" if not running else "Run: sudo systemctl stop squid && sudo systemctl disable squid",
        severity="medium",
        score_delta=0 if not running else -3,
        benchmark_id="CIS-2.2.13",
        section="System Maintenance",
    )


# ── 53. No SNMP Daemon ──────────────────────────────────────────────


@register(
    id="linux_no_snmpd",
    name="SNMP Daemon Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.2.14",
    section="System Maintenance",
)
def check_linux_no_snmpd() -> CheckResult:
    running = _service_active("snmpd")
    return CheckResult(
        check_id="linux_no_snmpd",
        name="SNMP Daemon Not Running",
        category=_CAT,
        status="pass" if not running else "warn",
        detail="snmpd is not active" if not running else "snmpd is active",
        remediation="" if not running else "Run: sudo systemctl stop snmpd && sudo systemctl disable snmpd",
        severity="medium",
        score_delta=0 if not running else -3,
        benchmark_id="CIS-2.2.14",
        section="System Maintenance",
    )


# ── 54. Chrony / NTP ────────────────────────────────────────────────


@register(
    id="linux_chrony_configured",
    name="Time Synchronization Configured",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.1.1.1",
    section="Time Synchronization",
)
def check_linux_chrony_configured() -> CheckResult:
    for svc in ("chronyd", "chrony", "ntpd", "ntp", "systemd-timesyncd"):
        if _service_active(svc):
            return CheckResult(
                check_id="linux_chrony_configured",
                name="Time Synchronization Configured",
                category=_CAT,
                status="pass",
                detail=f"{svc} is active",
                remediation="",
                severity="medium",
                score_delta=0,
                benchmark_id="CIS-2.1.1.1",
                section="Time Synchronization",
            )
    r = _run_cmd(["timedatectl", "show", "--property=NTPSynchronized", "--value"])
    if r.returncode == 0 and r.stdout.strip().lower() == "yes":
        return CheckResult(
            check_id="linux_chrony_configured",
            name="Time Synchronization Configured",
            category=_CAT,
            status="pass",
            detail="NTP synchronized via timedatectl",
            remediation="",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-2.1.1.1",
            section="Time Synchronization",
        )
    return CheckResult(
        check_id="linux_chrony_configured",
        name="Time Synchronization Configured",
        category=_CAT,
        status="fail",
        detail="No time synchronization service detected",
        remediation="Install chrony: sudo apt install chrony && sudo systemctl enable --now chrony",
        severity="medium",
        score_delta=-5,
        benchmark_id="CIS-2.1.1.1",
        section="Time Synchronization",
    )


# ── 55. Firewall Default Deny ───────────────────────────────────────


@register(
    id="linux_fw_default_deny",
    name="Firewall Default Deny Inbound",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-3.5.1.x",
    section="Firewall",
)
def check_linux_fw_default_deny() -> CheckResult:
    r = _run_cmd(["iptables", "-L", "INPUT", "-n"])
    if r.returncode == 0:
        first_line = r.stdout.splitlines()[0] if r.stdout.strip() else ""
        if "DROP" in first_line or "REJECT" in first_line:
            return CheckResult(
                check_id="linux_fw_default_deny",
                name="Firewall Default Deny Inbound",
                category=_CAT,
                status="pass",
                detail="iptables INPUT chain default policy is DROP/REJECT",
                remediation="",
                severity="high",
                score_delta=0,
                benchmark_id="CIS-3.5.1.x",
                section="Firewall",
            )

    r = _run_cmd(["nft", "list", "chain", "inet", "filter", "input"])
    if r.returncode == 0 and ("drop" in r.stdout.lower() or "reject" in r.stdout.lower()):
        return CheckResult(
            check_id="linux_fw_default_deny",
            name="Firewall Default Deny Inbound",
            category=_CAT,
            status="pass",
            detail="nftables input chain has drop/reject policy",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-3.5.1.x",
            section="Firewall",
        )

    r = _run_cmd(["ufw", "status", "verbose"])
    if r.returncode == 0 and "deny (incoming)" in r.stdout.lower():
        return CheckResult(
            check_id="linux_fw_default_deny",
            name="Firewall Default Deny Inbound",
            category=_CAT,
            status="pass",
            detail="ufw default incoming policy is deny",
            remediation="",
            severity="high",
            score_delta=0,
            benchmark_id="CIS-3.5.1.x",
            section="Firewall",
        )

    return CheckResult(
        check_id="linux_fw_default_deny",
        name="Firewall Default Deny Inbound",
        category=_CAT,
        status="fail",
        detail="No default-deny inbound firewall policy detected",
        remediation="Run: sudo ufw default deny incoming && sudo ufw enable",
        severity="high",
        score_delta=-10,
        benchmark_id="CIS-3.5.1.x",
        section="Firewall",
    )
