"""macOS hardening checks — 55 checks covering firewall, encryption, SIP, CIS benchmarks, etc.

Each check is registered via :func:`ralf.scanner.checks.register` and
discovered automatically by the runner on ``darwin`` platforms.
"""

from __future__ import annotations

import logging
import subprocess

from ralf.scanner import CheckResult
from ralf.scanner.checks import register

log = logging.getLogger(__name__)

_PLAT = ("darwin",)
_CAT = "host_hardening"


def _run_cmd(cmd: list[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing output. Never raises on non-zero exit."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, returncode=127, stdout="", stderr="command not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr="timeout")


def _defaults_read(domain: str, key: str) -> tuple[str, bool]:
    """Read a macOS defaults key. Returns (value_str, exists_bool)."""
    r = _run_cmd(["defaults", "read", domain, key])
    if r.returncode != 0:
        return ("", False)
    return (r.stdout.strip(), True)


def _plist_read(path: str, key: str) -> tuple[str, bool]:
    """Read a key from a plist via PlistBuddy. Returns (value_str, exists_bool)."""
    r = _run_cmd(["/usr/libexec/PlistBuddy", "-c", f"Print :{key}", path])
    if r.returncode != 0:
        return ("", False)
    return (r.stdout.strip(), True)


# ── 1. macOS Firewall ──────────────────────────────────────────────────


@register(
    id="macos_firewall",
    name="macOS Firewall",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_macos_firewall() -> CheckResult:
    r = _run_cmd([
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "--getglobalstate",
    ])
    enabled = "enabled" in r.stdout.lower()
    return CheckResult(
        check_id="macos_firewall",
        name="macOS Firewall",
        category=_CAT,
        status="pass" if enabled else "fail",
        detail="Firewall is enabled" if enabled else "Firewall is disabled",
        remediation=(
            "Run: sudo /usr/libexec/ApplicationFirewall/socketfilterfw "
            "--setglobalstate on"
        ),
        severity="high",
        score_delta=0 if enabled else -10,
    )


# ── 2. FileVault ───────────────────────────────────────────────────────


@register(
    id="macos_filevault",
    name="FileVault Disk Encryption",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_macos_filevault() -> CheckResult:
    r = _run_cmd(["fdesetup", "status"])
    on = "on" in r.stdout.lower()
    return CheckResult(
        check_id="macos_filevault",
        name="FileVault Disk Encryption",
        category=_CAT,
        status="pass" if on else "fail",
        detail="FileVault is On" if on else "FileVault is Off",
        remediation="Run: sudo fdesetup enable",
        severity="high",
        score_delta=0 if on else -10,
    )


# ── 3. System Integrity Protection ─────────────────────────────────────


@register(
    id="macos_sip",
    name="System Integrity Protection",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_macos_sip() -> CheckResult:
    r = _run_cmd(["csrutil", "status"])
    enabled = "enabled" in r.stdout.lower()
    return CheckResult(
        check_id="macos_sip",
        name="System Integrity Protection",
        category=_CAT,
        status="pass" if enabled else "fail",
        detail="SIP is enabled" if enabled else "SIP is disabled",
        remediation=(
            "Reboot into Recovery Mode (Cmd+R), open Terminal, run: csrutil enable"
        ),
        severity="high",
        score_delta=0 if enabled else -10,
    )


# ── 4. Gatekeeper ──────────────────────────────────────────────────────


@register(
    id="macos_gatekeeper",
    name="Gatekeeper",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_macos_gatekeeper() -> CheckResult:
    r = _run_cmd(["spctl", "--status"])
    enabled = "enabled" in r.stdout.lower() or "assessments enabled" in r.stdout.lower()
    return CheckResult(
        check_id="macos_gatekeeper",
        name="Gatekeeper",
        category=_CAT,
        status="pass" if enabled else "fail",
        detail="Gatekeeper is enabled" if enabled else "Gatekeeper is disabled",
        remediation="Run: sudo spctl --master-enable",
        severity="high",
        score_delta=0 if enabled else -8,
    )


# ── 5. AirDrop ─────────────────────────────────────────────────────────


@register(
    id="macos_airdrop",
    name="AirDrop Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_airdrop() -> CheckResult:
    r = _run_cmd([
        "defaults", "read", "com.apple.NetworkBrowser", "DisableAirDrop",
    ])
    # Value "1" means AirDrop is disabled (good).
    disabled = r.stdout.strip() == "1"
    return CheckResult(
        check_id="macos_airdrop",
        name="AirDrop Disabled",
        category=_CAT,
        status="pass" if disabled else "warn",
        detail="AirDrop is disabled" if disabled else "AirDrop is enabled",
        remediation=(
            "Run: defaults write com.apple.NetworkBrowser DisableAirDrop -bool true"
        ),
        severity="low",
        score_delta=0 if disabled else -3,
    )


# ── 6. Screen Sharing ──────────────────────────────────────────────────


@register(
    id="macos_screen_sharing",
    name="Screen Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_macos_screen_sharing() -> CheckResult:
    r = _run_cmd(["launchctl", "list", "com.apple.screensharing"])
    # Non-zero exit means the service is not loaded (good).
    off = r.returncode != 0
    return CheckResult(
        check_id="macos_screen_sharing",
        name="Screen Sharing Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="Screen Sharing is off" if off else "Screen Sharing is running",
        remediation=(
            "System Settings > General > Sharing > disable Screen Sharing"
        ),
        severity="medium",
        score_delta=0 if off else -5,
    )


# ── 7. Remote Login (SSH) ──────────────────────────────────────────────


@register(
    id="macos_remote_login",
    name="Remote Login (SSH) Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_macos_remote_login() -> CheckResult:
    r = _run_cmd(["systemsetup", "-getremotelogin"])
    off = "off" in r.stdout.lower()
    return CheckResult(
        check_id="macos_remote_login",
        name="Remote Login (SSH) Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="Remote Login is off" if off else "Remote Login is on",
        remediation="Run: sudo systemsetup -setremotelogin off",
        severity="medium",
        score_delta=0 if off else -5,
    )


# ── 8. Bluetooth ───────────────────────────────────────────────────────


@register(
    id="macos_bluetooth",
    name="Bluetooth Off or Managed",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_bluetooth() -> CheckResult:
    r = _run_cmd([
        "defaults", "read",
        "/Library/Preferences/com.apple.Bluetooth",
        "ControllerPowerState",
    ])
    off = r.stdout.strip() == "0"
    return CheckResult(
        check_id="macos_bluetooth",
        name="Bluetooth Off or Managed",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Bluetooth is off" if off else "Bluetooth is on",
        remediation=(
            "Run: sudo defaults write "
            "/Library/Preferences/com.apple.Bluetooth "
            "ControllerPowerState -int 0"
        ),
        severity="low",
        score_delta=0 if off else -2,
    )


# ── 9. Auto-Login ──────────────────────────────────────────────────────


@register(
    id="macos_auto_login",
    name="Auto-Login Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
)
def check_macos_auto_login() -> CheckResult:
    r = _run_cmd([
        "defaults", "read",
        "/Library/Preferences/com.apple.loginwindow",
        "autoLoginUser",
    ])
    # Non-zero exit (key does not exist) means auto-login is disabled (good).
    disabled = r.returncode != 0
    return CheckResult(
        check_id="macos_auto_login",
        name="Auto-Login Disabled",
        category=_CAT,
        status="pass" if disabled else "fail",
        detail="Auto-login is disabled" if disabled else f"Auto-login user: {r.stdout.strip()}",
        remediation=(
            "Run: sudo defaults delete "
            "/Library/Preferences/com.apple.loginwindow autoLoginUser"
        ),
        severity="high",
        score_delta=0 if disabled else -8,
    )


# ── 10. Siri ───────────────────────────────────────────────────────────


@register(
    id="macos_siri",
    name="Siri Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_siri() -> CheckResult:
    r = _run_cmd([
        "defaults", "read",
        "com.apple.assistant.support",
        "Assistant Enabled",
    ])
    disabled = r.stdout.strip() == "0"
    return CheckResult(
        check_id="macos_siri",
        name="Siri Disabled",
        category=_CAT,
        status="pass" if disabled else "warn",
        detail="Siri is disabled" if disabled else "Siri is enabled",
        remediation=(
            "Run: defaults write com.apple.assistant.support "
            "'Assistant Enabled' -bool false"
        ),
        severity="low",
        score_delta=0 if disabled else -2,
    )


# ── 11. Location Services ──────────────────────────────────────────────


@register(
    id="macos_location_services",
    name="Location Services Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_location_services() -> CheckResult:
    r = _run_cmd([
        "defaults", "read",
        "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd",
        "LocationServicesEnabled",
    ])
    off = r.stdout.strip() == "0"
    return CheckResult(
        check_id="macos_location_services",
        name="Location Services Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Location Services are off" if off else "Location Services are on",
        remediation=(
            "System Settings > Privacy & Security > Location Services > disable"
        ),
        severity="low",
        score_delta=0 if off else -2,
    )


# ── 12. Analytics / Telemetry ──────────────────────────────────────────


@register(
    id="macos_analytics",
    name="Analytics/Telemetry Disabled",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_analytics() -> CheckResult:
    r = _run_cmd([
        "defaults", "read",
        "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory",
        "AutoSubmit",
    ])
    # "0" means disabled (good). Non-zero exit (key missing) we treat as warn.
    disabled = r.stdout.strip() == "0"
    return CheckResult(
        check_id="macos_analytics",
        name="Analytics/Telemetry Disabled",
        category=_CAT,
        status="pass" if disabled else "warn",
        detail="Analytics submission is disabled" if disabled else "Analytics may be enabled",
        remediation=(
            "System Settings > Privacy & Security > Analytics & Improvements "
            "> disable all toggles"
        ),
        severity="low",
        score_delta=0 if disabled else -3,
    )


# ── 13. Spotlight Indexing ──────────────────────────────────────────────


@register(
    id="macos_spotlight_indexing",
    name="Spotlight Indexing",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_spotlight_indexing() -> CheckResult:
    r = _run_cmd(["mdutil", "-s", "/"])
    disabled = "disabled" in r.stdout.lower() or "indexing disabled" in r.stdout.lower()
    return CheckResult(
        check_id="macos_spotlight_indexing",
        name="Spotlight Indexing",
        category=_CAT,
        status="pass" if disabled else "info",
        detail="Spotlight indexing is disabled" if disabled else "Spotlight indexing is active (advisory for agent hosts)",
        remediation="Run: sudo mdutil -a -i off",
        severity="low",
        score_delta=0 if disabled else -1,
    )


# ── 14. iCloud Account ─────────────────────────────────────────────────


@register(
    id="macos_icloud",
    name="No iCloud Account (agent host)",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
)
def check_macos_icloud() -> CheckResult:
    r = _run_cmd(["defaults", "read", "MobileMeAccounts"])
    # If no accounts exist, defaults returns an error or empty Accounts array.
    has_account = "AccountID" in r.stdout
    return CheckResult(
        check_id="macos_icloud",
        name="No iCloud Account (agent host)",
        category=_CAT,
        status="pass" if not has_account else "warn",
        detail="No iCloud account configured" if not has_account else "iCloud account present — data sync risk on agent hosts",
        remediation=(
            "System Settings > Apple ID > Sign Out "
            "(or remove iCloud from agent host)"
        ),
        severity="low",
        score_delta=0 if not has_account else -2,
    )


# ── 15. XProtect Definitions ───────────────────────────────────────────


@register(
    id="macos_xprotect",
    name="XProtect Definitions",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
)
def check_macos_xprotect() -> CheckResult:
    import os
    xprotect_meta = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist"
    if os.path.exists(xprotect_meta):
        return CheckResult(
            check_id="macos_xprotect",
            name="XProtect Definitions",
            category=_CAT,
            status="pass",
            detail="XProtect bundle is present",
            remediation="",
            severity="medium",
            score_delta=0,
        )
    # Fallback: check via system_profiler (slow)
    r = _run_cmd(["system_profiler", "SPInstallHistoryDataType"], timeout=30)
    has_xprotect = "XProtect" in r.stdout
    return CheckResult(
        check_id="macos_xprotect",
        name="XProtect Definitions",
        category=_CAT,
        status="pass" if has_xprotect else "fail",
        detail="XProtect updates found in install history" if has_xprotect else "No XProtect updates found",
        remediation="Run: softwareupdate --install --all",
        severity="medium",
        score_delta=0 if has_xprotect else -5,
    )


# ── 16. Remote Apple Events ──────────────────────────────────────────


@register(
    id="macos_remote_apple_events",
    name="Remote Apple Events Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.3.2",
    section="Sharing and Services",
)
def check_macos_remote_apple_events() -> CheckResult:
    r = _run_cmd(["systemsetup", "-getremoteappleevents"])
    off = "off" in r.stdout.lower()
    return CheckResult(
        check_id="macos_remote_apple_events",
        name="Remote Apple Events Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="Remote Apple Events are off" if off else "Remote Apple Events are on",
        remediation="Run: sudo systemsetup -setremoteappleevents off",
        severity="medium",
        score_delta=0 if off else -5,
        benchmark_id="CIS-2.3.2",
        section="Sharing and Services",
    )


# ── 17. Media Sharing ────────────────────────────────────────────────


@register(
    id="macos_media_sharing",
    name="Media Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.3.6",
    section="Sharing and Services",
)
def check_macos_media_sharing() -> CheckResult:
    val, exists = _defaults_read("com.apple.amp.mediasharingd", "home-sharing-enabled")
    off = not exists or val == "0"
    return CheckResult(
        check_id="macos_media_sharing",
        name="Media Sharing Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Media Sharing is off" if off else "Media Sharing is enabled",
        remediation="System Settings > General > Sharing > disable Media Sharing",
        severity="low",
        score_delta=0 if off else -3,
        benchmark_id="CIS-2.3.6",
        section="Sharing and Services",
    )


# ── 18. Content Caching ──────────────────────────────────────────────


@register(
    id="macos_content_caching",
    name="Content Caching Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.3.3",
    section="Sharing and Services",
)
def check_macos_content_caching() -> CheckResult:
    r = _run_cmd(["AssetCacheManagerUtil", "isActivated"])
    off = r.returncode != 0 or "not activated" in r.stdout.lower()
    return CheckResult(
        check_id="macos_content_caching",
        name="Content Caching Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Content Caching is off" if off else "Content Caching is active",
        remediation="System Settings > General > Sharing > disable Content Caching",
        severity="low",
        score_delta=0 if off else -3,
        benchmark_id="CIS-2.3.3",
        section="Sharing and Services",
    )


# ── 19. File Sharing ─────────────────────────────────────────────────


@register(
    id="macos_file_sharing",
    name="File Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.3.1",
    section="Sharing and Services",
)
def check_macos_file_sharing() -> CheckResult:
    r = _run_cmd(["launchctl", "list", "com.apple.smbd"])
    off = r.returncode != 0
    return CheckResult(
        check_id="macos_file_sharing",
        name="File Sharing Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="File Sharing (SMB) is off" if off else "File Sharing (SMB) is running",
        remediation="System Settings > General > Sharing > disable File Sharing",
        severity="medium",
        score_delta=0 if off else -5,
        benchmark_id="CIS-2.3.1",
        section="Sharing and Services",
    )


# ── 20. Printer Sharing ──────────────────────────────────────────────


@register(
    id="macos_printer_sharing",
    name="Printer Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.3.4",
    section="Sharing and Services",
)
def check_macos_printer_sharing() -> CheckResult:
    r = _run_cmd(["cupsctl"])
    sharing_on = "_share_printers=1" in r.stdout
    return CheckResult(
        check_id="macos_printer_sharing",
        name="Printer Sharing Off",
        category=_CAT,
        status="pass" if not sharing_on else "warn",
        detail="Printer Sharing is off" if not sharing_on else "Printer Sharing is on",
        remediation="Run: cupsctl --no-share-printers",
        severity="low",
        score_delta=0 if not sharing_on else -3,
        benchmark_id="CIS-2.3.4",
        section="Sharing and Services",
    )


# ── 21. Internet Sharing ─────────────────────────────────────────────


@register(
    id="macos_internet_sharing",
    name="Internet Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.3.5",
    section="Sharing and Services",
)
def check_macos_internet_sharing() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/SystemConfiguration/com.apple.nat", "NAT|Enabled",
    )
    off = not exists or val == "0"
    return CheckResult(
        check_id="macos_internet_sharing",
        name="Internet Sharing Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="Internet Sharing is off" if off else "Internet Sharing is enabled",
        remediation="System Settings > General > Sharing > disable Internet Sharing",
        severity="medium",
        score_delta=0 if off else -5,
        benchmark_id="CIS-2.3.5",
        section="Sharing and Services",
    )


# ── 22. Screen Lock Timeout ──────────────────────────────────────────


@register(
    id="macos_screen_lock_timeout",
    name="Screen Lock Timeout <= 5 min",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.10.1",
    section="Screen and Login Security",
)
def check_macos_screen_lock_timeout() -> CheckResult:
    val, exists = _defaults_read("com.apple.screensaver", "idleTime")
    if not exists:
        return CheckResult(
            check_id="macos_screen_lock_timeout",
            name="Screen Lock Timeout <= 5 min",
            category=_CAT,
            status="warn",
            detail="Screen lock idle time not configured",
            remediation="System Settings > Lock Screen > set 'Start Screen Saver when inactive' to 5 minutes or less",
            severity="medium",
            score_delta=-3,
            benchmark_id="CIS-2.10.1",
            section="Screen and Login Security",
        )
    try:
        seconds = int(val)
    except ValueError:
        seconds = 9999
    ok = seconds <= 300
    return CheckResult(
        check_id="macos_screen_lock_timeout",
        name="Screen Lock Timeout <= 5 min",
        category=_CAT,
        status="pass" if ok else "fail",
        detail=f"Screen lock idle time is {seconds}s" if ok else f"Screen lock idle time is {seconds}s (> 300s)",
        remediation="System Settings > Lock Screen > set 'Start Screen Saver when inactive' to 5 minutes or less",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-2.10.1",
        section="Screen and Login Security",
    )


# ── 23. Require Password After Sleep ─────────────────────────────────


@register(
    id="macos_require_password",
    name="Require Password After Sleep",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.8",
    section="Screen and Login Security",
)
def check_macos_require_password() -> CheckResult:
    val, exists = _defaults_read("com.apple.screensaver", "askForPassword")
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_require_password",
        name="Require Password After Sleep",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="Password required after sleep/screensaver" if ok else "Password not required after sleep/screensaver",
        remediation="Run: defaults write com.apple.screensaver askForPassword -int 1",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-5.8",
        section="Screen and Login Security",
    )


# ── 24. Login Window Message ─────────────────────────────────────────


@register(
    id="macos_login_message",
    name="Login Window Message Set",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-5.9",
    section="Screen and Login Security",
)
def check_macos_login_message() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.loginwindow", "LoginwindowText",
    )
    ok = exists and len(val) > 0
    return CheckResult(
        check_id="macos_login_message",
        name="Login Window Message Set",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Login window message is set" if ok else "No login window message configured",
        remediation=(
            "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow "
            "LoginwindowText 'Authorized use only'"
        ),
        severity="low",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-5.9",
        section="Screen and Login Security",
    )


# ── 25. Login Window Name+Password ───────────────────────────────────


@register(
    id="macos_show_login_name",
    name="Login Window Shows Name+Password",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.6",
    section="Screen and Login Security",
)
def check_macos_show_login_name() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME",
    )
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_show_login_name",
        name="Login Window Shows Name+Password",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Login window shows name and password fields" if ok else "Login window shows user list",
        remediation=(
            "Run: sudo defaults write /Library/Preferences/com.apple.loginwindow "
            "SHOWFULLNAME -bool true"
        ),
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-5.6",
        section="Screen and Login Security",
    )


# ── 26. Diagnostic Submissions ───────────────────────────────────────


@register(
    id="macos_diagnostic_submissions",
    name="Diagnostic Submissions Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.6.1",
    section="Privacy and Telemetry",
)
def check_macos_diagnostic_submissions() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory",
        "AutoSubmit",
    )
    off = exists and val == "0"
    return CheckResult(
        check_id="macos_diagnostic_submissions",
        name="Diagnostic Submissions Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Diagnostic data submission is off" if off else "Diagnostic data submission may be on",
        remediation="System Settings > Privacy & Security > Analytics & Improvements > disable 'Share Mac Analytics'",
        severity="low",
        score_delta=0 if off else -2,
        benchmark_id="CIS-2.6.1",
        section="Privacy and Telemetry",
    )


# ── 27. Personalized Ads ─────────────────────────────────────────────


@register(
    id="macos_personalized_ads",
    name="Personalized Ads Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.6.5",
    section="Privacy and Telemetry",
)
def check_macos_personalized_ads() -> CheckResult:
    val, exists = _defaults_read("com.apple.AdLib", "allowApplePersonalizedAdvertising")
    off = exists and val == "0"
    return CheckResult(
        check_id="macos_personalized_ads",
        name="Personalized Ads Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Personalized ads are off" if off else "Personalized ads may be on",
        remediation="System Settings > Privacy & Security > Apple Advertising > disable Personalized Ads",
        severity="low",
        score_delta=0 if off else -2,
        benchmark_id="CIS-2.6.5",
        section="Privacy and Telemetry",
    )


# ── 28. Safari Fraudulent Sites ──────────────────────────────────────


@register(
    id="macos_safari_fraudulent_sites",
    name="Safari Fraudulent Site Warning On",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-6.3.3",
    section="Privacy and Telemetry",
)
def check_macos_safari_fraudulent_sites() -> CheckResult:
    val, exists = _defaults_read("com.apple.Safari", "WarnAboutFraudulentWebsites")
    ok = not exists or val == "1"
    return CheckResult(
        check_id="macos_safari_fraudulent_sites",
        name="Safari Fraudulent Site Warning On",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="Safari fraudulent site warning is on" if ok else "Safari fraudulent site warning is off",
        remediation="Safari > Settings > Security > enable 'Warn when visiting a fraudulent website'",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-6.3.3",
        section="Privacy and Telemetry",
    )


# ── 29. Safari Block Popups ──────────────────────────────────────────


@register(
    id="macos_safari_popups",
    name="Safari Block Popups On",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-6.3.2",
    section="Privacy and Telemetry",
)
def check_macos_safari_popups() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.Safari", "com.apple.Safari.ContentPageGroupIdentifier.WebKit2JavaScriptCanOpenWindowsAutomatically",
    )
    blocked = not exists or val == "0"
    return CheckResult(
        check_id="macos_safari_popups",
        name="Safari Block Popups On",
        category=_CAT,
        status="pass" if blocked else "warn",
        detail="Safari popup blocking is on" if blocked else "Safari popup blocking is off",
        remediation="Safari > Settings > Websites > Pop-up Windows > Block and Notify",
        severity="low",
        score_delta=0 if blocked else -2,
        benchmark_id="CIS-6.3.2",
        section="Privacy and Telemetry",
    )


# ── 30. Safari AutoFill Passwords ────────────────────────────────────


@register(
    id="macos_safari_autofill",
    name="Safari AutoFill Passwords Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-6.3.1",
    section="Privacy and Telemetry",
)
def check_macos_safari_autofill() -> CheckResult:
    val, exists = _defaults_read("com.apple.Safari", "AutoFillPasswords")
    off = exists and val == "0"
    return CheckResult(
        check_id="macos_safari_autofill",
        name="Safari AutoFill Passwords Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Safari password AutoFill is off" if off else "Safari password AutoFill is on",
        remediation="Safari > Settings > AutoFill > disable 'User names and passwords'",
        severity="medium",
        score_delta=0 if off else -3,
        benchmark_id="CIS-6.3.1",
        section="Privacy and Telemetry",
    )


# ── 31. Safari Cross-Site Trackers ───────────────────────────────────


@register(
    id="macos_safari_trackers",
    name="Safari Block Cross-Site Trackers",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-6.3.4",
    section="Privacy and Telemetry",
)
def check_macos_safari_trackers() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.Safari",
        "com.apple.Safari.ContentPageGroupIdentifier.WebKit2StorageBlockingPolicy",
    )
    ok = not exists or val in ("1", "2")
    return CheckResult(
        check_id="macos_safari_trackers",
        name="Safari Block Cross-Site Trackers",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Safari blocks cross-site trackers" if ok else "Safari cross-site tracking prevention may be off",
        remediation="Safari > Settings > Privacy > enable 'Prevent cross-site tracking'",
        severity="low",
        score_delta=0 if ok else -2,
        benchmark_id="CIS-6.3.4",
        section="Privacy and Telemetry",
    )


# ── 32. HTTP Server (httpd) ──────────────────────────────────────────


@register(
    id="macos_http_server",
    name="HTTP Server (httpd) Not Running",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-3.1",
    section="Network Security",
)
def check_macos_http_server() -> CheckResult:
    r = _run_cmd(["launchctl", "list", "org.apache.httpd"])
    off = r.returncode != 0
    return CheckResult(
        check_id="macos_http_server",
        name="HTTP Server (httpd) Not Running",
        category=_CAT,
        status="pass" if off else "fail",
        detail="httpd is not running" if off else "httpd is running",
        remediation="Run: sudo launchctl unload -w /System/Library/LaunchDaemons/org.apache.httpd.plist",
        severity="medium",
        score_delta=0 if off else -5,
        benchmark_id="CIS-3.1",
        section="Network Security",
    )


# ── 33. NFS Server ───────────────────────────────────────────────────


@register(
    id="macos_nfs_server",
    name="NFS Exports Empty",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-3.2",
    section="Network Security",
)
def check_macos_nfs_server() -> CheckResult:
    import os
    exports_path = "/etc/exports"
    if not os.path.exists(exports_path):
        empty = True
    else:
        r = _run_cmd(["cat", exports_path])
        content = r.stdout.strip()
        empty = len(content) == 0 or all(
            line.startswith("#") or line.strip() == "" for line in content.splitlines()
        )
    return CheckResult(
        check_id="macos_nfs_server",
        name="NFS Exports Empty",
        category=_CAT,
        status="pass" if empty else "fail",
        detail="No NFS exports configured" if empty else "NFS exports found in /etc/exports",
        remediation="Remove all non-comment lines from /etc/exports and run: sudo nfsd disable",
        severity="medium",
        score_delta=0 if empty else -5,
        benchmark_id="CIS-3.2",
        section="Network Security",
    )


# ── 34. Bluetooth Sharing ────────────────────────────────────────────


@register(
    id="macos_bluetooth_sharing",
    name="Bluetooth Sharing Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.3.7",
    section="Bluetooth and Wireless",
)
def check_macos_bluetooth_sharing() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.Bluetooth", "PrefKeyServicesEnabled",
    )
    off = not exists or val == "0"
    return CheckResult(
        check_id="macos_bluetooth_sharing",
        name="Bluetooth Sharing Off",
        category=_CAT,
        status="pass" if off else "fail",
        detail="Bluetooth Sharing is off" if off else "Bluetooth Sharing is enabled",
        remediation="System Settings > General > Sharing > disable Bluetooth Sharing",
        severity="medium",
        score_delta=0 if off else -5,
        benchmark_id="CIS-2.3.7",
        section="Bluetooth and Wireless",
    )


# ── 35. Wake on Network ──────────────────────────────────────────────


@register(
    id="macos_wake_on_network",
    name="Wake on Network Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.9",
    section="Bluetooth and Wireless",
)
def check_macos_wake_on_network() -> CheckResult:
    r = _run_cmd(["systemsetup", "-getwakeonnetworkaccess"])
    off = "off" in r.stdout.lower() or "not supported" in r.stdout.lower()
    return CheckResult(
        check_id="macos_wake_on_network",
        name="Wake on Network Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Wake on Network Access is off" if off else "Wake on Network Access is on",
        remediation="Run: sudo systemsetup -setwakeonnetworkaccess off",
        severity="low",
        score_delta=0 if off else -2,
        benchmark_id="CIS-2.9",
        section="Bluetooth and Wireless",
    )


# ── 36. Auto-Check for Updates ───────────────────────────────────────


@register(
    id="macos_auto_update_check",
    name="Auto-Check for Updates Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-1.1",
    section="Software Updates",
)
def check_macos_auto_update_check() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled",
    )
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_auto_update_check",
        name="Auto-Check for Updates Enabled",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="Automatic update check is enabled" if ok else "Automatic update check is disabled",
        remediation="Run: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-1.1",
        section="Software Updates",
    )


# ── 37. Auto-Download Updates ────────────────────────────────────────


@register(
    id="macos_auto_update_download",
    name="Auto-Download Updates Enabled",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.2",
    section="Software Updates",
)
def check_macos_auto_update_download() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticDownload",
    )
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_auto_update_download",
        name="Auto-Download Updates Enabled",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Automatic update download is enabled" if ok else "Automatic update download is disabled",
        remediation="Run: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-1.2",
        section="Software Updates",
    )


# ── 38. Auto-Install macOS Updates ───────────────────────────────────


@register(
    id="macos_auto_update_install",
    name="Auto-Install macOS Updates",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.3",
    section="Software Updates",
)
def check_macos_auto_update_install() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "AutomaticallyInstallMacOSUpdates",
    )
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_auto_update_install",
        name="Auto-Install macOS Updates",
        category=_CAT,
        status="pass" if ok else "warn",
        detail="Automatic macOS update install is enabled" if ok else "Automatic macOS update install is disabled",
        remediation="Run: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-1.3",
        section="Software Updates",
    )


# ── 39. Auto-Install Critical Updates ────────────────────────────────


@register(
    id="macos_auto_update_critical",
    name="Auto-Install Critical Updates",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-1.4",
    section="Software Updates",
)
def check_macos_auto_update_critical() -> CheckResult:
    val, exists = _defaults_read(
        "/Library/Preferences/com.apple.SoftwareUpdate", "CriticalUpdateInstall",
    )
    ok = exists and val == "1"
    return CheckResult(
        check_id="macos_auto_update_critical",
        name="Auto-Install Critical Updates",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="Critical update auto-install is enabled" if ok else "Critical update auto-install is disabled",
        remediation="Run: sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
        severity="high",
        score_delta=0 if ok else -8,
        benchmark_id="CIS-1.4",
        section="Software Updates",
    )


# ── 40. Software Update Recency ──────────────────────────────────────


@register(
    id="macos_software_update_days",
    name="Last Update Within 30 Days",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-1.5",
    section="Software Updates",
)
def check_macos_software_update_days() -> CheckResult:
    import os
    from datetime import datetime, timezone
    su_plist = "/Library/Preferences/com.apple.SoftwareUpdate.plist"
    if os.path.exists(su_plist):
        val, exists = _plist_read(su_plist, "LastSuccessfulDate")
        if exists and val:
            try:
                last = datetime.fromisoformat(val.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - last).days
                ok = age <= 30
                return CheckResult(
                    check_id="macos_software_update_days",
                    name="Last Update Within 30 Days",
                    category=_CAT,
                    status="pass" if ok else "fail",
                    detail=f"Last software update was {age} days ago" if ok else f"Last software update was {age} days ago (> 30)",
                    remediation="Run: softwareupdate --install --all",
                    severity="medium",
                    score_delta=0 if ok else -5,
                    benchmark_id="CIS-1.5",
                    section="Software Updates",
                )
            except (ValueError, TypeError):
                pass
    return CheckResult(
        check_id="macos_software_update_days",
        name="Last Update Within 30 Days",
        category=_CAT,
        status="warn",
        detail="Unable to determine last software update date",
        remediation="Run: softwareupdate --install --all",
        severity="medium",
        score_delta=-3,
        benchmark_id="CIS-1.5",
        section="Software Updates",
    )


# ── 41. Password Minimum Length ───────────────────────────────────────


@register(
    id="macos_password_min_length",
    name="Password Minimum Length >= 14",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.2.1",
    section="Password Policy",
)
def check_macos_password_min_length() -> CheckResult:
    r = _run_cmd(["pwpolicy", "getaccountpolicies"])
    has_length = "minChars" in r.stdout or "policyAttributePassword matches" in r.stdout
    ok = has_length
    if "minChars" in r.stdout:
        import re
        m = re.search(r"minChars\s*[>=<]*\s*(\d+)", r.stdout)
        if m:
            length = int(m.group(1))
            ok = length >= 14
            return CheckResult(
                check_id="macos_password_min_length",
                name="Password Minimum Length >= 14",
                category=_CAT,
                status="pass" if ok else "fail",
                detail=f"Password minimum length is {length}" if ok else f"Password minimum length is {length} (< 14)",
                remediation="Run: sudo pwpolicy setglobalpolicy 'minChars=14'",
                severity="high",
                score_delta=0 if ok else -8,
                benchmark_id="CIS-5.2.1",
                section="Password Policy",
            )
    return CheckResult(
        check_id="macos_password_min_length",
        name="Password Minimum Length >= 14",
        category=_CAT,
        status="warn",
        detail="Password length policy not explicitly configured",
        remediation="Run: sudo pwpolicy setglobalpolicy 'minChars=14'",
        severity="high",
        score_delta=-5,
        benchmark_id="CIS-5.2.1",
        section="Password Policy",
    )


# ── 42. Password History ─────────────────────────────────────────────


@register(
    id="macos_password_history",
    name="Password History >= 15",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.7",
    section="Password Policy",
)
def check_macos_password_history() -> CheckResult:
    r = _run_cmd(["pwpolicy", "getaccountpolicies"])
    import re
    m = re.search(r"usingHistory\s*[>=<]*\s*(\d+)", r.stdout)
    if m:
        history = int(m.group(1))
        ok = history >= 15
        return CheckResult(
            check_id="macos_password_history",
            name="Password History >= 15",
            category=_CAT,
            status="pass" if ok else "fail",
            detail=f"Password history is {history}" if ok else f"Password history is {history} (< 15)",
            remediation="Run: sudo pwpolicy setglobalpolicy 'usingHistory=15'",
            severity="medium",
            score_delta=0 if ok else -5,
            benchmark_id="CIS-5.2.7",
            section="Password Policy",
        )
    return CheckResult(
        check_id="macos_password_history",
        name="Password History >= 15",
        category=_CAT,
        status="warn",
        detail="Password history policy not configured",
        remediation="Run: sudo pwpolicy setglobalpolicy 'usingHistory=15'",
        severity="medium",
        score_delta=-3,
        benchmark_id="CIS-5.2.7",
        section="Password Policy",
    )


# ── 43. Max Password Age ─────────────────────────────────────────────


@register(
    id="macos_password_max_age",
    name="Max Password Age <= 365 Days",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-5.2.3",
    section="Password Policy",
)
def check_macos_password_max_age() -> CheckResult:
    r = _run_cmd(["pwpolicy", "getaccountpolicies"])
    import re
    m = re.search(r"maxMinutesUntilChangePassword\s*[>=<]*\s*(\d+)", r.stdout)
    if m:
        minutes = int(m.group(1))
        days = minutes // 1440
        ok = days <= 365
        return CheckResult(
            check_id="macos_password_max_age",
            name="Max Password Age <= 365 Days",
            category=_CAT,
            status="pass" if ok else "fail",
            detail=f"Max password age is {days} days" if ok else f"Max password age is {days} days (> 365)",
            remediation="Run: sudo pwpolicy setglobalpolicy 'maxMinutesUntilChangePassword=525600'",
            severity="medium",
            score_delta=0 if ok else -5,
            benchmark_id="CIS-5.2.3",
            section="Password Policy",
        )
    return CheckResult(
        check_id="macos_password_max_age",
        name="Max Password Age <= 365 Days",
        category=_CAT,
        status="warn",
        detail="Max password age policy not configured",
        remediation="Run: sudo pwpolicy setglobalpolicy 'maxMinutesUntilChangePassword=525600'",
        severity="medium",
        score_delta=-3,
        benchmark_id="CIS-5.2.3",
        section="Password Policy",
    )


# ── 44. Account Lockout ──────────────────────────────────────────────


@register(
    id="macos_account_lockout",
    name="Account Lockout After 5 Attempts",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.3",
    section="Password Policy",
)
def check_macos_account_lockout() -> CheckResult:
    r = _run_cmd(["pwpolicy", "getaccountpolicies"])
    import re
    m = re.search(r"maxFailedLoginAttempts\s*[>=<]*\s*(\d+)", r.stdout)
    if m:
        attempts = int(m.group(1))
        ok = attempts <= 5
        return CheckResult(
            check_id="macos_account_lockout",
            name="Account Lockout After 5 Attempts",
            category=_CAT,
            status="pass" if ok else "fail",
            detail=f"Account locks after {attempts} failed attempts" if ok else f"Account locks after {attempts} attempts (> 5)",
            remediation="Run: sudo pwpolicy setglobalpolicy 'maxFailedLoginAttempts=5'",
            severity="high",
            score_delta=0 if ok else -8,
            benchmark_id="CIS-5.3",
            section="Password Policy",
        )
    return CheckResult(
        check_id="macos_account_lockout",
        name="Account Lockout After 5 Attempts",
        category=_CAT,
        status="warn",
        detail="Account lockout policy not configured",
        remediation="Run: sudo pwpolicy setglobalpolicy 'maxFailedLoginAttempts=5'",
        severity="high",
        score_delta=-5,
        benchmark_id="CIS-5.3",
        section="Password Policy",
    )


# ── 45. iCloud Drive ─────────────────────────────────────────────────


@register(
    id="macos_icloud_drive",
    name="iCloud Drive Sync Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.1.3",
    section="iCloud/Sharing Audit",
)
def check_macos_icloud_drive() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.bird", "com.apple.bird.watchdog.enabled",
    )
    off = exists and val == "0"
    r = _run_cmd(["defaults", "read", "MobileMeAccounts"])
    no_account = "AccountID" not in r.stdout
    if no_account:
        off = True
    return CheckResult(
        check_id="macos_icloud_drive",
        name="iCloud Drive Sync Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="iCloud Drive sync is off" if off else "iCloud Drive sync may be active",
        remediation="System Settings > Apple ID > iCloud > disable iCloud Drive",
        severity="low",
        score_delta=0 if off else -2,
        benchmark_id="CIS-2.1.3",
        section="iCloud/Sharing Audit",
    )


# ── 46. iCloud Keychain ──────────────────────────────────────────────


@register(
    id="macos_icloud_keychain",
    name="iCloud Keychain Sync Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.1.4",
    section="iCloud/Sharing Audit",
)
def check_macos_icloud_keychain() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.icloud.fmfd", "IsKeychain",
    )
    off = not exists or val == "0"
    r = _run_cmd(["defaults", "read", "MobileMeAccounts"])
    no_account = "AccountID" not in r.stdout
    if no_account:
        off = True
    return CheckResult(
        check_id="macos_icloud_keychain",
        name="iCloud Keychain Sync Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="iCloud Keychain sync is off" if off else "iCloud Keychain sync may be active",
        remediation="System Settings > Apple ID > iCloud > Passwords & Keychain > disable",
        severity="medium",
        score_delta=0 if off else -3,
        benchmark_id="CIS-2.1.4",
        section="iCloud/Sharing Audit",
    )


# ── 47. iCloud Photos ────────────────────────────────────────────────


@register(
    id="macos_icloud_photos",
    name="iCloud Photos Sync Off",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.1.5",
    section="iCloud/Sharing Audit",
)
def check_macos_icloud_photos() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.imagent", "iCloudPhotosEnabled",
    )
    off = not exists or val == "0"
    r = _run_cmd(["defaults", "read", "MobileMeAccounts"])
    no_account = "AccountID" not in r.stdout
    if no_account:
        off = True
    return CheckResult(
        check_id="macos_icloud_photos",
        name="iCloud Photos Sync Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="iCloud Photos sync is off" if off else "iCloud Photos sync may be active",
        remediation="System Settings > Apple ID > iCloud > Photos > disable",
        severity="low",
        score_delta=0 if off else -2,
        benchmark_id="CIS-2.1.5",
        section="iCloud/Sharing Audit",
    )


# ── 48. Desktop & Documents iCloud ───────────────────────────────────


@register(
    id="macos_desktop_docs_icloud",
    name="Desktop & Documents iCloud Off",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.1.6",
    section="iCloud/Sharing Audit",
)
def check_macos_desktop_docs_icloud() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.bird",
        "com.apple.clouddocs.userdoc.enabled",
    )
    off = not exists or val == "0"
    r = _run_cmd(["defaults", "read", "MobileMeAccounts"])
    no_account = "AccountID" not in r.stdout
    if no_account:
        off = True
    return CheckResult(
        check_id="macos_desktop_docs_icloud",
        name="Desktop & Documents iCloud Off",
        category=_CAT,
        status="pass" if off else "warn",
        detail="Desktop & Documents iCloud sync is off" if off else "Desktop & Documents iCloud sync may be active",
        remediation="System Settings > Apple ID > iCloud > iCloud Drive > disable 'Desktop & Documents Folders'",
        severity="medium",
        score_delta=0 if off else -3,
        benchmark_id="CIS-2.1.6",
        section="iCloud/Sharing Audit",
    )


# ── 49. Full Disk Access Audit ───────────────────────────────────────


@register(
    id="macos_tcc_fda_audit",
    name="Full Disk Access Audit",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.7.1",
    section="System Hardening",
)
def check_macos_tcc_fda_audit() -> CheckResult:
    import os
    tcc_db = "/Library/Application Support/com.apple.TCC/TCC.db"
    if not os.path.exists(tcc_db):
        return CheckResult(
            check_id="macos_tcc_fda_audit",
            name="Full Disk Access Audit",
            category=_CAT,
            status="skip",
            detail="TCC database not accessible",
            remediation="Grant terminal Full Disk Access to audit TCC grants",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-2.7.1",
            section="System Hardening",
        )
    r = _run_cmd([
        "sqlite3", tcc_db,
        "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;",
    ])
    clients = [c for c in r.stdout.strip().splitlines() if c]
    ok = len(clients) <= 5
    return CheckResult(
        check_id="macos_tcc_fda_audit",
        name="Full Disk Access Audit",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"{len(clients)} apps have Full Disk Access" if ok else f"{len(clients)} apps have Full Disk Access (review recommended)",
        remediation="System Settings > Privacy & Security > Full Disk Access > review and remove unnecessary entries",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-2.7.1",
        section="System Hardening",
    )


# ── 50. Screen Recording Audit ───────────────────────────────────────


@register(
    id="macos_tcc_screen_recording",
    name="Screen Recording Audit",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-2.7.2",
    section="System Hardening",
)
def check_macos_tcc_screen_recording() -> CheckResult:
    import os
    tcc_db = "/Library/Application Support/com.apple.TCC/TCC.db"
    if not os.path.exists(tcc_db):
        return CheckResult(
            check_id="macos_tcc_screen_recording",
            name="Screen Recording Audit",
            category=_CAT,
            status="skip",
            detail="TCC database not accessible",
            remediation="Grant terminal Full Disk Access to audit TCC grants",
            severity="medium",
            score_delta=0,
            benchmark_id="CIS-2.7.2",
            section="System Hardening",
        )
    r = _run_cmd([
        "sqlite3", tcc_db,
        "SELECT client FROM access WHERE service='kTCCServiceScreenCapture' AND auth_value=2;",
    ])
    clients = [c for c in r.stdout.strip().splitlines() if c]
    ok = len(clients) <= 3
    return CheckResult(
        check_id="macos_tcc_screen_recording",
        name="Screen Recording Audit",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=f"{len(clients)} apps have Screen Recording access" if ok else f"{len(clients)} apps have Screen Recording access (review recommended)",
        remediation="System Settings > Privacy & Security > Screen Recording > review and remove unnecessary entries",
        severity="medium",
        score_delta=0 if ok else -3,
        benchmark_id="CIS-2.7.2",
        section="System Hardening",
    )


# ── 51. Firmware Password / Secure Boot ──────────────────────────────


@register(
    id="macos_firmware_password",
    name="Firmware Password or Secure Boot",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-5.10",
    section="System Hardening",
)
def check_macos_firmware_password() -> CheckResult:
    r_secure = _run_cmd(["/usr/sbin/ioreg", "-l", "-p", "IODeviceTree"])
    has_secure_boot = "secure-boot" in r_secure.stdout.lower()
    r_fw = _run_cmd(["firmwarepasswd", "-check"])
    has_fw_pwd = "yes" in r_fw.stdout.lower()
    ok = has_secure_boot or has_fw_pwd
    if has_secure_boot:
        detail_pass = "Secure Boot is enabled (Apple Silicon)"
    elif has_fw_pwd:
        detail_pass = "Firmware password is set"
    else:
        detail_pass = ""
    return CheckResult(
        check_id="macos_firmware_password",
        name="Firmware Password or Secure Boot",
        category=_CAT,
        status="pass" if ok else "warn",
        detail=detail_pass if ok else "No firmware password or Secure Boot detected",
        remediation="Intel: Run 'firmwarepasswd -setpasswd' from Recovery. Apple Silicon: Secure Boot is on by default.",
        severity="high",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-5.10",
        section="System Hardening",
    )


# ── 52. Lockdown Mode Advisory ───────────────────────────────────────


@register(
    id="macos_lockdown_mode",
    name="Lockdown Mode Advisory",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-2.14",
    section="System Hardening",
)
def check_macos_lockdown_mode() -> CheckResult:
    val, exists = _defaults_read(
        ".GlobalPreferences", "LDMGlobalEnabled",
    )
    on = exists and val == "1"
    return CheckResult(
        check_id="macos_lockdown_mode",
        name="Lockdown Mode Advisory",
        category=_CAT,
        status="pass" if on else "info",
        detail="Lockdown Mode is enabled" if on else "Lockdown Mode is not enabled (advisory for high-risk users)",
        remediation="System Settings > Privacy & Security > Lockdown Mode > Turn On (extreme measure for targeted attack scenarios)",
        severity="low",
        score_delta=0,
        benchmark_id="CIS-2.14",
        section="System Hardening",
    )


# ── 53. Mail Remote Content ──────────────────────────────────────────


@register(
    id="macos_mail_remote_content",
    name="Mail Suppress Remote Content",
    category=_CAT,
    platforms=_PLAT,
    severity="low",
    benchmark_id="CIS-6.2",
    section="Mail and Messaging",
)
def check_macos_mail_remote_content() -> CheckResult:
    val, exists = _defaults_read(
        "com.apple.mail-shared", "DisableURLLoading",
    )
    suppressed = exists and val == "1"
    return CheckResult(
        check_id="macos_mail_remote_content",
        name="Mail Suppress Remote Content",
        category=_CAT,
        status="pass" if suppressed else "warn",
        detail="Mail remote content loading is suppressed" if suppressed else "Mail may load remote content",
        remediation="Mail > Settings > Privacy > enable 'Protect Mail Activity' or disable 'Load remote content in messages'",
        severity="low",
        score_delta=0 if suppressed else -2,
        benchmark_id="CIS-6.2",
        section="Mail and Messaging",
    )


# ── 54. Install Log Retention ────────────────────────────────────────


@register(
    id="macos_install_log",
    name="Install Log Retention Present",
    category=_CAT,
    platforms=_PLAT,
    severity="medium",
    benchmark_id="CIS-3.3",
    section="Logging",
)
def check_macos_install_log() -> CheckResult:
    import os
    log_path = "/var/log/install.log"
    exists = os.path.exists(log_path)
    if exists:
        stat = os.stat(log_path)
        size_ok = stat.st_size > 0
    else:
        size_ok = False
    ok = exists and size_ok
    return CheckResult(
        check_id="macos_install_log",
        name="Install Log Retention Present",
        category=_CAT,
        status="pass" if ok else "fail",
        detail="Install log is present and non-empty" if ok else "Install log is missing or empty",
        remediation="Verify /var/log/install.log exists and log rotation is configured",
        severity="medium",
        score_delta=0 if ok else -5,
        benchmark_id="CIS-3.3",
        section="Logging",
    )


# ── 55. Security Audit (OpenBSM) ─────────────────────────────────────


@register(
    id="macos_security_audit",
    name="Security Audit Running (OpenBSM)",
    category=_CAT,
    platforms=_PLAT,
    severity="high",
    benchmark_id="CIS-3.4",
    section="Logging",
)
def check_macos_security_audit() -> CheckResult:
    r = _run_cmd(["launchctl", "list", "com.apple.auditd"])
    running = r.returncode == 0
    return CheckResult(
        check_id="macos_security_audit",
        name="Security Audit Running (OpenBSM)",
        category=_CAT,
        status="pass" if running else "fail",
        detail="OpenBSM audit daemon (auditd) is running" if running else "OpenBSM audit daemon (auditd) is not running",
        remediation="Run: sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist",
        severity="high",
        score_delta=0 if running else -8,
        benchmark_id="CIS-3.4",
        section="Logging",
    )
