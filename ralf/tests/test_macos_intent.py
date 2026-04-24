"""Tests for :mod:`ralf.macos.intent_classifier`.

Module is pure Python, so these tests run on Linux too. They exercise
the macOS-specific rule additions (launchctl, plutil, defaults,
codesign, xattr, csrutil, spctl, brew) and confirm the shared table
entries still behave correctly in the fork.
"""
from __future__ import annotations

from ralf.macos.intent_classifier import (
    CommandIntent,
    IntentClassifier,
    classify,
)


# --- macOS-specific: launchctl ---


def test_launchctl_list_read() -> None:
    res = IntentClassifier.classify("launchctl", "launchctl list")
    assert res.intent == CommandIntent.READ


def test_launchctl_load_persist() -> None:
    res = IntentClassifier.classify(
        "launchctl", "launchctl load ~/Library/LaunchAgents/evil.plist"
    )
    assert res.intent == CommandIntent.PERSIST


def test_launchctl_unload_disrupt() -> None:
    res = IntentClassifier.classify(
        "launchctl", "launchctl unload /System/Library/LaunchDaemons/sshd.plist"
    )
    assert res.intent == CommandIntent.DISRUPT


# --- macOS-specific: plutil ---


def test_plutil_print_read() -> None:
    res = IntentClassifier.classify("plutil", "plutil -p Info.plist")
    assert res.intent == CommandIntent.READ


def test_plutil_replace_edit() -> None:
    res = IntentClassifier.classify(
        "plutil", "plutil -replace CFBundleDisplayName -string Evil Info.plist"
    )
    assert res.intent == CommandIntent.EDIT


# --- macOS-specific: defaults ---


def test_defaults_read() -> None:
    res = IntentClassifier.classify("defaults", "defaults read com.apple.dock")
    assert res.intent == CommandIntent.READ


def test_defaults_write() -> None:
    res = IntentClassifier.classify(
        "defaults", "defaults write com.apple.loginwindow AutoLoginUser hacker"
    )
    assert res.intent == CommandIntent.EDIT


# --- macOS-specific: codesign / xattr / csrutil / spctl ---


def test_codesign_remove_signature_escalate() -> None:
    res = IntentClassifier.classify(
        "codesign", "codesign --remove-signature /Applications/Trusted.app"
    )
    assert res.intent == CommandIntent.ESCALATE


def test_codesign_verify_read() -> None:
    res = IntentClassifier.classify("codesign", "codesign -v /Applications/Safari.app")
    assert res.intent == CommandIntent.READ


def test_xattr_strip_quarantine_escalate() -> None:
    res = IntentClassifier.classify(
        "xattr", "xattr -d com.apple.quarantine /path/to/downloaded.app"
    )
    assert res.intent == CommandIntent.ESCALATE


def test_csrutil_status_read() -> None:
    res = IntentClassifier.classify("csrutil", "csrutil status")
    assert res.intent == CommandIntent.READ


def test_csrutil_disable_escalate() -> None:
    res = IntentClassifier.classify("csrutil", "csrutil disable")
    assert res.intent == CommandIntent.ESCALATE


def test_spctl_assess_read() -> None:
    res = IntentClassifier.classify("spctl", "spctl --assess /Applications/Trusted.app")
    assert res.intent == CommandIntent.READ


def test_spctl_master_disable_escalate() -> None:
    res = IntentClassifier.classify("spctl", "spctl --master-disable")
    assert res.intent == CommandIntent.ESCALATE


# --- macOS-specific: brew ---


def test_brew_list_read() -> None:
    res = IntentClassifier.classify("brew", "brew list")
    assert res.intent == CommandIntent.READ


def test_brew_install_operate() -> None:
    res = IntentClassifier.classify("brew", "brew install wget")
    assert res.intent == CommandIntent.OPERATE


# --- BSD base64 flag ---


def test_base64_uppercase_d_decode() -> None:
    """macOS base64 uses -D; must classify as READ."""
    res = IntentClassifier.classify("base64", "base64 -D file.b64")
    assert res.intent == CommandIntent.READ


def test_base64_lowercase_d_still_works() -> None:
    """Homebrew coreutils on macOS supports -d too; must still work."""
    res = IntentClassifier.classify("base64", "base64 -d file.b64")
    assert res.intent == CommandIntent.READ


# --- shared table still works in the fork ---


def test_git_status_read_macos() -> None:
    res = IntentClassifier.classify("git", "git status")
    assert res.intent == CommandIntent.READ


def test_curl_fetch_macos() -> None:
    res = IntentClassifier.classify("curl", "curl https://example.com")
    assert res.intent == CommandIntent.FETCH


def test_docker_privileged_macos() -> None:
    res = IntentClassifier.classify("docker", "docker run --privileged ubuntu")
    assert res.intent == CommandIntent.ESCALATE


def test_unknown_binary_macos() -> None:
    res = IntentClassifier.classify("quuxfoobar", "quuxfoobar --help")
    assert res.intent == CommandIntent.UNKNOWN


def test_classify_shim_macos() -> None:
    assert classify("ls", "ls /Applications") == CommandIntent.READ
