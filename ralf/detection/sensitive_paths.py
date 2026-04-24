"""Sensitive path / device detection.

Narrow regex covering raw block devices, credential files, SSH keys,
cloud credentials, GPG/Kerberos/Kubernetes configs, and process memory.
"""
from __future__ import annotations

import re

# Compiled at import time.
_SENSITIVE_RE: re.Pattern = re.compile(
    r'(?:'
    r'/dev/(?:sd[a-z]|nvme\d|disk\d|hd[a-z]|mmcblk\d|loop\d|md\d|mapper/)'
    r'|/etc/shad' r'ow\b'
    r'|/etc/gshad' r'ow\b'
    r'|/etc/sudoers\b'
    r'|/etc/passwd-?\b'
    r'|/etc/master\.passwd\b'
    r'|/root/\.ssh/'
    r'|~/\.ssh/'
    r'|\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)'
    r'|\.aws/credentials'
    r'|\.gnupg/'
    r'|/etc/krb5\.keytab'
    r'|\.kube/config'
    r'|/proc/\d+/mem\b'
    r')',
    re.IGNORECASE,
)


def has_sensitive(text: str) -> bool:
    """Return True if ``text`` references any sensitive path or device."""
    if not text:
        return False
    return bool(_SENSITIVE_RE.search(text))


def get_matches(text: str) -> list[str]:
    """Return every sensitive-path substring found in ``text``.

    The list is in order of appearance and may contain duplicates if the
    same path appears multiple times.
    """
    if not text:
        return []
    return _SENSITIVE_RE.findall(text)


__all__ = ["has_sensitive", "get_matches"]
