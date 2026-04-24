"""Shared pytest fixtures.

Isolates the per-session drift ledger and provenance ledger between tests
so they don't accumulate state across the whole pytest process. Previously
tests sharing a PPID-derived session id polluted each other's drift
baseline and flipped benign commands to "review".

The fix is lightweight: redirect ``XDG_CACHE_HOME`` to a fresh tmpdir per
test function. Tests that need a specific session id set ``RALF_SESSION_ID``
themselves.
"""

from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _isolate_ralf_cache(monkeypatch, tmp_path):
    """Every test gets its own XDG_CACHE_HOME.

    Applied automatically to every test (``autouse=True``). Tests that
    override this via their own ``monkeypatch.setenv`` still work — this
    just establishes a clean default so tests that DON'T explicitly set it
    still see an empty ledger.
    """
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
