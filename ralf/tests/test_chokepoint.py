"""Chokepoint invariant tests (Phase I, 2026-04-14).

The ``NormalizedSegment`` / ``normalize_command`` pair is the single
source of truth for command normalization. Detectors that want
per-segment view consume the list; detectors that operate on the full
command keep their existing signature. The INVARIANT we guard:

    normalize_command is called at most ONCE per score_command() call.

If multiple detectors each call their own normalizer, the
supply-chain-bypass class of bug becomes possible again (different
normalizers can miss different wrappers). These tests lock in the
single-computation invariant.
"""

from __future__ import annotations

import pytest

from ralf.shared import bash_split
from ralf.shared.bash_split import (
    NormalizedSegment, first_tokens_from_segments, normalize_command,
    normalized_chain,
)
from ralf.shared.verdict_engine import score_command


# ── normalize_command basics ───────────────────────────────────────────────


class TestNormalizeCommand:
    def test_simple_bash(self):
        segs = normalize_command("ls -la")
        assert len(segs) == 1
        assert segs[0].first_token == "ls"
        assert not segs[0].is_wrapper

    def test_compound_command(self):
        segs = normalize_command("ls && pip install flask")
        assert len(segs) == 2
        tokens = {s.first_token for s in segs}
        assert tokens == {"ls", "pip"}

    def test_bash_c_wrapper(self):
        segs = normalize_command('bash -c "pip install flask"')
        assert len(segs) == 1
        assert segs[0].first_token == "pip"
        assert segs[0].is_wrapper

    def test_subshell_wrapper(self):
        segs = normalize_command("$(pip install flask)")
        assert len(segs) == 1
        assert segs[0].first_token == "pip"
        assert segs[0].is_wrapper

    def test_sudo_stripped(self):
        segs = normalize_command("sudo pip install flask")
        assert len(segs) == 1
        assert segs[0].first_token == "pip"

    def test_nohup_env_stripped(self):
        segs = normalize_command("nohup env X=1 pip install flask")
        assert len(segs) == 1
        assert segs[0].first_token == "pip"

    def test_empty_command(self):
        assert normalize_command("") == []

    def test_mid_pipeline_subshell_stays(self):
        """`echo $(date) && pip install foo` — NOT a whole-command wrapper."""
        segs = normalize_command("echo $(date) && pip install foo")
        # Two top-level segments; subshell stays as part of first segment.
        first_tokens = {s.first_token for s in segs}
        assert "pip" in first_tokens
        assert "echo" in first_tokens


# ── Helper functions ────────────────────────────────────────────────────────


class TestHelpers:
    def test_first_tokens_from_segments(self):
        segs = normalize_command("ls && grep foo | pip install flask")
        tokens = first_tokens_from_segments(segs)
        assert tokens == {"ls", "grep", "pip"}

    def test_normalized_chain(self):
        segs = normalize_command("sudo pip install flask; ls -la")
        chain = normalized_chain(segs)
        # Stripped of sudo; semicolon-joined
        assert "pip install flask" in chain
        assert "ls -la" in chain
        assert "sudo" not in chain


# ── Chokepoint invariant ────────────────────────────────────────────────────


class TestSingleComputationInvariant:
    def test_normalize_command_called_once_per_score(self, monkeypatch):
        """Chokepoint: normalize_command runs at most once per score_command()."""
        call_count = [0]
        real_fn = bash_split.normalize_command

        def counted(command, *args, **kwargs):
            call_count[0] += 1
            return real_fn(command, *args, **kwargs)

        monkeypatch.setattr(bash_split, "normalize_command", counted)
        # Also patch the attribute in verdict_engine's import namespace
        # (the import-at-call pattern re-resolves via the module).
        import ralf.shared.verdict_engine as ve
        # The call site uses ``from ralf.shared.bash_split import ... as _normalize_command``
        # inside score_command — so when we patch the bash_split module,
        # subsequent imports in score_command resolve to the patched function.
        score_command("ls && pip install flask==0.12.1")
        assert call_count[0] == 1, (
            f"normalize_command called {call_count[0]} times per score; "
            "chokepoint invariant violated"
        )

    def test_compound_command_uses_chokepoint(self):
        """The supply chain detector reads from chokepoint segments."""
        v = score_command("ls && pip install flask==0.12.1")
        # Verdict must catch the flask==0.12.1 CVE via the segment walk.
        # If chokepoint was broken, only 'ls' would be seen and this
        # would be allow.
        assert "flask" in v.reason.lower() or v.score >= 5

    def test_wrapper_command_uses_chokepoint(self):
        """bash -c wrapper is unwrapped exactly once via chokepoint."""
        v = score_command('bash -c "pip install flask==0.12.1"')
        assert "flask" in v.reason.lower() or v.score >= 5


# ── Regression: existing detector behavior preserved ────────────────────────


class TestRegressionPreserved:
    """The chokepoint refactor must not change verdict for existing cases."""

    def test_clean_ls(self):
        v = score_command("ls /tmp")
        assert v.decision == "allow"

    def test_flask_cve_still_blocks(self):
        v = score_command("pip install flask==0.12.1")
        assert v.decision == "block"

    def test_sudo_flask_still_blocks(self):
        v = score_command("sudo pip install flask==0.12.1")
        assert v.decision == "block"
