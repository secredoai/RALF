"""Cross-adapter shared types — event schema + audit recorder.

The ``ralf.core`` package contains the canonical event shape that every
adapter (claude_code, gemini_cli, codex_cli) emits to the audit log,
plus the thin recorder that wraps :mod:`ralf.shared.audit_log`.

Importantly, ``ralf.core`` does NOT import any adapter — adapters
import ``ralf.core``. This keeps the dependency direction one-way and
avoids circular imports.
"""
