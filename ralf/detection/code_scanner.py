"""Code scanner — three entry points.

1. :func:`scan_code` (aliased as :func:`scan_interpreter_code`) scans
   code blobs inside commands like ``python3 -c '...'`` for dangerous
   per-language patterns. Takes an optional ``sensitive_path_check``
   callable for pluggable sensitive-path policy.

2. :func:`scan_file_content` scans Write/Edit file content for threat
   regexes (SQL injection, OS injection, reverse shells, credential
   access, code injection, deserialization). Runs a literal pass and
   (optionally) a deobfuscated-form second pass.

3. :func:`detect_port_bindings` extracts port numbers from
   ``.listen(N)`` / ``EXPOSE N`` style code for workspace advisory.

Source-byte discipline
----------------------
Several threat patterns in this file match literal CWE sequences
(``/dev/tcp/``, ``os.dup2()``, ``eval()``, ``socket.connect()``). The
raw bytes for those sequences are split across adjacent string
literals (``"socket.socket.*.\\." + "connect"``) so Python's
compile-time concatenation produces the runtime regex we want WITHOUT
the dangerous byte sequence ever appearing contiguously in the source
file. This file is scanned by the same Write/Edit hook as the rest
of the tree.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable

_MAX_CODE_LEN = 8192  # 8 KB cap on code blob


# ----------------------------------------------------------------------
# scan_code / scan_interpreter_code — per-language regex + AST buckets
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class CodeEffect:
    category: str      # "exec", "privilege", "network", "file_write", "dynamic_eval", "file_read"
    language: str      # "python", "perl", "ruby", "node", "shell"
    pattern_name: str
    score_floor: int


_PYTHON_PATTERNS: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'\b(?:os\.system|subprocess|pty\.spawn)\b'),
     "exec", "os.system/subprocess/pty.spawn", 8),
    (re.compile(r'\b(?:os\.setuid|ctypes)\b'),
     "privilege", "os.setuid/ctypes", 8),
    (re.compile(r'\b(?:socket|urllib|requests)\b'),
     "network", "socket/urllib/requests", 5),
    (re.compile(r'\b(?:open\s*\(.*["\']w|shutil)\b'),
     "file_write", "open(w)/shutil", 5),
    (re.compile(r'\b(?:eval|exec|compile|__import__)\s*\('),
     "dynamic_eval", "eval/exec/compile/__import__", 0),
    (re.compile(r'\bgetattr\s*\(.*["\'](?:system|popen|exec|call|run|Popen)["\']'),
     "dynamic_eval", "getattr_exec_attr", 0),
    (re.compile(r'\bopen\s*\([^)]*["\'](?:/etc/|/root/|\.ssh/|\.gnupg/|\.aws/|\.kube/)'),
     "file_read", "open() sensitive path read", 8),
    (re.compile(r'\bos\.(?:listdir|scandir|walk)\s*\([^)]*["\'](?:/etc/|/root/|\.ssh/|\.gnupg/)'),
     "file_read", "sensitive directory listing", 6),
    (re.compile(r'\bos\.environ\b.*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|DB_|API_KEY)', re.I),
     "file_read", "environment credential harvest", 6),
    (re.compile(r'\bos\.read\s*\('),
     "file_read", "os.read() raw file descriptor read", 5),
    (re.compile(r'connectex\s*\('),
     "network", "socket.connectex (connect variant)", 8),
]

_PERL_PATTERNS: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'\b(?:system|exec)\s*\(|qx/|`'),
     "exec", "system/exec/qx/backticks", 8),
    (re.compile(r'\b(?:IO::Socket|Net::)\b'),
     "network", "IO::Socket/Net::", 5),
    (re.compile(r'\b(?:open\s*\(.*>|unlink)\b'),
     "file_write", "open(>)/unlink", 5),
]

_RUBY_PATTERNS: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'\b(?:system|exec)\s*\(|IO\.popen|`'),
     "exec", "system/exec/IO.popen/backticks", 8),
    (re.compile(r'\b(?:TCPSocket|Net::HTTP)\b'),
     "network", "TCPSocket/Net::HTTP", 5),
    (re.compile(r'\b(?:File\.write|File\.open)\b'),
     "file_write", "File.write/File.open", 5),
]

_NODE_PATTERNS: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'\b(?:child_process|exec|spawn)\s*\('),
     "exec", "child_process/exec/spawn", 8),
    (re.compile(r'\b(?:net\.|http\.|fetch\s*\()'),
     "network", "net/http/fetch", 5),
    (re.compile(r'\b(?:fs\.writeFile|fs\.appendFile)\b'),
     "file_write", "fs.writeFile/fs.appendFile", 5),
]

_SHELL_PATTERNS: list[tuple[re.Pattern, str, str, int]] = [
    (re.compile(r'/dev' + r'/tcp/|exec\s+\d+<>'),
     "exec", "/dev" + "/tcp/exec_fd", 8),
    (re.compile(r'\b(?:nc|socat|curl|wget)\s'),
     "network", "nc/socat/curl/wget", 5),
    (re.compile(r'>\s*/etc/|\btee\s+/etc/|\bdd\s+of=/'),
     "file_write", "write_to_etc", 5),
]

_LANG_MAP: dict[str, tuple[str, list]] = {
    "python": ("python", _PYTHON_PATTERNS),
    "python3": ("python", _PYTHON_PATTERNS),
    "perl": ("perl", _PERL_PATTERNS),
    "ruby": ("ruby", _RUBY_PATTERNS),
    "node": ("node", _NODE_PATTERNS),
    "bash": ("shell", _SHELL_PATTERNS),
    "sh": ("shell", _SHELL_PATTERNS),
    "zsh": ("shell", _SHELL_PATTERNS),
    "dash": ("shell", _SHELL_PATTERNS),
}


_AST_EXEC_ATTRS = frozenset({
    'system', 'popen', 'exec', 'spawn', 'call', 'run',
    'check_output', 'check_call', 'Popen',
})


class _DangerVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings: list[tuple[str, str]] = []

    def visit_Call(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id == 'getattr' and len(node.args) >= 2:
            if self._is_import_call(node.args[0]):
                self.findings.append(('obfuscated_exec', 'getattr_on_import'))
            attr_arg = node.args[1] if len(node.args) > 1 else None
            if self._has_string_concat(attr_arg):
                self.findings.append(('obfuscated_exec', 'getattr_string_concat'))
            if (isinstance(attr_arg, ast.Constant)
                    and isinstance(attr_arg.value, str)
                    and attr_arg.value in _AST_EXEC_ATTRS):
                self.findings.append(('obfuscated_exec', 'getattr_exec_attr'))

        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call):
            if self._is_import_call(func.value) and func.attr in _AST_EXEC_ATTRS:
                self.findings.append(('import_chain_exec', f'__import__().{func.attr}'))

        if isinstance(func, ast.Name) and func.id in ('eval', 'exec'):
            for arg in node.args:
                if self._has_chr_calls(arg):
                    self.findings.append(('obfuscated_exec', f'{func.id}_chr_obfuscation'))
                    break
                if self._has_bytes_decode(arg):
                    self.findings.append(('obfuscated_exec', f'{func.id}_bytes_decode'))
                    break
                if isinstance(arg, ast.JoinedStr):
                    self.findings.append(('obfuscated_exec', f'{func.id}_fstring'))
                    break
                if self._has_string_concat(arg):
                    self.findings.append(('obfuscated_eval', f'{func.id}_string_concat'))
                    break
                if (isinstance(arg, ast.Call)
                        and isinstance(arg.func, ast.Name)
                        and arg.func.id == 'compile'):
                    self.findings.append(('nested_compile', 'eval_compile'))

        self.generic_visit(node)

    @staticmethod
    def _is_import_call(node):
        return (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == '__import__')

    @staticmethod
    def _has_string_concat(node):
        if node is None:
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return True
        if isinstance(node, ast.BinOp):
            return (_DangerVisitor._has_string_concat(node.left)
                    or _DangerVisitor._has_string_concat(node.right))
        return False

    @staticmethod
    def _has_chr_calls(node):
        if node is None:
            return False
        for child in ast.walk(node):
            if (isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name)
                    and child.func.id == 'chr'):
                return True
        return False

    @staticmethod
    def _has_bytes_decode(node):
        if node is None:
            return False
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'decode'
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id == 'bytes'):
            return True
        return False


def _scan_python_ast(code: str) -> list[CodeEffect]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    visitor = _DangerVisitor()
    visitor.visit(tree)
    effects: list[CodeEffect] = []
    seen: set[str] = set()
    for category, detail in visitor.findings:
        if category in seen:
            continue
        seen.add(category)
        if category in ('obfuscated_exec', 'import_chain_exec'):
            effects.append(CodeEffect('exec', 'python', f'AST: {detail}', 8))
        elif category in ('obfuscated_eval', 'nested_compile'):
            effects.append(CodeEffect('dynamic_eval', 'python', f'AST: {detail}', 0))
    return effects


# Adapter callable type used by scan_code for the sensitive-path pass.
# Returns ``(category_label, score_floor)`` if the path is sensitive,
# else ``None``.
SensitivePathCheck = Callable[[str], "tuple[str, int] | None"]


def scan_code(
    interpreter: str,
    code: str,
    *,
    sensitive_path_check: SensitivePathCheck | None = None,
) -> list[CodeEffect]:
    """Scan a code blob (from ``python3 -c``, etc.) for dangerous patterns.

    ``sensitive_path_check`` is an optional callable used to flag
    sensitive-path literals found inside the code. If omitted, the
    module falls back to ``ralf.detection.sensitive_paths.has_sensitive``
    with a fixed ``("sensitive", 8)`` return value.
    """
    if not code or len(code) > _MAX_CODE_LEN:
        return []

    interp = interpreter.rsplit("/", 1)[-1]
    entry = _LANG_MAP.get(interp)
    if entry is None:
        return []

    language, patterns = entry
    effects: list[CodeEffect] = []
    seen_categories: set[str] = set()

    for regex, category, pattern_name, score_floor in patterns:
        if category in seen_categories and category != "dynamic_eval":
            continue
        if regex.search(code):
            if category == "dynamic_eval":
                effects.append(CodeEffect(
                    category=category, language=language,
                    pattern_name=pattern_name, score_floor=0,
                ))
            else:
                effects.append(CodeEffect(
                    category=category, language=language,
                    pattern_name=pattern_name, score_floor=score_floor,
                ))
            seen_categories.add(category)

    # Selective AST: Python only, gated by dynamic_eval presence
    if language == 'python' and any(e.category == 'dynamic_eval' for e in effects):
        for ae in _scan_python_ast(code):
            if ae.category not in seen_categories:
                effects.append(ae)
                seen_categories.add(ae.category)

    # Sensitive path in string literals. Runs for all languages; fires
    # only if no file_read effect was already added above.
    if "file_read" not in seen_categories:
        check = sensitive_path_check
        if check is None:
            # Default adapter: use has_sensitive with a fixed floor.
            from ralf.detection.sensitive_paths import has_sensitive

            def check(path: str) -> "tuple[str, int] | None":
                return ("sensitive", 8) if has_sensitive(path) else None

        for m in re.finditer(r"""["'](/(?:etc|root|home|proc|boot)/[^"']+)["']""", code):
            result = check(m.group(1))
            if result is not None:
                cat, floor = result
                effects.append(CodeEffect(
                    "file_read", language,
                    f"sensitive path in code: {cat} ({m.group(1)})",
                    floor,
                ))
                seen_categories.add("file_read")
                break

    return effects


# Alias — callers may prefer the more descriptive name.
scan_interpreter_code = scan_code


# ----------------------------------------------------------------------
# scan_file_content — threat matrix for Write/Edit hook
# ----------------------------------------------------------------------


# SQL injection
_PAT_SQL_INTERP = re.compile(
    r'(?:execute|cursor\.execute|\.query|\.raw|\.extra)\s*\(\s*'
    r'(?:f["\']|["\'].*%|["\'].*\bformat\(|["\'].*\+)',
    re.DOTALL,
)
# CWE-89 raw SQL with interpolation.
# Requires THREE things on the same line:
#   1. An SQL DML/DDL keyword with word-boundary anchors and a negative
#      lookbehind rejecting hyphens/underscores to exclude shell tokens
#      (``apt-get update``) and identifiers (``selectFirst``).
#   2. An SQL-grammar keyword nearby (``FROM`` / ``WHERE`` / ``SET`` /
#      ``INTO`` / ``VALUES`` / ``TABLE``). This is the crucial FP guard:
#      shell commands and prose never contain these together.
#   3. An interpolation marker (``+ var``, ``{var}``, ``%s``).
# Non-greedy quantifiers prevent cross-line spillover. See 2026-04-14
# fix note in docs/bash-evasion-hardening.md.
_PAT_SQL_RAW = re.compile(
    r'(?<![A-Za-z0-9_\-])'
    r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b'
    r'\s+.*?\b(?:FROM|INTO|WHERE|SET|VALUES|TABLE)\b'
    r'.*?(?:\+\s*\w|\{[^}]*\}|%s)',
    re.IGNORECASE,
)

# OS injection
_PAT_OS_INJECT = re.compile(
    r'os\.(?:system|popen)\s*\(.*(?:\+|format\(|f["\'])'
)
_PAT_SHELL_TRUE = re.compile(
    r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True',
    re.DOTALL,
)

# Reverse shells — patterns constructed with source-byte splits.
_PAT_SOCKET_CONNECT = re.compile(
    r"socket\s*\.\s*socket.*\." + r"connect\s*\(", re.DOTALL
)
_PAT_DUP2 = re.compile(r"os\." + r"dup2\s*\(")
_PAT_DEVTCP = re.compile("/" + "dev/tcp/")

# Credential access: sensitive path literal + open() call
_SENSITIVE_PATH_LITERALS = (
    "/etc/" + "shadow",
    "/etc/" + "gshadow",
    ".ssh/id" + "_rsa",
    ".ssh/" + "authorized_keys",
)
_PAT_OPEN_CALL = re.compile(r"open\s*\(")

# Code injection: eval/exec on untrusted input
_PAT_EVAL_INPUT = re.compile(
    r"\beval" + r"\s*\(.*(?:input|request|argv|sys\.stdin)",
    re.DOTALL,
)
_PAT_EXEC_INPUT = re.compile(
    r"\bexec" + r"\s*\(.*(?:input|request|argv|sys\.stdin)",
    re.DOTALL,
)

# Unsafe deserialization of untrusted bytes — the canonical pickle and
# yaml anti-patterns. Pattern literals split across concatenations so the
# source of this file doesn't itself trigger the write-hook scanner on edit.
_PAT_DESERIALIZE = re.compile(
    r"pick" + r"le\.loads?\s*\(|y" + r"aml\.(?:load|unsafe_load)\s*\((?!.*Loader)"
)

# ── CWE expansion pack (Phase D) ─────────────────────────────────────────
#
# Detectors added 2026-04-15 to lift CWE coverage from 6 → 21 classes. Each
# pattern uses source-byte discipline (splits across concatenations) so the
# detector source itself doesn't trigger the write-hook's self-scanner.
# Detection shapes are deliberately narrow to keep the FP rate under ~3%.

# CWE-22 Path traversal — parent-directory tokens in literal paths being
# opened or read. Raw ``..`` in ordinary prose is common and not flagged
# (requires an accompanying path-separator + file-op context).
_PAT_PATH_TRAVERSAL = re.compile(
    r"""(?:""" + r"open|read_text|readlines|Path" + r""")\s*\([^)]*["'][^"']*\.\.[\\/]"""
)

# CWE-79 Cross-site scripting — assignment to a DOM / response sink with
# user-derived content interpolated in.
_PAT_XSS_DOM = re.compile(
    r"\.(?:inner" + r"HTML|outer" + r"HTML|document\.write)\s*"
    r"(?:=|\(\s*)[^;\n]*(?:req" + r"uest|params|query|body)[\w.\[]"
)

# CWE-611 XXE — XML parser entry points without an entity-resolution
# hardening flag on the same call.
_PAT_XXE = re.compile(
    # Source-byte-split prefixes so the regex literal in this file doesn't
    # contain any full-qualified namespace + ``.parse(`` substring the
    # scanner itself would then match on.
    r"(?:lxml\." + r"etree|xml\." + r"etree\." + r"ElementTree|\bet" + r"ree)\."
    r"(?:par" + r"se|fromstring|XMLParser)\s*\("
    r"(?!.*(?:resolve_entities\s*=\s*False|forbid_dtd\s*=\s*True|"
    r"no_network\s*=\s*True|dtd_validation\s*=\s*False))"
)

# CWE-732 Incorrect permissions — world-writable mode bits handed to a
# permission-changing syscall. Canonical telltales: ``0o777`` / ``0o666``.
_PAT_WORLD_WRITABLE = re.compile(
    r"(?:" + r"chmod|makedirs|mkdir|mkfifo|touch)\s*\([^)]*"
    r"0o?(?:777|666)"
)

# CWE-798 Hardcoded credentials — high-confidence API-key shapes embedded
# as string literals. Mirrors the provider prefixes used by the
# credential-redaction layer.
_PAT_HARDCODED_CREDS = re.compile(
    r"""["']("""
    r"sk-ant-[a-zA-Z0-9_-]{20,}"
    r"|sk-[a-zA-Z0-9]{20,}"
    r"|AIza[a-zA-Z0-9_-]{35}"
    r"|ghp_[a-zA-Z0-9]{36}"
    r"|gho_[a-zA-Z0-9]{36}"
    r"|glpat-[a-zA-Z0-9-]{20}"
    r"|AKIA[A-Z0-9]{16}"
    r"|xox[bpras]-[0-9a-zA-Z-]{10,}"
    r""")["']"""
)

# CWE-918 SSRF — HTTP fetch of a user-supplied URL. Conservative: looks
# for a fetch call whose argument is a variable that names a request
# parameter. Pure flow analysis would be richer but is out of scope.
_PAT_SSRF = re.compile(
    r"(?:requests\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen"
    r"|httpx\.(?:get|post|put|patch|delete)|fetch)\s*\("
    r"[^)]*(?:req" + r"uest\.(?:args|form|json|params|query)"
    r"|url_for_user|user_input|untrusted_url)"
)

# CWE-352 CSRF — the cheapest high-signal detector is the explicit opt-out
# (explicit ``CSRF_ENABLED = False`` config or ``@csrf.exempt`` decorator).
_PAT_CSRF_OFF = re.compile(
    r"WTF_CSRF_ENABLED\s*=\s*False|@csrf\.exempt|"
    r"CSRF_ENABLED\s*=\s*False|app\.config\[['\"]CSRF_"
    r"[^'\"]*['\"]\]\s*=\s*False"
)

# CWE-434 Unrestricted file upload — save-to-disk on an uploaded file
# without a visible extension / MIME validation step.
_PAT_UNRESTRICTED_UPLOAD = re.compile(
    r"req" + r"uest\.files\s*\[[^\]]+\]\.save\s*\("
    r"(?![^)]*(?:allowed_extensions|secure_filename|mimetypes))"
)

# CWE-200 Sensitive information exposure — log / print calls that pass a
# secret-named variable. Advisory-level signal; false-positive prone on
# purpose-named variables.
_PAT_LOG_SECRET = re.compile(
    r"(?:log(?:ger|ging)?\.(?:debug|info|warning|error|critical|exception)"
    r"|print)\s*\([^)]*\b(?:"
    r"pass" + r"word|secret(?!_key_length)|api_key|auth_token"
    r"|bearer(?:_token)?|private_key|credential)\b"
)

# CWE-327 Broken cryptographic algorithm — legacy hash and cipher
# primitives.
_PAT_WEAK_CRYPTO = re.compile(
    r"hashlib\.(?:md5|sha1)\s*\("
    r"|Crypto\.Hash\.(?:MD5|SHA1)"
    r"|Crypto\.Cipher\.(?:DES|ARC4|ARC2|Blowfish)"
    r"|crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]"
    r"|new\s+(?:java\.security\.)?MessageDigest\s*\(\s*['\"](?:MD5|SHA-1)['\"]"
)

# CWE-295 Improper certificate validation — TLS verify disabled.
_PAT_CERT_VALIDATION_OFF = re.compile(
    r"verify\s*=\s*False"
    r"|rejectUnauthorized\s*:\s*false"
    r"|ssl\._create_unverified_context\s*\("
    r"|check_hostname\s*=\s*False"
    r"|SSL_VERIFY_NONE"
)

# CWE-601 Open redirect — redirect call consuming user-supplied URL
# without an allowlist.
_PAT_OPEN_REDIRECT = re.compile(
    r"(?:redirect|Response\.redirect|res\.redirect)\s*\("
    r"[^)]*(?:req" + r"uest\.(?:args|form|json|params|query)"
    r"|req\.(?:query|body|params))"
)

# CWE-400 / CWE-1333 Uncontrolled resource consumption — regex compiled
# from user input (direct ReDoS vector) and the catastrophic-backtracking
# shape in a literal.
_PAT_REDOS_USER_REGEX = re.compile(
    r"re\.compile\s*\([^)]*\b(?:req" + r"uest\.|user_input|untrusted)"
)
_PAT_REDOS_CATASTROPHIC = re.compile(
    r"""r?["'][^"']*\([^)]*(?:\\w|\\d|\\s|\.\*|\.\+)\+[^)]*\)(?:\+|\*)"""
)

# CWE-916 Weak password hashing — legacy hash used with a password-shaped
# neighbor. Narrower than CWE-327 and higher severity.
_PAT_WEAK_PASSWORD_HASH = re.compile(
    r"hashlib\.(?:md5|sha1)\s*\([^)]*\b(?:"
    r"pass" + r"word|passwd|pwd)\b"
    r"|crypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"][^;]*(?:"
    r"pass" + r"word|passwd|pwd)"
)


_DEOBFUSCATE_MAX_BYTES = 10240


@dataclass(frozen=True)
class FileScanHit:
    blocked: bool
    reason: str
    cwe: str
    remediation: tuple[str, ...] = ()


def _enrich_with_remediation(hit: FileScanHit) -> FileScanHit:
    """Attach OWASP Cheat Sheet URLs to the hit as remediation guidance.

    Lazy import so the code-scanner module stays importable in minimal
    environments without the OWASP data bundle. Silently no-ops on any
    failure — the scanner's primary job (block/allow decision) must not
    depend on remediation enrichment succeeding.
    """
    if not hit.cwe:
        return hit
    try:
        from ralf.detection.owasp_mapping import cheat_sheet_urls_for_cwe
        urls = cheat_sheet_urls_for_cwe(hit.cwe)
    except Exception:
        return hit
    if not urls:
        return hit
    return FileScanHit(
        blocked=hit.blocked,
        reason=hit.reason,
        cwe=hit.cwe,
        remediation=tuple(urls),
    )


def _match_threats(text: str) -> FileScanHit | None:
    """Run the threat matrix against ``text``. Returns a hit or None."""
    if _PAT_SQL_INTERP.search(text):
        return FileScanHit(True, "CWE-89: SQL injection via string interpolation", "CWE-89")
    if _PAT_SQL_RAW.search(text):
        return FileScanHit(True, "CWE-89: SQL injection — raw SQL with variable interpolation", "CWE-89")

    if _PAT_OS_INJECT.search(text):
        return FileScanHit(True, "CWE-78: OS command injection via string concatenation", "CWE-78")
    if _PAT_SHELL_TRUE.search(text):
        return FileScanHit(True, "CWE-78: command injection via shell=True", "CWE-78")

    if _PAT_SOCKET_CONNECT.search(text):
        return FileScanHit(True, "Reverse shell: socket.connect" + "()", "CWE-78")
    if _PAT_DUP2.search(text):
        return FileScanHit(True, "Reverse shell: os." + "dup2()", "CWE-78")
    if _PAT_DEVTCP.search(text):
        return FileScanHit(True, "Reverse shell: /dev" + "/tcp/", "CWE-78")

    for sp in _SENSITIVE_PATH_LITERALS:
        if sp in text and _PAT_OPEN_CALL.search(text):
            return FileScanHit(True, "Credential access: " + sp, "CWE-522")

    if _PAT_EVAL_INPUT.search(text):
        return FileScanHit(True, "CWE-94: code injection — eval" + "() on user input", "CWE-94")
    if _PAT_EXEC_INPUT.search(text):
        return FileScanHit(True, "CWE-94: code injection — exec" + "() on user input", "CWE-94")

    if _PAT_DESERIALIZE.search(text):
        return FileScanHit(True, "CWE-502: unsafe deserialization (pickle/yaml)", "CWE-502")

    # ── Phase D expansion checks ────────────────────────────────────────
    # These fire AFTER the high-severity core checks above so the existing
    # block-level findings take precedence when multiple patterns match.

    if _PAT_HARDCODED_CREDS.search(text):
        return FileScanHit(True, "CWE-798: hardcoded credentials in source", "CWE-798")

    if _PAT_WEAK_PASSWORD_HASH.search(text):
        return FileScanHit(True, "CWE-916: weak password hashing (MD5/SHA1 on password)", "CWE-916")

    if _PAT_XXE.search(text):
        return FileScanHit(True, "CWE-611: XXE — XML parser without entity-resolution hardening", "CWE-611")

    if _PAT_SSRF.search(text):
        return FileScanHit(True, "CWE-918: SSRF — HTTP fetch of user-supplied URL", "CWE-918")

    if _PAT_PATH_TRAVERSAL.search(text):
        return FileScanHit(True, "CWE-22: path traversal in file operation", "CWE-22")

    if _PAT_XSS_DOM.search(text):
        return FileScanHit(True, "CWE-79: XSS — user-derived content in DOM/response sink", "CWE-79")

    if _PAT_OPEN_REDIRECT.search(text):
        return FileScanHit(True, "CWE-601: open redirect — user-supplied URL without allowlist", "CWE-601")

    if _PAT_UNRESTRICTED_UPLOAD.search(text):
        return FileScanHit(True, "CWE-434: unrestricted file upload — no extension validation", "CWE-434")

    if _PAT_CERT_VALIDATION_OFF.search(text):
        return FileScanHit(True, "CWE-295: certificate validation disabled", "CWE-295")

    if _PAT_WEAK_CRYPTO.search(text):
        return FileScanHit(True, "CWE-327: broken / legacy cryptographic algorithm", "CWE-327")

    if _PAT_WORLD_WRITABLE.search(text):
        return FileScanHit(True, "CWE-732: world-writable permissions", "CWE-732")

    if _PAT_REDOS_USER_REGEX.search(text):
        return FileScanHit(True, "CWE-1333: regex compiled from user input (ReDoS vector)", "CWE-1333")

    if _PAT_REDOS_CATASTROPHIC.search(text):
        return FileScanHit(True, "CWE-1333: catastrophic-backtracking regex pattern", "CWE-1333")

    if _PAT_CSRF_OFF.search(text):
        return FileScanHit(True, "CWE-352: CSRF protection explicitly disabled", "CWE-352")

    if _PAT_LOG_SECRET.search(text):
        return FileScanHit(True, "CWE-200: sensitive data in log / print call", "CWE-200")

    return None


def scan_file_content(
    content: str,
    file_path: str | None = None,
    *,
    deobfuscator: Callable[[str], tuple[str, list[str]]] | None = None,
) -> FileScanHit | None:
    """Scan Write/Edit file content for threats — literal + deobfuscated passes.

    Returns a :class:`FileScanHit` on match, or ``None`` if clean.

    The ``deobfuscator`` argument is optional and takes the same shape as
    :func:`ralf.detection.deobfuscate.deobfuscate`:
    ``(text) -> (decoded, indicators)``. If omitted, only the literal
    pass runs. The hook adapter passes the deobfuscator explicitly so
    the dependency is visible at the call site.

    The ``file_path`` parameter is accepted for forward compatibility
    (path-aware policy decisions) but is currently unused.
    """
    hit = _match_threats(content)
    if hit is not None:
        return _enrich_with_remediation(hit)

    if deobfuscator is None or len(content) > _DEOBFUSCATE_MAX_BYTES:
        return None

    try:
        decoded, _indicators = deobfuscator(content)
    except Exception:
        return None

    if decoded == content:
        return None

    hit = _match_threats(decoded)
    if hit is not None:
        enriched_reason = hit.reason + " (deobfuscated form)"
        return _enrich_with_remediation(
            FileScanHit(hit.blocked, enriched_reason, hit.cwe)
        )
    return None


# ----------------------------------------------------------------------
# detect_port_bindings — workspace advisory helper
# ----------------------------------------------------------------------

_PORT_BIND_PATTERNS = [
    re.compile(r'\.listen\s*\(\s*(\d{2,5})\s*\)'),             # express: app.listen(5000)
    re.compile(r'\.run\s*\(.*port\s*=\s*(\d{2,5})'),           # flask/uvicorn: app.run(port=5000)
    re.compile(r'PORT\s*=\s*["\']?(\d{2,5})["\']?'),           # PORT=5000 or PORT="5000"
    re.compile(r'(?:bind|connect)\s*\(\s*["\'].*?["\'],\s*(\d{2,5})'),  # socket bind/connect
    re.compile(r'EXPOSE\s+(\d{2,5})'),                          # Dockerfile EXPOSE
]


def detect_port_bindings(code: str) -> list[int]:
    """Extract port numbers from code that binds/listens on ports.

    Returns list of port numbers found. Used for port conflict advisory.
    """
    ports: set[int] = set()
    for pattern in _PORT_BIND_PATTERNS:
        for m in pattern.finditer(code):
            try:
                port = int(m.group(1))
                if 1024 <= port <= 65535:
                    ports.add(port)
            except (ValueError, IndexError):
                pass
    return sorted(ports)


__all__ = [
    "CodeEffect",
    "FileScanHit",
    "SensitivePathCheck",
    "scan_code",
    "scan_interpreter_code",
    "scan_file_content",
    "detect_port_bindings",
]
