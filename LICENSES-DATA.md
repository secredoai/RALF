# Data Attribution & Licenses

RALF Free (the code) is licensed under **Apache-2.0** (see `LICENSE`). RALF Free
also bundles or fetches security-knowledge data from several upstream sources;
each of those sources carries its own license. This file enumerates every data
source that ships with or is fetched by RALF Free, cites the relevant license,
and describes the attribution we carry.

If you redistribute RALF Free (fork, repackage, or include in a derivative
tool), you must preserve the attribution listed here and comply with each
upstream license's terms.

---

## CVE / vulnerability data

### OSV.dev — `https://osv.dev/`

- **Bundled location**: `~/.config/ralf/advisories_osv.db` (populated on first
  `ralf-free sync cve`)
- **Per-ecosystem licensing** (as declared by the OSV ecosystem feeds):
  - PyPI / PyPA advisories — **CC0 1.0** (no attribution required, but we
    acknowledge the PyPA Advisory Database anyway)
  - GitHub Security Advisory (GHSA) subset — **CC-BY-4.0**
  - crates.io / RustSec — **CC0 1.0 + MIT/Apache-2.0 dual** (RustSec)
  - RubyGems advisories — **CC-BY-4.0**
  - Go Vulnerability Database (`pkg.go.dev`) — **BSD-3-Clause / CC-BY-4.0**
  - Packagist (PHP) — **CC-BY-4.0**
- **Attribution requirement** (CC-BY-4.0): "Vulnerability data © the respective
  database publishers, distributed by OSV.dev. Attribution: https://osv.dev/"

### GitHub Security Advisory (GHSA) — `https://github.com/advisories`

- License: **CC-BY-4.0**
- Attribution: "GitHub Advisory Database, © GitHub Inc., CC-BY-4.0
  (https://github.com/github/advisory-database)."

### National Vulnerability Database (NVD) — `https://nvd.nist.gov/`

- License: **Public Domain** (US Government work)
- **Not directly bundled or fetched by RALF Free.** OSV advisories reference
  CVE IDs assigned through the NVD / MITRE CVE Program, and those IDs appear
  in our DB; the advisory text itself comes from OSV, not NVD. No attribution
  required; we credit NVD in docs as a courtesy for the CVE-ID namespace.

### NuGet / Microsoft .NET advisories

- License when sourced via OSV: **CC-BY-SA-4.0** (Share-Alike)
- **RALF Free DOES NOT bundle NuGet advisories by default** — the CVE
  federator excludes NuGet to avoid the Share-Alike clause's
  derivative-relicensing obligation on RALF Free's Apache-2.0 tool code.
- Users who want NuGet coverage can opt in with
  `ralf-free sync cve --ecosystems NuGet` and must accept the CC-BY-SA-4.0
  obligation on the resulting local DB.

---

## Framework / taxonomy data

### MITRE ATT&CK

- Source: `https://attack.mitre.org/`
- Bundled files: `ralf/data/mitre_attack_linux.json`, `mitre_attack_macos.json`
- License: **© MITRE, usage governed by the MITRE ATT&CK Terms of Use**
  (https://attack.mitre.org/resources/terms-of-use/). The terms permit free
  use provided attribution is maintained.
- Attribution in every file: `"source": "MITRE ATT&CK Enterprise Matrix"` +
  URL reference.

### MITRE CWE (Common Weakness Enumeration)

- Source: `https://cwe.mitre.org/`
- Bundled file: `ralf/data/cwe_top25.json`
- License: **© MITRE, per the CWE Terms of Use** — free for commercial and
  non-commercial use with attribution.
- Attribution in file: `"source": "MITRE CWE — https://cwe.mitre.org/"`.

### OWASP Top 10 (2021)

- Source: `https://owasp.org/Top10/`
- Bundled file: `ralf/data/owasp_top10_2021.json`
- License: **CC-BY-SA-4.0** (Share-Alike)
- **Attribution + Share-Alike obligation**: any redistribution of the Top 10
  content (or recognizable derivatives) must be licensed under CC-BY-SA-4.0.
  The RALF Free *code* remains Apache-2.0; the *Top 10 data bundle* carries
  forward OWASP's CC-BY-SA-4.0 license.

### OWASP ASVS v5

- Source: `https://owasp.org/www-project-application-security-verification-standard/`
- Bundled file: `ralf/data/owasp_asvs_v5.json`
- License: **CC-BY-SA-4.0** — same attribution + Share-Alike obligation as Top 10.

### OWASP Cheat Sheet Series

- Source: `https://cheatsheetseries.owasp.org/`
- Bundled: only URL references (no cheat-sheet content is copied into RALF).
- License: **CC-BY-SA-4.0** — since we only reference URLs, not content, the
  SA clause does not trigger for RALF's bundle.

---

## Host-hardening catalogs

### GTFOBins — `https://gtfobins.github.io/`

- Bundled: `ralf/data/gtfobins_capabilities.json` + rules in
  `learned_rules.yaml` tagged `source: gtfobins_*`.
- License: **CC-BY-3.0**
- Attribution: "GTFOBins, © the GTFOBins community, licensed CC-BY-3.0
  (https://gtfobins.github.io/)."

### LOOBins — `https://www.loobins.io/` (github.com/infosecB/LOOBins)

- Bundled: `ralf/data/loobins_capabilities.json`
- License: **MIT**
- Attribution in file: `"source": "loobins.io"`.

### NIST macOS Security Compliance Project (mSCP)

- Source: `https://github.com/usnistgov/macos_security`
- Bundled file: `ralf/data/mscp_rules.json`
- License: **Public Domain** (US Government work, NIST SP 800-219 / mSCP)
- No attribution required; we credit NIST in the file header as a courtesy.

### CIS Benchmarks

- Source: `https://www.cisecurity.org/cis-benchmarks/`
- Bundled: 80 host-posture checks (40 Linux, 40 macOS) carry a `benchmark_id`
  field that cross-references the applicable CIS section number (e.g.
  "CIS-5.2.7"). All check implementations are independently authored; no CIS
  prose, remediation text, or scoring criteria is copied verbatim.
- License: **Benchmark content is CIS-copyrighted**; references to section
  numbers for cross-linking are fair-use. If you redistribute a product that
  copies CIS Benchmark text verbatim, you must obtain a CIS license.

### Objective-See Malware Feed

- Source: `https://github.com/objective-see/Malware`
- Bundled: IOC records (SHA-256 hashes, bundle IDs) synced on demand via
  ``ralf-free threats sync`` into a local SQLite database. No feed content is
  shipped in the package; the user fetches it explicitly.
- License: **Objective-See community project**. The malware catalog is published
  publicly for community use. We store only hash digests and bundle identifiers;
  no sample binaries or copyrightable analysis text is retained.

---

## SAST-integration tools (invoked at runtime, not bundled)

### Ruff — `https://github.com/astral-sh/ruff`

- License: **MIT**
- Not bundled; RALF Free invokes `ruff` if installed on the user's PATH.

### Bandit — `https://github.com/PyCQA/bandit`

- License: **Apache-2.0**
- Not bundled; invoked via PATH.

### ast-grep — `https://github.com/ast-grep/ast-grep`

- License: **MIT**
- Not bundled; invoked via PATH.

### Semgrep (not bundled)

- License: **LGPL-2.1** (Semgrep OSS core)
- Not bundled. RALF invokes Semgrep as an external tool if installed on the
  system. When configured, Semgrep retrieves and manages its own rulesets
  locally under its own licensing terms. RALF does not bundle, store, or
  distribute any Semgrep rule content. RALF stores only ruleset *names*
  (e.g. ``p/ci``, ``p/security-audit``) as configuration strings passed
  to the Semgrep CLI via ``--config`` flags.

---

## Agent integration data

### MITRE ATT&CK techniques for threat-intel tagging

- Covered above under "MITRE ATT&CK."

### Claude Code / Gemini CLI / Codex CLI hook schemas

- Documented in each agent's public docs; RALF Free's adapter code consumes
  documented JSON envelopes. No vendor data is bundled.

---

## Quick-reference license obligations

| Obligation | Trigger |
|---|---|
| Attribution (CC-BY / CC-BY-SA) | Whenever you redistribute the bundled data, keep this file and per-file `"source"` / `"url"` attributions intact |
| Share-Alike (CC-BY-SA-4.0) | Applies to OWASP Top 10, OWASP ASVS. Means derivatives of **that specific data** (not the Apache-2.0 tool code) must carry forward CC-BY-SA-4.0 |
| NuGet SA clause | Avoided by default: the federator skips NuGet unless opted in |
| RALF Free tool code | Apache-2.0, unchanged |

---

## Disclaimer

RALF Free aggregates public security-knowledge data for detection purposes.
The advisories / rules / taxonomies are *as provided* by the upstream
publishers. RALF Free does not warrant completeness, accuracy, or currency of
the aggregated data. Protection against a specific vulnerability requires the
relevant upstream source to have published that advisory — if the upstream
doesn't have it, RALF Free can't know about it.

For any ambiguity in this file, the upstream license wins over RALF Free's
summary here. When in doubt, consult the upstream source directly.
