# Open Source License Compliance Audit — `psf/requests`

| | |
|---|---|
| **Project** | requests (Python HTTP library), https://github.com/psf/requests |
| **Version audited** | 2.34.2 (working tree at commit `f361ead0`, branch `main`) |
| **Audit date** | 2026-07-10 |
| **Declared license** | Apache-2.0 (`LICENSE`, `NOTICE`, `pyproject.toml`, PyPI classifier) |
| **Audit depth** | Repository-wide, file-level and **snippet-level** (function-level provenance) |
| **Overall risk** | **LOW** — no license conflicts; a small number of attribution-hygiene gaps |

---

## 1. Executive summary

`requests` 2.34.2 is licensed Apache-2.0 and its four runtime dependencies are all
permissive or weak-copyleft (MIT ×2, BSD-3-Clause, MPL-2.0). There is **no vendored
third-party package code** in the tree (vendoring of urllib3/chardet ended in v2.16,
2017; `src/requests/packages.py` is import aliasing only). Distribution artifacts
(sdist/wheel) ship `LICENSE` and `NOTICE` correctly and **exclude** the two
non-Apache areas of the repo (`ext/` brand artwork, `docs/` theme).

Snippet-level review found **six third-party-derived code snippets** across the tree.
Three are properly attributed (Werkzeug utilities in `utils.py`, Flask docs theme).
Two are **unattributed derivations of CPython stdlib code** (PSF-2.0) — license-compatible
with Apache-2.0 but missing the notice retention the PSF license expects. One
(`guess_json_utf`) looks like a Stack Overflow copy but was verified via git history to be
a direct contribution by its original author (no CC BY-SA obligation).

No copyleft (GPL/LGPL/AGPL) code is present in the distributed package. The one
LGPL touchpoint — `chardet` — is an **opt-in extra** only, and chardet itself
relicensed to 0BSD in its 7.x line (verified on PyPI; ≤6.0.0 remains LGPL-2.1-or-later).

**Bottom line:** safe to use and redistribute under Apache-2.0 terms. Recommended
remediations are attribution hygiene, not legal blockers (§7).

---

## 2. Scope and methodology

**In scope:** entire working tree at `f361ead0` (147 files scanned), with emphasis on
what ships to PyPI (`src/requests/*` per `MANIFEST.in` + `[tool.setuptools]
license-files`), plus docs, tests, CI, and repo-level assets. Untracked local build
artifacts (`build/`, `src/requests.egg-info/`, `.claude/settings.local.json` — all
git-ignored) were examined and excluded from findings.

**Methods used (all four cross-checked):**

1. **Automated license/copyright scan** — ScanCode-Toolkit 32.5.0
   (`--license --copyright --info --package --email --url --classify`), full JSON in
   [`scancode-full-results.json`](./scancode-full-results.json).
2. **Manual snippet-level review** — every file in `src/requests/` read in full;
   tests, docs themes, and packaging files reviewed; attribution-marker grep
   (`stackoverflow|taken from|adapted from|copied|with permission|public domain|…`)
   across the tree.
3. **Provenance verification against upstreams** — suspect functions compared
   line-by-line against CPython `urllib/request.py` and Werkzeug; verbatim-comment
   fingerprints used as evidence (§4).
4. **Git archaeology** — `git log -S` on each suspect snippet to identify the
   introducing commit, author, and stated origin.

**SBOM generation:** clean Python 3.12 venv → `pip install .` from this tree →
CycloneDX 1.6 via cyclonedx-py (OWASP) and SPDX 2.3 via syft (§5).

---

## 3. Project licensing posture (file level)

| Artifact | Status |
|---|---|
| `LICENSE` | Full Apache-2.0 text, verbatim (ScanCode 100% match) |
| `NOTICE` | "Requests — Copyright 2019 Kenneth Reitz" (Apache §4(d) notice file) |
| `pyproject.toml` | `license = {text = "Apache-2.0"}`; classifier `OSI Approved :: Apache Software License`; `license-files = ["LICENSE", "NOTICE"]` → both files ship in wheels |
| `MANIFEST.in` | sdist ships `README.md LICENSE NOTICE HISTORY.md`, tests + test certs. **Does not ship** `ext/` or `docs/` |
| Per-file headers | `__init__.py`, `api.py` carry `:license: Apache 2.0` docstring headers; `__version__.py` has `__license__ = "Apache-2.0"`. Most modules have no license header (normal for this project; see R3) |
| Copyright holders detected in-repo | Kenneth Reitz (2011/2012/2017/2019, plus undated); "Kenneth Reitz and contributors" (docs); Armin Ronacher 2010 (docs theme only) |

**Relicensing history (matters for very old forks):** requests was ISC-licensed
before v1.0.0; the switch to Apache-2.0 shipped in **1.0.0 (2012-12-17)**
(`HISTORY.md:1543`, confirmed in `docs/api.rst:197`). All 2.x code is Apache-2.0.

**Repo-level nuance:** the repository as a whole is *not* 100 % Apache-2.0 —
`ext/` is "All rights reserved" and `docs/_themes/` is modified-BSD (see F-4, F-5).
Neither ships in the PyPI artifacts, so this affects repo cloners, not package users.

---

## 4. Snippet-level findings

Findings are ordered by attention required. "Risk" reflects realistic legal exposure
for the project and downstream users.

### F-1 — CPython-derived digest-auth implementation, unattributed
- **Location:** `src/requests/auth.py:157-266` (`HTTPDigestAuth.build_digest_header`)
- **Origin:** CPython `Lib/urllib/request.py`, `AbstractDigestAuthHandler.get_authorization` + `get_cnonce` (lineage back to Python 2 `urllib2`)
- **License of origin:** PSF-2.0 (Python Software Foundation License)
- **Introduced:** commit `60b37e54`, 2011-10-23, Kenneth Reitz ("Digest authentication support!") — no attribution in code or commit
- **Evidence (verbatim fingerprints shared with CPython):**
  - `# XXX not implemented yet` (entity digest, line 213)
  - `# XXX handle auth-int.` (line 247)
  - `# XXX should the partial digests be encoded too?` (line 252)
  - identical `A1`/`A2`/`KD` construction, `ncvalue = %08x` nonce counter, `cnonce = sha1(...)[:16]`, and the same header-assembly order (username, realm, nonce, uri, response → opaque → algorithm/digest → qop/nc/cnonce)
- **Assessment:** PSF-2.0 is permissive and Apache-2.0-compatible; ironically the
  project is PSF-stewarded, but the PSF license still asks that its copyright notice be
  retained in derivative code. Currently nothing marks this as CPython-derived.
- **Risk: Low.** Remediation R1.

### F-2 — CPython-derived Windows proxy-bypass, unattributed
- **Location:** `src/requests/utils.py:96-146` (`proxy_bypass_registry`, `proxy_bypass` on win32)
- **Origin:** CPython `Lib/urllib/request.py` `proxy_bypass_registry`, modified to skip DNS lookups
- **License of origin:** PSF-2.0
- **Introduced:** commit `1c38e1f5`, 2017-04-20, Marc Schlaich ("proxy bypass on Windows without DNS lookups") — no attribution
- **Evidence (verbatim fingerprints):** comment block "make a check value list from the
  registry entry: replace the '<local>' string by the localhost entry and the
  corresponding canonical entry" and the trio `# mask dots` / `# change glob sequence`
  / `# change glob char`, identical registry-key logic
- **Risk: Low.** Remediation R1.

### F-3 — Werkzeug HTTP-header utilities, attributed ("used with permission")
- **Location:** `src/requests/utils.py:407-497` — three functions, each individually marked
  `# From mitsuhiko/werkzeug (used with permission).`: `parse_list_header` (407),
  `parse_dict_header` (439), `unquote_header_value` (474)
- **Origin:** Werkzeug (`werkzeug/http.py`), BSD-3-Clause, © 2007-2011 Werkzeug Team
- **Introduced:** commit `9966017a`, 2011-10-23, Kenneth Reitz ("Add new utilities from werkzeug")
- **Assessment:** attribution comment present; the "used with permission" wording
  indicates a direct grant from the author in addition to BSD terms. Strict BSD-3
  compliance would also reproduce Werkzeug's copyright notice in distributions; the
  personal permission grant makes this technically moot but historically undocumented.
- **Risk: Very low.** Optional hardening in R1.

### F-4 — Flask docs theme Pygments style (verbatim third-party file, license retained)
- **Location:** `docs/_themes/flask_theme_support.py` (whole file, 87 lines) + `docs/_themes/LICENSE`
- **Origin:** Armin Ronacher's flask-sphinx-themes ("flasky extensions"), verbatim
- **License:** modified BSD (dual copyright: © 2010 Armin Ronacher, modifications © 2011 Kenneth Reitz) with an added precatory clause: *"We kindly ask you to only use these themes in an unmodified manner just for Flask and Flask-related products…"* (ScanCode: 61% BSD-2-Clause match — i.e., non-standard text)
- **Actively used:** yes — `docs/conf.py:106` sets `pygments_style = "flask_theme_support.FlaskyStyle"` (the old krTheme HTML/CSS is gone; `html_theme = "alabaster"`)
- **Assessment:** LICENSE file is retained alongside the copy — compliant. The "kindly
  ask" clause is a request, not a binding condition, and applies to the *theme*;
  requests' historical use predates today's norms and the file is docs-only (never in
  sdist/wheel/PyPI).
- **Risk: Very low.** No action required; noted for completeness.

### F-5 — `ext/` brand artwork is proprietary ("All rights reserved")
- **Location:** `ext/LICENSE` ("Copyright 2019 Kenneth Reitz. All rights reserved."), covering `requests-logo.{svg,png,ai}`, `kr.png`, `psf.png`
- **Assessment:** intentional — these are logos/brand assets, deliberately excluded
  from the open-source grant, from the sdist (`MANIFEST.in`), and from lint tooling
  (`.pre-commit-config.yaml` excludes `ext/`). `README.md:76` displays two of them,
  which is use by the rights holders themselves.
- **Compliance impact:** anyone forking/redistributing the *repository* (not the PyPI
  package) must treat `ext/` as not-open-source, and the GitHub "Apache-2.0" repo label
  overstates coverage slightly.
- **Risk: Low** (repo-level only). Remediation R2.

### F-6 — `guess_json_utf`: Stack Overflow lookalike, provenance verified clean
- **Location:** `src/requests/utils.py:1002-1037`
- **Concern checked:** the identical BOM/null-counting technique circulates on Stack
  Overflow (CC BY-SA), which would carry attribution/share-alike obligations
- **Verification:** introduced by commit `4decc798` (2012-10-25) authored by
  **Martijn Pieters himself** — the same person who posted the technique on SO. Direct
  contribution by the copyright holder under the project's inbound=outbound Apache-2.0
  ⇒ **no CC BY-SA derivation**.
- **Risk: None.** Informational.

### F-7 — Remaining utility functions: no external provenance found
`address_in_network` / `dotted_netmask` / `is_ipv4_address` / `is_valid_cidr`
(`utils.py:726-784`) were introduced by Kamil Madac in 2013 (`8aff6f5e`,
"Redesigned no_proxy ip range implementation to use only stdlib functions") as an
ordinary contribution; ScanCode and manual comparison found no matching upstream.
`super_len`, `requote_uri`, redirect handling, `CaseInsensitiveDict`, cookies
machinery, `models/sessions/adapters` are original to requests (the latter use
urllib3 strictly through its public API — no copied urllib3 code found).
Test TLS certificates in `tests/certs/` are first-party generated
(subject `O=Python Software Foundation, OU=python-requests`; Makefiles included).

### Triaged automated-scan hits (false positives / non-code)
| ScanCode hit | Explanation |
|---|---|
| `docs/api.rst` → "ISC AND Apache-2.0" | Prose describing the 2012 ISC→Apache relicense, not embedded ISC code |
| `docs/user/advanced.rst` → "LGPL-2.0+ AND MIT" | Prose discussing chardet's (then-)LGPL license and MIT charset-normalizer |
| `HISTORY.md` → "MIT AND Apache-2.0" | Changelog entries mentioning licenses |
| `.claude/settings.local.json` → "Python-2.0" | Local git-ignored tool config, not part of the project |
| `build/lib/requests/*` → Apache-2.0 | Untracked local build artifact (duplicate of src) |

---

## 5. SBOM

Two SBOM files are delivered alongside this report, generated from a clean-room
install of this exact tree (Python 3.12 venv):

- **[`sbom-requests-2.34.2.cyclonedx.json`](./sbom-requests-2.34.2.cyclonedx.json)** — CycloneDX 1.6 (JSON), root component `pkg:pypi/requests@2.34.2`, full dependency graph
- **[`sbom-requests-2.34.2.spdx.json`](./sbom-requests-2.34.2.spdx.json)** — SPDX 2.3 (JSON), generated by syft

### 5.1 Runtime dependencies (as resolved on audit date)

| Package | Version | License (SPDX) | purl | Role |
|---|---|---|---|---|
| **requests** | 2.34.2 | Apache-2.0 | `pkg:pypi/requests@2.34.2` | subject of audit |
| urllib3 | 2.7.0 | MIT | `pkg:pypi/urllib3@2.7.0` | HTTP transport |
| charset-normalizer | 3.4.9 | MIT | `pkg:pypi/charset-normalizer@3.4.9` | encoding detection |
| idna | 3.18 | BSD-3-Clause | `pkg:pypi/idna@3.18` | IDNA hostnames |
| certifi | 2026.6.17 | **MPL-2.0** | `pkg:pypi/certifi@2026.6.17` | CA bundle (Mozilla-derived) |

Declared ranges (`pyproject.toml`) are wider than the resolution above:
`urllib3>=1.26,<3`, `charset_normalizer>=2,<4`, `idna>=2.5,<4`, `certifi>=2023.5.7`.
The SBOM captures one concrete, current resolution; regenerate for a locked deployment.

### 5.2 Optional extras (not in SBOM — install-time opt-in)

| Extra | Package | License | Note |
|---|---|---|---|
| `socks` | PySocks >=1.5.6,!=1.5.7 | BSD | permissive |
| `use_chardet_on_py3` | chardet >=3.0.2,<8 | **version-dependent**: ≤6.0.0 → LGPL-2.1-or-later; 7.x → 0BSD (relicensed 2026, verified on PyPI) | see §6.2 |

### 5.3 Development / docs / CI dependencies (never distributed)

pytest (MIT), pytest-cov (MIT), pytest-httpbin 2.1.0 (MIT), httpbin ~=0.10 (MIT/ISC),
trustme (MIT OR Apache-2.0), wheel (MIT), Sphinx 7.2.6 (BSD-2-Clause), alabaster
theme (BSD-3-Clause), ruff + pre-commit-hooks (MIT), pyright (MIT). GitHub Actions
workflows use standard `actions/*` (MIT). No compliance obligations flow to users of
the package from these.

---

## 6. License compatibility & obligations analysis

### 6.1 Compatibility matrix (into an Apache-2.0 work)

| Component/snippet | License | Compatible with Apache-2.0? | Obligation triggered |
|---|---|---|---|
| CPython snippets (F-1, F-2) | PSF-2.0 | ✅ Yes (permissive) | Retain PSF copyright/license notice in derivative code |
| Werkzeug snippets (F-3) | BSD-3-Clause (+ personal permission) | ✅ Yes | Retain copyright notice (covered by permission grant; see R1) |
| urllib3, charset-normalizer | MIT | ✅ Yes | Include MIT notice when redistributing binaries |
| idna | BSD-3-Clause | ✅ Yes | Include BSD notice when redistributing binaries |
| certifi | MPL-2.0 | ✅ Yes (file-level copyleft; used unmodified as a dependency) | Keep MPL notice; if you *modify* certifi's `cacert.pem`, make that file's source available under MPL-2.0 |
| chardet ≤6 (optional) | LGPL-2.1-or-later | ⚠️ Yes for normal (dynamic import) use; **caution when freezing/bundling** (PyInstaller, single-binary) — LGPL §6 relink/replace obligations | Only if the extra is installed |
| chardet 7.x (optional) | 0BSD | ✅ Yes (no notice requirement) | None |
| Flask theme (docs only) | Modified BSD + precatory request | ✅ (not distributed) | LICENSE retained in-tree — done |
| `ext/` artwork | Proprietary | N/A — excluded from grant | Do not redistribute outside this repo context |

**No GPL/AGPL anywhere in the tree or dependency graph. No license conflicts exist.**

### 6.2 The chardet nuance (historical + current)

requests deliberately demoted chardet to an opt-in extra in v2.26 (HISTORY.md:378:
*"use the MIT-licensed charset_normalizer … to remove license ambiguity for projects
bundling requests"*). That mitigation remains correct. Newly verified during this
audit: chardet's PyPI metadata declares **0BSD from the 7.x line** (7.4.3 checked),
while 5.2.0 and 6.0.0 still declare LGPL-2.1-or-later — so even the extra is
permissive if resolution lands on 7.x. Pin `chardet>=7` if the LGPL matters to you.

### 6.3 Downstream redistribution checklist (for consumers of requests 2.34.2)

1. Include requests' `LICENSE` (Apache-2.0) and `NOTICE` file (Apache §4(d)) — both ship inside the wheel's `*.dist-info/licenses/`.
2. If bundling dependencies (containers/freezers): carry MIT texts (urllib3, charset-normalizer), BSD-3 text (idna), and MPL-2.0 text (certifi). Don't modify `cacert.pem` without MPL source-availability for it.
3. If you modify requests itself: Apache §4(b) — state changes; keep existing attribution comments (werkzeug markers etc.).
4. Trademark: the requests logo (`ext/`) is not licensed for reuse.

---

## 7. Recommended remediations (all low severity, hygiene-grade)

| # | Priority | Action |
|---|---|---|
| **R1** | Medium | Add in-file attribution for the two CPython-derived snippets, e.g. `# Adapted from CPython Lib/urllib/request.py (PSF-2.0); see NOTICE.` at `utils.py:96` and `auth.py:157`, and append a short third-party-notices block (PSF-2.0 for CPython snippets; Werkzeug © 2007-2011 BSD-3-Clause) to `NOTICE` or a `THIRD_PARTY_NOTICES` file included in `license-files`. This fully discharges PSF/BSD notice-retention. |
| **R2** | Low | Add one line to `ext/LICENSE` or a `README` in `ext/` clarifying these are trademark/brand assets excluded from the Apache-2.0 grant, and consider a "License" section in the top-level README stating the three zones (code: Apache-2.0; docs theme: BSD; ext: reserved). |
| **R3** | Low | Consistency pass: `NOTICE` year (2019) vs headers (2012/2017) vs undated `__copyright__`; consider `SPDX-License-Identifier: Apache-2.0` headers (REUSE spec) so file-level tooling stops flagging headerless modules. |
| **R4** | Cosmetic | Modernize `pyproject.toml` to PEP 639: `license = "Apache-2.0"` (SPDX expression string) + top-level `license-files`, replacing the deprecated `{text = ...}` table and `[tool.setuptools]` key. |

Nothing found requires code removal, relicensing, or legal escalation.

---

## 8. Reproduction

```bash
# ScanCode (snippet/license/copyright scan)
scancode --license --copyright --info --package --email --url --classify \
  --json-pp scancode-full-results.json --ignore "*.git/*" --ignore "*.egg-info/*" .

# SBOMs from a clean venv
uv venv --python 3.12 /tmp/sbomenv && uv pip install --python /tmp/sbomenv/bin/python .
uvx --from cyclonedx-bom cyclonedx-py environment /tmp/sbomenv/bin/python \
  --spec-version 1.6 --output-format JSON -o sbom.cdx.json
syft scan dir:/tmp/sbomenv -o spdx-json=sbom.spdx.json

# Provenance archaeology
git log -S "XXX should the partial digests" --oneline --reverse   # → 60b37e54 (2011)
git log -S "proxy_bypass_registry" --oneline --reverse            # → 1c38e1f5 (2017)
git log -S "guess_json_utf" --oneline --reverse                   # → 4decc798 (Pieters, 2012)
```

**Tooling:** ScanCode-Toolkit 32.5.0 · syft (SPDX 2.3) · cyclonedx-py (CycloneDX 1.6) ·
pip-licenses · manual review of all 19 `src/requests` modules, tests, docs, packaging.

*This report is a technical compliance analysis, not legal advice.*
