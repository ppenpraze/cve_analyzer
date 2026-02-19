# CVE Analyzer — Claude Instructions

## Purpose & User Context

This tool is used by **application managers and teams** to independently verify
CVE findings reported by their Information Security team. The goal is to answer
one question per CVE: **"Does this actually affect our environment?"**

The environment is **exclusively Red Hat Enterprise Linux (RHEL) and OpenShift
Container Platform (OCP)**. Nothing else is in scope.

The output is a CSV loaded into a spreadsheet. Reviewers scan many CVEs at once,
so **brevity and clarity in every row matters more than exhaustive detail**.

---

## Single Source of Truth: `cve_analyzer.py`

The entire tool lives in one file. Do not split it across modules unless the
file exceeds ~600 lines or the user explicitly requests it.

**`requirements.txt`** — only external dependency is `requests`.

---

## Output Design — The Most Important Constraint

> **At most two rows per CVE: one for RHEL, one for OpenShift.**

This was a deliberate decision. Previous per-product-per-row designs produced
18+ rows for a single CVE, making the spreadsheet unworkable. Never revert to
a per-product row model without explicit user instruction.

Each row consolidates all product-level entries for one platform into a single
summary. The `Impacted Version(s)` field lists every affected minor version
(e.g., `RHEL 8, RHEL 8.1, RHEL 8.6, RHEL 9, RHEL 9.2`).

---

## CSV Schema

| Column | Description |
|---|---|
| `CVE` | CVE identifier (e.g., `CVE-2023-38408`) |
| `Severity` | RedHat `threat_severity` (Critical/Important/Moderate/Low), NIST fallback |
| `Score` | CVSS3 base score; CVSS2 fallback |
| `Platform` | `RHEL`, `OpenShift`, or `RHEL / OpenShift` (no-data fallback only) |
| `Applicable?` | `Yes` / `No` / `Unknown` |
| `Affected Component(s)` | Package or image names (RPM name only, no version) |
| `Fix Advisory` | Comma-separated RHSA IDs that address this CVE |
| `Impacted Version(s)` | Numerically sorted versions, e.g. `RHEL 8, RHEL 8.6, OCP 4.13` |
| `Component Type(s)` | `RPM (BaseOS)`, `RPM (AppStream)`, `RHCOS`, `Operator`, etc. |
| `Justification` | Human-readable sentence explaining the verdict |
| `URL` | RedHat CVE page; appended with errata URL when sourced from RHSA |

---

## Data Sources

### RedHat Security Data API
- **CVE detail**: `GET .../securitydata/cve/{CVE_ID}.json`
  - Severity key is **`threat_severity`** — NOT `severity` (common mistake)
  - CVSS3 score: `cvss3.cvss3_base_score`
  - CVSS2 score: `cvss.cvss_base_score`
  - `affected_release[]` — products where a fix has been shipped; each entry has
    `product_name`, `cpe`, `package` (NEVRA string), `advisory`
  - `package_state[]` — products with known but unfixed status; each entry has
    `product_name`, `cpe`, `package_name`, `fix_state`
- **Advisory → CVE list**: `GET .../securitydata/cve.json?advisory=RHSA-YYYY:NNNN`
  - Returns a JSON **array** of CVE summary objects; each has a `CVE` key (uppercase)
  - **The `/advisory/{id}.json` endpoint does not exist publicly** — do not use it

### NIST NVD API 2.0
- `GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-...`
- Score path: `vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore`
- Severity v3: nested inside `cvssData.baseSeverity`
- Severity v2: top-level `baseSeverity` (not nested)
- **Rate limits**: 5 req/30 s (no key) → use ≥6.5 s delay; 50 req/30 s (with key)
- Pass API key as HTTP header `apiKey`, not as a query param

---

## Platform Classification Rules

Classification order is critical — **OpenShift is checked before RHEL**.

This prevents `Red Hat Enterprise Linux CoreOS` (which contains "Enterprise Linux")
from being misclassified as RHEL. RHCOS is an OCP node OS, not standalone RHEL.

```
classify_entry(product_name, cpe):
  if is_openshift(combined) → "OpenShift"
  elif get_rhel_major(combined) in RHEL_VERSIONS → "RHEL"
  else → None  (skip, not in scope)
```

**OpenShift signals** (any match → OpenShift):
- `OpenShift Container Platform`, `OpenShift 4.`, `OpenShift Virtualization`
- `RHCOS`, `Red Hat CoreOS`, `Enterprise Linux CoreOS`
- CPE `cpe:/a:redhat:openshift`

**RHEL signals** (extract major version, must be in `RHEL_VERSIONS`):
- Product name: `Enterprise Linux <N>` — captures first digit after keyword
- CPE: `enterprise_linux:<N>`
- Short CPE: `:<N>::`
- Short form: `RHEL <N>`
- RPM tag: `.el<N>`

**To add RHEL 10**: change one line — `RHEL_VERSIONS = (8, 9, 10)`

---

## `fix_state` Values and Their Meaning

From `package_state[].fix_state` in the RedHat API:

| fix_state | Applicable? | Meaning |
|---|---|---|
| `Not affected` | No | Package is not vulnerable on this platform |
| `Affected` | Yes | Vulnerable; fix not yet released |
| `Will not fix` | Yes | Vulnerable; Red Hat will not release a patch |
| `Out of support scope` | Yes | Platform EOL; no patch coming |
| `Fix deferred` | Yes | Fix postponed to a future release |
| `Under investigation` | Unknown | Actively researching; verdict pending |

When `affected_release` entries exist for a platform, the CVE was patched
(Applicable=Yes, the version was vulnerable before the fix). `package_state`
entries only matter when there are no `affected_release` entries for that platform.

---

## Key Functions

| Function | Role |
|---|---|
| `classify_entry(product_name, cpe)` | Returns `"RHEL"`, `"OpenShift"`, or `None` |
| `build_platform_row(...)` | Consolidates all releases/states for one platform into one CSV row |
| `analyze_cve(cve_id, ...)` | Calls `build_platform_row` for RHEL and OCP; returns 1–2 rows |
| `extract_cves_from_rhsa(rhsa_id)` | Queries RedHat API for CVEs in an advisory |
| `sort_versions(versions)` | Numerically sorts version strings (`RHEL 8` < `RHEL 8.6` < `RHEL 9`) |

---

## Coding Conventions

- Python 3.10+ type hints (`X | Y`, `list[dict]`)
- All progress output goes to **stderr**; only the CSV goes to the output file
- HTTP requests always include `User-Agent: cve-analyzer/1.0`
- `extrasaction="ignore"` on `DictWriter` — internal `_product` keys are safely dropped
- No third-party libraries beyond `requests`; keep it that way unless the user asks

---

## Validation — Reference CVEs for Testing

Use `--no-nist` flag to skip NIST calls and speed up tests significantly.

| CVE | What to verify |
|---|---|
| `CVE-2023-38408` (OpenSSH) | RHEL row: `Applicable=Yes`, versions RHEL 8 through RHEL 8.6 |
| `CVE-2023-0286` (OpenSSL) | RHEL row with both RHEL 8.x and RHEL 9.x versions consolidated |
| `CVE-2021-44228` (Log4Shell) | RHEL `Applicable=No`; OpenShift `Applicable=Yes` (OCP 4.x) |

Quick smoke test:
```bash
echo "CVE-2021-44228 CVE-2023-38408" | python cve_analyzer.py --no-nist -o /tmp/test.csv
```
Expected: 3 rows total — 1 RHEL + 1 OCP for Log4Shell, 1 RHEL for OpenSSH.

---

## What NOT to Do

- Do not revert to per-product rows — the two-row-per-CVE model is intentional
- Do not add features that call APIs other than RedHat Security Data and NIST NVD
  without user approval
- Do not auto-commit; only commit when explicitly asked
- Do not add dependencies beyond `requests`
- Do not broaden RHEL detection to versions outside `RHEL_VERSIONS` — the tuple
  is the authoritative list of what this environment runs
