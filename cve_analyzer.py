#!/usr/bin/env python3
"""
cve_analyzer.py - CVE/RHSA Analyzer

Reads CVE IDs (CVE-YYYY-NNNNN) and/or RHSA advisory IDs (RHSA-YYYY:NNNN)
from stdin or command-line arguments, queries RedHat Security Data API and
NIST NVD, and writes a CSV report assessing RHEL 8/9 and OpenShift impact.

Each CVE produces at most two rows — one summarising RHEL impact and one
summarising OpenShift impact — making the output easy to review in a
spreadsheet without row explosion.

CSV schema:
  CVE, Severity, Score, Platform, Applicable?, Affected Component(s),
  Fix Advisory, Impacted Version(s), Component Type(s), Justification, URL

Usage:
  echo "CVE-2023-38408 RHSA-2023:4329" | python cve_analyzer.py
  python cve_analyzer.py -o report.csv CVE-2023-38408 RHSA-2023:4329
  python cve_analyzer.py < ids.txt -o report.csv
"""

import os
import sys
import csv
import re
import time
import argparse
import requests
import requests.auth
from datetime import datetime

# Optional NTLM auth — requires the requests-ntlm package
try:
    from requests_ntlm import HttpNtlmAuth as _HttpNtlmAuth
    _NTLM_AVAILABLE = True
except ImportError:
    _HttpNtlmAuth = None   # satisfies static analysis; guarded by _NTLM_AVAILABLE
    _NTLM_AVAILABLE = False

# ── API Endpoints ──────────────────────────────────────────────────────────────
RH_CVE_API          = "https://access.redhat.com/hydra/rest/securitydata/cve/{}.json"
RH_ADVISORY_CVE_API = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
NIST_API            = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RH_CVE_PAGE    = "https://access.redhat.com/security/cve/{}"
RH_ERRATA_PAGE = "https://access.redhat.com/errata/{}"

# ── Patterns ───────────────────────────────────────────────────────────────────
CVE_RE  = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
RHSA_RE = re.compile(r'RH[SEB]A-\d{4}:\d+(?:-\d+)?', re.IGNORECASE)

# RHEL major versions to track (add 10 here when the time comes)
RHEL_VERSIONS = (8, 9)

# ── CSV Schema ─────────────────────────────────────────────────────────────────
CSV_FIELDS = [
    'CVE',
    'Severity',
    'Score',
    'Platform',
    'Applicable?',
    'Environment Match',      # Confirmed / Likely / Possible / Not Detected
    'Matched On',             # Which hosts/components matched
    'Affected Component(s)',
    'Fix Advisory',
    'Impacted Version(s)',
    'Component Type(s)',
    'Justification',
    'URL',
]

# ── Rate-limiting for NIST ────────────────────────────────────────────────────
_last_nist_call: float = 0.0
NIST_DELAY_NO_KEY   = 6.5   # 5 req / 30 s without API key
NIST_DELAY_WITH_KEY = 0.7   # 50 req / 30 s with key

# ── HTTP session ───────────────────────────────────────────────────────────────
# Single shared session — proxy and auth are configured once via configure_proxy()
# before any requests are made.
_SESSION: requests.Session = requests.Session()
_SESSION.headers["User-Agent"] = "cve-analyzer/1.0"


def configure_proxy(
    proxy_url: str = "",
    auth_type: str = "",
    username: str = "",
    password: str = "",
) -> None:
    """
    Configure the shared HTTP session for proxy access.

    Parameters are resolved in this order: CLI argument → environment variable.

    Environment variables
    ─────────────────────
    HTTPS_PROXY          Proxy URL, e.g. http://proxy.corp.com:8080
                         Also accepts HTTP_PROXY as a fallback.
    CVE_PROXY_AUTH       Authentication type: basic | ntlm | digest
                         Defaults to 'basic' when credentials are supplied.
    CVE_PROXY_USERNAME   Proxy username.
                         For NTLM use DOMAIN\\username format.
    CVE_PROXY_PASSWORD   Proxy password.

    Authentication types
    ─────────────────────
    basic   HTTP Basic proxy authentication (RFC 7235).
    digest  HTTP Digest proxy authentication (RFC 7616).
    ntlm    Microsoft NTLM — requires the requests-ntlm package.
            Install: pip install requests-ntlm
            If the package is absent, falls back to basic authentication.
    """
    url  = proxy_url or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
    if not url:
        return

    auth = (auth_type or os.environ.get("CVE_PROXY_AUTH", "basic")).lower().strip()
    user = username or os.environ.get("CVE_PROXY_USERNAME", "")
    pw   = password or os.environ.get("CVE_PROXY_PASSWORD", "")

    _SESSION.proxies.update({"http": url, "https": url})

    if not user:
        print(f"[INFO] Proxy: {url} (no authentication)", file=sys.stderr)
        return

    if auth == "ntlm":
        if not _NTLM_AVAILABLE:
            print(
                "[WARN] NTLM proxy auth requested but requests-ntlm is not installed.\n"
                "       Install it with: pip install requests-ntlm\n"
                "       Falling back to Basic authentication.",
                file=sys.stderr,
            )
            _SESSION.auth = requests.auth.HTTPProxyAuth(user, pw)
            print(f"[INFO] Proxy: {url} (Basic auth fallback, user={user})", file=sys.stderr)
        else:
            _SESSION.auth = _HttpNtlmAuth(user, pw)
            print(f"[INFO] Proxy: {url} (NTLM auth, user={user})", file=sys.stderr)
    elif auth == "digest":
        _SESSION.auth = requests.auth.HTTPDigestAuth(user, pw)
        print(f"[INFO] Proxy: {url} (Digest auth, user={user})", file=sys.stderr)
    else:
        _SESSION.auth = requests.auth.HTTPProxyAuth(user, pw)
        print(f"[INFO] Proxy: {url} (Basic auth, user={user})", file=sys.stderr)


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(url: str, params: dict | None = None, timeout: int = 20) -> dict | None:
    """GET JSON from *url*, returning parsed dict or None on any error."""
    try:
        resp = _SESSION.get(url, params=params, timeout=timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        print(f"[WARN] GET {url} failed: {exc}", file=sys.stderr)
        return None


def fetch_rh_cve(cve_id: str) -> dict:
    """Fetch CVE data from RedHat Security Data API."""
    return _get(RH_CVE_API.format(cve_id.upper())) or {}


def fetch_rh_rhsa_cves(rhsa_id: str) -> list:
    """
    Return a list of CVE summary dicts for *rhsa_id* by querying the
    RedHat CVE endpoint filtered by advisory ID.
    """
    try:
        resp = _SESSION.get(
            RH_ADVISORY_CVE_API,
            params={"advisory": rhsa_id.upper()},
            timeout=20,
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
    except Exception as exc:
        print(f"[WARN] RedHat advisory fetch failed for {rhsa_id}: {exc}", file=sys.stderr)
        return []


def fetch_nist_cve(cve_id: str, api_key: str = "") -> dict:
    """Fetch CVE data from NIST NVD API 2.0 with rate-limiting."""
    global _last_nist_call
    delay = NIST_DELAY_WITH_KEY if api_key else NIST_DELAY_NO_KEY
    elapsed = time.monotonic() - _last_nist_call
    if elapsed < delay:
        time.sleep(delay - elapsed)

    extra_headers = {}
    if api_key:
        extra_headers["apiKey"] = api_key

    try:
        resp = _SESSION.get(
            NIST_API,
            params={"cveId": cve_id.upper()},
            headers=extra_headers,
            timeout=20,
        )
        _last_nist_call = time.monotonic()
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        return vulns[0].get("cve", {}) if vulns else {}
    except Exception as exc:
        print(f"[WARN] NIST fetch failed for {cve_id}: {exc}", file=sys.stderr)
        _last_nist_call = time.monotonic()
        return {}


# ── Platform detection ─────────────────────────────────────────────────────────

def is_openshift(text: str) -> bool:
    """
    Return True if *text* references an OpenShift / RHCOS product.

    OpenShift is checked before RHEL so that RHCOS entries (which mention
    "Enterprise Linux CoreOS") are classified as OpenShift, not RHEL.
    """
    return bool(re.search(
        r'OpenShift\s+Container\s+Platform'
        r'|OpenShift\s+4\.'
        r'|RHCOS'
        r'|Red Hat CoreOS'
        r'|Enterprise Linux CoreOS'      # RHCOS full product name
        r'|OpenShift\s+Virtualization'
        r'|cpe:/a:redhat:openshift',
        text, re.IGNORECASE,
    ))


def get_rhel_major(text: str) -> int | None:
    """
    Return the RHEL major version (8 or 9) found in *text*, or None.
    Only returns versions listed in RHEL_VERSIONS.
    """
    # Product name: "Enterprise Linux 8", "Enterprise Linux 9.2", etc.
    m = re.search(r'Enterprise Linux[^\d]*(\d+)', text, re.IGNORECASE)
    if m:
        v = int(m.group(1))
        if v in RHEL_VERSIONS:
            return v

    # CPE: enterprise_linux:8 or enterprise_linux:9
    m = re.search(r'enterprise_linux:(\d+)', text, re.IGNORECASE)
    if m:
        v = int(m.group(1))
        if v in RHEL_VERSIONS:
            return v

    # Short CPE form: :8:: or :9::
    m = re.search(r':(\d+)::', text)
    if m:
        v = int(m.group(1))
        if v in RHEL_VERSIONS:
            return v

    # RHEL short form: "RHEL 8", "RHEL-9", etc.
    m = re.search(r'\bRHEL[_\-\s]?(\d+)', text, re.IGNORECASE)
    if m:
        v = int(m.group(1))
        if v in RHEL_VERSIONS:
            return v

    # RPM release tag: .el8 or .el9
    m = re.search(r'\.el(\d+)', text)
    if m:
        v = int(m.group(1))
        if v in RHEL_VERSIONS:
            return v

    return None


def classify_entry(product_name: str, cpe: str) -> str | None:
    """
    Classify an affected_release or package_state entry as 'OpenShift',
    'RHEL', or None (not relevant to our environment).

    OpenShift is evaluated first so that RHCOS entries are not mistakenly
    classified as RHEL.
    """
    combined = product_name + " " + cpe
    if is_openshift(combined):
        return "OpenShift"
    if get_rhel_major(combined) is not None:
        return "RHEL"
    return None


# ── Version extraction ─────────────────────────────────────────────────────────

def extract_rhel_version(product_name: str, cpe: str = "") -> str:
    """
    Return the specific RHEL version string, e.g. "RHEL 8", "RHEL 8.6",
    "RHEL 9.2".
    """
    major = get_rhel_major(product_name + " " + cpe)
    if not major:
        return ""

    m = re.search(rf'Enterprise Linux[^\d]*{major}\.(\d+)', product_name, re.IGNORECASE)
    if m:
        return f"RHEL {major}.{m.group(1)}"

    m = re.search(rf'enterprise_linux:{major}\.(\d+)', cpe, re.IGNORECASE)
    if m:
        return f"RHEL {major}.{m.group(1)}"

    # EUS CPE form: rhel_eus:8.4, rhel_eus:9.0, etc.
    m = re.search(rf'rhel_eus:{major}\.(\d+)', cpe, re.IGNORECASE)
    if m:
        return f"RHEL {major}.{m.group(1)}"

    return f"RHEL {major}"


def extract_ocp_version(product_name: str, cpe: str = "") -> str:
    """
    Return the OCP version string, e.g. "OCP 4.12", "OCP 4.14".
    Falls back to "RHCOS" for CoreOS entries without a version number.
    """
    # Try "4.NN" pattern in the product name
    m = re.search(r'\b(4\.\d+)\b', product_name)
    if m:
        return f"OCP {m.group(1)}"

    # Try CPE: openshift:4.12
    m = re.search(r'openshift[_:](\d+\.\d+)', cpe, re.IGNORECASE)
    if m:
        return f"OCP {m.group(1)}"

    # RHCOS without version number
    if re.search(r'RHCOS|CoreOS', product_name, re.IGNORECASE):
        return "RHCOS"

    return "OCP"


def extract_platform_version(product_name: str, cpe: str, platform: str) -> str:
    """Dispatch to the correct version extractor for *platform*."""
    if platform == "OpenShift":
        return extract_ocp_version(product_name, cpe)
    return extract_rhel_version(product_name, cpe)


# ── Component type classification ──────────────────────────────────────────────

def rhel_component_type(product_name: str) -> str:
    n = product_name.lower()
    if "baseos"       in n or "base os"          in n: return "RPM (BaseOS)"
    if "appstream"    in n or "application stream" in n: return "RPM (AppStream)"
    if "supplementary" in n:                             return "RPM (Supplementary)"
    if "highavailability" in n or "high availability" in n: return "RPM (HighAvailability)"
    if "resilientstorage" in n or "resilient storage"  in n: return "RPM (ResilientStorage)"
    if "nfv"          in n:                              return "RPM (NFV)"
    if "satellite"    in n:                              return "RPM (Satellite)"
    if "container"    in n:                              return "Container Image"
    if "module"       in n:                              return "Module"
    return "RPM"


def ocp_component_type(product_name: str) -> str:
    n = product_name.lower()
    if "coreos" in n or "rhcos" in n:        return "RHCOS"
    if "virtualization" in n:                return "OpenShift Virtualization"
    if "gitops" in n:                        return "Operator (GitOps)"
    if "pipelines" in n:                     return "Operator (Pipelines)"
    if "operator" in n:                      return "Operator"
    if "logging" in n:                       return "Operator (Logging)"
    if "monitoring" in n:                    return "Operator (Monitoring)"
    return "OCP Service"


def platform_component_type(product_name: str, platform: str) -> str:
    if platform == "OpenShift":
        return ocp_component_type(product_name)
    return rhel_component_type(product_name)


# ── Misc helpers ───────────────────────────────────────────────────────────────

def pkg_name_only(pkg_str: str) -> str:
    """Strip version/release/arch from an RPM NEVRA string → package name only."""
    match = re.match(r'^([a-zA-Z0-9_+.-]+?)-\d', pkg_str)
    if match:
        return match.group(1)
    return pkg_str.split("-")[0]


def sort_versions(versions: set[str]) -> list[str]:
    """Sort version strings numerically (RHEL 8 < RHEL 8.1 < RHEL 9, OCP 4.11 < 4.12)."""
    def key(v: str):
        return [int(x) for x in re.findall(r'\d+', v)]
    return sorted(versions, key=key)


# ── Inventory loading & matching ───────────────────────────────────────────────

def load_inventory(path: str) -> dict:
    """Load and return the inventory JSON file, or {} on any error."""
    import json
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if data.get("schema_version") != "1.0":
            print(f"[WARN] Inventory schema version '{data.get('schema_version')}' "
                  f"may not be compatible (expected 1.0)", file=sys.stderr)
        return data
    except FileNotFoundError:
        print(f"[ERROR] Inventory file not found: {path}", file=sys.stderr)
        return {}
    except Exception as exc:
        print(f"[ERROR] Failed to load inventory {path}: {exc}", file=sys.stderr)
        return {}


def _ver_tuple(version_str: str) -> tuple[int, ...]:
    """
    Convert a version string to a comparable tuple of ints.
    Strips epoch prefix and takes only the version segment (before '-').
    Examples: "2.14.1" → (2,14,1)  |  "1:3.0.7-1.el9" → (3,0,7)
    """
    s = re.sub(r'^\d+:', '', str(version_str))   # drop epoch
    s = s.split('-')[0]                           # drop release
    nums = re.findall(r'\d+', s)
    return tuple(int(x) for x in nums[:4]) if nums else ()


def _is_older(installed: str, fixed: str) -> bool | None:
    """
    Return True if installed < fixed (vulnerable), False if >=, None if indeterminate.
    """
    iv, fv = _ver_tuple(installed), _ver_tuple(fixed)
    if not iv or not fv:
        return None
    if iv < fv:
        return True
    if iv > fv:
        return False
    # Same version — also compare release portion when both present
    def rel_tuple(s: str) -> tuple[int, ...]:
        rel = s.split('-')[1] if '-' in s else ""
        nums = re.findall(r'\d+', rel)
        return tuple(int(x) for x in nums[:4]) if nums else ()
    ir, fr = rel_tuple(str(installed)), rel_tuple(str(fixed))
    if ir and fr:
        return ir < fr
    return None


def _affected_pkgs(releases: list[dict], states: list[dict]) -> dict[str, str]:
    """
    Build {package_name: fixed_version} from CVE data.

    For affected_release entries the package field contains the FIXED NEVRA;
    everything older is vulnerable.  For package_state entries we know the
    name but not a pinned fixed version.
    """
    result: dict[str, str] = {}

    for r in releases:
        pkg_str = r.get("package", "")
        if not pkg_str:
            continue
        name = pkg_name_only(pkg_str)
        if not name:
            continue
        # Strip "name-" then epoch to reach "version-release.arch"
        rest = pkg_str[len(name):].lstrip('-')
        rest = re.sub(r'^\d+:', '', rest)           # drop epoch
        m = re.match(r'^(\d[^-]*)', rest)
        fixed_ver = m.group(1) if m else ""
        # Keep the lowest fixed version seen (most conservative)
        if name not in result or (fixed_ver and _ver_tuple(fixed_ver) < _ver_tuple(result[name])):
            result[name] = fixed_ver

    for s in states:
        pkg_name = (s.get("package_name") or "").strip()
        if pkg_name and pkg_name not in result:
            result[pkg_name] = ""   # known affected, no pinned fix version

    return result


def match_inventory(
    platform: str,
    releases: list[dict],
    states: list[dict],
    inventory: dict,
) -> tuple[str, str]:
    """
    Compare CVE affected packages against the environment inventory.

    Returns (match_tier, match_detail).

    Tiers (in descending certainty):
      Confirmed  — RPM found (high confidence), version confirmed older than fix
      Likely     — non-RPM component found, version confirmed older than fix
      Possible   — name match but version cannot be compared
      Not Detected — no matching component found (may be incomplete inventory)
      No Inventory — no inventory file was provided
    """
    if not inventory:
        return "No Inventory", ""

    hosts = inventory.get("hosts", [])
    if not hosts:
        return "No Inventory", ""

    affected = _affected_pkgs(releases, states)
    if not affected:
        return "Insufficient CVE data", "No package names found in CVE data"

    platform_type = "RHEL" if platform == "RHEL" else "OpenShift"
    scoped_hosts = [h for h in hosts if h.get("platform", {}).get("type") == platform_type]
    if not scoped_hosts:
        return f"Not Detected (0 {platform_type} hosts in inventory)", ""

    confirmed: list[dict] = []
    likely:    list[dict] = []
    possible:  list[dict] = []

    for host in scoped_hosts:
        hostname   = host.get("hostname", "unknown")
        components = host.get("components", [])

        for comp in components:
            comp_name    = (comp.get("name") or "").strip()
            comp_ver     = (comp.get("version") or "").strip()
            comp_type    = comp.get("type", "binary")
            comp_conf    = comp.get("detection_confidence", "low")
            comp_path    = comp.get("path") or ""
            artifact_id  = (comp.get("jar_fields") or {}).get("artifact_id", "")

            # ── Name resolution ───────────────────────────────────────────────
            matched_pkg = None
            for pkg_name_key in affected:
                target = pkg_name_key.lower()
                # 1. Exact match
                if comp_name.lower() == target:
                    matched_pkg = pkg_name_key
                    break
                # 2. JAR artifact_id match
                if artifact_id and artifact_id.lower() == target:
                    matched_pkg = pkg_name_key
                    break
                # 3. Prefix match (e.g. "log4j" matches "log4j-core")
                if (comp_name.lower().startswith(target + '-') or
                        comp_name.lower().startswith(target + '_')):
                    matched_pkg = pkg_name_key
                    break

            if not matched_pkg:
                continue

            fixed_ver = affected[matched_pkg]
            location  = f"{comp_path or 'RPM'}, {hostname}"
            label     = (
                f"{comp_name} {comp_ver or '(unknown version)'} "
                f"[{comp_type}, {location}]"
            )

            if not comp_ver or not fixed_ver:
                possible.append({"label": label, "hostname": hostname})
                continue

            older = _is_older(comp_ver, fixed_ver)
            if older is None:
                possible.append({"label": label, "hostname": hostname})
            elif older:
                entry = {"label": label, "hostname": hostname}
                if comp_conf == "high":
                    confirmed.append(entry)
                else:
                    likely.append(entry)
            # else: version >= fixed → not vulnerable for this component

    total = len(scoped_hosts)

    if confirmed:
        n = len({m["hostname"] for m in confirmed})
        detail = "; ".join(m["label"] for m in confirmed[:6])
        if likely or possible:
            extra = len(likely) + len(possible)
            detail += f" (+{extra} additional match(es))"
        return f"Confirmed ({n}/{total} hosts)", detail

    if likely:
        n = len({m["hostname"] for m in likely})
        detail = "; ".join(m["label"] for m in likely[:6])
        if possible:
            detail += f" (+{len(possible)} possible match(es))"
        return f"Likely ({n}/{total} hosts)", detail

    if possible:
        n = len({m["hostname"] for m in possible})
        detail = "; ".join(m["label"] for m in possible[:6])
        return f"Possible ({n}/{total} hosts)", detail

    return f"Not Detected ({total} hosts checked)", ""


# ── CVSS / severity extraction ─────────────────────────────────────────────────

def extract_score_severity(rh: dict, nist: dict) -> tuple[str, str]:
    """Return (severity_str, score_str) preferring RedHat data, falling back to NIST."""
    severity = rh.get("threat_severity", "") or ""

    cvss3 = rh.get("cvss3") or {}
    score = str(cvss3.get("cvss3_base_score", "") or "")

    if not score:
        cvss2 = rh.get("cvss") or {}
        score = str(cvss2.get("cvss_base_score", "") or "")

    if nist:
        metrics = nist.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                if not score:
                    score = str(cvss_data.get("baseScore", "") or "")
                if not severity:
                    severity = str(cvss_data.get("baseSeverity", "") or "")
                break
        if not score:
            v2 = metrics.get("cvssMetricV2", [])
            if v2:
                score    = score    or str(v2[0].get("cvssData", {}).get("baseScore", "") or "")
                severity = severity or str(v2[0].get("baseSeverity", "") or "")

    return severity.capitalize() if severity else "Unknown", score or "N/A"


# ── Per-platform row builder ───────────────────────────────────────────────────

def build_platform_row(
    cve_id: str,
    severity: str,
    score: str,
    url: str,
    platform: str,
    releases: list[dict],
    states: list[dict],
    components_fallback: str,
) -> dict:
    """
    Produce a single CSV row summarising all *releases* and *states* for
    the given *platform* (either "RHEL" or "OpenShift").

    - If there are fixed releases   → Applicable? = Yes
    - If only package states exist  → Applicable? derived from worst fix_state
    """
    all_components: set[str] = set()
    all_versions:   set[str] = set()
    all_advisories: set[str] = set()
    all_comp_types: set[str] = set()

    for r in releases:
        pname = r.get("product_name", "")
        cpe   = r.get("cpe", "")
        pkg   = r.get("package", "")
        adv   = r.get("advisory", "")

        if pkg:
            all_components.add(pkg_name_only(pkg))
        if adv:
            all_advisories.add(adv)

        ver = extract_platform_version(pname, cpe, platform)
        if ver:
            all_versions.add(ver)

        all_comp_types.add(platform_component_type(pname, platform))

    for s in states:
        pname = s.get("product_name", "")
        pkg   = s.get("package_name", "")
        cpe   = s.get("cpe", "")

        if pkg:
            all_components.add(pkg)

        ver = extract_platform_version(pname, cpe, platform)
        if ver:
            all_versions.add(ver)

        all_comp_types.add(platform_component_type(pname, platform))

    components_str = ", ".join(sorted(all_components)) or components_fallback
    versions_str   = ", ".join(sort_versions(all_versions))
    comp_type_str  = ", ".join(sorted(all_comp_types))
    advisory_str   = ", ".join(sorted(all_advisories))

    # ── Determine applicability ───────────────────────────────────────────────
    if releases:
        applicable    = "Yes"
        justification = (
            f"Patched in {platform} via {advisory_str}. "
            f"Affected component(s): {components_str}. "
            f"See URL for fixed package details."
        )
    elif states:
        fix_states = [s.get("fix_state", "") for s in states]
        fs_set     = set(fix_states)
        pkgs_str   = ", ".join(sorted(all_components))

        if fs_set == {"Not affected"}:
            applicable    = "No"
            justification = (
                f"RedHat confirms [{pkgs_str}] are NOT affected in {platform}."
            )
        elif "Under investigation" in fs_set:
            applicable    = "Unknown"
            justification = (
                f"[{pkgs_str}] in {platform} are under investigation. "
                f"No fix available yet — monitor RedHat advisories."
            )
        elif "Will not fix" in fs_set or "Out of support scope" in fs_set:
            worst         = "Will not fix" if "Will not fix" in fs_set else "Out of support scope"
            applicable    = "Yes"
            justification = (
                f"[{pkgs_str}] in {platform}: status '{worst}'. "
                f"No patch will be released — evaluate mitigations."
            )
        elif "Fix deferred" in fs_set or "Affected" in fs_set:
            worst         = "Fix deferred" if "Fix deferred" in fs_set else "Affected"
            applicable    = "Yes"
            justification = (
                f"[{pkgs_str}] in {platform}: status '{worst}'. "
                f"No fix released yet — monitor RedHat advisories."
            )
        else:
            # Mixed or unexpected states
            applicable    = "Yes"
            state_summary = ", ".join(sorted(fs_set))
            justification = (
                f"[{pkgs_str}] in {platform}: fix state(s) = {state_summary}."
            )
    else:
        applicable    = "No"
        justification = f"No {platform} affected releases or package states found."

    return {
        "CVE":                   cve_id,
        "Severity":              severity,
        "Score":                 score,
        "Platform":              platform,
        "Applicable?":           applicable,
        "Affected Component(s)": components_str,
        "Fix Advisory":          advisory_str,
        "Impacted Version(s)":   versions_str,
        "Component Type(s)":     comp_type_str,
        "Justification":         justification,
        "URL":                   url,
    }


# ── CVE analysis ───────────────────────────────────────────────────────────────

def analyze_cve(
    cve_id: str,
    nist_api_key: str = "",
    skip_nist: bool = False,
    inventory: dict | None = None,
) -> list[dict]:
    """
    Analyze a single CVE and return one or two CSV row dicts:
      - Row 1: RHEL impact summary  (always present)
      - Row 2: OpenShift impact summary  (present only when OCP data exists)

    Each row consolidates all product-level entries for that platform so
    there is no per-product row explosion.
    """
    cve_id = cve_id.upper()
    print(f"  [INFO] Fetching {cve_id} ...", file=sys.stderr)

    rh   = fetch_rh_cve(cve_id)
    nist = {} if skip_nist else fetch_nist_cve(cve_id, nist_api_key)

    severity, score = extract_score_severity(rh, nist)
    url             = RH_CVE_PAGE.format(cve_id)

    # ── Global component list (used as fallback when platform data is empty) ──
    all_pkg_names: set[str] = set()
    for rel in rh.get("affected_release", []) or []:
        pkg = rel.get("package", "")
        if pkg:
            all_pkg_names.add(pkg_name_only(pkg))
    for state in rh.get("package_state", []) or []:
        pkg = state.get("package_name", "")
        if pkg:
            all_pkg_names.add(pkg)
    if not all_pkg_names and nist:
        for cfg in nist.get("configurations", []):
            for node in cfg.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    parts = m.get("criteria", "").split(":")
                    if len(parts) > 4 and parts[4]:
                        all_pkg_names.add(parts[4])
    components_fallback = ", ".join(sorted(all_pkg_names)) if all_pkg_names else "N/A"

    # ── Partition entries by platform ─────────────────────────────────────────
    rhel_releases: list[dict] = []
    ocp_releases:  list[dict] = []
    rhel_states:   list[dict] = []
    ocp_states:    list[dict] = []

    for r in rh.get("affected_release", []) or []:
        p = classify_entry(r.get("product_name", ""), r.get("cpe", ""))
        if p == "OpenShift":
            ocp_releases.append(r)
        elif p == "RHEL":
            rhel_releases.append(r)

    for s in rh.get("package_state", []) or []:
        p = classify_entry(s.get("product_name", ""), s.get("cpe", ""))
        if p == "OpenShift":
            ocp_states.append(s)
        elif p == "RHEL":
            rhel_states.append(s)

    rows: list[dict] = []

    # All releases/states across every platform — used to build the full package
    # name set for inventory matching.  Non-RPM components (JARs, binaries) may
    # appear only in a non-RHEL Red Hat product release even when the CVE impacts
    # a RHEL host where that component was deployed outside the package manager.
    all_releases = (rh.get("affected_release", []) or [])
    all_states   = (rh.get("package_state",    []) or [])

    # ── RHEL row ──────────────────────────────────────────────────────────────
    if rhel_releases or rhel_states:
        row = build_platform_row(
            cve_id, severity, score, url,
            "RHEL", rhel_releases, rhel_states, components_fallback,
        )
        env_match, matched_on = match_inventory(
            "RHEL", all_releases, all_states, inventory or {},
        )
        row["Environment Match"] = env_match
        row["Matched On"]        = matched_on
        rows.append(row)

    # ── OpenShift row ─────────────────────────────────────────────────────────
    if ocp_releases or ocp_states:
        row = build_platform_row(
            cve_id, severity, score, url,
            "OpenShift", ocp_releases, ocp_states, components_fallback,
        )
        env_match, matched_on = match_inventory(
            "OpenShift", ocp_releases, ocp_states, inventory or {},
        )
        row["Environment Match"] = env_match
        row["Matched On"]        = matched_on
        rows.append(row)

    # ── No data for either platform ───────────────────────────────────────────
    if not rows:
        has_any_rh_data = bool(
            rh.get("affected_release") or rh.get("package_state")
        )
        if not rh and not nist:
            justification = "Could not retrieve data from RedHat or NIST."
            applicable    = "Unknown"
        elif has_any_rh_data:
            justification = (
                "RedHat has data for this CVE but no RHEL 8/9 or "
                "OpenShift affected releases or package states were found."
            )
            applicable = "No"
        else:
            justification = (
                "No RedHat entry found. CVE may not affect RHEL or "
                "OpenShift components — verify against upstream source."
            )
            applicable = "No"

        rows.append({
            "CVE":                   cve_id,
            "Severity":              severity,
            "Score":                 score,
            "Platform":              "RHEL / OpenShift",
            "Applicable?":           applicable,
            "Environment Match":     "No Inventory" if not inventory else "N/A",
            "Matched On":            "",
            "Affected Component(s)": components_fallback,
            "Fix Advisory":          "",
            "Impacted Version(s)":   "",
            "Component Type(s)":     "",
            "Justification":         justification,
            "URL":                   url,
        })

    return rows


# ── RHSA → CVE expansion ───────────────────────────────────────────────────────

def extract_cves_from_rhsa(rhsa_id: str) -> list[str]:
    """
    Query the RedHat CVE list endpoint filtered by *rhsa_id* and return
    the list of CVE IDs contained in that advisory.
    """
    rhsa_id = rhsa_id.upper()
    print(f"  [INFO] Fetching advisory {rhsa_id} ...", file=sys.stderr)

    cve_summaries = fetch_rh_rhsa_cves(rhsa_id)
    if not cve_summaries:
        print(f"  [WARN] No CVE data returned for {rhsa_id}", file=sys.stderr)
        return []

    cve_ids: list[str] = []
    for item in cve_summaries:
        cve_id = ""
        if isinstance(item, dict):
            cve_id = item.get("CVE") or item.get("cve") or item.get("id") or ""
        elif isinstance(item, str):
            cve_id = item
        if cve_id and CVE_RE.fullmatch(cve_id.strip()):
            cve_ids.append(cve_id.strip().upper())

    return cve_ids


# ── Input parsing ──────────────────────────────────────────────────────────────

def parse_ids(tokens: list[str]) -> tuple[list[str], list[str]]:
    """
    Classify each token as a CVE ID or an RHSA/RHBA/RHEA advisory ID.
    Returns (cve_list, rhsa_list).  Unrecognised tokens are warned and skipped.
    """
    cves:  list[str] = []
    rhsas: list[str] = []

    for tok in tokens:
        tok = tok.strip().upper()
        if not tok:
            continue
        if CVE_RE.fullmatch(tok):
            cves.append(tok)
        elif RHSA_RE.fullmatch(tok):
            rhsas.append(tok)
        else:
            print(f"  [WARN] Unrecognised ID '{tok}' — skipping.", file=sys.stderr)

    return cves, rhsas


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze CVE/RHSA identifiers and generate a CSV report "
            "assessing impact on RHEL 8/9 and OpenShift."
        ),
        epilog=(
            "IDs can be passed as positional arguments and/or piped via stdin.\n"
            "Each CVE produces at most two rows: one for RHEL and one for OpenShift.\n\n"
            "Examples:\n"
            "  echo 'CVE-2023-38408 RHSA-2023:4329' | python cve_analyzer.py\n"
            "  python cve_analyzer.py CVE-2023-38408 -o report.csv\n"
            "  python cve_analyzer.py < ids.txt -o report.csv"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "ids", nargs="*", metavar="ID",
        help="CVE or RHSA IDs to analyze (in addition to stdin).",
    )
    parser.add_argument(
        "-o", "--output", default="", metavar="FILE",
        help=(
            "Output CSV file path. "
            "Defaults to cve_analysis_YYYYMMDD_HHMMSS.csv."
        ),
    )
    parser.add_argument(
        "--nist-api-key", default="", metavar="KEY",
        help=(
            "NIST NVD API key (optional). Raises rate limit from 5 to 50 req/30s. "
            "Register at https://nvd.nist.gov/developers/request-an-api-key"
        ),
    )
    parser.add_argument(
        "--no-nist", action="store_true",
        help="Skip NIST NVD lookups (faster, but less complete data).",
    )

    proxy = parser.add_argument_group(
        "proxy",
        "HTTP proxy settings. CLI flags override the corresponding environment variables.",
    )
    proxy.add_argument(
        "--proxy", default="", metavar="URL",
        help="Proxy URL, e.g. http://proxy.corp.com:8080  (env: HTTPS_PROXY)",
    )
    proxy.add_argument(
        "--proxy-auth", default="", metavar="TYPE",
        choices=["basic", "ntlm", "digest"],
        help="Proxy authentication type: basic | ntlm | digest  (env: CVE_PROXY_AUTH)",
    )
    proxy.add_argument(
        "--proxy-user", default="", metavar="USER",
        help="Proxy username. For NTLM use DOMAIN\\\\username  (env: CVE_PROXY_USERNAME)",
    )
    proxy.add_argument(
        "--proxy-password", default="", metavar="PASS",
        help=(
            "Proxy password  (env: CVE_PROXY_PASSWORD). "
            "Prefer the environment variable over this flag to avoid "
            "exposing credentials in process listings."
        ),
    )

    parser.add_argument(
        "--inventory", default="", metavar="FILE",
        help=(
            "Path to environment inventory JSON file (produced by the Ansible collector). "
            "When provided, each row gains 'Environment Match' and 'Matched On' columns "
            "showing whether affected packages were found in your environment."
        ),
    )
    args = parser.parse_args()

    # ── Proxy (must be configured before any HTTP calls) ──────────────────────
    configure_proxy(
        proxy_url=args.proxy,
        auth_type=args.proxy_auth,
        username=args.proxy_user,
        password=args.proxy_password,
    )

    # ── Collect IDs from CLI + stdin ──────────────────────────────────────────
    raw_tokens: list[str] = list(args.ids)
    if not sys.stdin.isatty():
        for line in sys.stdin:
            raw_tokens.extend(line.split())

    if not raw_tokens:
        parser.print_help()
        sys.exit(1)

    cve_ids, rhsa_ids = parse_ids(raw_tokens)

    # ── Expand RHSA → CVEs ────────────────────────────────────────────────────
    rhsa_source: dict[str, str] = {}
    for rhsa_id in rhsa_ids:
        found = extract_cves_from_rhsa(rhsa_id)
        if found:
            print(f"  [INFO] {rhsa_id} contains: {', '.join(found)}", file=sys.stderr)
            for c in found:
                if c not in cve_ids:
                    cve_ids.append(c)
                rhsa_source[c] = rhsa_id
        else:
            print(f"  [WARN] No CVEs found in {rhsa_id}.", file=sys.stderr)

    # De-duplicate while preserving order
    seen: set[str] = set()
    unique_cves: list[str] = []
    for c in cve_ids:
        if c not in seen:
            seen.add(c)
            unique_cves.append(c)

    if not unique_cves:
        print("[ERROR] No valid CVE IDs to process.", file=sys.stderr)
        sys.exit(1)

    output_path = args.output or f"cve_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    # ── Load inventory (optional) ─────────────────────────────────────────────
    inventory: dict = {}
    if args.inventory:
        inventory = load_inventory(args.inventory)
        if inventory:
            host_count = len(inventory.get("hosts", []))
            print(f"[INFO] Loaded inventory: {host_count} host(s) from '{args.inventory}'",
                  file=sys.stderr)
        else:
            print("[WARN] Inventory file could not be loaded — environment matching disabled.",
                  file=sys.stderr)

    # ── Analyze ───────────────────────────────────────────────────────────────
    all_rows: list[dict] = []
    total = len(unique_cves)
    print(f"\n[INFO] Analyzing {total} CVE(s) ...\n", file=sys.stderr)

    for idx, cve_id in enumerate(unique_cves, 1):
        print(f"[{idx}/{total}] {cve_id}", file=sys.stderr)
        rows = analyze_cve(
            cve_id,
            nist_api_key=args.nist_api_key,
            skip_nist=args.no_nist,
            inventory=inventory or None,
        )

        if cve_id in rhsa_source:
            rhsa_url = RH_ERRATA_PAGE.format(rhsa_source[cve_id])
            for row in rows:
                row["URL"] = f"{row['URL']}  |  {rhsa_url}"

        all_rows.extend(rows)

    # ── Write CSV ─────────────────────────────────────────────────────────────
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=CSV_FIELDS,
            quoting=csv.QUOTE_ALL,  # type: ignore[arg-type]
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n[DONE] Wrote {len(all_rows)} row(s) to '{output_path}'.", file=sys.stderr)


if __name__ == "__main__":
    main()
