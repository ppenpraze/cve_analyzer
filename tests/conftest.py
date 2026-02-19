"""
Shared pytest fixtures — realistic mock payloads matching the actual
RedHat Security Data API and NIST NVD API 2.0 response structures.
"""

import pytest


# ── RedHat CVE API mock payloads ───────────────────────────────────────────────

@pytest.fixture
def rh_cve_rhel8_fixed():
    """CVE patched in RHEL 8 (BaseOS) and RHEL 8.6 EUS."""
    return {
        "threat_severity": "Important",
        "cvss3": {"cvss3_base_score": "7.5"},
        "cvss": {},
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux BaseOS (v. 8)",
                "advisory": "RHSA-2023:1234",
                "package": "curl-7.76.1-26.el8_8.2.x86_64",
                "cpe": "cpe:/o:redhat:enterprise_linux:8::baseos",
            },
            {
                "product_name": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                "advisory": "RHSA-2023:1235",
                "package": "curl-7.76.1-23.el8_6.4.x86_64",
                "cpe": "cpe:/o:redhat:rhel_eus:8.6::baseos",
            },
        ],
        "package_state": [],
    }


@pytest.fixture
def rh_cve_rhel9_fixed():
    """CVE patched in RHEL 9 (AppStream)."""
    return {
        "threat_severity": "Critical",
        "cvss3": {"cvss3_base_score": "9.8"},
        "cvss": {},
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux AppStream (v. 9)",
                "advisory": "RHSA-2023:5000",
                "package": "openssh-8.7p1-30.el9_1.x86_64",
                "cpe": "cpe:/o:redhat:enterprise_linux:9::appstream",
            },
        ],
        "package_state": [],
    }


@pytest.fixture
def rh_cve_both_rhel_and_ocp():
    """CVE patched in RHEL 9 and OCP 4.12 — triggers two output rows."""
    return {
        "threat_severity": "Critical",
        "cvss3": {"cvss3_base_score": "9.8"},
        "cvss": {},
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux 9",
                "advisory": "RHSA-2023:2000",
                "package": "openssh-8.7p1-30.el9_1.x86_64",
                "cpe": "cpe:/o:redhat:enterprise_linux:9::baseos",
            },
            {
                "product_name": "Red Hat OpenShift Container Platform 4.12",
                "advisory": "RHSA-2023:2001",
                "package": "openshift4/ose-base:v4.12.0",
                "cpe": "cpe:/a:redhat:openshift:4.12::el9",
            },
        ],
        "package_state": [],
    }


@pytest.fixture
def rh_cve_rhel8_not_affected():
    """CVE where RHEL 8 is explicitly confirmed not affected."""
    return {
        "threat_severity": "Critical",
        "cvss3": {"cvss3_base_score": "9.8"},
        "cvss": {},
        "affected_release": [],
        "package_state": [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "fix_state": "Not affected",
                "package_name": "java-1.8.0-openjdk",
                "cpe": "cpe:/o:redhat:enterprise_linux:8",
            },
        ],
    }


@pytest.fixture
def rh_cve_will_not_fix():
    """CVE where RHEL 9 will not receive a patch."""
    return {
        "threat_severity": "Moderate",
        "cvss3": {"cvss3_base_score": "5.3"},
        "cvss": {},
        "affected_release": [],
        "package_state": [
            {
                "product_name": "Red Hat Enterprise Linux 9",
                "fix_state": "Will not fix",
                "package_name": "some-lib",
                "cpe": "cpe:/o:redhat:enterprise_linux:9",
            },
        ],
    }


@pytest.fixture
def rh_cve_under_investigation():
    """CVE under investigation on RHEL 8."""
    return {
        "threat_severity": "Important",
        "cvss3": {"cvss3_base_score": "7.0"},
        "cvss": {},
        "affected_release": [],
        "package_state": [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "fix_state": "Under investigation",
                "package_name": "kernel",
                "cpe": "cpe:/o:redhat:enterprise_linux:8",
            },
        ],
    }


@pytest.fixture
def rh_cve_rhcos():
    """CVE patched in RHCOS (OCP node OS) — must not be classified as RHEL."""
    return {
        "threat_severity": "Important",
        "cvss3": {"cvss3_base_score": "7.8"},
        "cvss": {},
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux CoreOS 4.13",
                "advisory": "RHSA-2023:4000",
                "package": "kernel-5.14.0-284.30.1.el9_2.x86_64",
                "cpe": "cpe:/a:redhat:openshift:4.13::el9",
            },
        ],
        "package_state": [],
    }


@pytest.fixture
def rh_cve_empty():
    """Empty / no-data response from RedHat."""
    return {}


@pytest.fixture
def rh_cve_multi_rhel_versions():
    """CVE fixed across multiple RHEL 8.x and RHEL 9.x minor versions."""
    return {
        "threat_severity": "Important",
        "cvss3": {"cvss3_base_score": "7.4"},
        "cvss": {},
        "affected_release": [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "advisory": "RHSA-2023:1440",
                "package": "openssl-1:3.0.7-1.el8.x86_64",
                "cpe": "cpe:/o:redhat:enterprise_linux:8::baseos",
            },
            {
                "product_name": "Red Hat Enterprise Linux 8.6 Extended Update Support",
                "advisory": "RHSA-2023:1441",
                "package": "openssl-1:3.0.1-47.el8_6.x86_64",
                "cpe": "cpe:/o:redhat:rhel_eus:8.6::baseos",
            },
            {
                "product_name": "Red Hat Enterprise Linux 9",
                "advisory": "RHSA-2023:1442",
                "package": "openssl-1:3.0.7-1.el9.x86_64",
                "cpe": "cpe:/o:redhat:enterprise_linux:9::baseos",
            },
            {
                "product_name": "Red Hat Enterprise Linux 9.0 Extended Update Support",
                "advisory": "RHSA-2023:1443",
                "package": "openssl-1:3.0.1-43.el9_0.x86_64",
                "cpe": "cpe:/o:redhat:rhel_eus:9.0::baseos",
            },
        ],
        "package_state": [],
    }


# ── NIST NVD API mock payloads ─────────────────────────────────────────────────

@pytest.fixture
def nist_v31():
    """NIST response with CVSS v3.1 data."""
    return {
        "id": "CVE-2023-TEST",
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                    }
                }
            ]
        },
    }


@pytest.fixture
def nist_v2_only():
    """NIST response with only CVSS v2 data (older CVEs)."""
    return {
        "id": "CVE-2015-TEST",
        "metrics": {
            "cvssMetricV2": [
                {
                    "cvssData": {"baseScore": 6.5},
                    "baseSeverity": "MEDIUM",
                }
            ]
        },
    }


@pytest.fixture
def nist_empty():
    """Empty NIST response."""
    return {}
