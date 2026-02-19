"""
Tests for platform detection and version/component-type extraction.

These are all pure-function tests — no network calls, no mocking needed.
"""

import pytest
from cve_analyzer import (
    is_openshift,
    get_rhel_major,
    classify_entry,
    extract_rhel_version,
    extract_ocp_version,
    extract_platform_version,
    rhel_component_type,
    ocp_component_type,
    platform_component_type,
    RHEL_VERSIONS,
)


# ── is_openshift ───────────────────────────────────────────────────────────────

class TestIsOpenShift:
    def test_ocp_full_product_name(self):
        assert is_openshift("Red Hat OpenShift Container Platform 4.12") is True

    def test_openshift_short_with_version(self):
        assert is_openshift("OpenShift 4.14") is True

    def test_rhcos_short(self):
        assert is_openshift("RHCOS") is True

    def test_enterprise_linux_coreos_is_openshift(self):
        # CRITICAL: RHCOS product name contains "Enterprise Linux" —
        # must be classified as OpenShift, not RHEL.
        assert is_openshift("Red Hat Enterprise Linux CoreOS 4.12") is True

    def test_red_hat_coreos(self):
        assert is_openshift("Red Hat CoreOS 4.11") is True

    def test_openshift_virtualization(self):
        assert is_openshift("OpenShift Virtualization 4.13") is True

    def test_cpe_openshift(self):
        assert is_openshift("cpe:/a:redhat:openshift:4.12::el9") is True

    def test_rhel8_is_not_openshift(self):
        assert is_openshift("Red Hat Enterprise Linux 8") is False

    def test_rhel9_baseos_is_not_openshift(self):
        assert is_openshift("Red Hat Enterprise Linux BaseOS (v. 9)") is False

    def test_rhel_eus_is_not_openshift(self):
        assert is_openshift("Red Hat Enterprise Linux 8.6 Extended Update Support") is False

    def test_empty_string(self):
        assert is_openshift("") is False

    def test_unrelated_product(self):
        assert is_openshift("Windows Server 2022") is False


# ── get_rhel_major ─────────────────────────────────────────────────────────────

class TestGetRhelMajor:
    def test_rhel8_plain(self):
        assert get_rhel_major("Red Hat Enterprise Linux 8") == 8

    def test_rhel9_plain(self):
        assert get_rhel_major("Red Hat Enterprise Linux 9") == 9

    def test_rhel8_with_minor_version(self):
        # "8.9" must yield major=8, NOT 9 — a common false-positive trap.
        assert get_rhel_major("Red Hat Enterprise Linux 8.9") == 8

    def test_rhel9_with_minor_version(self):
        assert get_rhel_major("Red Hat Enterprise Linux 9.2") == 9

    def test_rhel8_baseos_product_name(self):
        assert get_rhel_major("Red Hat Enterprise Linux BaseOS (v. 8)") == 8

    def test_rhel9_appstream_product_name(self):
        assert get_rhel_major("Red Hat Enterprise Linux AppStream (v. 9)") == 9

    def test_rhel8_eus_product_name(self):
        assert get_rhel_major("Red Hat Enterprise Linux 8.6 Extended Update Support") == 8

    def test_rhel7_is_not_in_scope(self):
        # RHEL 7 is EOL and not in RHEL_VERSIONS — must return None.
        assert get_rhel_major("Red Hat Enterprise Linux 7") is None

    def test_rhel7_minor_is_not_in_scope(self):
        assert get_rhel_major("Red Hat Enterprise Linux 7.9") is None

    def test_cpe_rhel8(self):
        assert get_rhel_major("cpe:/o:redhat:enterprise_linux:8::baseos") == 8

    def test_cpe_rhel9_with_minor(self):
        assert get_rhel_major("cpe:/o:redhat:enterprise_linux:9.1::appstream") == 9

    def test_short_cpe_form_8(self):
        assert get_rhel_major(":8::") == 8

    def test_short_cpe_form_9(self):
        assert get_rhel_major(":9::") == 9

    def test_rhel_short_form_with_space(self):
        assert get_rhel_major("RHEL 9") == 9

    def test_rhel_short_form_with_dash(self):
        assert get_rhel_major("RHEL-8") == 8

    def test_rhel_short_form_no_separator(self):
        assert get_rhel_major("RHEL8") == 8

    def test_rpm_el8_release_tag(self):
        assert get_rhel_major("curl-7.76.1-26.el8_8.2.x86_64") == 8

    def test_rpm_el9_release_tag(self):
        assert get_rhel_major("openssl-3.0.1-47.el9_1.x86_64") == 9

    def test_empty_string(self):
        assert get_rhel_major("") is None

    def test_unrelated_text(self):
        assert get_rhel_major("Windows Server 2019 Standard") is None

    def test_all_tracked_versions_are_detected(self):
        for v in RHEL_VERSIONS:
            assert get_rhel_major(f"Red Hat Enterprise Linux {v}") == v


# ── classify_entry ─────────────────────────────────────────────────────────────

class TestClassifyEntry:
    def test_rhel8_baseos(self):
        assert classify_entry(
            "Red Hat Enterprise Linux BaseOS (v. 8)",
            "cpe:/o:redhat:enterprise_linux:8::baseos",
        ) == "RHEL"

    def test_rhel9_appstream(self):
        assert classify_entry(
            "Red Hat Enterprise Linux AppStream (v. 9)",
            "cpe:/o:redhat:enterprise_linux:9::appstream",
        ) == "RHEL"

    def test_rhel8_eus(self):
        assert classify_entry(
            "Red Hat Enterprise Linux 8.6 Extended Update Support",
            "cpe:/o:redhat:rhel_eus:8.6::baseos",
        ) == "RHEL"

    def test_ocp_4_12(self):
        assert classify_entry(
            "Red Hat OpenShift Container Platform 4.12",
            "cpe:/a:redhat:openshift:4.12::el9",
        ) == "OpenShift"

    def test_ocp_4_14(self):
        assert classify_entry(
            "Red Hat OpenShift Container Platform 4.14",
            "cpe:/a:redhat:openshift:4.14::el9",
        ) == "OpenShift"

    def test_rhcos_classified_as_openshift_not_rhel(self):
        # THE critical classification test.
        # "Enterprise Linux CoreOS" contains "Enterprise Linux" but is OCP.
        assert classify_entry(
            "Red Hat Enterprise Linux CoreOS 4.13",
            "cpe:/a:redhat:openshift:4.13::el9",
        ) == "OpenShift"

    def test_openshift_virtualization(self):
        assert classify_entry(
            "OpenShift Virtualization 4.13",
            "cpe:/a:redhat:openshift:4.13",
        ) == "OpenShift"

    def test_rhel7_returns_none(self):
        # RHEL 7 is out of scope for this environment.
        assert classify_entry(
            "Red Hat Enterprise Linux 7",
            "cpe:/o:redhat:enterprise_linux:7",
        ) is None

    def test_windows_returns_none(self):
        assert classify_entry("Windows Server 2022", "") is None

    def test_empty_returns_none(self):
        assert classify_entry("", "") is None

    def test_ocp_takes_priority_over_rhel_signal(self):
        # If both signals are present, OpenShift wins.
        assert classify_entry(
            "Red Hat Enterprise Linux CoreOS 4.12",
            "cpe:/o:redhat:enterprise_linux:8 cpe:/a:redhat:openshift:4.12",
        ) == "OpenShift"


# ── extract_rhel_version ───────────────────────────────────────────────────────

class TestExtractRhelVersion:
    def test_rhel8_no_minor(self):
        assert extract_rhel_version("Red Hat Enterprise Linux 8") == "RHEL 8"

    def test_rhel9_no_minor(self):
        assert extract_rhel_version("Red Hat Enterprise Linux 9") == "RHEL 9"

    def test_rhel8_with_minor_from_product_name(self):
        assert extract_rhel_version(
            "Red Hat Enterprise Linux 8.6 Extended Update Support"
        ) == "RHEL 8.6"

    def test_rhel9_with_minor_from_product_name(self):
        assert extract_rhel_version(
            "Red Hat Enterprise Linux 9.2 Extended Update Support"
        ) == "RHEL 9.2"

    def test_rhel8_minor_from_cpe_fallback(self):
        assert extract_rhel_version(
            "Red Hat Enterprise Linux BaseOS",
            "cpe:/o:redhat:rhel_eus:8.4::baseos",
        ) == "RHEL 8.4"

    def test_rhel8_baseos_product_name(self):
        # "(v. 8)" form — must still extract 8
        assert extract_rhel_version(
            "Red Hat Enterprise Linux BaseOS (v. 8)",
            "cpe:/o:redhat:enterprise_linux:8::baseos",
        ) == "RHEL 8"

    def test_rhel7_returns_empty(self):
        assert extract_rhel_version("Red Hat Enterprise Linux 7") == ""

    def test_empty_returns_empty(self):
        assert extract_rhel_version("", "") == ""

    def test_rhel_short_form(self):
        # "for RHEL 8" in a product name
        assert extract_rhel_version("JBoss Core Services for RHEL 8") == "RHEL 8"


# ── extract_ocp_version ────────────────────────────────────────────────────────

class TestExtractOcpVersion:
    def test_ocp_4_12_from_product_name(self):
        assert extract_ocp_version("Red Hat OpenShift Container Platform 4.12") == "OCP 4.12"

    def test_ocp_4_14_from_product_name(self):
        assert extract_ocp_version("OpenShift 4.14") == "OCP 4.14"

    def test_ocp_from_cpe_fallback(self):
        assert extract_ocp_version(
            "Red Hat OpenShift Container Platform",
            "cpe:/a:redhat:openshift:4.13::el9",
        ) == "OCP 4.13"

    def test_rhcos_without_version_falls_back(self):
        # RHCOS entry with no version number in the name → "RHCOS"
        result = extract_ocp_version("Red Hat Enterprise Linux CoreOS", "")
        assert result == "RHCOS"

    def test_rhcos_with_version(self):
        result = extract_ocp_version("Red Hat Enterprise Linux CoreOS 4.12", "")
        assert result == "OCP 4.12"

    def test_openshift_virtualization(self):
        assert extract_ocp_version("OpenShift Virtualization 4.13") == "OCP 4.13"


# ── extract_platform_version ───────────────────────────────────────────────────

class TestExtractPlatformVersion:
    def test_rhel_dispatch(self):
        result = extract_platform_version(
            "Red Hat Enterprise Linux 8.6 Extended Update Support",
            "cpe:/o:redhat:rhel_eus:8.6::baseos",
            "RHEL",
        )
        assert result == "RHEL 8.6"

    def test_ocp_dispatch(self):
        result = extract_platform_version(
            "Red Hat OpenShift Container Platform 4.13",
            "cpe:/a:redhat:openshift:4.13::el9",
            "OpenShift",
        )
        assert result == "OCP 4.13"


# ── rhel_component_type ────────────────────────────────────────────────────────

class TestRhelComponentType:
    def test_baseos(self):
        assert rhel_component_type("Red Hat Enterprise Linux BaseOS (v. 8)") == "RPM (BaseOS)"

    def test_appstream(self):
        assert rhel_component_type("Red Hat Enterprise Linux AppStream (v. 9)") == "RPM (AppStream)"

    def test_supplementary(self):
        assert rhel_component_type("Red Hat Enterprise Linux Supplementary (v. 8)") == "RPM (Supplementary)"

    def test_high_availability(self):
        assert rhel_component_type("Red Hat Enterprise Linux High Availability (v. 8)") == "RPM (HighAvailability)"

    def test_resilient_storage(self):
        assert rhel_component_type("Red Hat Enterprise Linux Resilient Storage (v. 8)") == "RPM (ResilientStorage)"

    def test_nfv(self):
        assert rhel_component_type("Red Hat Enterprise Linux NFV (v. 8)") == "RPM (NFV)"

    def test_satellite(self):
        assert rhel_component_type("Red Hat Satellite 6 for RHEL 8") == "RPM (Satellite)"

    def test_generic_rhel_defaults_to_rpm(self):
        assert rhel_component_type("Red Hat Enterprise Linux 8") == "RPM"

    def test_eus_defaults_to_rpm(self):
        assert rhel_component_type("Red Hat Enterprise Linux 8.6 Extended Update Support") == "RPM"


# ── ocp_component_type ─────────────────────────────────────────────────────────

class TestOcpComponentType:
    def test_rhcos(self):
        assert ocp_component_type("Red Hat Enterprise Linux CoreOS 4.12") == "RHCOS"

    def test_rhcos_short(self):
        assert ocp_component_type("RHCOS") == "RHCOS"

    def test_generic_operator(self):
        assert ocp_component_type("Red Hat OpenShift Operator 4.12") == "Operator"

    def test_gitops_operator(self):
        assert ocp_component_type("Red Hat OpenShift GitOps 1.9") == "Operator (GitOps)"

    def test_pipelines_operator(self):
        assert ocp_component_type("Red Hat OpenShift Pipelines 1.10") == "Operator (Pipelines)"

    def test_logging_operator(self):
        assert ocp_component_type("Red Hat OpenShift Logging 5.6") == "Operator (Logging)"

    def test_virtualization(self):
        assert ocp_component_type("OpenShift Virtualization 4.13") == "OpenShift Virtualization"

    def test_generic_ocp_defaults(self):
        assert ocp_component_type("Red Hat OpenShift Container Platform 4.12") == "OCP Service"


# ── platform_component_type ────────────────────────────────────────────────────

class TestPlatformComponentType:
    def test_rhel_dispatch(self):
        result = platform_component_type("Red Hat Enterprise Linux BaseOS (v. 8)", "RHEL")
        assert result == "RPM (BaseOS)"

    def test_openshift_dispatch(self):
        result = platform_component_type("Red Hat Enterprise Linux CoreOS 4.12", "OpenShift")
        assert result == "RHCOS"
