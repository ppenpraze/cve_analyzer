"""
Tests for build_platform_row and analyze_cve.

HTTP calls are fully mocked — no network access required.
"""

import pytest
from unittest.mock import patch
from cve_analyzer import build_platform_row, analyze_cve


# ── build_platform_row — releases present ──────────────────────────────────────

class TestBuildPlatformRowReleases:
    """When affected_releases are present the CVE is applicable."""

    def test_single_rhel8_release_applicable(self):
        releases = [{
            "product_name": "Red Hat Enterprise Linux BaseOS (v. 8)",
            "advisory":     "RHSA-2023:1234",
            "package":      "curl-7.76.1-26.el8_8.2.x86_64",
            "cpe":          "cpe:/o:redhat:enterprise_linux:8::baseos",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.5",
            "https://example.com", "RHEL", releases, [], "curl",
        )
        assert row["Applicable?"] == "Yes"
        assert row["Platform"] == "RHEL"
        assert row["Fix Advisory"] == "RHSA-2023:1234"
        assert "curl" in row["Affected Component(s)"]
        assert "RHEL 8" in row["Impacted Version(s)"]

    def test_multiple_advisories_and_versions_joined(self):
        releases = [
            {
                "product_name": "Red Hat Enterprise Linux BaseOS (v. 8)",
                "advisory":     "RHSA-2023:1234",
                "package":      "curl-7.76.1-26.el8_8.2.x86_64",
                "cpe":          "cpe:/o:redhat:enterprise_linux:8::baseos",
            },
            {
                "product_name": "Red Hat Enterprise Linux BaseOS (v. 9)",
                "advisory":     "RHSA-2023:1235",
                "package":      "curl-7.76.1-30.el9.x86_64",
                "cpe":          "cpe:/o:redhat:enterprise_linux:9::baseos",
            },
        ]
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.5",
            "https://example.com", "RHEL", releases, [], "curl",
        )
        assert "RHSA-2023:1234" in row["Fix Advisory"]
        assert "RHSA-2023:1235" in row["Fix Advisory"]
        assert "RHEL 8" in row["Impacted Version(s)"]
        assert "RHEL 9" in row["Impacted Version(s)"]
        # RHEL 8 must be listed before RHEL 9 (numeric sort)
        assert row["Impacted Version(s)"].index("RHEL 8") < row["Impacted Version(s)"].index("RHEL 9")

    def test_ocp_release_row(self):
        releases = [{
            "product_name": "Red Hat OpenShift Container Platform 4.12",
            "advisory":     "RHSA-2023:2001",
            "package":      "openshift4/ose-base:v4.12.0",
            "cpe":          "cpe:/a:redhat:openshift:4.12::el9",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Critical", "9.8",
            "https://example.com", "OpenShift", releases, [], "N/A",
        )
        assert row["Applicable?"] == "Yes"
        assert row["Platform"] == "OpenShift"
        assert "OCP 4.12" in row["Impacted Version(s)"]

    def test_components_fallback_used_when_package_is_absent(self):
        releases = [{
            "product_name": "Red Hat Enterprise Linux 8",
            "advisory":     "RHSA-2023:9999",
            "package":      "",
            "cpe":          "cpe:/o:redhat:enterprise_linux:8",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Low", "3.1",
            "https://example.com", "RHEL", releases, [], "fallback-pkg",
        )
        assert row["Affected Component(s)"] == "fallback-pkg"

    def test_all_csv_fields_present(self):
        releases = [{
            "product_name": "Red Hat Enterprise Linux 9",
            "advisory":     "RHSA-2023:0001",
            "package":      "openssl-3.0.7-1.el9.x86_64",
            "cpe":          "cpe:/o:redhat:enterprise_linux:9::baseos",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "High", "8.0",
            "https://example.com/cve", "RHEL", releases, [], "openssl",
        )
        expected_keys = {
            "CVE", "Severity", "Score", "Platform", "Applicable?",
            "Affected Component(s)", "Fix Advisory", "Impacted Version(s)",
            "Component Type(s)", "Justification", "URL",
        }
        assert expected_keys.issubset(row.keys())


# ── build_platform_row — package states only ───────────────────────────────────

class TestBuildPlatformRowStates:
    """When only package_state entries exist, Applicable? is derived from fix_state."""

    def test_not_affected_is_no(self):
        states = [{
            "product_name": "Red Hat Enterprise Linux 8",
            "fix_state":    "Not affected",
            "package_name": "java-1.8.0-openjdk",
            "cpe":          "cpe:/o:redhat:enterprise_linux:8",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Critical", "9.8",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "No"
        assert "NOT affected" in row["Justification"]

    def test_will_not_fix_is_yes(self):
        states = [{
            "product_name": "Red Hat Enterprise Linux 9",
            "fix_state":    "Will not fix",
            "package_name": "some-lib",
            "cpe":          "cpe:/o:redhat:enterprise_linux:9",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Moderate", "5.3",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "Yes"
        assert "Will not fix" in row["Justification"]

    def test_under_investigation_is_unknown(self):
        states = [{
            "product_name": "Red Hat Enterprise Linux 8",
            "fix_state":    "Under investigation",
            "package_name": "kernel",
            "cpe":          "cpe:/o:redhat:enterprise_linux:8",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.0",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "Unknown"

    def test_fix_deferred_is_yes(self):
        states = [{
            "product_name": "Red Hat Enterprise Linux 9",
            "fix_state":    "Fix deferred",
            "package_name": "lib-xyz",
            "cpe":          "cpe:/o:redhat:enterprise_linux:9",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.5",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "Yes"

    def test_out_of_support_scope_is_yes(self):
        states = [{
            "product_name": "Red Hat Enterprise Linux 8",
            "fix_state":    "Out of support scope",
            "package_name": "old-lib",
            "cpe":          "cpe:/o:redhat:enterprise_linux:8",
        }]
        row = build_platform_row(
            "CVE-2023-0001", "Low", "2.0",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "Yes"

    def test_mixed_states_single_not_affected_does_not_win(self):
        # "Not affected" + "Will not fix" → not all "Not affected", so Yes
        states = [
            {
                "product_name": "Red Hat Enterprise Linux 8",
                "fix_state":    "Not affected",
                "package_name": "pkg-a",
                "cpe":          "cpe:/o:redhat:enterprise_linux:8",
            },
            {
                "product_name": "Red Hat Enterprise Linux 9",
                "fix_state":    "Will not fix",
                "package_name": "pkg-b",
                "cpe":          "cpe:/o:redhat:enterprise_linux:9",
            },
        ]
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.5",
            "https://example.com", "RHEL", [], states, "N/A",
        )
        assert row["Applicable?"] == "Yes"


# ── build_platform_row — empty inputs ──────────────────────────────────────────

class TestBuildPlatformRowEmpty:
    def test_no_releases_or_states_returns_no(self):
        row = build_platform_row(
            "CVE-2023-0001", "Important", "7.5",
            "https://example.com", "RHEL", [], [], "N/A",
        )
        assert row["Applicable?"] == "No"
        assert "No RHEL" in row["Justification"]

    def test_openshift_no_data_justification_mentions_openshift(self):
        row = build_platform_row(
            "CVE-2023-0001", "Low", "2.5",
            "https://example.com", "OpenShift", [], [], "N/A",
        )
        assert "No OpenShift" in row["Justification"]


# ── analyze_cve ─────────────────────────────────────────────────────────────────

class TestAnalyzeCve:
    """End-to-end tests for analyze_cve with mocked HTTP helpers."""

    def test_rhel_only_data_returns_one_row(self, rh_cve_rhel8_fixed):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel8_fixed):
            rows = analyze_cve("CVE-2023-0001", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Platform"] == "RHEL"
        assert rows[0]["Applicable?"] == "Yes"

    def test_ocp_only_data_returns_one_row(self, rh_cve_rhcos):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhcos):
            rows = analyze_cve("CVE-2023-0002", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Platform"] == "OpenShift"
        assert rows[0]["Applicable?"] == "Yes"

    def test_both_platforms_produces_two_rows(self, rh_cve_both_rhel_and_ocp):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_both_rhel_and_ocp):
            rows = analyze_cve("CVE-2023-0003", skip_nist=True)
        assert len(rows) == 2
        platforms = {r["Platform"] for r in rows}
        assert platforms == {"RHEL", "OpenShift"}

    def test_no_data_returns_single_fallback_row(self):
        with patch("cve_analyzer.fetch_rh_cve", return_value={}):
            rows = analyze_cve("CVE-9999-0001", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Platform"] == "RHEL / OpenShift"
        assert rows[0]["Applicable?"] == "Unknown"

    def test_rhel_not_affected_row(self, rh_cve_rhel8_not_affected):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel8_not_affected):
            rows = analyze_cve("CVE-2023-0004", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Platform"] == "RHEL"
        assert rows[0]["Applicable?"] == "No"

    def test_will_not_fix_state(self, rh_cve_will_not_fix):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_will_not_fix):
            rows = analyze_cve("CVE-2023-0005", skip_nist=True)
        assert rows[0]["Applicable?"] == "Yes"
        assert "Will not fix" in rows[0]["Justification"]

    def test_under_investigation_state(self, rh_cve_under_investigation):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_under_investigation):
            rows = analyze_cve("CVE-2023-0006", skip_nist=True)
        assert rows[0]["Applicable?"] == "Unknown"

    def test_severity_and_score_populated_from_redhat(self, rh_cve_rhel8_fixed):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel8_fixed):
            rows = analyze_cve("CVE-2023-0007", skip_nist=True)
        assert rows[0]["Severity"] == "Important"
        assert rows[0]["Score"] == "7.5"

    def test_cve_id_normalized_to_uppercase(self, rh_cve_rhel8_fixed):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel8_fixed):
            rows = analyze_cve("cve-2023-0099", skip_nist=True)
        assert rows[0]["CVE"] == "CVE-2023-0099"

    def test_url_contains_cve_id(self, rh_cve_rhel8_fixed):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel8_fixed):
            rows = analyze_cve("CVE-2023-9876", skip_nist=True)
        assert "CVE-2023-9876" in rows[0]["URL"]

    def test_multi_rhel_versions_consolidated_into_one_row(self, rh_cve_multi_rhel_versions):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_multi_rhel_versions):
            rows = analyze_cve("CVE-2023-0008", skip_nist=True)
        rhel_rows = [r for r in rows if r["Platform"] == "RHEL"]
        assert len(rhel_rows) == 1
        versions = rhel_rows[0]["Impacted Version(s)"]
        assert "RHEL 8" in versions
        assert "RHEL 9" in versions

    def test_rhel9_fixed_returns_correct_platform_and_advisory(self, rh_cve_rhel9_fixed):
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhel9_fixed):
            rows = analyze_cve("CVE-2023-0009", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Platform"] == "RHEL"
        assert "RHSA-2023:5000" in rows[0]["Fix Advisory"]
        assert "RHEL 9" in rows[0]["Impacted Version(s)"]

    def test_non_rhel_ocp_affected_release_returns_no_row(self):
        """Data from RedHat but no RHEL/OCP entries → single 'No' fallback row."""
        rh_data = {
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "7.5"},
            "affected_release": [{
                "product_name": "Windows Server 2022",
                "advisory":     "some-advisory",
                "package":      "some-package",
                "cpe":          "cpe:/o:microsoft:windows_server",
            }],
            "package_state": [],
        }
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_data):
            rows = analyze_cve("CVE-2023-9999", skip_nist=True)
        assert len(rows) == 1
        assert rows[0]["Applicable?"] == "No"

    def test_nist_severity_used_when_redhat_severity_missing(self, nist_v31):
        rh_data = {
            "threat_severity": "",
            "cvss3": {},
            "cvss": {},
            "affected_release": [{
                "product_name": "Red Hat Enterprise Linux 9",
                "advisory":     "RHSA-2023:0001",
                "package":      "openssl-3.0.7-1.el9.x86_64",
                "cpe":          "cpe:/o:redhat:enterprise_linux:9::baseos",
            }],
            "package_state": [],
        }
        with (
            patch("cve_analyzer.fetch_rh_cve", return_value=rh_data),
            patch("cve_analyzer.fetch_nist_cve", return_value=nist_v31),
        ):
            rows = analyze_cve("CVE-2023-0010")
        # NIST reports HIGH at 7.5
        assert rows[0]["Score"] == "7.5"
        assert rows[0]["Severity"] == "High"

    def test_rhcos_not_classified_as_rhel(self, rh_cve_rhcos):
        """RHCOS entry must appear in an OpenShift row, never a RHEL row."""
        with patch("cve_analyzer.fetch_rh_cve", return_value=rh_cve_rhcos):
            rows = analyze_cve("CVE-2023-0011", skip_nist=True)
        platforms = [r["Platform"] for r in rows]
        assert "RHEL" not in platforms
        assert "OpenShift" in platforms
