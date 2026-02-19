"""
Tests for misc helper utilities: pkg_name_only, sort_versions, parse_ids,
and extract_cves_from_rhsa.
"""

import pytest
from unittest.mock import patch
from cve_analyzer import (
    pkg_name_only,
    sort_versions,
    parse_ids,
    extract_cves_from_rhsa,
)


# ── pkg_name_only ──────────────────────────────────────────────────────────────

class TestPkgNameOnly:
    def test_standard_nevra(self):
        assert pkg_name_only("curl-7.76.1-26.el8_8.2.x86_64") == "curl"

    def test_epoch_nevra(self):
        # Epoch prefix must not confuse the parser — name is still "openssl"
        assert pkg_name_only("openssl-1:3.0.7-1.el9.x86_64") == "openssl"

    def test_multi_word_package_name(self):
        # The lazy regex stops at the first -digit boundary (-1 in "java-1"),
        # so the returned name is "java" — not the full "java-1.8.0-openjdk".
        assert pkg_name_only("java-1.8.0-openjdk-1.8.0.342.b07-1.el8.x86_64") == "java"

    def test_plain_package_name_no_version(self):
        assert pkg_name_only("kernel") == "kernel"

    def test_container_image_falls_back_to_first_dash_split(self):
        # Container refs don't follow RPM NEVRA; split on first "-"
        result = pkg_name_only("openshift4/ose-base:v4.12.0")
        assert result == "openshift4/ose"

    def test_package_with_plus_in_name(self):
        assert pkg_name_only("openssl+1-3.0.1-1.el9.x86_64") == "openssl+1"


# ── sort_versions ──────────────────────────────────────────────────────────────

class TestSortVersions:
    def test_rhel_major_ascending(self):
        assert sort_versions({"RHEL 9", "RHEL 8"}) == ["RHEL 8", "RHEL 9"]

    def test_rhel_major_before_minor(self):
        result = sort_versions({"RHEL 9", "RHEL 8.10", "RHEL 8", "RHEL 8.1"})
        assert result == ["RHEL 8", "RHEL 8.1", "RHEL 8.10", "RHEL 9"]

    def test_rhel_8_9_minor_does_not_sort_after_rhel_9(self):
        # "RHEL 8.9" must sort between 8.x and 9, NOT after RHEL 9
        result = sort_versions({"RHEL 9", "RHEL 8.9", "RHEL 8"})
        assert result.index("RHEL 8.9") < result.index("RHEL 9")

    def test_ocp_versions_ascending(self):
        result = sort_versions({"OCP 4.14", "OCP 4.12", "OCP 4.13"})
        assert result == ["OCP 4.12", "OCP 4.13", "OCP 4.14"]

    def test_single_element(self):
        assert sort_versions({"RHEL 9"}) == ["RHEL 9"]

    def test_empty_set(self):
        assert sort_versions(set()) == []


# ── parse_ids ──────────────────────────────────────────────────────────────────

class TestParseIds:
    def test_single_cve(self):
        cves, rhsas = parse_ids(["CVE-2023-38408"])
        assert cves == ["CVE-2023-38408"]
        assert rhsas == []

    def test_single_rhsa(self):
        cves, rhsas = parse_ids(["RHSA-2023:4329"])
        assert cves == []
        assert rhsas == ["RHSA-2023:4329"]

    def test_mixed_ids(self):
        cves, rhsas = parse_ids(["CVE-2023-38408", "RHSA-2023:4329", "CVE-2021-44228"])
        assert cves == ["CVE-2023-38408", "CVE-2021-44228"]
        assert rhsas == ["RHSA-2023:4329"]

    def test_lowercase_ids_are_uppercased(self):
        cves, rhsas = parse_ids(["cve-2023-38408", "rhsa-2023:4329"])
        assert cves == ["CVE-2023-38408"]
        assert rhsas == ["RHSA-2023:4329"]

    def test_rhba_and_rhea_accepted(self):
        _, rhsas = parse_ids(["RHBA-2023:1234", "RHEA-2023:5678"])
        assert "RHBA-2023:1234" in rhsas
        assert "RHEA-2023:5678" in rhsas

    def test_garbage_token_skipped_with_warning(self, capsys):
        cves, rhsas = parse_ids(["NOT-AN-ID", "CVE-2023-38408"])
        assert cves == ["CVE-2023-38408"]
        assert rhsas == []
        captured = capsys.readouterr()
        assert "Unrecognised" in captured.err

    def test_empty_and_whitespace_tokens_are_skipped(self):
        cves, rhsas = parse_ids(["", "   ", "CVE-2023-0001"])
        assert cves == ["CVE-2023-0001"]
        assert rhsas == []

    def test_order_is_preserved(self):
        tokens = ["CVE-2023-0003", "CVE-2023-0001", "CVE-2023-0002"]
        cves, _ = parse_ids(tokens)
        assert cves == ["CVE-2023-0003", "CVE-2023-0001", "CVE-2023-0002"]


# ── extract_cves_from_rhsa ─────────────────────────────────────────────────────

class TestExtractCvesFromRhsa:
    def test_returns_cve_ids_from_dict_list(self):
        mock_data = [
            {"CVE": "CVE-2023-38408"},
            {"CVE": "CVE-2023-0286"},
        ]
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=mock_data):
            result = extract_cves_from_rhsa("RHSA-2023:4329")
        assert result == ["CVE-2023-38408", "CVE-2023-0286"]

    def test_returns_empty_when_no_data(self):
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=[]):
            result = extract_cves_from_rhsa("RHSA-2023:9999")
        assert result == []

    def test_ignores_entries_with_invalid_cve_format(self):
        mock_data = [
            {"CVE": "CVE-2023-38408"},
            {"CVE": "NOT-A-CVE"},
            {"CVE": ""},
        ]
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=mock_data):
            result = extract_cves_from_rhsa("RHSA-2023:4329")
        assert result == ["CVE-2023-38408"]

    def test_accepts_plain_string_items(self):
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=["CVE-2023-0001"]):
            result = extract_cves_from_rhsa("RHSA-2023:0001")
        assert result == ["CVE-2023-0001"]

    def test_lowercase_cve_in_data_is_uppercased(self):
        mock_data = [{"CVE": "cve-2023-38408"}]
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=mock_data):
            result = extract_cves_from_rhsa("RHSA-2023:4329")
        assert result == ["CVE-2023-38408"]

    def test_multiple_cves_all_returned(self):
        mock_data = [
            {"CVE": "CVE-2023-0001"},
            {"CVE": "CVE-2023-0002"},
            {"CVE": "CVE-2023-0003"},
        ]
        with patch("cve_analyzer.fetch_rh_rhsa_cves", return_value=mock_data):
            result = extract_cves_from_rhsa("RHSA-2023:9999")
        assert len(result) == 3
