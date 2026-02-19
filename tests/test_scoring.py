"""
Tests for CVSS score and severity extraction.

Verifies that RedHat data is preferred, NIST is used as a fallback,
and the correct path is walked for each CVSS version.
"""

import pytest
from cve_analyzer import extract_score_severity


class TestExtractScoreSeverity:

    # ── RedHat-only data ───────────────────────────────────────────────────────

    def test_redhat_cvss3_preferred(self):
        rh = {
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "7.5"},
        }
        severity, score = extract_score_severity(rh, {})
        assert severity == "Important"
        assert score == "7.5"

    def test_redhat_severity_capitalised(self):
        rh = {"threat_severity": "critical", "cvss3": {"cvss3_base_score": "9.8"}}
        severity, _ = extract_score_severity(rh, {})
        assert severity == "Critical"

    def test_redhat_cvss2_fallback_when_no_cvss3(self):
        rh = {
            "threat_severity": "Low",
            "cvss3": {},
            "cvss": {"cvss_base_score": "3.5"},
        }
        _, score = extract_score_severity(rh, {})
        assert score == "3.5"

    def test_redhat_no_score_returns_na(self):
        rh = {"threat_severity": "Moderate", "cvss3": {}, "cvss": {}}
        _, score = extract_score_severity(rh, {})
        assert score == "N/A"

    # ── NIST fallback ──────────────────────────────────────────────────────────

    def test_nist_v31_used_when_no_redhat_score(self, nist_v31):
        rh = {"threat_severity": "", "cvss3": {}, "cvss": {}}
        severity, score = extract_score_severity(rh, nist_v31)
        assert score == "7.5"
        assert severity == "High"

    def test_nist_v2_fallback_when_no_v3(self, nist_v2_only):
        rh = {"threat_severity": "", "cvss3": {}, "cvss": {}}
        severity, score = extract_score_severity(rh, nist_v2_only)
        assert score == "6.5"
        assert severity == "Medium"

    def test_redhat_score_not_overridden_by_nist(self, nist_v31):
        # RedHat has a score; NIST should not replace it.
        rh = {
            "threat_severity": "Important",
            "cvss3": {"cvss3_base_score": "8.1"},
        }
        severity, score = extract_score_severity(rh, nist_v31)
        assert score == "8.1"      # RedHat's value, not NIST's 7.5
        assert severity == "Important"

    def test_redhat_severity_not_overridden_by_nist(self, nist_v31):
        rh = {
            "threat_severity": "Critical",
            "cvss3": {},
        }
        severity, _ = extract_score_severity(rh, nist_v31)
        assert severity == "Critical"  # RedHat's value, not NIST's HIGH

    # ── Empty / missing data ───────────────────────────────────────────────────

    def test_both_empty_returns_defaults(self, nist_empty):
        severity, score = extract_score_severity({}, nist_empty)
        assert severity == "Unknown"
        assert score == "N/A"

    def test_none_values_handled_gracefully(self):
        rh = {"threat_severity": None, "cvss3": None, "cvss": None}
        severity, score = extract_score_severity(rh, {})
        assert severity == "Unknown"
        assert score == "N/A"
