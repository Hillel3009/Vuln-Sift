"""Tests for the P1-P4 prioritization rules."""

import pytest

from vulnsift.prioritize import prioritize, sort_key
from vulnsift.trivy import Finding


def make(severity="LOW", epss=None, kev=False, fixed=None, cve="CVE-2099-0001"):
    """Build a finding with only the fields a test cares about."""
    return Finding(cve=cve, severity=severity, epss=epss, kev=kev, fixed=fixed)


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (make(kev=True), "P1"),
        (make(kev=True, severity="LOW", epss=0.001), "P1"),     # KEV beats everything
        (make(epss=0.10), "P2"),                                # exactly the threshold
        (make(epss=0.85, severity="MEDIUM"), "P2"),
        (make(epss=0.0999, severity="CRITICAL"), "P3"),         # just under the threshold
        (make(severity="HIGH"), "P3"),                          # no EPSS data must not crash
        (make(severity="MEDIUM", epss=0.01), "P4"),
        (make(severity="UNKNOWN"), "P4"),
    ],
)
def test_priority_rules(finding, expected):
    prioritize(finding)
    assert finding.priority == expected


def test_every_decision_has_a_reason():
    f = make(epss=0.25)
    prioritize(f)
    assert "EPSS 25%" in f.reason


def test_most_urgent_first():
    findings = [
        make(cve="P4", severity="LOW"),
        make(cve="P3-no-fix", severity="HIGH"),
        make(cve="P3-fix", severity="HIGH", fixed="1.2"),
        make(cve="P2-low-epss", epss=0.2),
        make(cve="P2-high-epss", epss=0.9),
        make(cve="P1", kev=True),
    ]
    for f in findings:
        prioritize(f)
    findings.sort(key=sort_key)
    assert [f.cve for f in findings] == [
        "P1", "P2-high-epss", "P2-low-epss", "P3-fix", "P3-no-fix", "P4",
    ]