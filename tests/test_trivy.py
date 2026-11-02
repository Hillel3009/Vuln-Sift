"""Tests for the Trivy report loader."""

from pathlib import Path

from vulnsift.trivy import load_findings

SAMPLE = Path(__file__).parent / "fixtures" / "trivy_sample.json"


def test_one_finding_per_cve():
    cves = [f.cve for f in load_findings(SAMPLE)]
    assert sorted(cves) == ["CVE-2023-38545", "CVE-2023-44487"]


def test_collects_every_affected_package():
    findings = {f.cve: f for f in load_findings(SAMPLE)}
    assert findings["CVE-2023-38545"].packages == ["curl", "libcurl4"]


def test_empty_fixed_version_means_no_fix():
    findings = {f.cve: f for f in load_findings(SAMPLE)}
    assert findings["CVE-2023-44487"].fixed is None


def test_keeps_severity_and_versions():
    findings = {f.cve: f for f in load_findings(SAMPLE)}
    curl = findings["CVE-2023-38545"]
    assert curl.severity == "CRITICAL"
    assert curl.installed == "7.88.1-10"
    assert curl.fixed == "7.88.1-10+deb12u4"