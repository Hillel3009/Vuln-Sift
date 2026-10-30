"""Read Trivy JSON reports."""

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """One CVE found in an image, with every package it affects."""

    cve: str
    severity: str
    title: str = ""
    packages: list[str] = field(default_factory=list)
    installed: str = ""
    fixed: str | None = None
    # Filled later by enrichment and prioritization
    epss: float | None = None
    kev: bool = False
    priority: str = ""
    reason: str = ""


def load_findings(path: Path) -> list[Finding]:
    """Read a Trivy report and return one Finding per unique CVE."""
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: dict[str, Finding] = {}

    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities") or []:
            cve = v["VulnerabilityID"]
            if not cve.startswith("CVE-"):
                continue
            if cve not in findings:
                findings[cve] = Finding(
                    cve=cve,
                    severity=v.get("Severity", "UNKNOWN"),
                    title=v.get("Title", ""),
                    installed=v.get("InstalledVersion", ""),
                    fixed=v.get("FixedVersion") or None,
                )
            findings[cve].packages.append(v["PkgName"])

    return list(findings.values())