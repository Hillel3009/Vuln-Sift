"""Command-line entry point."""

import argparse
from pathlib import Path

from vulnsift.enrich import enrich
from vulnsift.prioritize import prioritize, sort_key
from vulnsift.report import show
from vulnsift.trivy import load_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vulnsift",
        description="Explainable triage of container image vulnerabilities.",
    )
    parser.add_argument(
        "report", type=Path, help="Trivy JSON report (trivy image -f json -o report.json IMAGE)"
    )
    parser.add_argument("--top", type=int, default=15, help="How many findings to show")
    args = parser.parse_args()

    findings = load_findings(args.report)
    print(f"Fetching EPSS and KEV data for {len(findings)} CVEs...")
    enrich(findings)

    for f in findings:
        prioritize(f)
    findings.sort(key=sort_key)

    show(findings, args.report.name, args.top)