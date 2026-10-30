"""Command-line entry point."""

import argparse
from pathlib import Path

from vulnsift.enrich import enrich
from vulnsift.trivy import load_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vulnsift",
        description="Explainable triage of container image vulnerabilities.",
    )
    parser.add_argument(
        "report", type=Path, help="Trivy JSON report (trivy image -f json -o report.json IMAGE)"
    )
    args = parser.parse_args()

    findings = load_findings(args.report)
    print(f"{len(findings)} unique CVEs, fetching EPSS and KEV data...")
    enrich(findings)

    in_kev = [f for f in findings if f.kev]
    print(f"{len(in_kev)} known exploited (KEV): {', '.join(f.cve for f in in_kev)}")

    top = sorted(findings, key=lambda f: f.epss or 0, reverse=True)[:5]
    print("\nTop 5 by EPSS:")
    for f in top:
        print(f"  {f.cve:<18} {f.epss or 0:>7.2%}  {f.severity}")