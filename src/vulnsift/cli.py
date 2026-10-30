"""Command-line entry point."""

import argparse
from collections import Counter
from pathlib import Path

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
    print(f"{len(findings)} unique CVEs")
    for severity, count in Counter(f.severity for f in findings).most_common():
        print(f"  {severity:<8} {count}")

    grouped = [f for f in findings if len(f.packages) > 1]
    print(f"\n{len(grouped)} CVEs affect several packages")
    if grouped:
        example = grouped[0]
        print(f"  e.g. {example.cve}: {', '.join(example.packages)}")