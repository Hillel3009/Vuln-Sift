import json
from collections import Counter

# 1. Read the Trivy report
with open("nginx.json", encoding="utf-8") as f:
    data = json.load(f)

print("Image:", data["ArtifactName"])

severities = Counter()
cves = []

# 2. Walk through each scanned target (OS packages, Python libs, etc.)
for result in data.get("Results", []):
    vulns = result.get("Vulnerabilities") or []
    print(f"- {result['Target']}: {len(vulns)} vulnerabilities")

    # 3. Count every vulnerability by severity
    for v in vulns:
        severities[v["Severity"]] += 1
        cves.append(v["VulnerabilityID"])

print("\nBy severity:")
for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
    print(f"  {sev:<8} {severities[sev]}")

print(f"\nTotal: {len(cves)} findings, {len(set(cves))} unique CVEs")