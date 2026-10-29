import json

import httpx

EPSS_API = "https://api.first.org/data/v1/epss"

# 1. Collect unique CVEs and keep the scanner's severity for each one
with open("nginx.json", encoding="utf-8") as f:
    data = json.load(f)

severity_by_cve = {}
for result in data.get("Results", []):
    for v in result.get("Vulnerabilities") or []:
        cve = v["VulnerabilityID"]
        if cve.startswith("CVE-"):
            severity_by_cve[cve] = v["Severity"]

cves = sorted(severity_by_cve)
print(f"{len(cves)} unique CVEs to look up")

# 2. Ask the EPSS API, 100 CVEs per request
epss = {}
for i in range(0, len(cves), 100):
    batch = cves[i : i + 100]
    resp = httpx.get(EPSS_API, params={"cve": ",".join(batch)}, timeout=30)
    resp.raise_for_status()
    for row in resp.json()["data"]:
        epss[row["cve"]] = float(row["epss"])

print(f"EPSS found for {len(epss)} CVEs\n")

# 3. Top 10 by exploitation probability
top = sorted(epss.items(), key=lambda item: item[1], reverse=True)[:10]
print("Top 10 by EPSS (probability of exploitation in the next 30 days):")
for cve, score in top:
    print(f"  {cve:<18} {score:>7.2%}   scanner severity: {severity_by_cve[cve]}")

# 4. How many CRITICAL CVEs are actually likely to be exploited?
critical = [c for c, s in severity_by_cve.items() if s == "CRITICAL"]
likely = [c for c in critical if epss.get(c, 0) >= 0.10]
print(f"\nCRITICAL CVEs: {len(critical)}, of which EPSS >= 10%: {len(likely)}")