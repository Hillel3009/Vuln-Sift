import json

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# 1. Unique CVE ids from the scan (a set removes duplicates automatically)
with open("nginx.json", encoding="utf-8") as f:
    data = json.load(f)

cves = {
    v["VulnerabilityID"]
    for result in data.get("Results", [])
    for v in result.get("Vulnerabilities") or []
    if v["VulnerabilityID"].startswith("CVE-")
}

# 2. Download the KEV catalog (one file with every known exploited CVE)
resp = httpx.get(KEV_URL, timeout=60)
resp.raise_for_status()
catalog = resp.json()
kev = {item["cveID"]: item for item in catalog["vulnerabilities"]}
print(f"KEV catalog {catalog['catalogVersion']}: {len(kev)} known exploited vulnerabilities")

# 3. Which of our CVEs are in it?
found = sorted(cves & kev.keys())
print(f"{len(found)} of our {len(cves)} CVEs are known to be exploited:\n")
for cve in found:
    item = kev[cve]
    print(f"  {cve:<18} {item['vulnerabilityName']}")
    print(f"  {'':<18} added {item['dateAdded']}, ransomware: {item['knownRansomwareCampaignUse']}")