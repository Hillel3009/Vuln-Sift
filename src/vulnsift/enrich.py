"""Add public threat intelligence (EPSS, CISA KEV) to findings."""

import httpx

from vulnsift.trivy import Finding

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BATCH_SIZE = 100


def fetch_epss(cves: list[str], client: httpx.Client) -> dict[str, float]:
    """Return {cve: probability of exploitation in the next 30 days}."""
    scores: dict[str, float] = {}
    for i in range(0, len(cves), BATCH_SIZE):
        batch = cves[i : i + BATCH_SIZE]
        resp = client.get(EPSS_API, params={"cve": ",".join(batch)})
        resp.raise_for_status()
        for row in resp.json()["data"]:
            scores[row["cve"]] = float(row["epss"])
    return scores


def fetch_kev(client: httpx.Client) -> set[str]:
    """Return the set of CVE ids listed in the CISA KEV catalog."""
    resp = client.get(KEV_URL)
    resp.raise_for_status()
    return {item["cveID"] for item in resp.json()["vulnerabilities"]}


def enrich(findings: list[Finding]) -> None:
    """Fill the epss and kev fields of each finding, in place."""
    cves = [f.cve for f in findings]
    with httpx.Client(timeout=60) as client:
        epss = fetch_epss(cves, client)
        kev = fetch_kev(client)

    for f in findings:
        f.epss = epss.get(f.cve)
        f.kev = f.cve in kev