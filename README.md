# VulnSift

**Fix first what attackers actually exploit.**

Container scanners report hundreds of vulnerabilities per image, and most of them will never
be exploited. VulnSift takes a [Trivy](https://trivy.dev) scan, adds public threat
intelligence, and gives you a short, explained, prioritized list.

On `nginx:1.25`, Trivy reports **131 CRITICAL or HIGH** vulnerabilities.
VulnSift keeps **11 that really need attention now**, and tells you why.

## How it works

Each vulnerability goes through simple, documented rules. The first one that matches wins:

| Level | Rule | Meaning |
| --- | --- | --- |
| **P1** | Listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited in the wild: fix now |
| **P2** | [EPSS](https://www.first.org/epss/) ≥ 10% | Likely to be exploited soon |
| **P3** | Rated CRITICAL or HIGH | Severe on paper, no sign of exploitation |
| **P4** | Everything else | Low risk for now |

- **Severity / CVSS**: how bad it would be if exploited (theoretical).
- **EPSS** (FIRST): probability of exploitation in the next 30 days.
- **KEV** (CISA): vulnerabilities with evidence of real-world exploitation.

Findings are grouped by CVE: one fix often closes the same CVE in several packages.

## Install

Requires Python 3.12+ and Trivy.

```bash
git clone https://github.com/<Hillel3009>/vulnsift.git
cd vulnsift
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
trivy image -f json -o report.json nginx:1.25
vulnsift report.json
vulnsift report.json --top 30
```

## Roadmap

- [x] Trivy report parsing, grouped by CVE
- [x] EPSS and CISA KEV enrichment
- [x] Explainable P1–P4 prioritization
- [ ] Tests and continuous integration
- [ ] Direct scan command (`vulnsift scan IMAGE`)
- [ ] AI layer: plain-language explanation and context for each urgent finding
- [ ] Reports in English, French and Hebrew; compliance exports (EU CRA)

## License

Apache 2.0