"""Tests for EPSS and KEV enrichment, without any network access."""

import httpx
import pytest

from vulnsift.enrich import enrich, fetch_epss
from vulnsift.trivy import Finding

FAKE_EPSS = {"CVE-2023-44487": "0.94", "CVE-2023-38545": "0.04"}
FAKE_KEV = {"vulnerabilities": [{"cveID": "CVE-2023-44487"}]}


def fake_api(request: httpx.Request) -> httpx.Response:
    """Answer like the real EPSS and KEV services would."""
    if request.url.host == "api.first.org":
        asked = request.url.params["cve"].split(",")
        data = [{"cve": c, "epss": FAKE_EPSS[c]} for c in asked if c in FAKE_EPSS]
        return httpx.Response(200, json={"data": data})
    if request.url.host == "www.cisa.gov":
        return httpx.Response(200, json=FAKE_KEV)
    return httpx.Response(404)


@pytest.fixture
def client():
    with httpx.Client(transport=httpx.MockTransport(fake_api)) as c:
        yield c


def test_enrich_fills_epss_and_kev(client):
    findings = [
        Finding(cve="CVE-2023-44487", severity="HIGH"),
        Finding(cve="CVE-2023-38545", severity="CRITICAL"),
        Finding(cve="CVE-2099-0001", severity="LOW"),  # unknown to EPSS
    ]
    enrich(findings, client)
    by_cve = {f.cve: f for f in findings}
    assert by_cve["CVE-2023-44487"].epss == 0.94
    assert by_cve["CVE-2023-44487"].kev is True
    assert by_cve["CVE-2023-38545"].kev is False
    assert by_cve["CVE-2099-0001"].epss is None


def test_epss_is_requested_in_batches_of_100():
    calls = []

    def counting_api(request):
        calls.append(request)
        return httpx.Response(200, json={"data": []})

    with httpx.Client(transport=httpx.MockTransport(counting_api)) as c:
        fetch_epss([f"CVE-2099-{i:04d}" for i in range(250)], c)
    assert len(calls) == 3


def test_api_error_is_not_silent():
    def broken_api(request):
        return httpx.Response(503)

    with httpx.Client(transport=httpx.MockTransport(broken_api)) as c:
        with pytest.raises(httpx.HTTPStatusError):
            fetch_epss(["CVE-2023-44487"], c)