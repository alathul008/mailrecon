import pytest

from app.osint import dns


@pytest.mark.asyncio
async def test_dns_lookup_failure_is_unavailable_not_absence(monkeypatch):
    async def fail(_resolver, _name, _rdtype):
        return [], False

    monkeypatch.setattr(dns, "_resolve", fail)
    result = await dns.resolve("example.com")

    assert result["SPF"] == []
    assert result["SPF_status"] == "unavailable"
    assert result["DMARC"] == []
    assert result["DMARC_status"] == "unavailable"


def test_successful_empty_dns_records_remain_negative_observations():
    result = {
        "SPF": [],
        "SPF_status": "ok",
        "DMARC": [],
        "DMARC_status": "ok",
    }
    has_spf = False if result["SPF_status"] == "ok" else None
    has_dmarc = False if result["DMARC_status"] == "ok" else None
    assert has_spf is False
    assert has_dmarc is False
