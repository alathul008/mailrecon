import asyncio

import dns.exception
import dns.resolver

from app.osint import dns as dns_osint


class FakeRecord:
    def __init__(self, value):
        self.value = value

    def to_text(self):
        return self.value


class FakeAnswer:
    def __init__(self, values):
        self.values = [FakeRecord(value) for value in values]

    def __iter__(self):
        return iter(self.values)


class FakeResolver:
    lifetime = None

    def __init__(self, responses):
        self.responses = responses

    async def resolve(self, name, rdtype):
        result = self.responses[(name, rdtype)]
        if isinstance(result, BaseException):
            raise result
        return FakeAnswer(result)


def test_record_presence_distinguishes_no_result_from_unavailable():
    assert dns_osint.record_presence([], "no_result") is False
    assert dns_osint.record_presence(["v=spf1 -all"], "ok") is True
    assert dns_osint.record_presence([], "unavailable") is None
    assert dns_osint.record_presence([], "error") is None


def test_resolve_preserves_dns_states_and_observations(monkeypatch):
    domain = "example.test"
    responses = {}
    for kind in ("A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY"):
        responses[(domain, kind)] = {
            "A": ["192.0.2.10"],
            "AAAA": [],
            "MX": ["10 mail.example.test."],
            "NS": ["ns1.example.test."],
            "CNAME": [],
            "TXT": ["v=spf1 -all", "not-spf"],
            "DS": ["12345 13 2 abcdef"],
            "DNSKEY": ["257 3 13 key"],
        }[kind]
    responses[(f"_dmarc.{domain}", "TXT")] = ["v=DMARC1; p=reject"]
    for selector in ("google", "selector1", "selector2", "default", "dkim", "mail"):
        responses[(f"{selector}._domainkey.{domain}", "TXT")] = []
    responses[("selector1._domainkey.example.test", "TXT")] = ["v=DKIM1; k=rsa; p=abc"]

    monkeypatch.setattr(dns_osint.dns.asyncresolver, "Resolver", lambda: FakeResolver(responses))
    result = asyncio.run(dns_osint.resolve(domain))

    assert result["SPF"] == ["v=spf1 -all"]
    assert result["SPF_status"] == "ok"
    assert result["DMARC"] == ["v=DMARC1; p=reject"]
    assert result["DMARC_status"] == "ok"
    assert result["DKIM"] == ["selector1: v=DKIM1; k=rsa; p=abc"]
    assert result["DKIM_status"] == "ok"
    assert result["DNSSEC"] is True
    assert result["DNSSEC_status"] == "ok"


def test_dnssec_absence_is_not_a_failure(monkeypatch):
    domain = "unsigned.example"
    responses = {(domain, kind): [] for kind in ("A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY")}
    responses[(f"_dmarc.{domain}", "TXT")] = dns.resolver.NXDOMAIN()
    for selector in ("google", "selector1", "selector2", "default", "dkim", "mail"):
        responses[(f"{selector}._domainkey.{domain}", "TXT")] = dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns_osint.dns.asyncresolver, "Resolver", lambda: FakeResolver(responses))
    result = asyncio.run(dns_osint.resolve(domain))

    assert result["DNSSEC"] is False
    assert result["DNSSEC_status"] == "no_result"
    assert result["DMARC"] == []
    assert result["DMARC_status"] == "no_result"


def test_dns_provider_failure_is_unknown_not_negative(monkeypatch):
    domain = "timeout.example"
    responses = {(domain, kind): dns.exception.Timeout() for kind in ("A", "AAAA", "MX", "NS", "CNAME", "TXT", "DS", "DNSKEY")}
    responses[(f"_dmarc.{domain}", "TXT")] = dns.exception.Timeout()
    for selector in ("google", "selector1", "selector2", "default", "dkim", "mail"):
        responses[(f"{selector}._domainkey.{domain}", "TXT")] = dns.exception.Timeout()

    monkeypatch.setattr(dns_osint.dns.asyncresolver, "Resolver", lambda: FakeResolver(responses))
    result = asyncio.run(dns_osint.resolve(domain))

    assert result["SPF"] == []
    assert result["SPF_status"] == "unavailable"
    assert result["DMARC_status"] == "unavailable"
    assert result["DNSSEC"] is None
    assert result["DNSSEC_status"] == "unavailable"
