import pytest
from app.core.security import validate_external_url
from app.risk.engine import calculate


def test_ssrf_blocks_private_and_non_https():
    for url in ('http://127.0.0.1/','https://127.0.0.1/','file:///etc/passwd','https://user:pass@example.com/'):
        with pytest.raises(ValueError): validate_external_url(url)


def test_risk_is_dimensioned_and_explainable():
    result=calculate({'disposable':False,'suspicious_chars':False,'idn':False,'has_dmarc':False,'has_spf':False,'dnssec':False}, [{'finding_type':'breach','value':'A','confidence':1.0},{'finding_type':'breach','value':'B','confidence':1.0}])
    assert 0 <= result.score <= 100
    assert set(result.dimensions)=={'identity_exposure','breach_exposure','domain_security','public_footprint'}
    assert any(f['dimension']=='breach_exposure' for f in result.factors)
