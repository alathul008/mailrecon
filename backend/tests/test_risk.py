from app.risk.engine import calculate


def test_risk_is_dimensioned_and_explainable():
    result=calculate({'disposable':False,'suspicious_chars':False,'idn':False,'has_dmarc':False,'has_spf':False,'dnssec':False}, [{'finding_type':'breach','value':'A','confidence':1.0},{'finding_type':'breach','value':'B','confidence':1.0}])
    assert 0 <= result.score <= 100
    assert set(result.dimensions)=={'identity_exposure','breach_exposure','domain_security','public_footprint'}
    assert any(f['dimension']=='breach_exposure' for f in result.factors)
    assert result.dimensions['breach_exposure'] > 0


def test_mitigating_domain_signal_never_creates_negative_risk():
    result=calculate({'disposable':False,'suspicious_chars':False,'idn':False,'has_dmarc':True,'has_spf':True,'dnssec':True}, [])
    assert result.score == 0
    assert all(v >= 0 for v in result.dimensions.values())
