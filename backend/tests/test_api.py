from datetime import datetime, timezone

from fastapi.testclient import TestClient
from app.core.config import get_settings
from app.main import app
from app.api.routes import module_projection
from app.models import ModuleRun


def test_health_and_security_headers():
    with TestClient(app) as c:
        r=c.get('/api/health')
        assert r.status_code == 200
        assert r.json()['status']=='ok'
        assert r.headers['x-content-type-options']=='nosniff'
        assert r.headers['x-frame-options']=='DENY'


def test_protected_api_requires_configuration():
    settings=get_settings()
    original=settings.api_key
    settings.api_key=None
    try:
        with TestClient(app) as c:
            r=c.get('/api/providers')
            assert r.status_code == 503
    finally:
        settings.api_key=original


def test_protected_api_rejects_missing_and_invalid_keys():
    settings=get_settings()
    original=settings.api_key
    settings.api_key='test-secret-key'
    try:
        with TestClient(app) as c:
            assert c.get('/api/providers').status_code == 401
            assert c.get('/api/providers', headers={'Authorization':'Bearer wrong-key'}).status_code == 401
            assert c.get('/api/service-catalog').status_code == 401
    finally:
        settings.api_key=original


def test_protected_api_accepts_valid_bearer_key():
    settings=get_settings()
    original=settings.api_key
    settings.api_key='test-secret-key'
    try:
        with TestClient(app) as c:
            r=c.get('/api/providers', headers={'Authorization':'Bearer test-secret-key'})
            assert r.status_code == 200
            providers={x['name']:x for x in r.json()}
            assert {'DNS','RDAP','Gravatar','GitHub','GitLab','Have I Been Pwned','Public Web','Ollama'} <= set(providers)
            assert providers['GitLab']['supported'] is True
            assert providers['GitLab']['account_discovery'] is True
            assert providers['Public Web']['account_discovery'] is True
            catalog=c.get('/api/service-catalog', headers={'Authorization':'Bearer test-secret-key'})
            assert catalog.status_code == 200
            github=next(x for x in catalog.json() if x['service']=='GitHub')
            assert {'service','category','supported','provider','discovery_methods'} <= set(github)
            gitlab=next(x for x in catalog.json() if x['service']=='GitLab')
            assert gitlab['supported'] is True
    finally:
        settings.api_key=original


def test_provider_states_are_explicit():
    settings=get_settings()
    original=settings.api_key
    settings.api_key='test-secret-key'
    try:
        with TestClient(app) as c:
            data=c.get('/api/providers', headers={'Authorization':'Bearer test-secret-key'}).json()
            assert all(x['status'] for x in data)
    finally:
        settings.api_key=original


def test_timeline_requires_bearer_authentication():
    settings=get_settings()
    original=settings.api_key
    settings.api_key='test-secret-key'
    try:
        with TestClient(app) as c:
            assert c.get('/api/investigations/1/timeline').status_code == 401
            assert c.get('/api/investigations/1/timeline', headers={'Authorization':'Bearer wrong-key'}).status_code == 401
    finally:
        settings.api_key=original


def test_module_projection_marks_only_authoritative_attempt_current():
    started = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
    abandoned = ModuleRun(module="rdap",status="abandoned",execution_id="execution-1",execution_attempt_id="attempt-a",started_at=started,finished_at=None,message="historical attempt")
    current = ModuleRun(module="rdap",status="running",execution_id="execution-1",execution_attempt_id="attempt-b",started_at=started,finished_at=None,message="current attempt")
    old_view = module_projection(abandoned, "attempt-b")
    current_view = module_projection(current, "attempt-b")
    assert old_view["status"] == "abandoned"
    assert old_view["execution_attempt_id"] == "attempt-a"
    assert old_view["current"] is False
    assert old_view["started_at"] == started
    assert current_view["execution_attempt_id"] == "attempt-b"
    assert current_view["current"] is True
