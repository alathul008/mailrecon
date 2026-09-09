from fastapi.testclient import TestClient
from app.core.config import get_settings
from app.main import app


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
            assert {'DNS','RDAP','Gravatar','GitHub','Have I Been Pwned','Ollama'} <= {x['name'] for x in r.json()}
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
