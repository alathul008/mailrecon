from fastapi.testclient import TestClient
from app.main import app


def test_health_and_security_headers():
    with TestClient(app) as c:
        r=c.get('/api/health')
        assert r.status_code == 200
        assert r.json()['status']=='ok'
        assert r.headers['x-content-type-options']=='nosniff'
        assert r.headers['x-frame-options']=='DENY'


def test_provider_states_are_explicit():
    with TestClient(app) as c:
        data=c.get('/api/providers').json()
        names={x['name'] for x in data}
        assert {'DNS','RDAP','Gravatar','GitHub','Have I Been Pwned','Ollama'} <= names
        assert all(x['status'] for x in data)
