

def test_docker_build_uses_lockfile_enforced_npm_ci():
    dockerfile=Path(__file__).resolve().parents[2] / "Dockerfile"; text=dockerfile.read_text(encoding="utf-8")
    assert "RUN npm ci --no-audit --no-fund" in text
    assert "RUN npm install --no-audit --no-fund" not in text


def test_ci_security_jobs_and_pinned_scanners_are_present():
    workflow=(Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for job in ("secret-scan:","sast:","container-scan:","workflow-security:"): assert job in workflow
    for action in ("gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e","github/codeql-action/init@cdf488f595d80d6e07e03d4674febd5ab45fa938","ghcr.io/aquasecurity/trivy:0.74.0@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9","zizmorcore/zizmor-action@3dc1ecc9bcb9e94e9b2c709687979e1298497054"): assert action in workflow
