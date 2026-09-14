# Testing and Verification

## Authoritative verification

The GitHub Actions CI workflow is the authoritative verification mechanism for a release. Release claims should be tied to a completed green CI run for the exact commit being released.

The workflow verifies the following categories:

- focused Phase/regression suites where applicable
- complete backend `pytest` suite
- `pip-audit` dependency vulnerability audit
- frontend tests
- frontend lint
- TypeScript type checking
- production frontend build
- secret scanning with Gitleaks
- CodeQL/SAST analysis
- container image scanning
- workflow security analysis with zizmor

The repository intentionally does not hard-code a test count here. The suite evolves as regression coverage grows; the CI workflow and its exact run for the release commit are the source of truth.

## Local backend verification

Run:

```bash
cd backend
python -m pytest -q
```

Focused Phase/regression suites can be run directly when investigating a specific area, for example:

```bash
python -m pytest -q tests/test_phase41_full_pipeline_e2e.py
python -m pytest -q tests/test_phase42_runtime_network_accounting.py
```

## Frontend verification

Run in an environment with the Node dependencies installed:

```bash
cd frontend
npm ci
npm test
npm run lint
npx tsc --noEmit
npm run build
```

Vite's production build is performed with `vite build`. A production frontend verification claim should only be made when dependency installation and the build complete successfully in CI.

## Security and supply-chain verification

The release CI also performs dependency auditing, secret scanning, CodeQL/SAST, container scanning, and workflow-security analysis. These checks are part of the authoritative release verification rather than optional historical phase checks.

## Docker

Build and run:

```bash
docker compose up --build
```

The container includes a health check against `/api/health`, runs as a non-root user, drops Linux capabilities and uses `no-new-privileges`.
