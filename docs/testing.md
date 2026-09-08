# Testing and Verification

## Backend

Run:

```bash
cd backend
python -m pytest -q
```

The release baseline currently passes 8 tests covering API behavior, email analysis, risk calculation and SSRF/security controls.

## Frontend

Run in an environment with the Node dependencies installed:

```bash
cd frontend
npm install
npm test
npm run build
```

Vite's production build is performed with `vite build`. The repository intentionally does not claim a verified frontend production build unless dependency installation and the build complete successfully.

## Docker

Build and run:

```bash
docker compose up --build
```

The container includes a health check against `/api/health`, runs as a non-root user, drops Linux capabilities and uses `no-new-privileges`.
