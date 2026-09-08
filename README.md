# MailRecon

**Privacy-first Email Intelligence & OSINT Platform**

MailRecon is a local-first defensive investigation workspace for analyzing an email address using public information and legitimate provider APIs. It emphasizes **evidence provenance, provider transparency, explainable risk, and reproducible reports** rather than pretending that an OSINT hit is proof of identity.

## Core capabilities

- Email normalization, classification and username candidate generation
- Public DNS analysis: A/AAAA/MX/NS/CNAME, SPF, DMARC and DNSSEC signals
- RDAP domain intelligence
- Gravatar correlation
- GitHub public-profile correlation
- HIBP breach metadata integration when an API key is configured
- Optional local Ollama evidence-grounded summary
- Evidence records with source, confidence, severity and collection time
- Provider execution states: `ok`, `unconfigured`, `rate_limited`, `unavailable`, `error`
- Multidimensional risk model: identity, breach, domain security and public footprint
- Relationship graph and investigation timeline
- JSON, CSV, HTML and PDF reports
- Local SQLite persistence with privacy mode for reducing raw provider payload retention
- SSRF-conscious outbound URL validation and browser/API security headers
- Bearer API-key authentication for protected API endpoints
- CLI and Docker workflow

## Security model

MailRecon is intended for **authorized defensive research and public-data investigations**. It does not retrieve passwords, bypass authentication, defeat CAPTCHAs, or access private accounts.

Protected API endpoints require `MAILRECON_API_KEY`. The `/api/health` endpoint remains public for health checks. The browser UI accepts the key and stores it locally so the same build works with the local Docker deployment and a separately served development frontend. This is a single-user/local access-control mechanism, not multi-user authentication.

The application uses HTTPS-only outbound validation for generic external URLs, blocks non-public destinations, rejects URL userinfo, limits request bodies, and exposes explicit provider failure states. See `docs/security.md` and `SECURITY.md`.

## Risk model

The overall score is an explainable assessment, **not a probability of compromise**. Scores are composed from independently bounded dimensions:

- Identity exposure
- Breach exposure
- Domain security
- Public footprint

Every risk contribution is stored as a finding so an analyst can inspect *why* the score changed.

## Run locally

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Create `.env` from `.env.example` and set a strong `MAILRECON_API_KEY` before using protected endpoints.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` if the API is not running at `http://127.0.0.1:8000/api`. When the UI opens, enter the same `MAILRECON_API_KEY` configured for the backend.

### Docker

```bash
docker compose up --build
```

Docker binds port 8000 to localhost by default. Configure `MAILRECON_API_KEY` in `.env` before starting the container.

## Optional providers

Copy `.env.example` to `.env` and configure only the services you want. HIBP and GitHub tokens are optional. Ollama is optional and remains local when enabled.

## Verification status

The repository CI workflow verifies:

- backend pytest suite, including API authentication regression coverage;
- frontend unit tests;
- TypeScript compilation;
- production frontend build.

The Phase 1 authentication branch has passed both backend and frontend CI jobs. Keep the verification status tied to CI rather than claiming local-only checks that were not run.

## Responsible use

Use MailRecon only against targets and data you are authorized to investigate. Public profile correlation is probabilistic. A missing result means only that the provider did not return a matching observation; it is not proof that an account, breach, or identity does not exist.