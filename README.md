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
- CLI and Docker workflow

## Security model

MailRecon is intended for **authorized defensive research and public-data investigations**. It does not retrieve passwords, bypass authentication, defeat CAPTCHAs, or access private accounts.

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

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL` if the API is not running at `http://127.0.0.1:8000/api`.

### Docker

```bash
docker compose up --build
```

## Optional providers

Copy `.env.example` to `.env` and configure only the services you want. HIBP and GitHub tokens are optional. Ollama is optional and remains local when enabled.

## Verification status

Backend verification currently includes:

- Python compile check
- **8 passing pytest tests**
- FastAPI health/security-header test
- Provider-state API test
- Demo investigation API test
- Risk endpoint
- Timeline endpoint
- Graph endpoint
- JSON/CSV/HTML/PDF report generation

The frontend source and test configuration are included, but a full production frontend build still requires a successful dependency installation in the target environment. The development environment used for this release could not complete `npm install` before its execution timeout, so the frontend build is **not falsely marked as verified**.

## Responsible use

Use MailRecon only against targets and data you are authorized to investigate. Public profile correlation is probabilistic. A missing result means only that the provider did not return a matching observation; it is not proof that an account, breach, or identity does not exist.
