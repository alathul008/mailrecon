# MailRecon v1.0.0 Release Checklist

Release gate for the final v1.0 commit.

## Source and build

- [ ] Exact release main SHA verified
- [ ] Frontend `npm ci` succeeds
- [ ] Frontend tests, lint, type-check and production build succeed
- [ ] Backend dependencies install from `requirements.lock`
- [ ] Backend test suite succeeds
- [ ] Dependency audit succeeds

## Security

- [ ] CodeQL/SAST green
- [ ] Secret scan green
- [ ] Workflow security/Zizmor green
- [ ] Container scan green with no release-blocking findings
- [ ] No accidental secrets or sensitive configuration in release artifacts

## Runtime and Docker

- [ ] Docker production image builds from pinned base-image digests
- [ ] Compose publishes port 8000 on localhost by default
- [ ] Container runs without unnecessary privileges
- [ ] Health endpoint succeeds
- [ ] Backend startup and database initialization succeed

## Product smoke test

- [ ] Authentication and protected endpoints verified
- [ ] Email investigation created with safe test data
- [ ] Email OSINT execution completes or reports provider states correctly
- [ ] Evidence and provenance verified
- [ ] Risk verified
- [ ] Correlations verified as qualified/derived, not identity confirmation
- [ ] Graph and timeline verified
- [ ] Analyst briefing verified
- [ ] JSON/CSV/HTML/PDF reports verified
- [ ] Investigation comparison verified where applicable
- [ ] Investigation deletion verified
- [ ] Late/stale execution cannot resurrect deleted investigation

## Documentation and release

- [ ] README matches implementation
- [ ] SECURITY documentation matches implementation
- [ ] `.env.example` matches configuration behavior
- [ ] Version/changelog metadata is consistent
- [ ] Release notes describe only shipped capabilities
- [ ] Accepted limitations are documented
- [ ] Release tag/release points to the intended final main commit

## Final decision

V1.0 STATUS: **READY** only when all required release gates above are verified and no P0/P1 blocker remains.
