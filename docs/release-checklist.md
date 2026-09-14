# Release Checklist

Use this checklist for a portfolio/release snapshot. The GitHub Actions workflow and the exact release commit are authoritative.

## Verification

- [ ] Confirm the intended release commit is the current `main` HEAD.
- [ ] Confirm the complete GitHub Actions workflow is green for that exact commit.
- [ ] Confirm backend tests and dependency audit are green.
- [ ] Confirm frontend tests, lint, TypeScript and production build are green.
- [ ] Confirm Gitleaks, CodeQL/SAST, container scanning and workflow-security checks are green.

## Functional demonstration

- [ ] Create an authorized investigation.
- [ ] Show provider configuration and external-provider disclosure state.
- [ ] Execute the investigation and show provider execution outcomes.
- [ ] Open findings and demonstrate source/provenance/evidence state.
- [ ] Open the explainable risk view and show contributing findings.
- [ ] Open the relationship graph and investigation timeline.
- [ ] Run a second attempt and demonstrate execution history/comparison.
- [ ] Export at least one report format.
- [ ] Demonstrate deletion of the local investigation when finished.

## Portfolio presentation

- [ ] README opens with the project purpose and strongest engineering differentiators.
- [ ] README includes the architecture diagram and security model.
- [ ] README links to testing, architecture, security and release documentation.
- [ ] Add real application screenshots only after capturing them from the verified build; never use fabricated UI images.
- [ ] Keep screenshots focused on investigation flow, provider transparency, evidence, risk, graph/timeline and attempt comparison.
- [ ] Keep demo data synthetic or otherwise authorized; never publish real sensitive investigation data.

## Release discipline

- [ ] Do not describe provider failures or missing results as proof of absence.
- [ ] Do not publish API keys, provider credentials or raw sensitive evidence.
- [ ] Tie release claims to the exact green CI commit.
- [ ] Record the final `main` SHA and CI run used for the portfolio snapshot.
