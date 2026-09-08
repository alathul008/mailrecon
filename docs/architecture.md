# Architecture

MailRecon is split into a React frontend, FastAPI service layer, provider modules, OSINT analyzers, risk engine, report renderer, and SQLite persistence.

The orchestrator executes independent providers concurrently. A provider error is recorded as a module failure/unavailable state rather than aborting the whole investigation.

Core flow: input validation → local parsing → DNS/domain analysis → public provider collection → normalization → risk scoring → graph construction → report export.
