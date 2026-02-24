# dmark Improvement Backlog

This backlog tracks the execution plan for maintainability, reliability, and delivery quality.

## P0 (In Progress)

- [x] Protect output contracts with golden snapshots in tests.
- [x] Ensure golden fixtures are committed and fail-fast when missing.
- [x] Move large `DomainSummary.to_dict()` implementation out of `models.py` into a dedicated payload module.
- [x] Split inline web frontend into template/static assets.
- [x] Add upload-size clamp safeguards and regression tests.
- [x] Add bounded PST job retention (`--job-ttl-seconds`, `--max-jobs`) with cleanup behavior.
- [x] Add structured runtime logging for web analysis flows and PST job lifecycle.
- [x] Add dedicated CI workflow for pull requests and pushes (`tests`, `ruff`, targeted `mypy`).

## P1 (Next)

- [ ] Continue splitting `summary_payload.py` into focused builders:
  - sender inventory / source classification
  - score + readiness computations
  - payload assembly + response projection
- [x] Add schema-level compatibility test for domain payload keys (contract guard beyond snapshots).
- [x] Add integration tests for:
  - `/api/analyze-path` error branches and thresholds
  - `/api/analyze-upload` malformed/mixed payload cases
  - reporting auto-tuning behavior under large candidate sets
- [x] Add CLI integration tests for end-to-end `analyze` + `--json-out` behavior.

## P2 (Planned)

- [ ] Add request-level input validation helpers shared across web endpoints.
- [ ] Add API rate-limiting or request throttling safeguards for long-running web sessions.
- [ ] Add coverage reporting to CI and set an initial minimum threshold.
- [ ] Expand mypy scope module-by-module as type hints are tightened.
- [ ] Introduce structured log context IDs across CLI/reporting/web layers.
