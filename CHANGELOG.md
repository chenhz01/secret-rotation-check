# Changelog — secret-rotation-check

All notable changes. Format based on Keep a Changelog; versioning: SemVer.

## [0.1.1] - 2026-10-12

### Added
- Documentation layer: README (problem/how-it-works/quickstart with timing, why-not-X with real anchor citation, fallback plan, trade-offs, limits, FAQ, assumption register), ALIGNMENT.md (rules 85-100 audit), this CHANGELOG, and MIT LICENSE.

### Fixed
- `make_event` now validates the `rotated_at` date format at construction time (previously a malformed date like `01/01/2026` was accepted into the ledger and only surfaced later during `check`). Constructing events with invalid dates now raises `ValueError` immediately.
- `check_ledger` accepts a policy as a dict **or** a path to a JSON policy file (the CLI already passed a path; the library API now matches). Non-dict, non-path policies raise `ValueError` instead of `AttributeError`.
- Self-test repairs: A07's assertion contained a stray `.split` call on a dict, and C11 double-encoded its ledger fixture; both rewritten to test what their names promise.

### Changed
- Self-test suite now 55 cases (20 functional / 15 exception-CLI / 20 extreme-edge). Final run: `SUMMARY: PASS 55/55`.

## [0.1.0] - 2026-10-11

### Added
- JSONL append-only rotation ledger with sha256-derived 16-hex event hashes and GENESIS-rooted `prev_hash` chaining.
- `check` subcommand: overdue/expiring-soon (≥80% of budget) detection against a policy (global `default_max_age_days` + per-secret overrides), plus violation classes: bad action/date, missing owner, double create, out-of-order dates, events after retire.
- `verify` subcommand: full chain recomputation with `broken_link` / `bad_hash` reporting by event index.
- `add` subcommand: appends one event with a correctly chained hash.
- CLI exit-code discipline: 0 clean / 1 findings / 2 input error. Self-test suite: 55 cases across functional, exception/CLI, and extreme-edge tiers (500-secret ledgers, 1000-event chains, leap-day dates, unicode ids/owners, 200k-char owners).
