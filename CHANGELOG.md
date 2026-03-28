# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.1] - 2026-03-28

### Fixed

- Use module logger (`LOG.debug`) instead of root `logging.debug` in `_detect_hubble_cmd`.
- Replace `assert` guards in reader threads with early-return checks (assertions are stripped under `python -O`).
- Guard `cursor_flow_idx` when `ordered_keys` is empty in watch select mode.
- Close capture file handle on early exit paths to prevent resource leak.
- Add missing `py.typed` marker file (referenced in CHANGELOG since v0.4.0 but never created).
- Add `types-PyYAML` to dev dependencies so local `mypy` works without manual installs.
- Add `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/` to `.gitignore`.

## [0.7.0] - 2026-03-27

### Added

- Loki authentication: Basic auth (`--loki-user` / `--loki-password`), Bearer token (`--loki-token`), and custom TLS CA certificate (`--loki-tls-ca`).
- Mutual exclusivity validation for `--loki-token` and `--loki-user`.

### Fixed

- Add missing `import urllib.error` (was resolved implicitly at runtime).

## [0.6.0] - 2026-03-27

### Changed

- Rewrite README to highlight live and Loki flow sources.

## [0.5.1] - 2026-03-26

### Fixed

- Fix `ruff format` violations in Loki test file.

## [0.5.0] - 2026-03-26

### Added

- Loki backend: query Hubble flows directly from a Grafana Loki instance with `--from loki --loki-url`.
- New flags: `--loki-query`, `--since`, `--until`, `--loki-limit` for controlling Loki queries.
- `parse_flows()` accepts an optional `flow_iter` keyword argument, decoupling flow ingestion from file I/O.
- Tests for duration parsing, Loki HTTP interaction (mocked), pagination, and end-to-end Loki-to-policy generation.

## [0.4.1] - 2026-03-21

### Changed

- Add "Intended Audience :: Developers" classifier to better target SREs and platform engineers.

## [0.4.0] - 2026-03-21

### Added

- Unit test suite covering helpers, flow parsing, policy construction, and file output.
- GitHub Actions CI workflow (lint, type-check, test on Python 3.10–3.12).
- `pyproject.toml` dev dependencies (`pytest`, `ruff`, `mypy`), tool configuration, and `py.typed` marker.

### Fixed

- Rename `hubble-audit2policy.py` to `hubble_audit2policy.py` — hyphens in filenames prevent Python module import, breaking the `pyproject.toml` entry point.

### Changed

- Update README examples to use the new `hubble_audit2policy.py` filename.

## [0.3.0] - 2026-03-21

### Changed

- Replace mutable-container workaround in watch mode with `nonlocal` for cleaner closure semantics.
- Extract shared `_write_policy_dir()` helper to deduplicate file-writing logic between watch mode and CLI.
- Move `_EXCLUDED_LABEL_PREFIXES` to module-level constant to avoid per-call tuple allocation.

## [0.2.0] - 2026-03-21

### Fixed

- Label key priority order in `_parse_identity_label` — keys are now matched in the documented priority order (`k8s:app` before `k8s:app.kubernetes.io/name`) regardless of label list ordering.
- Return type annotation for `_read_flows` (`Any` → `Iterator[tuple[int, dict[str, Any]]]`).

## [0.1.0] - 2026-03-21

### Added

- Initial release.
- Parse Hubble JSON flow logs (JSONL or JSON array) into per-workload CiliumNetworkPolicy YAML.
- Ingress and egress rule generation with port consolidation.
- Cluster enrichment via `cilium endpoint list` / `cilium endpoint get` for authoritative security labels.
- Multi-file, single-file, and dry-run output modes.
- Flow frequency report (`--report`, `--report-only`).
- Live watch mode with curses TUI, auto-reconnection, and interactive flow selection.
- Capture-and-replay workflow (`--capture-file`).
- Namespace and verdict filtering.
- Custom workload label key support (`--label-key`).
- Reserved Cilium identity handling (host, world, kube-apiserver, etc.).
- Directory traversal protection for output file paths.
