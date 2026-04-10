# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.17.1] - 2026-04-10

### Fixed

- Drop `re.escape()` from LogQL line filters. Python's `re.escape` injects backslashes before hyphens (e.g. `kube\-system`), which are invalid in LogQL Go-style string literals, causing namespace filters with hyphens to silently return 0 results.

## [0.17.0] - 2026-04-10

### Added

- fluent-bit support: Loki log lines wrapped in a `{"log": "..."}` JSON envelope are now automatically detected and unwrapped, so flows ingested via fluent-bit work out of the box alongside promtail.
- Default `--loki-query` changed from `{container="cilium-agent"}` (promtail) to `{app_kubernetes_io_name="cilium-agent"}` (fluent-bit). Promtail users can override with `--loki-query '{container="cilium-agent"}'`.

### Fixed

- Loki server-side line filters now use format-agnostic regex patterns (`verdict.{0,5}:.{0,5}AUDIT`) instead of literal JSON patterns (`"verdict":"AUDIT"`), so they match both promtail (plain quotes) and fluent-bit (escaped quotes) log formats.

## [0.13.0] - 2026-04-02

### Added

- Retry with exponential backoff for Loki chunk fetches: transient errors (timeouts, connection resets) are retried up to 3 times (1s, 2s, 4s delays) before giving up on a chunk.
- New `--loki-retries N` CLI flag to control the number of retries per chunk (default: 3, set to 0 to disable).
- Server-side verdict filter (`|= "\"verdict\":"`) is now always appended to Loki queries, reducing data transfer by filtering out non-flow cilium-agent log lines at the Loki level.
- Summary warning printed after Loki fetch when retries or chunk failures occurred, with hints to adjust `--loki-timeout` or `--loki-chunk`.
- Partial results from Loki are now flagged via `LokiResult.partial` when any chunk failed after exhausting retries.

## [0.7.6] - 2026-03-28

### Changed

- Rewrite README to clarify project motivation: overcome the 5-minute Hubble ring buffer limit using Loki for long-term flow history.
- Document zero-trust workflow: start from default-deny, filter on audit verdicts, and generate policies for the gaps.
- Promote Loki backend as the recommended flow source in Quick Start.
## [0.7.5] - 2026-03-28

### Fixed

- Fix `_ReconnectState` dataclass: promote `_DELAY_INIT` and `_DELAY_MAX` from instance fields to `ClassVar` so they no longer pollute `__init__`, `__eq__`, or `__repr__`.
- Fix thread-safety gap in `LiveFlowStore.suspend_capture()`: acquire lock when swapping `_capture_fh` to match lock discipline in `add()`.
- Fix `--capture-file` help text: replace incorrect "Append" wording with "Write" to match actual `"w"` (overwrite) behaviour.

### Changed

- CI lint and typecheck jobs now install from `.[dev]` instead of ad-hoc unpinned `pip install`, ensuring consistent tool versions across all CI jobs.
- Expand `.gitignore` with common Unix/Linux/IDE entries (vim swap files, `.idea/`, `.tox/`, `.coverage`, `Thumbs.db`, etc.).

### Added

- CLI integration tests (`tests/test_cli.py`): 14 new tests covering dry-run output, output-dir writes, single-file mode, report-only exit code, namespace/verdict filtering, empty/missing file exit codes, and all argument validation paths (134 total).

## [0.7.4] - 2026-03-28

### Fixed

- Catch `IndexError` and `KeyError` in `_cilium_endpoint_get` when Cilium returns an empty or unexpected response.

### Changed

- Add `Repository` URL to `pyproject.toml` project URLs.
- Remove `py.typed` marker and `package-data` config (ineffective for single-file module layout).

## [0.7.3] - 2026-03-28

### Fixed

- Add missing Loki auth flags (`--loki-user`, `--loki-password`, `--loki-token`, `--loki-tls-ca`) to README usage signature and flag reference table.
- Declare `py.typed` in `pyproject.toml` `[tool.setuptools.package-data]` so the marker is included in built distributions.

## [0.7.2] - 2026-03-28

### Changed

- Refactor watch mode: extract `_handle_key`, `_draw_header`, `_draw_content` helpers from 271-line nested `_run` function.
- Replace `reconnect_state` dict with `_ReconnectState` dataclass for type-safe reconnection state.
- Replace all Unicode symbols with ASCII equivalents throughout TUI and CLI output.

### Added

- Tests for `_dump_yaml`, `_write_multi_doc_yaml`, `_find_unknown_flows`, `_print_unknown_warnings`, `_print_summary`, `_trunc`, `_print_report`, `_ReconnectState`, and `_handle_key` (39 new tests, 120 total).
- Error-path tests for `_parse_duration` and `_read_flows`.

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
