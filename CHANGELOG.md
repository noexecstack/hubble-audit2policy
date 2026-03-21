# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
