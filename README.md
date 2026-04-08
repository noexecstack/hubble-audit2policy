# hubble-audit2policy

Generate least-privilege [CiliumNetworkPolicy](https://docs.cilium.io/en/stable/security/policy/) YAML from real observed traffic -- no enterprise license required.

## Why this exists

Cilium OSS gives you Hubble for flow observability, but it has a hard limit: Hubble keeps only 5 minutes of flows in its ring buffer before they are gone. There is no built-in way to look back over hours or days of traffic and generate network policies from what actually happened. Cisco's/Isovalent's enterprise offering, Timescape, fills that gap, but it requires an enterprise license.

This tool takes a different approach. If you are already shipping Hubble flows to Grafana Loki (or any log pipeline), you have a long-term record of every connection your workloads make. hubble-audit2policy queries that record and turns it into per-workload CiliumNetworkPolicy files with proper ingress and egress rules, enriched with real Cilium endpoint labels.

The key benefit is **capturing workload ground noise** -- the full picture of what your services actually talk to, including the traffic that only happens during UAT, development, cron jobs, nightly batches, cache warming, leader elections, or once-a-week reconciliation loops. With only a 5-minute ring buffer, you will never catch all of that by watching live. Loki keeps it all, and this tool reads it all back.

The typical workflow is to start from a zero-trust baseline (default-deny policies) and then use this tool filtered to audit verdicts only (`--verdict audit`) to see what traffic would be blocked. Those audit flows represent the gaps in your policy -- the legitimate connections that need to be allowed. hubble-audit2policy turns them directly into the CiliumNetworkPolicy rules that fill those gaps.

You get the same outcome as an enterprise policy-generation feature, using infrastructure you probably already run.

## How it works

1. Hubble flows get shipped to Loki (via fluentd, promtail, or whatever you use)
2. hubble-audit2policy queries Loki for flows over any time range you choose
3. It groups flows by workload, resolves real Cilium endpoint labels from the cluster, and writes one CiliumNetworkPolicy YAML per workload

It also works with live Hubble streams and plain JSON files if that is what you have, but the Loki backend is where the real value lives.

## Installation

```bash
pip install git+https://github.com/noexecstack/hubble-audit2policy.git
```

For development (includes pytest, ruff, mypy):

```bash
git clone https://github.com/noexecstack/hubble-audit2policy.git
cd hubble-audit2policy
pip install -e ".[dev]"
```

## Quick Start

### From Loki (recommended)

Query your existing log pipeline -- no port-forwarding, no time pressure, full history:

```bash
hubble-audit2policy --from loki --loki-url http://loki:3100 -o policies/
```

### Live from the cluster

Auto-detects Hubble, streams flows, shows an interactive TUI:

```bash
hubble-audit2policy --watch -o policies/
```

### From a file

If you already have exported flows:

```bash
hubble-audit2policy flows.json -o policies/
```

All three produce the same output: one CiliumNetworkPolicy YAML per workload.

### Common options

```bash
# Preview policies on stdout without writing files:
hubble-audit2policy --from loki --loki-url http://loki:3100 --dry-run

# Write all policies into a single multi-document YAML:
hubble-audit2policy --from loki --loki-url http://loki:3100 --single-file policies/all.yaml

# Scope to specific namespaces:
hubble-audit2policy --from loki --loki-url http://loki:3100 -n monitoring -n default -o policies/

# Custom time window -- last 24 hours:
hubble-audit2policy --from loki --loki-url http://loki:3100 --since 24h -o policies/

# Print a flow frequency report (works with any source):
hubble-audit2policy --from loki --loki-url http://loki:3100 --report
hubble-audit2policy flows.json --report-only
```

## Loki Backend

Query a Grafana Loki instance directly -- ideal when Hubble flows are already being shipped to Loki via fluentd, promtail, or another collector.

The default LogQL selector is `{container="cilium-agent"}`, which matches the standard Cilium agent container label. Override it with `--loki-query` if your setup uses different labels.

```bash
# All flows from the last hour (uses default query {container="cilium-agent"}):
hubble-audit2policy --from loki --loki-url http://loki:3100 --dry-run

# Scoped to a namespace with a custom time window:
hubble-audit2policy --from loki --loki-url http://loki:3100 --since 2h --until 30m -n kube-system -o policies/

# Custom LogQL selector (adjust to match your labels):
hubble-audit2policy --from loki --loki-url http://loki:3100 --loki-query '{namespace="hubble"}'

# Interactive TUI for browsing and selecting Loki flows:
hubble-audit2policy --from loki --loki-url http://loki:3100 --watch
```

### Loki authentication

```bash
# Bearer token (e.g. Grafana Cloud):
hubble-audit2policy --from loki --loki-url https://loki.example.com --loki-token "$LOKI_TOKEN"

# HTTP Basic auth:
hubble-audit2policy --from loki --loki-url https://loki.example.com --loki-user admin --loki-password secret

# Multi-tenant Loki (auth_enabled=true) -- sends the X-Scope-OrgID header:
hubble-audit2policy --from loki --loki-url http://loki:3100 --loki-org-id my-tenant

# Self-signed TLS certificate:
hubble-audit2policy --from loki --loki-url https://loki.internal:3100 --loki-tls-ca /path/to/ca.pem
```

All existing filters (`-n`, `--verdict`, `--label-key`, `--report`, etc.) work identically with the Loki backend.

## Live Watch Mode

Watch mode presents an interactive curses-based TUI with a continuously refreshed flow-frequency report. It works with both live Hubble streams and historical Loki data:

- **Live** (default): spawns `hubble observe` internally, no separate terminal needed.
- **Loki** (`--from loki --watch`): fetches historical flows from Loki and presents them in the same TUI for browsing and selection.

For live mode, just run:

```bash
hubble-audit2policy --watch
```

Hubble is auto-detected: the `hubble` binary on PATH is tried first (with `-P` for port-forwarding), falling back to `kubectl exec` into a Cilium DaemonSet pod.

### Useful watch options

```bash
# Single namespace, 5s refresh, rolling 2-minute window:
hubble-audit2policy --watch -n default --interval 5 --window 120

# Seed from an existing file, then follow live:
hubble-audit2policy flows.json --watch

# Custom hubble command (e.g. kubectl exec):
hubble-audit2policy --watch --hubble-cmd 'kubectl exec -n kube-system cilium-xyz -- hubble observe'
```

### Capture and replay

Record live flows for later replay or sharing:

```bash
hubble-audit2policy --watch --capture-file session.jsonl
hubble-audit2policy session.jsonl -o policies/
```

### Interactive flow selection

Press `s` in watch mode to enter select mode, pick the flows you care about, then press `Enter` to generate policies from just those flows:

```bash
hubble-audit2policy --watch --output-dir policies/
hubble-audit2policy --watch --dry-run   # preview selected policies on stdout
```

### Watch mode keys

| Key | Action |
|-----|--------|
| `j/down`, `k/up` | Scroll down / up one line |
| `d/PgDn`, `u/PgUp` | Scroll half a page |
| `g/Home`, `G/End` | Jump to top / bottom |
| `Space` | Pause/resume (normal); toggle selection (select mode) |
| `s` | Enter / exit flow-selection mode |
| `Enter` | Generate policies from selected flows and quit |
| `Esc` | Exit select mode and clear selections |
| `q / Ctrl-C` | Quit (last report is printed to the terminal) |

## Supported Flow Formats

The tool accepts Hubble flows in two formats:

- **Flat flow objects** -- the standard JSONL output from `hubble observe -o json`, where each line is a flow dict with `source`, `destination`, `l4`, etc. at the top level.
- **Envelope format** (`{"flow": {...}}`) -- used by Hubble dynamic exports configured via the Cilium configmap (`hubble.export.*`). The envelope is automatically unwrapped.

Both formats work with all backends (file, Loki, live watch).

## Cluster Enrichment

By default the tool queries `cilium endpoint list` and `cilium endpoint get` on each Cilium DaemonSet pod to resolve the authoritative security-relevant labels for every workload seen in the flows. This produces accurate `endpointSelector` and `matchLabels` in the generated policies instead of a simple `app` label fallback.

Requires `kubectl` access. Skip it when working offline:

```bash
hubble-audit2policy flows.json -o policies/ --no-enrich
```

## Full Flag Reference

```
hubble-audit2policy [-h] [-o OUTPUT_DIR] [-n NAMESPACE]
                    [--dry-run] [--single-file FILE]
                    [--verdict VERDICT] [--label-key LABEL_KEY]
                    [--report] [--report-only]
                    [-w] [--interval SECONDS] [--window SECONDS]
                    [--hubble-cmd CMD] [--capture-file FILE]
                    [--no-enrich]
                    [--from {file,loki}] [--loki-url URL]
                    [--loki-query LOGQL] [--since DURATION]
                    [--until DURATION] [--loki-limit N]
                    [--loki-user USER] [--loki-password PASSWORD]
                    [--loki-token TOKEN] [--loki-tls-ca PATH]
                    [--loki-org-id ORG_ID] [--loki-threads N]
                    [--loki-chunk DURATION] [--loki-timeout SECONDS]
                    [-v] [-V]
                    [flows_file]
```

| Flag | Description |
|------|-------------|
| `-o, --output-dir` | Directory to write policy YAML files (default: `.`) |
| `-n, --namespace` | Only generate policies for this namespace (repeatable) |
| `--dry-run` | Print policies to stdout instead of writing files |
| `--single-file FILE` | Write all policies to a single YAML file |
| `--verdict VERDICT` | Only include flows with this verdict (repeatable) |
| `--label-key KEY` | Label key to identify workloads (repeatable; default: `k8s:app`, `k8s:app.kubernetes.io/name`) |
| `--report` | Print a flow frequency report to stderr |
| `--report-only` | Print the flow report and exit without generating policies |
| `-w, --watch` | Live monitoring mode with interactive TUI |
| `--interval SECONDS` | Screen refresh interval for watch mode (default: `2.0`) |
| `--window SECONDS` | Rolling time window for watch mode; `0` keeps all flows (default: `0`) |
| `--hubble-cmd CMD` | Override the hubble observe command for watch mode |
| `--capture-file FILE` | Record all watch-mode flows to FILE as JSONL for later replay |
| `--no-enrich` | Skip live cluster enrichment via Cilium endpoints |
| `--from {file,loki}` | Flow source backend (default: `file`) |
| `--loki-url URL` | Loki base URL, e.g. `http://loki:3100` |
| `--loki-query LOGQL` | LogQL stream selector (default: `{container="cilium-agent"}`) |
| `--since DURATION` | How far back to query, e.g. `30m`, `2h`, `1d` (default: `1h`) |
| `--until DURATION` | End of query window as duration before now (default: `0s` = now) |
| `--loki-limit N` | Max entries per Loki request batch (default: `5000`) |
| `--loki-user USER` | Username for Loki HTTP Basic authentication |
| `--loki-password PASSWORD` | Password for Loki HTTP Basic authentication (used with `--loki-user`) |
| `--loki-token TOKEN` | Bearer token for Loki (`Authorization: Bearer ...`) header |
| `--loki-tls-ca PATH` | Path to a PEM CA certificate for verifying the Loki server (self-signed certs) |
| `--loki-org-id ORG_ID` | Tenant ID sent as `X-Scope-OrgID` header (required when Loki `auth_enabled=true`) |
| `--loki-threads N` | Number of parallel worker threads for Loki queries (default: `4`) |
| `--loki-chunk DURATION` | Max time window per Loki request, e.g. `5s`, `30s`, `1m` (default: auto-scaled to ~200 chunks, min `1m`) |
| `--loki-timeout SECONDS` | HTTP request timeout in seconds for each Loki request (default: `30`) |
| `-v, --verbose` | Enable verbose logging |
| `-V, --version` | Show version and exit |

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
