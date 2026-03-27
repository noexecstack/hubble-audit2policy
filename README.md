# hubble-audit2policy

Generate least-privilege [CiliumNetworkPolicy](https://docs.cilium.io/en/stable/security/policy/) YAML from observed Hubble traffic -- no manual flow capture required.

Point it at your cluster and get policies. The tool connects to [Hubble](https://github.com/cilium/hubble) directly, queries [Grafana Loki](https://grafana.com/oss/loki/), or reads a file you already have. It produces per-workload CiliumNetworkPolicy files with ingress and egress rules, enriched with real Cilium endpoint labels.

Built for platform engineers, SREs, and security engineers who need to bootstrap or audit Kubernetes network policies from real observed traffic rather than guessing.

## Installation

```bash
pip install hubble-audit2policy
```

For development (includes pytest, ruff, mypy):

```bash
pip install -e ".[dev]"
```

## Quick Start

### One command, three ways to get flows

Pick whichever fits your setup -- the tool handles the rest:

**Live from the cluster** -- auto-detects Hubble, streams flows, shows an interactive TUI:

```bash
hubble-audit2policy --watch -o policies/
```

**From Grafana Loki** -- queries your existing log pipeline, no port-forwarding needed:

```bash
hubble-audit2policy --from loki --loki-url http://loki:3100 -o policies/
```

**From a file** -- if you already have exported flows:

```bash
hubble-audit2policy flows.json -o policies/
```

All three produce the same output: one CiliumNetworkPolicy YAML per workload.

### Common options

```bash
# Preview policies on stdout without writing files:
hubble-audit2policy --watch --dry-run

# Write all policies into a single multi-document YAML:
hubble-audit2policy --from loki --loki-url http://loki:3100 --single-file policies/all.yaml

# Scope to specific namespaces:
hubble-audit2policy --watch -n monitoring -n default -o policies/

# Print a flow frequency report (works with any source):
hubble-audit2policy --watch --report
hubble-audit2policy flows.json --report-only
```

## Live Watch Mode

Watch mode spawns `hubble observe` internally and continuously refreshes a flow-frequency report in a curses-based TUI. No separate terminal or manual capture needed -- just run:

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
| `j/↓`, `k/↑` | Scroll down / up one line |
| `d/PgDn`, `u/PgUp` | Scroll half a page |
| `g/Home`, `G/End` | Jump to top / bottom |
| `Space` | Pause/resume (normal); toggle selection (select mode) |
| `s` | Enter / exit flow-selection mode |
| `Enter` | Generate policies from selected flows and quit |
| `Esc` | Exit select mode and clear selections |
| `q / Ctrl-C` | Quit (last report is printed to the terminal) |

## Loki Backend

Query a Grafana Loki instance directly -- ideal when Hubble flows are already being shipped to Loki via fluentd or another collector:

```bash
# All flows from the last hour:
hubble-audit2policy --from loki --loki-url http://loki:3100 --dry-run

# Scoped to a namespace with a custom time window:
hubble-audit2policy --from loki --loki-url http://loki:3100 --since 2h --until 30m -n kube-system -o policies/

# Custom LogQL selector (adjust to match your labels):
hubble-audit2policy --from loki --loki-url http://loki:3100 --loki-query '{namespace="hubble"}'
```

All existing filters (`-n`, `--verdict`, `--label-key`, `--report`, etc.) work identically with the Loki backend.

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
| `--loki-query LOGQL` | LogQL stream selector (default: `{app="hubble"}`) |
| `--since DURATION` | How far back to query, e.g. `30m`, `2h`, `1d` (default: `1h`) |
| `--until DURATION` | End of query window as duration before now (default: `0s` = now) |
| `--loki-limit N` | Max entries per Loki request batch (default: `5000`) |
| `-v, --verbose` | Enable verbose logging |
| `-V, --version` | Show version and exit |

## License

Apache-2.0 -- see [LICENSE](LICENSE) for details.
