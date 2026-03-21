# hubble-audit2policy

Generate least-privilege [CiliumNetworkPolicy](https://docs.cilium.io/en/stable/security/policy/) YAML from [Hubble](https://github.com/cilium/hubble) flow logs.

Built for platform engineers, SREs, and security engineers who need to bootstrap or audit Kubernetes network policies from real observed traffic rather than guessing. Parses Hubble JSON flow logs (JSONL or JSON array) and produces per-workload CiliumNetworkPolicy files with ingress and egress rules. Supports offline file-based generation and a live watch mode with an interactive TUI.

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Capture flows with Hubble

```bash
# Single namespace:
hubble observe -P -n <namespace> --verdict AUDIT -o json -f > <namespace>-flows.json

# All namespaces:
hubble observe -P --all-namespaces --verdict AUDIT -o json -f > cluster-flows.json
```

### 2. Generate policies

```bash
# Write per-workload YAML files to a directory:
./hubble-audit2policy.py flows.json -o policies/

# Preview to stdout without writing files:
./hubble-audit2policy.py flows.json --dry-run

# Write all policies to a single multi-document YAML file:
./hubble-audit2policy.py flows.json --single-file policies/all.yaml

# Filter by namespace:
./hubble-audit2policy.py flows.json -n monitoring -n default -o policies/

# Print a flow frequency report:
./hubble-audit2policy.py flows.json --report
```

### 3. Live watch mode

Watch mode spawns `hubble observe` internally and continuously refreshes a flow-frequency report in a curses-based TUI. No separate terminal needed.

```bash
# All namespaces, auto-detect hubble:
./hubble-audit2policy.py --watch

# Single namespace, 5s refresh, rolling 2-minute window:
./hubble-audit2policy.py --watch -n default --interval 5 --window 120

# Seed from an existing file, then follow live:
./hubble-audit2policy.py flows.json --watch

# Custom hubble command (e.g. kubectl exec):
./hubble-audit2policy.py --watch --hubble-cmd 'kubectl exec -n kube-system cilium-xyz -- hubble observe'
```

Hubble is auto-detected: the `hubble` binary on PATH is tried first (with `-P` for port-forwarding), falling back to `kubectl exec` into a Cilium DaemonSet pod.

**Capture while watching** for later replay:

```bash
./hubble-audit2policy.py --watch --capture-file session.jsonl
./hubble-audit2policy.py session.jsonl -o policies/
```

**Interactive flow selection** — press `s` in watch mode to enter select mode, pick the flows you care about, then press `Enter` to generate policies from just those flows:

```bash
./hubble-audit2policy.py --watch --output-dir policies/
./hubble-audit2policy.py --watch --dry-run   # preview selected policies on stdout
```

#### Watch mode keys

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

## Cluster Enrichment

By default the tool queries `cilium endpoint list` and `cilium endpoint get` on each Cilium DaemonSet pod to resolve the authoritative security-relevant labels for every workload seen in the flows. This produces accurate `endpointSelector` and `matchLabels` in the generated policies instead of a simple `app` label fallback.

Requires `kubectl` access. Skip it when working offline:

```bash
./hubble-audit2policy.py flows.json -o policies/ --no-enrich
```

## Usage

```
hubble-audit2policy [-h] [-o OUTPUT_DIR] [-n NAMESPACE]
                    [--dry-run] [--single-file FILE]
                    [--verdict VERDICT] [--label-key LABEL_KEY]
                    [--report] [--report-only]
                    [-w] [--interval SECONDS] [--window SECONDS]
                    [--hubble-cmd CMD] [--capture-file FILE]
                    [--no-enrich] [-v] [-V]
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
| `-v, --verbose` | Enable verbose logging |
| `-V, --version` | Show version and exit |

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
