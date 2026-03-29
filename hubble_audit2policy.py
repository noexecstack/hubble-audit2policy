#!/usr/bin/env python3
"""Generate CiliumNetworkPolicy from Hubble AUDIT flows.

Parses Hubble JSON flow logs and produces per-workload
CiliumNetworkPolicy YAML files with least-privilege rules
derived from observed traffic.
"""

from __future__ import annotations

__version__ = "0.9.0"
__author__ = "noexecstack"
__license__ = "Apache-2.0"

import argparse
import base64
import curses
import dataclasses
import io
import json
import logging
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import IO, Any, ClassVar, cast

import yaml

LOG = logging.getLogger("hubble-audit2policy")

# Type aliases for readability.
RuleTuple = tuple[str, str, int, str]  # (ns, app, port, proto)
RuleSet = dict[str, set[RuleTuple]]  # {"egress": {...}, "ingress": {...}}
PolicyKey = tuple[str, str]  # (namespace, app)
FlowKey = tuple[str, str, str, str, int, str]  # (src_ns, src_app, dst_ns, dst_app, port, proto)
EndpointLabelCache = dict[tuple[str, str], list[str]]  # (ns, pod) -> security labels
WorkloadLabels = dict[PolicyKey, dict[str, str]]  # (ns, app) -> matchLabels
AppPods = dict[PolicyKey, set[tuple[str, str]]]  # (ns, app) -> {(ns, pod)}

# Return type shared by parse_flows() and _parse_flow_list().
ParseResult = tuple[
    dict[PolicyKey, RuleSet],
    Counter[FlowKey],
    int,
    int,
    AppPods,
]

# Exit codes
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NO_POLICIES = 2

# Label prefixes searched in priority order to identify workloads.
DEFAULT_LABEL_KEYS = [
    "k8s:app",
    "k8s:app.kubernetes.io/name",
]

# Reserved Cilium identities mapped to their CiliumNetworkPolicy entity names.
RESERVED_IDENTITY_ENTITIES: dict[str, str] = {
    "reserved:host": "host",
    "reserved:world": "world",
    "reserved:unmanaged": "unmanaged",
    "reserved:health": "health",
    "reserved:init": "init",
    "reserved:remote-node": "remote-node",
    "reserved:kube-apiserver": "kube-apiserver",
    "reserved:ingress": "ingress",
}

# Label prefixes excluded when converting Cilium security labels to matchLabels.
_EXCLUDED_LABEL_PREFIXES = (
    "k8s:io.cilium.k8s.namespace.labels.",
    "k8s:io.cilium.k8s.policy.cluster=",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sanitize_name(value: str | None) -> str:
    """Return a filename-safe version of *value* (alphanumeric, hyphens, dots)."""
    return re.sub(r"[^a-zA-Z0-9\-.]", "", value or "")


def _parse_identity_label(labels: list[str] | None, label_keys: list[str]) -> str | None:
    """Return the first matching identity label value, or *None*.

    *label_keys* are searched in priority order: the first key that matches
    any label wins, regardless of label list ordering.
    """
    for key in label_keys:
        prefix = key + "="
        for label in labels or []:
            if label.startswith(prefix):
                return label.split("=", 1)[1]
    return None


def _parse_reserved_identity(labels: list[str] | None) -> str | None:
    """Return the Cilium entity name if *labels* contain a reserved identity."""
    for label in labels or []:
        if label in RESERVED_IDENTITY_ENTITIES:
            return RESERVED_IDENTITY_ENTITIES[label]
    return None


# ---------------------------------------------------------------------------
# Cluster enrichment – query Cilium for real endpoint labels
# ---------------------------------------------------------------------------


def _run_kubectl(*args: str, timeout: int = 30) -> bytes:
    """Run ``kubectl`` and return stdout bytes.  Raises ``RuntimeError`` on failure."""
    try:
        result = subprocess.run(
            ["kubectl", *args],
            capture_output=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("kubectl not found in PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"kubectl {' '.join(args)} timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"kubectl {' '.join(args)} exited {result.returncode}: "
            f"{result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def _build_pod_node_map() -> dict[tuple[str, str], str]:
    """Return ``{(namespace, pod_name): node_name}`` for all pods in one kubectl call."""
    raw = _run_kubectl("get", "pods", "--all-namespaces", "-o", "json")
    data = json.loads(raw)
    mapping: dict[tuple[str, str], str] = {}
    for pod in data.get("items", []):
        ns = pod["metadata"].get("namespace", "")
        name = pod["metadata"].get("name", "")
        node = pod["spec"].get("nodeName", "")
        if ns and name and node:
            mapping[(ns, name)] = node
    return mapping


def _build_cilium_node_map() -> dict[str, str]:
    """Return ``{node_name: cilium_pod_name}`` from the cilium DaemonSet pods."""
    raw = _run_kubectl(
        "get",
        "pods",
        "-n",
        "kube-system",
        "-l",
        "k8s-app=cilium",
        "-o",
        "json",
    )
    data = json.loads(raw)
    mapping: dict[str, str] = {}
    for pod in data.get("items", []):
        node = pod["spec"].get("nodeName", "")
        name = pod["metadata"].get("name", "")
        if node and name:
            mapping[node] = name
    return mapping


def _cilium_endpoint_list(cilium_pod: str) -> list[dict[str, Any]]:
    """Run ``cilium endpoint list -o json`` on *cilium_pod* and return parsed list."""
    try:
        raw = _run_kubectl(
            "exec",
            "-n",
            "kube-system",
            cilium_pod,
            "--",
            "cilium",
            "endpoint",
            "list",
            "-o",
            "json",
            timeout=60,
        )
        result: list[dict[str, Any]] = json.loads(raw)
        return result
    except (RuntimeError, json.JSONDecodeError) as exc:
        LOG.warning("cilium endpoint list failed on %s: %s", cilium_pod, exc)
        return []


def _cilium_endpoint_get(cilium_pod: str, endpoint_id: int) -> dict[str, Any] | None:
    """Run ``cilium endpoint get <id> -o json`` and return the endpoint object."""
    try:
        raw = _run_kubectl(
            "exec",
            "-n",
            "kube-system",
            cilium_pod,
            "--",
            "cilium",
            "endpoint",
            "get",
            str(endpoint_id),
            "-o",
            "json",
            timeout=30,
        )
        data: Any = json.loads(raw)
        ep: dict[str, Any] = cast(dict[str, Any], data[0] if isinstance(data, list) else data)
        return ep
    except (RuntimeError, json.JSONDecodeError, IndexError, KeyError) as exc:
        LOG.warning("cilium endpoint get %d failed on %s: %s", endpoint_id, cilium_pod, exc)
        return None


def _security_labels_to_match_labels(security_labels: list[str]) -> dict[str, str]:
    """Convert Cilium ``security-relevant`` labels to ``matchLabels`` entries.

    Excluded:
    * ``k8s:io.cilium.k8s.namespace.labels.*`` – derived from Namespace labels
    * ``k8s:io.cilium.k8s.policy.cluster=*``   – cluster-scoped, redundant

    The ``k8s:`` source prefix is stripped; Cilium adds it back automatically
    when evaluating ``matchLabels`` on Kubernetes endpoints.
    """
    result: dict[str, str] = {}
    for lbl in security_labels:
        if any(lbl.startswith(p) for p in _EXCLUDED_LABEL_PREFIXES):
            continue
        if lbl.startswith("reserved:"):
            continue
        raw = lbl.removeprefix("k8s:")
        if "=" not in raw:
            continue
        key, val = raw.split("=", 1)
        result[key] = val
    return result


def build_endpoint_label_cache(pods: set[tuple[str, str]]) -> EndpointLabelCache:
    """Query Cilium for the authoritative ``security-relevant`` labels of each pod.

    For every ``(namespace, pod_name)`` pair the algorithm:

    1. Resolves the pod's node with a single ``kubectl get pods --all-namespaces``.
    2. Finds the Cilium DaemonSet pod running on that node.
    3. Runs ``cilium endpoint list`` on that Cilium pod to locate the endpoint ID.
    4. Runs ``cilium endpoint get <id>`` to retrieve the precise label set.

    Returns ``{(namespace, pod_name): security_relevant_labels}``.
    Failures are logged as warnings; the cache is returned partially populated
    rather than raising an exception.
    """
    if not pods:
        return {}

    LOG.info("Building endpoint label cache for %d pod(s) …", len(pods))
    try:
        pod_node_map = _build_pod_node_map()
        cilium_node_map = _build_cilium_node_map()
    except RuntimeError as exc:
        LOG.warning("Cluster enrichment skipped: %s", exc)
        return {}

    if not cilium_node_map:
        LOG.warning("No Cilium DaemonSet pods found; cluster enrichment skipped.")
        return {}

    # Group target pods by the cilium pod that manages them for batching.
    cilium_to_pods: dict[str, list[tuple[str, str]]] = {}
    for ns, pod_name in pods:
        node = pod_node_map.get((ns, pod_name))
        if node is None:
            LOG.warning("Node not found for %s/%s; skipping.", ns, pod_name)
            continue
        cilium_pod = cilium_node_map.get(node)
        if cilium_pod is None:
            LOG.warning("No Cilium pod on node %s for %s/%s; skipping.", node, ns, pod_name)
            continue
        cilium_to_pods.setdefault(cilium_pod, []).append((ns, pod_name))

    cache: EndpointLabelCache = {}
    for cilium_pod, target_pods in sorted(cilium_to_pods.items()):
        LOG.info("Querying %s (hosts %d target pod(s)) …", cilium_pod, len(target_pods))

        # Step 3: one 'cilium endpoint list' per Cilium pod.
        ep_list = _cilium_endpoint_list(cilium_pod)
        if not ep_list:
            continue

        # Build (k8s-namespace, k8s-pod-name) -> endpoint_id index.
        ep_id_index: dict[tuple[str, str], int] = {}
        for ep in ep_list:
            status: dict[str, Any] = ep.get("status", {})
            ext: dict[str, Any] = status.get("external-identifiers", {})
            ep_ns: str = ext.get("k8s-namespace", "")
            ep_pod: str = ext.get("k8s-pod-name", "")
            if ep_ns and ep_pod:
                ep_id_index[(ep_ns, ep_pod)] = ep["id"]

        for ns, pod_name in target_pods:
            ep_id = ep_id_index.get((ns, pod_name))
            if ep_id is None:
                LOG.warning(
                    "Endpoint for %s/%s not found in cilium endpoint list on %s; skipping.",
                    ns,
                    pod_name,
                    cilium_pod,
                )
                continue

            LOG.info(
                "  %s/%s → endpoint %d; fetching labels via cilium endpoint get …",
                ns,
                pod_name,
                ep_id,
            )

            # Step 4: precise label fetch via 'cilium endpoint get <id>'.
            detail = _cilium_endpoint_get(cilium_pod, ep_id)
            if detail is None:
                continue

            detail_status: dict[str, Any] = detail.get("status", {})
            detail_labels: dict[str, Any] = detail_status.get("labels", {})
            labels: list[str] = detail_labels.get("security-relevant", [])
            if labels:
                cache[(ns, pod_name)] = labels
                LOG.debug("  Labels for %s/%s: %s", ns, pod_name, labels)
            else:
                LOG.warning(
                    "No security-relevant labels for %s/%s (endpoint %d).",
                    ns,
                    pod_name,
                    ep_id,
                )

    LOG.info("Endpoint label cache: %d/%d pod(s) resolved.", len(cache), len(pods))
    return cache


# ---------------------------------------------------------------------------
# Flow parsing
# ---------------------------------------------------------------------------


def _read_flows(path: str) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield *(lineno, flow_dict)* from a JSONL file or a JSON-array file."""
    with open(path, encoding="utf-8") as f:
        # Peek at the first non-whitespace character to detect format.
        first_char = None
        while True:
            ch = f.read(1)
            if not ch:
                return
            if not ch.isspace():
                first_char = ch
                break
        f.seek(0)

        if first_char == "[":
            try:
                flows = json.load(f)
            except json.JSONDecodeError as exc:
                LOG.error("Failed to parse JSON array: %s", exc)
                return
            yield from enumerate(flows, 1)
        else:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield lineno, json.loads(line)
                except json.JSONDecodeError as exc:
                    LOG.warning("Skipping malformed JSON on line %d: %s", lineno, exc)


def _parse_duration(value: str) -> float:
    """Parse a human-friendly duration string into seconds.

    Accepted formats: ``30s``, ``5m``, ``2h``, ``1d``, plain seconds (``3600``).
    """
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd])?", value.strip())
    if not match:
        raise argparse.ArgumentTypeError(
            f"Invalid duration {value!r} — expected e.g. 30s, 5m, 2h, 1d"
        )
    num = float(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return num * multipliers[unit]


def _build_loki_ssl_context(
    ca_cert: str | None = None,
) -> ssl.SSLContext | None:
    """Return an SSL context for Loki requests, or *None* for defaults.

    Parameters
    ----------
    ca_cert:
        Path to a PEM-encoded CA certificate file for verifying the
        Loki server certificate (useful for self-signed certs).
    """
    if not ca_cert:
        return None
    ctx = ssl.create_default_context(cafile=ca_cert)
    return ctx


def _read_flows_loki(
    loki_url: str,
    query: str,
    since_seconds: float,
    until_seconds: float,
    limit: int = 5000,
    *,
    loki_user: str | None = None,
    loki_password: str | None = None,
    loki_token: str | None = None,
    loki_tls_ca: str | None = None,
) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield *(lineno, flow_dict)* by querying a Loki instance.

    Parameters
    ----------
    loki_url:
        Base URL of the Loki instance, e.g. ``http://loki:3100``.
    query:
        LogQL stream selector, e.g. ``{app="hubble"}``.
    since_seconds:
        Start of the query window as seconds before *now*.
    until_seconds:
        End of the query window as seconds before *now* (0 = now).
    limit:
        Maximum number of log entries per request batch.
    loki_user:
        Username for HTTP Basic authentication.
    loki_password:
        Password for HTTP Basic authentication.
    loki_token:
        Bearer token for ``Authorization: Bearer ...`` header.
    loki_tls_ca:
        Path to a PEM CA certificate for TLS verification.
    """
    now = time.time()
    start_ns = int((now - since_seconds) * 1_000_000_000)
    end_ns = int((now - until_seconds) * 1_000_000_000)

    base = loki_url.rstrip("/")
    fetched = 0

    # Build auth header (if any).
    headers: dict[str, str] = {"Accept": "application/json"}
    if loki_token:
        headers["Authorization"] = f"Bearer {loki_token}"
    elif loki_user:
        cred = base64.b64encode(f"{loki_user}:{loki_password or ''}".encode()).decode("ascii")
        headers["Authorization"] = f"Basic {cred}"

    ssl_ctx = _build_loki_ssl_context(loki_tls_ca)

    while True:
        params = urllib.parse.urlencode(
            {
                "query": query,
                "start": str(start_ns),
                "end": str(end_ns),
                "limit": str(limit),
                "direction": "FORWARD",
            }
        )
        url = f"{base}/loki/api/v1/query_range?{params}"
        LOG.debug("Loki request: %s", url)

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30, context=ssl_ctx) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            LOG.error("Failed to query Loki at %s: %s", loki_url, exc)
            return

        status = body.get("status")
        if status != "success":
            LOG.error("Loki query failed (status=%s): %s", status, body)
            return

        streams = body.get("data", {}).get("result", [])
        batch_count = 0
        last_ts: int | None = None

        for stream in streams:
            for ts_str, line in stream.get("values", []):
                fetched += 1
                batch_count += 1
                last_ts = int(ts_str)
                line = line.strip()
                if not line:
                    continue
                try:
                    yield fetched, json.loads(line)
                except json.JSONDecodeError as exc:
                    LOG.warning("Skipping malformed JSON from Loki (entry %d): %s", fetched, exc)

        # If we got fewer entries than the limit, we've exhausted the range.
        if batch_count < limit:
            break

        # Otherwise paginate forward: start just after the last timestamp.
        if last_ts is not None:
            start_ns = last_ts + 1
        else:
            break

    LOG.debug("Fetched %d log entries from Loki", fetched)


def parse_flows(
    path: str,
    label_keys: list[str],
    verdicts: set[str],
    namespaces: set[str],
    *,
    flow_iter: Iterator[tuple[int, dict[str, Any]]] | None = None,
) -> ParseResult:
    """Parse Hubble flows into per-workload rule sets.

    Returns a ``ParseResult`` tuple of:
        policies    - dict[(namespace, app)] -> {"egress": set, "ingress": set}
        flow_counts - Counter keyed by (src_ns, src_app, dst_ns, dst_app, port, proto)
        total       - total flow count
        matched     - flows that contributed at least one rule
        app_pods    - dict[(namespace, app)] -> {(namespace, pod_name)} seen in flows
                      (covers both policy subjects and their peers; used for cluster
                      enrichment to look up real Cilium endpoint labels)
    """
    policies: defaultdict[PolicyKey, RuleSet] = defaultdict(
        lambda: {"egress": set(), "ingress": set()}
    )
    flow_counts: Counter[FlowKey] = Counter()
    app_pods: defaultdict[PolicyKey, set[tuple[str, str]]] = defaultdict(set)
    total = matched = 0

    source = flow_iter if flow_iter is not None else _read_flows(path)
    for _lineno, flow in source:
        total += 1

        # Support the {"flow": {...}} envelope used by some Hubble versions.
        if "flow" in flow and "source" not in flow:
            flow = flow["flow"]

        # Verdict filtering (case-insensitive).
        if verdicts:
            if flow.get("verdict", "").upper() not in verdicts:
                continue

        if _apply_flow(flow, label_keys, namespaces, policies, flow_counts, app_pods):
            matched += 1

    return policies, flow_counts, total, matched, dict(app_pods)


def _apply_flow(
    flow: dict[str, Any],
    label_keys: list[str],
    namespaces: set[str],
    policies: defaultdict[PolicyKey, RuleSet],
    flow_counts: Counter[FlowKey],
    app_pods: defaultdict[PolicyKey, set[tuple[str, str]]],
) -> bool:
    """Process a single pre-filtered flow dict, updating the three shared data structures.

    The caller is responsible for verdict filtering and ``{"flow": ...}`` envelope
    unwrapping before calling this function.

    Returns True if the flow contributed to at least one policy rule.
    """
    src = flow.get("source", {})
    dst = flow.get("destination", {})

    src_ns = src.get("namespace")
    dst_ns = dst.get("namespace")
    src_app = _parse_identity_label(src.get("labels"), label_keys)
    dst_app = _parse_identity_label(dst.get("labels"), label_keys)
    src_entity = _parse_reserved_identity(src.get("labels"))
    dst_entity = _parse_reserved_identity(dst.get("labels"))

    src_pod: str = src.get("pod_name") or ""
    dst_pod: str = dst.get("pod_name") or ""

    l4 = flow.get("l4", {})
    port: int | None = None
    proto: str | None = None
    for proto_name in ("TCP", "UDP", "SCTP"):
        if proto_name in l4:
            port = l4[proto_name].get("destination_port")
            proto = proto_name
            break

    if port is None or proto is None:
        return False

    # Use pod_name as fallback display identifier when no label key matches,
    # so the report shows something meaningful instead of bare "unknown".
    src_display = src_app or src_pod or "unknown"
    dst_display = dst_app or dst_pod or "unknown"

    flow_counts[
        (
            (src_ns or "?") if not src_entity else "",
            f"reserved:{src_entity}" if src_entity else src_display,
            (dst_ns or "?") if not dst_entity else "",
            f"reserved:{dst_entity}" if dst_entity else dst_display,
            port,
            proto,
        )
    ] += 1

    # Encode reserved entities with a prefix so build_policy() can
    # distinguish them from regular workload names.
    dst_peer = f"entity:{dst_entity}" if dst_entity else (dst_app or "")
    src_peer = f"entity:{src_entity}" if src_entity else (src_app or "")

    if src_ns and src_app and src_pod:
        app_pods[(src_ns, src_app)].add((src_ns, src_pod))
    if dst_ns and dst_app and dst_pod:
        app_pods[(dst_ns, dst_app)].add((dst_ns, dst_pod))

    hit = False
    if src_ns and src_app and (not namespaces or src_ns in namespaces):
        policies[(src_ns, src_app)]["egress"].add((dst_ns or "", dst_peer, port, proto))
        hit = True
    if dst_ns and dst_app and (not namespaces or dst_ns in namespaces):
        policies[(dst_ns, dst_app)]["ingress"].add((src_ns or "", src_peer, port, proto))
        hit = True
    return hit


def _parse_flow_list(
    flows: list[dict[str, Any]],
    label_keys: list[str],
    verdicts: set[str],
    namespaces: set[str],
) -> ParseResult:
    """Parse an in-memory list of flow dicts into per-workload rule sets.

    Mirrors ``parse_flows`` but takes a pre-loaded list instead of a file path.
    Flows in the list must already be unwrapped (no ``{"flow": ...}`` envelope).
    Used by live watch mode to re-derive a fresh snapshot on each refresh cycle.
    """
    policies: defaultdict[PolicyKey, RuleSet] = defaultdict(
        lambda: {"egress": set(), "ingress": set()}
    )
    flow_counts: Counter[FlowKey] = Counter()
    app_pods: defaultdict[PolicyKey, set[tuple[str, str]]] = defaultdict(set)
    total = matched = 0

    for flow in flows:
        total += 1
        if verdicts and flow.get("verdict", "").upper() not in verdicts:
            continue
        if _apply_flow(flow, label_keys, namespaces, policies, flow_counts, app_pods):
            matched += 1

    return dict(policies), flow_counts, total, matched, dict(app_pods)


# ---------------------------------------------------------------------------
# Policy construction
# ---------------------------------------------------------------------------


def _consolidate_rules(
    rule_tuples: set[RuleTuple],
) -> list[tuple[str, str, list[tuple[int, str]]]]:
    """Group *(ns, app, port, proto)* tuples by endpoint and merge ports.

    Returns a sorted list of *(ns, app, [(port, proto), ...]).*.
    """
    grouped: defaultdict[tuple[str, str], set[tuple[int, str]]] = defaultdict(set)
    for ns, app, port, proto in rule_tuples:
        grouped[(ns, app)].add((port, proto))
    return [(ns, app, sorted(ports)) for (ns, app), ports in sorted(grouped.items())]


def build_policy(
    ns: str,
    app: str,
    rules: RuleSet,
    workload_labels: WorkloadLabels | None = None,
) -> dict[str, Any]:
    """Build a CiliumNetworkPolicy dict for a single workload.

    When *workload_labels* is provided (populated by cluster enrichment) the
    ``endpointSelector`` and ``fromEndpoints``/``toEndpoints`` rules use the
    actual Cilium security labels retrieved from the live cluster instead of
    the simplified ``app`` label extracted from flow data.
    """

    def _selector(peer_ns: str, peer_app: str) -> dict[str, str]:
        """Return matchLabels for *peer_app* in *peer_ns*, using real labels if available."""
        if workload_labels and (peer_ns, peer_app) in workload_labels:
            return dict(workload_labels[(peer_ns, peer_app)])
        # Fallback: legacy single-label selector.
        labels: dict[str, str] = {"app": peer_app}
        if peer_ns and peer_ns != ns:
            labels["k8s:io.kubernetes.pod.namespace"] = peer_ns
        return labels

    selector_labels = _selector(ns, app)
    policy: dict[str, Any] = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": f"allow-{app}", "namespace": ns},
        "spec": {
            "endpointSelector": {"matchLabels": selector_labels},
        },
    }

    # Egress -- consolidated by destination endpoint
    egress: list[dict[str, Any]] = []
    for dst_ns, dst_app, ports in _consolidate_rules(rules["egress"]):
        port_list = [{"port": str(p), "protocol": pr} for p, pr in ports]
        rule: dict[str, Any] = {"toPorts": [{"ports": port_list}]}
        if dst_app.startswith("entity:"):
            rule["toEntities"] = [dst_app.removeprefix("entity:")]
        elif dst_app:
            rule["toEndpoints"] = [{"matchLabels": _selector(dst_ns, dst_app)}]
        else:
            LOG.debug("Skipping egress rule with unidentified destination for %s/%s", ns, app)
            continue
        egress.append(rule)
    if egress:
        policy["spec"]["egress"] = egress

    # Ingress -- consolidated by source endpoint
    ingress: list[dict[str, Any]] = []
    for src_ns, src_app, ports in _consolidate_rules(rules["ingress"]):
        port_list = [{"port": str(p), "protocol": pr} for p, pr in ports]
        rule = {"toPorts": [{"ports": port_list}]}
        if src_app.startswith("entity:"):
            rule["fromEntities"] = [src_app.removeprefix("entity:")]
        elif src_app:
            rule["fromEndpoints"] = [{"matchLabels": _selector(src_ns, src_app)}]
        else:
            LOG.debug("Skipping ingress rule with unidentified source for %s/%s", ns, app)
            continue
        ingress.append(rule)
    if ingress:
        policy["spec"]["ingress"] = ingress

    return policy


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _dump_yaml(policy: dict[str, Any], stream: IO[str]) -> None:
    """Serialize a policy dict to YAML preserving key insertion order."""
    yaml.dump(policy, stream, default_flow_style=False, sort_keys=False)


def _write_multi_doc_yaml(
    policies_iter: list[tuple[str, str, RuleSet]],
    stream: IO[str],
    workload_labels: WorkloadLabels | None = None,
) -> None:
    """Write multiple policies as a ``---``-separated YAML stream."""
    for idx, (ns, app, rules) in enumerate(policies_iter):
        if idx > 0:
            stream.write("---\n")
        _dump_yaml(build_policy(ns, app, rules, workload_labels=workload_labels), stream)


def _write_policy_dir(
    sorted_policies: list[tuple[str, str, RuleSet]],
    output_dir: str,
    workload_labels: WorkloadLabels | None = None,
) -> int:
    """Write per-workload YAML files to *output_dir* with path-safety checks.

    Returns the number of files successfully written.
    """
    os.makedirs(output_dir, exist_ok=True)
    real_dir = os.path.realpath(output_dir)
    written = 0
    for ns, app, rules in sorted_policies:
        safe_ns = sanitize_name(ns)
        safe_app = sanitize_name(app)
        if not safe_ns or not safe_app:
            LOG.warning("Skipping workload with unsanitizable name: %s/%s", ns, app)
            continue
        filepath = os.path.realpath(os.path.join(real_dir, f"{safe_ns}-{safe_app}.yaml"))
        if not filepath.startswith(real_dir + os.sep):
            LOG.warning("Skipping unsafe path for %s/%s", ns, app)
            continue
        with open(filepath, "w", encoding="utf-8") as fh:
            _dump_yaml(build_policy(ns, app, rules, workload_labels=workload_labels), fh)
        LOG.debug("Generated: %s", filepath)
        written += 1
    return written


def _find_unknown_flows(flow_counts: Counter[FlowKey]) -> list[FlowKey]:
    """Return flow keys where source or destination could not be identified."""
    return [key for key in flow_counts if key[1] == "unknown" or key[3] == "unknown"]


def _print_unknown_warnings(
    unknown_keys: list[FlowKey],
    flow_counts: Counter[FlowKey],
    file: IO[str] = sys.stderr,
) -> None:
    """Print an explicit warning block listing unidentified endpoints."""
    w = file.write
    total_unknown = sum(flow_counts[k] for k in unknown_keys)
    sep = "!" * 78
    w(f"\n{sep}\n")
    w(
        f"WARNING: {len(unknown_keys)} unique flow(s) ({total_unknown} total) have "
        f"unidentified endpoints.\n"
    )
    w(
        "These flows have no recognised workload label or reserved identity\n"
        "and will NOT be covered by any generated policy.\n"
    )
    w(f"{sep}\n")
    for key in unknown_keys:
        src_ns, src_app, dst_ns, dst_app, port, proto = key
        src = f"{src_ns}/{src_app}" if src_ns else src_app
        dst = f"{dst_ns}/{dst_app}" if dst_ns else dst_app
        w(f"  {src:<30}  ->  {dst:<30}  {port:>5}  {proto}  (x{flow_counts[key]})\n")
    w(f"{sep}\n")
    w("Hint: use --label-key to add additional workload label keys.\n\n")


def _print_summary(total: int, matched: int, policy_count: int, file: IO[str] = sys.stderr) -> None:
    count_word = "policy" if policy_count == 1 else "policies"
    print(
        f"Processed {total} flows - {matched} matched - {policy_count} {count_word} generated.",
        file=file,
    )


def _trunc(s: str, width: int) -> str:
    """Truncate *s* to *width* chars, appending ``...`` when cut."""
    return (s[: width - 3] + "...") if len(s) > width else s


def _print_report(
    flow_counts: Counter[FlowKey],
    total: int,
    matched: int,
    file: IO[str] = sys.stderr,
    term_width: int | None = None,
) -> list[FlowKey]:
    """Print a frequency-sorted table of unique observed flows.

    Column widths adapt to the actual data and the available terminal width.

    Returns the flow keys in the same order they were rendered (most-common
    first), enabling callers to map display rows back to their FlowKey.
    """
    w = file.write

    if term_width is None:
        term_width = shutil.get_terminal_size((100, 40)).columns

    # Build display strings first so we can measure natural column widths.
    rows: list[tuple[str, str, int, str, int]] = []
    ordered_keys: list[FlowKey] = []
    for (src_ns, src_app, dst_ns, dst_app, port, proto), count in flow_counts.most_common():
        src = f"{src_ns}/{src_app}" if src_ns else src_app
        dst = f"{dst_ns}/{dst_app}" if dst_ns else dst_app
        rows.append((src, dst, port, proto, count))
        ordered_keys.append((src_ns, src_app, dst_ns, dst_app, port, proto))

    max_src = max((len(r[0]) for r in rows), default=16)
    max_dst = max((len(r[1]) for r in rows), default=16)
    # Ensure proto column is at least as wide as the "PROTO" header word.
    max_proto = max((len(r[3]) for r in rows), default=5) if rows else 5
    max_proto = max(max_proto, 5)

    # Fixed overhead per row: COUNT(7) + 2 + "->"(2) + 2 + PORT(5) + 2 + PROTO + gaps(6)
    FIXED = 7 + 2 + 2 + 2 + 5 + 2 + max_proto + 4
    available = max(term_width - FIXED, 20)

    # Distribute available space between the two name columns.
    total_natural = max_src + max_dst
    if total_natural <= available:
        src_col = max_src
        dst_col = max_dst
    else:
        # Give each side a proportional share, minimum 10 chars each.
        src_col = max(10, int(available * max_src / total_natural))
        dst_col = max(10, available - src_col)

    row_len = FIXED + src_col + dst_col
    sep = "=" * row_len
    dash = "-" * row_len

    w(f"\n{sep}\n")
    w("FLOW REPORT - unique observed connections (sorted by frequency)\n")
    w(f"{sep}\n")
    hdr = (
        f"{'COUNT':>7}  {'SOURCE':<{src_col}}  {'':2}  "
        f"{'DESTINATION':<{dst_col}}  {'PORT':>5}  {'PROTO':<{max_proto}}"
    )
    w(f"{hdr}\n")
    w(f"{dash}\n")

    for src, dst, port, proto, count in rows:
        w(
            f"{count:>7}  {_trunc(src, src_col):<{src_col}}  "
            f"->  {_trunc(dst, dst_col):<{dst_col}}  {port:>5}  {proto:<{max_proto}}\n"
        )

    w(f"{dash}\n")
    w(f"Total: {total} flows, {matched} matched, {len(flow_counts)} unique connections\n")
    w(f"{sep}\n")
    return ordered_keys


# ---------------------------------------------------------------------------
# Live watch mode
# ---------------------------------------------------------------------------


class LiveFlowStore:
    """Thread-safe rolling buffer of unwrapped Hubble flow dicts.

    The store optionally enforces a sliding time window: entries older than
    ``window_seconds`` are pruned automatically.  Set ``window_seconds=0``
    (the default) to accumulate all flows without limit.
    """

    def __init__(self, window_seconds: float = 0, capture_fh: IO[str] | None = None) -> None:
        self._lock = threading.Lock()
        self._flows: deque[tuple[float, dict[str, Any]]] = deque()
        self.window_seconds = window_seconds
        self.total_received = 0
        self.connected: bool = False
        self.last_error: str = ""
        self._capture_fh = capture_fh

    def add(self, flow: dict[str, Any]) -> None:
        now = time.monotonic()
        with self._lock:
            self._flows.append((now, flow))
            self.total_received += 1
            self._prune(now)
            if self._capture_fh is not None:
                self._capture_fh.write(json.dumps(flow) + "\n")
                self._capture_fh.flush()

    def _prune(self, now: float) -> None:
        """Drop entries outside the rolling window. Caller must hold the lock."""
        if self.window_seconds > 0:
            cutoff = now - self.window_seconds
            while self._flows and self._flows[0][0] < cutoff:
                self._flows.popleft()

    def snapshot(self) -> list[dict[str, Any]]:
        """Return a point-in-time copy of all flows currently in the window."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return [flow for _, flow in self._flows]

    @contextmanager
    def suspend_capture(self) -> Generator[None, None, None]:
        """Context manager that suppresses flow capture for its duration."""
        with self._lock:
            saved = self._capture_fh
            self._capture_fh = None
        try:
            yield
        finally:
            with self._lock:
                self._capture_fh = saved

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._flows)


def _detect_hubble_cmd() -> tuple[list[str], bool]:
    """Return the base ``hubble observe`` command and whether it is the PATH binary.

    Tries the ``hubble`` binary on PATH first (using ``-P`` for automatic
    port-forwarding to hubble-relay).  Falls back to ``kubectl exec`` into the
    first available Cilium DaemonSet pod if the PATH binary is not found.

    Returns a ``(cmd_base, is_path_binary)`` tuple so callers can add ``-P``
    only when appropriate.
    """
    if shutil.which("hubble"):
        LOG.debug("hubble: using PATH binary with -P (auto port-forward)")
        return ["hubble", "observe"], True
    # Fall back to kubectl exec into a Cilium pod.
    if shutil.which("kubectl"):
        try:
            cilium_node_map = _build_cilium_node_map()
            if cilium_node_map:
                cilium_pod = next(iter(sorted(cilium_node_map.values())))
                LOG.debug("hubble: using kubectl exec into %s", cilium_pod)
                return [
                    "kubectl",
                    "exec",
                    "-n",
                    "kube-system",
                    "-i",
                    cilium_pod,
                    "--",
                    "hubble",
                    "observe",
                ], False
        except RuntimeError:
            pass
    raise RuntimeError(
        "hubble CLI not found in PATH and no Cilium pod could be located via "
        "kubectl. Install hubble (https://github.com/cilium/hubble) or ensure "
        "kubectl is configured. Use --hubble-cmd to specify the command manually."
    )


def _build_hubble_observe_cmd(args: argparse.Namespace) -> list[str]:
    """Build the complete ``hubble observe`` command list from parsed CLI args."""
    add_port_forward = False
    if args.hubble_cmd:
        base = shlex.split(args.hubble_cmd)
    else:
        base, add_port_forward = _detect_hubble_cmd()

    cmd = list(base)
    if add_port_forward:
        cmd += ["-P"]  # auto port-forward to hubble-relay (hubble >= 0.12)
    cmd += ["-o", "json", "--follow"]

    namespaces: set[str] = set(args.namespaces or [])
    if namespaces:
        for ns in sorted(namespaces):
            cmd += ["-n", ns]
    else:
        cmd += ["--all-namespaces"]

    if args.verdict:
        for v in args.verdict:
            cmd += ["--verdict", v]

    return cmd


def _hubble_reader_thread(
    proc: subprocess.Popen[str],
    store: LiveFlowStore,
    stop_event: threading.Event,
) -> None:
    """Read JSON flow lines from hubble stdout and feed them into *store*."""
    if proc.stdout is None:
        return
    for line in proc.stdout:
        if stop_event.is_set():
            break
        line = line.strip()
        if not line:
            continue
        try:
            obj: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Unwrap {"flow": {...}} envelope emitted by Hubble relay / CLI.
        raw: Any = obj["flow"] if "flow" in obj and "source" not in obj else obj
        if not isinstance(raw, dict):
            continue
        flow: dict[str, Any] = cast(dict[str, Any], raw)
        store.add(flow)


def _hubble_stderr_thread(
    proc: subprocess.Popen[str],
    store: LiveFlowStore,
    stop_event: threading.Event,
) -> None:
    """Drain hubble stderr and record the last meaningful line in *store*."""
    if proc.stderr is None:
        return
    for line in proc.stderr:
        if stop_event.is_set():
            break
        line = line.strip()
        if line:
            store.last_error = line
    # Process has exited; mark as disconnected (unless Ctrl+C already set).
    if not stop_event.is_set():
        store.connected = False


def _launch_hubble(
    hubble_cmd: list[str],
    store: LiveFlowStore,
    stop_event: threading.Event,
) -> subprocess.Popen[str]:
    """Start ``hubble observe`` and its two reader threads; return the process."""
    proc: subprocess.Popen[str] = subprocess.Popen(
        hubble_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    store.connected = True
    for target, name in [
        (_hubble_reader_thread, "hubble-stdout"),
        (_hubble_stderr_thread, "hubble-stderr"),
    ]:
        t = threading.Thread(target=target, args=(proc, store, stop_event), daemon=True, name=name)
        t.start()
    return proc


def _build_policies_from_flow_keys(keys: set[FlowKey]) -> dict[PolicyKey, RuleSet]:
    """Build a policies dict from an explicit set of flow keys.

    Mirrors the rule-building logic of ``_apply_flow`` so that watch-mode
    interactive selection produces the same policy structure as a full parse.
    In flow_counts keys, reserved entities are stored as ``reserved:X``;
    RuleSet tuples use ``entity:X`` — this function converts between them.
    """
    policies: defaultdict[PolicyKey, RuleSet] = defaultdict(
        lambda: {"egress": set(), "ingress": set()}
    )

    def _to_peer(app: str) -> str:
        return "entity:" + app.removeprefix("reserved:") if app.startswith("reserved:") else app

    def _is_workload(ns: str, app: str) -> bool:
        return bool(ns and app and app not in ("", "unknown") and not app.startswith("reserved:"))

    for src_ns, src_app, dst_ns, dst_app, port, proto in keys:
        if _is_workload(src_ns, src_app):
            policies[(src_ns, src_app)]["egress"].add(
                (dst_ns or "", _to_peer(dst_app), port, proto)
            )
        if _is_workload(dst_ns, dst_app):
            policies[(dst_ns, dst_app)]["ingress"].add(
                (src_ns or "", _to_peer(src_app), port, proto)
            )
    return dict(policies)


@dataclasses.dataclass
class _ReconnectState:
    """Mutable state for exponential-backoff reconnection in watch mode."""

    _DELAY_INIT: ClassVar[float] = 2.0
    _DELAY_MAX: ClassVar[float] = 60.0

    delay: float = 2.0
    at: float = 0.0

    def reset(self) -> None:
        self.delay = self._DELAY_INIT

    def backoff(self, now: float) -> None:
        self.at = now + self.delay
        self.delay = min(self.delay * 2, self._DELAY_MAX)


def _handle_key(
    key: int,
    *,
    is_paused: bool,
    is_selecting: bool,
    cursor_flow_idx: int,
    ordered_keys: list[FlowKey],
    selected_keys: set[FlowKey],
    scroll_offset: int,
    is_following: bool,
    half_page: int,
    content_lines_len: int,
) -> tuple[bool | None, bool, bool, int, int, bool, bool]:
    """Process a single curses key press and return updated TUI state.

    Returns ``(quit_signal, is_paused, is_selecting, cursor_flow_idx,
    scroll_offset, is_following, generate_flag)``.

    *quit_signal*: ``True`` = quit, ``None`` = key not handled (no-op),
    ``False`` = handled, continue.
    """
    if key in (ord("q"), ord("Q"), 3):  # quit
        return (True, is_paused, is_selecting, cursor_flow_idx, scroll_offset, is_following, False)

    if key == ord(" "):
        if is_selecting:  # toggle selection
            if 0 <= cursor_flow_idx < len(ordered_keys):
                fk = ordered_keys[cursor_flow_idx]
                if fk in selected_keys:
                    selected_keys.discard(fk)
                else:
                    selected_keys.add(fk)
        else:  # pause / resume
            is_paused = not is_paused
        return (False, is_paused, is_selecting, cursor_flow_idx, scroll_offset, is_following, False)

    if key in (ord("s"), ord("S")):  # toggle select mode
        if not is_selecting and not ordered_keys:
            return (
                None,
                is_paused,
                is_selecting,
                cursor_flow_idx,
                scroll_offset,
                is_following,
                False,
            )
        is_selecting = not is_selecting
        if is_selecting:
            cursor_flow_idx = min(cursor_flow_idx, len(ordered_keys) - 1)
        return (False, is_paused, is_selecting, cursor_flow_idx, scroll_offset, is_following, False)

    if key == 27:  # Esc -- exit select + clear
        return False, is_paused, False, 0, scroll_offset, is_following, False

    if key in (10, 13, curses.KEY_ENTER):  # Enter -- generate + quit
        if is_selecting and selected_keys:
            return (
                True,
                is_paused,
                is_selecting,
                cursor_flow_idx,
                scroll_offset,
                is_following,
                True,
            )
        return (
            None,
            is_paused,
            is_selecting,
            cursor_flow_idx,
            scroll_offset,
            is_following,
            False,
        )

    # -- navigation --------------------------------------------------------
    if key in (ord("j"), curses.KEY_DOWN):
        if is_selecting and ordered_keys:
            cursor_flow_idx = min(cursor_flow_idx + 1, len(ordered_keys) - 1)
        else:
            scroll_offset += 1
            is_following = False

    elif key in (ord("k"), curses.KEY_UP):
        if is_selecting and ordered_keys:
            cursor_flow_idx = max(0, cursor_flow_idx - 1)
        else:
            scroll_offset = max(0, scroll_offset - 1)

    elif key in (ord("d"), curses.KEY_NPAGE):
        if is_selecting and ordered_keys:
            cursor_flow_idx = min(cursor_flow_idx + half_page, len(ordered_keys) - 1)
        else:
            scroll_offset += half_page
            is_following = False

    elif key in (ord("u"), curses.KEY_PPAGE):
        if is_selecting and ordered_keys:
            cursor_flow_idx = max(0, cursor_flow_idx - half_page)
        else:
            scroll_offset = max(0, scroll_offset - half_page)

    elif key in (ord("g"), curses.KEY_HOME):
        if is_selecting:
            cursor_flow_idx = 0
        scroll_offset = 0
        is_following = True

    elif key in (ord("G"), curses.KEY_END):
        if is_selecting and ordered_keys:
            cursor_flow_idx = len(ordered_keys) - 1
        scroll_offset = content_lines_len  # clamped by caller
        is_following = False

    else:
        return (
            None,
            is_paused,
            is_selecting,
            cursor_flow_idx,
            scroll_offset,
            is_following,
            False,
        )

    return (
        False,
        is_paused,
        is_selecting,
        cursor_flow_idx,
        scroll_offset,
        is_following,
        False,
    )


def _draw_header(
    stdscr: Any,
    width: int,
    *,
    cmd_display: str,
    interval: float,
    store: LiveFlowStore,
    capture_file: str | None,
    is_paused: bool,
    is_selecting: bool,
    selected_count: int,
    reconn: _ReconnectState,
    now_mono: float,
) -> None:
    """Render the fixed header rows (0-2) of the watch mode TUI."""
    # Row 0: command + timestamp
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    left = f"Every {interval:.1f}s: {cmd_display}"
    if len(left) > width - len(now_str) - 2:
        left = left[: width - len(now_str) - 5] + "..."
    padding = max(1, width - len(left) - len(now_str))
    try:
        stdscr.addnstr(0, 0, f"{left}{' ' * padding}{now_str}", width - 1)
    except curses.error:
        pass

    # Row 1: window info + status badge
    win_label = (
        f"Window: last {store.window_seconds:.0f}s"
        if store.window_seconds > 0
        else "Window: all flows"
    )
    cap_note = f"  |  Capturing -> {capture_file}" if capture_file else ""
    prefix = (
        f"{win_label}  |  In window: {store.count}"
        f"  |  Total received: {store.total_received}{cap_note}  "
    )
    if is_paused:
        badge, badge_attr = (
            "|| PAUSED",
            curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD,
        )
    elif store.connected:
        badge, badge_attr = (
            "* Live",
            curses.color_pair(1) if curses.has_colors() else curses.A_NORMAL,
        )
    elif now_mono < reconn.at:
        secs_left = int(reconn.at - now_mono)
        badge = f"! Disconnected - reconnecting in {secs_left}s"
        badge_attr = curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL
    else:
        badge, badge_attr = (
            "! Reconnecting...",
            curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL,
        )
    try:
        stdscr.addnstr(1, 0, prefix, width - 1)
        stdscr.addnstr(1, len(prefix), badge, width - 1 - len(prefix), badge_attr)
    except curses.error:
        pass

    # Row 2: selection hint (select mode) OR last hubble error OR blank
    if is_selecting:
        sel_hint = (
            f"SELECT  Space toggle  Enter generate ({selected_count} selected)"
            "  j/k move  s/Esc exit"
        )
        sel_attr = curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        try:
            stdscr.addnstr(2, 0, sel_hint, width - 1, sel_attr)
        except curses.error:
            pass
    elif not store.connected and store.last_error:
        err_text = f"Last error: {_trunc(store.last_error, width - 13)}"
        err_attr = curses.color_pair(3) if curses.has_colors() else curses.A_NORMAL
        try:
            stdscr.addnstr(2, 0, err_text, width - 1, err_attr)
        except curses.error:
            pass


def _draw_loki_header(
    stdscr: Any,
    width: int,
    *,
    loki_url: str,
    loki_query: str,
    since: str,
    until: str,
    flow_count: int,
    is_selecting: bool,
    selected_count: int,
) -> None:
    """Render the fixed header rows (0-2) for Loki watch mode TUI."""
    # Row 0: source + timestamp
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    left = f"Loki: {loki_url}  query={loki_query}"
    if len(left) > width - len(now_str) - 2:
        left = left[: width - len(now_str) - 5] + "..."
    padding = max(1, width - len(left) - len(now_str))
    try:
        stdscr.addnstr(0, 0, f"{left}{' ' * padding}{now_str}", width - 1)
    except curses.error:
        pass

    # Row 1: time range + flow count + status badge
    prefix = f"Range: since={since} until={until}  |  Flows: {flow_count}  "
    badge = "* Loaded"
    badge_attr = curses.color_pair(1) if curses.has_colors() else curses.A_NORMAL
    try:
        stdscr.addnstr(1, 0, prefix, width - 1)
        stdscr.addnstr(1, len(prefix), badge, width - 1 - len(prefix), badge_attr)
    except curses.error:
        pass

    # Row 2: selection hint or blank
    if is_selecting:
        sel_hint = (
            f"SELECT  Space toggle  Enter generate ({selected_count} selected)"
            "  j/k move  s/Esc exit"
        )
        sel_attr = curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        try:
            stdscr.addnstr(2, 0, sel_hint, width - 1, sel_attr)
        except curses.error:
            pass


def _draw_content(
    stdscr: Any,
    width: int,
    height: int,
    *,
    content_lines: list[str],
    scroll_offset: int,
    is_selecting: bool,
    is_following: bool,
    cursor_flow_idx: int,
    key_map: dict[int, FlowKey],
    selected_keys: set[FlowKey],
    header_lines: int,
    data_row_offset: int,
) -> None:
    """Render the scrollable content area and corner scroll indicator."""
    content_viewport = max(1, height - header_lines)
    max_scroll = max(0, len(content_lines) - content_viewport)

    cursor_line = data_row_offset + cursor_flow_idx if is_selecting else -1
    for i, line in enumerate(content_lines[scroll_offset : scroll_offset + content_viewport]):
        abs_idx = scroll_offset + i
        attr = curses.A_NORMAL
        if is_selecting and abs_idx in key_map:
            fk = key_map[abs_idx]
            if fk in selected_keys:
                attr |= (
                    curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
                )
            if abs_idx == cursor_line:
                attr |= curses.A_REVERSE
        try:
            stdscr.addnstr(header_lines + i, 0, line, width - 1, attr)
        except curses.error:
            pass

    # Corner scroll indicator
    if len(content_lines) > content_viewport:
        if is_following:
            indicator = " TOP  j/d v "
        else:
            pct = int(100 * scroll_offset / max(1, max_scroll))
            indicator = f" {pct}%  k/u ^  j/d v  g# "
        try:
            col = max(0, width - len(indicator) - 1)
            stdscr.addnstr(height - 1, col, indicator, width - 1, curses.A_REVERSE)
        except curses.error:
            pass


def _loki_watch_mode(args: argparse.Namespace) -> None:
    """Interactive TUI for Loki flows with workload selection.

    Fetches historical flows from a Loki instance, then presents the same
    curses TUI as live watch mode so the user can browse, scroll, and
    interactively select workloads to generate policies for.

    Keys are the same as live watch mode (j/k scroll, s select, Space
    toggle, Enter generate, q quit) except that pause/resume is not
    applicable since flows are pre-loaded.
    """
    label_keys: list[str] = args.label_keys or DEFAULT_LABEL_KEYS
    verdicts: set[str] = {v.upper() for v in args.verdict} if args.verdict else set()
    namespaces: set[str] = set(args.namespaces or [])
    interval: float = args.interval

    # Validate Loki arguments.
    if not args.loki_url:
        LOG.error("--loki-url is required when using --from loki")
        sys.exit(EXIT_ERROR)
    if args.loki_token and args.loki_user:
        LOG.error("--loki-token and --loki-user are mutually exclusive")
        sys.exit(EXIT_ERROR)
    if args.loki_password and not args.loki_user:
        LOG.error("--loki-password requires --loki-user")
        sys.exit(EXIT_ERROR)

    since_sec = _parse_duration(args.since)
    until_sec = _parse_duration(args.until)

    print(
        f"Querying Loki at {args.loki_url} "
        f"(query={args.loki_query!r}, since={args.since}, until={args.until}) ...",
        file=sys.stderr,
    )

    loki_flows: list[dict[str, Any]] = []
    for _, flow in _read_flows_loki(
        args.loki_url,
        args.loki_query,
        since_sec,
        until_sec,
        args.loki_limit,
        loki_user=args.loki_user,
        loki_password=args.loki_password,
        loki_token=args.loki_token,
        loki_tls_ca=args.loki_tls_ca,
    ):
        loki_flows.append(flow)

    print(f"Loaded {len(loki_flows)} flows from Loki.", file=sys.stderr)

    if not loki_flows:
        LOG.warning("No flows returned from Loki query")
        sys.exit(EXIT_NO_POLICIES)

    # Header layout matches live watch mode.
    HEADER_LINES = 4
    DATA_ROW_OFFSET = 6

    # Shared state between _run() and the outer scope.
    final_content: list[str] = []
    generate_flag: bool = False
    selected_keys_final: set[FlowKey] = set()

    def _run(stdscr: curses.window) -> None:  # type: ignore[name-defined]
        nonlocal final_content, generate_flag
        if curses.has_colors():
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        scroll_offset = 0
        is_following = True
        is_paused = False
        is_selecting = False
        cursor_flow_idx = 0
        selected_keys: set[FlowKey] = set()

        ordered_keys: list[FlowKey] = []
        key_map: dict[int, FlowKey] = {}
        content_lines: list[str] = []
        last_refresh = 0.0

        while True:
            key = stdscr.getch()
            height, width = stdscr.getmaxyx()
            half_page = max(1, (height - HEADER_LINES) // 2)

            if key != -1:
                (
                    quit_sig,
                    is_paused,
                    is_selecting,
                    cursor_flow_idx,
                    scroll_offset,
                    is_following,
                    gen,
                ) = _handle_key(
                    key,
                    is_paused=is_paused,
                    is_selecting=is_selecting,
                    cursor_flow_idx=cursor_flow_idx,
                    ordered_keys=ordered_keys,
                    selected_keys=selected_keys,
                    scroll_offset=scroll_offset,
                    is_following=is_following,
                    half_page=half_page,
                    content_lines_len=len(content_lines),
                )
                if quit_sig:
                    if gen:
                        generate_flag = True
                        selected_keys_final.update(selected_keys)
                    break
                if key == 27:
                    selected_keys.clear()

            now_mono = time.monotonic()

            # Refresh the report periodically.
            if now_mono - last_refresh >= interval:
                last_refresh = now_mono

                _, flow_counts, total, matched, _ = _parse_flow_list(
                    loki_flows, label_keys, verdicts, namespaces
                )

                buf = io.StringIO()
                ordered_keys = _print_report(
                    flow_counts, total, matched, file=buf, term_width=width
                )
                key_map = {DATA_ROW_OFFSET + i: fk for i, fk in enumerate(ordered_keys)}

                unknown_keys = _find_unknown_flows(flow_counts)
                if unknown_keys:
                    _print_unknown_warnings(unknown_keys, flow_counts, file=buf)

                buf.write(
                    "\nj/k line  |  d/u half-page  |  g/G top/bottom  |  s select  |  q quit\n"
                )
                content_lines = buf.getvalue().splitlines()
                final_content = content_lines

                if ordered_keys:
                    cursor_flow_idx = min(cursor_flow_idx, len(ordered_keys) - 1)
                else:
                    cursor_flow_idx = 0

            # Clamp scroll / auto-follow.
            content_viewport = max(1, height - HEADER_LINES)
            max_scroll = max(0, len(content_lines) - content_viewport)

            if is_following:
                scroll_offset = 0
            else:
                scroll_offset = min(scroll_offset, max_scroll)
                if scroll_offset <= 0:
                    is_following = True

            if is_selecting and ordered_keys:
                cursor_line = DATA_ROW_OFFSET + cursor_flow_idx
                if not is_following:
                    if cursor_line < scroll_offset:
                        scroll_offset = cursor_line
                    elif cursor_line >= scroll_offset + content_viewport:
                        scroll_offset = min(cursor_line - content_viewport + 1, max_scroll)

            # Draw.
            stdscr.erase()
            _draw_loki_header(
                stdscr,
                width,
                loki_url=args.loki_url,
                loki_query=args.loki_query,
                since=args.since,
                until=args.until,
                flow_count=len(loki_flows),
                is_selecting=is_selecting,
                selected_count=len(selected_keys),
            )
            _draw_content(
                stdscr,
                width,
                height,
                content_lines=content_lines,
                scroll_offset=scroll_offset,
                is_selecting=is_selecting,
                is_following=is_following,
                cursor_flow_idx=cursor_flow_idx,
                key_map=key_map,
                selected_keys=selected_keys,
                header_lines=HEADER_LINES,
                data_row_offset=DATA_ROW_OFFSET,
            )
            stdscr.refresh()
            time.sleep(0.05)

    try:
        curses.wrapper(_run)
    except KeyboardInterrupt:
        pass

    # Print the last snapshot so the user is not left with a blank screen.
    if final_content:
        print()
        for line in final_content:
            print(line)

    # Generate policies from selected flows (triggered by Enter in select mode).
    if generate_flag and selected_keys_final:
        policies = _build_policies_from_flow_keys(selected_keys_final)
        sorted_policies = [(ns, app, rules) for (ns, app), rules in sorted(policies.items())]
        n_pol = len(sorted_policies)
        print(
            f"\nGenerating {n_pol} {'policy' if n_pol == 1 else 'policies'} "
            f"from {len(selected_keys_final)} selected flows...",
            file=sys.stderr,
        )
        if args.dry_run:
            _write_multi_doc_yaml(sorted_policies, sys.stdout)
        else:
            written = _write_policy_dir(sorted_policies, args.output_dir)
            print(
                f"Wrote {written} {'policy' if written == 1 else 'policies'} "
                f"to {os.path.realpath(args.output_dir)}",
                file=sys.stderr,
            )

    print("\nLoki watch mode stopped.", file=sys.stderr)


def _watch_mode(args: argparse.Namespace) -> None:
    """Live monitoring mode: spawn ``hubble observe`` and refresh the report.

    Keys (Mac-primary, all modes):
      j / down  scroll down one line
      k / up    scroll up one line
      d         scroll down half a page
      u         scroll up half a page
      g         jump to top / re-enable auto-follow
      G         jump to bottom
      Space     pause / resume live capture (normal mode)
                toggle selection of highlighted flow (select mode)
      s         enter / exit flow-selection mode
      Enter     generate policies from selected flows and quit (select mode)
      Esc       exit select mode and clear selections
      q / ^C    quit -- last report is printed to the terminal

    PgUp / PgDn / Home / End also work for non-Mac keyboards.

    In select mode each flow row can be toggled with Space; j/k/d/u move a
    cursor through the rows and scroll the view to keep it visible.  On
    Enter the selected flows are used to generate CiliumNetworkPolicy files
    (written to --output-dir, or printed with --dry-run).

    --capture-file writes every incoming flow as JSONL so the session can
    later be replayed: %(prog)s captured.jsonl -o policies/
    """
    label_keys: list[str] = args.label_keys or DEFAULT_LABEL_KEYS
    verdicts: set[str] = {v.upper() for v in args.verdict} if args.verdict else set()
    namespaces: set[str] = set(args.namespaces or [])
    interval: float = args.interval
    window: float = args.window

    capture_fh: IO[str] | None = None
    if getattr(args, "capture_file", None):
        capture_fh = open(args.capture_file, "w", encoding="utf-8")

    store = LiveFlowStore(window_seconds=window, capture_fh=capture_fh)

    # Optionally seed from an existing flows file (useful to pre-populate history).
    # Seeded flows are NOT written to the capture file (they already exist on disk).
    if args.flows_file and os.path.isfile(args.flows_file):
        with store.suspend_capture():  # suppress capture during seed
            for _, flow in _read_flows(args.flows_file):
                if "flow" in flow and "source" not in flow:
                    flow = flow["flow"]
                store.add(flow)
        print(f"Seeded {store.count} flows from {args.flows_file}", file=sys.stderr)

    # Build and (attempt to) launch the hubble observe subprocess.
    try:
        hubble_cmd = _build_hubble_observe_cmd(args)
    except RuntimeError as exc:
        if capture_fh:
            capture_fh.close()
        LOG.error("%s", exc)
        sys.exit(EXIT_ERROR)

    cmd_display = " ".join(shlex.quote(c) for c in hubble_cmd)
    if capture_fh:
        print(f"Capturing flows to: {args.capture_file}", file=sys.stderr)
    print(f"Starting: {cmd_display}", file=sys.stderr)

    stop_event = threading.Event()
    try:
        proc_holder = [_launch_hubble(hubble_cmd, store, stop_event)]
    except FileNotFoundError:
        if capture_fh:
            capture_fh.close()
        LOG.error("Command not found: %s", hubble_cmd[0])
        sys.exit(EXIT_ERROR)

    reconn = _ReconnectState()

    # Header layout (screen rows):
    #   0  command + timestamp
    #   1  window / connection / pause status
    #   2  last hubble error  OR  selection mode hint
    #   3  blank separator
    # Scrollable content starts at row 4.
    HEADER_LINES = 4

    # _print_report always writes these many lines before the first data row:
    #   "" (leading \n), sep, "FLOW REPORT...", sep, header-row, dash  = 6 lines
    DATA_ROW_OFFSET = 6

    # Shared state between _run() and the outer scope.
    final_content: list[str] = []
    generate_flag: bool = False
    selected_keys_final: set[FlowKey] = set()

    capture_file_name: str | None = args.capture_file if capture_fh else None

    def _run(stdscr: curses.window) -> None:  # type: ignore[name-defined]
        nonlocal final_content, generate_flag
        if curses.has_colors():
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)  # live / selected
            curses.init_pair(2, curses.COLOR_YELLOW, -1)  # paused / warning
            curses.init_pair(3, curses.COLOR_RED, -1)  # error
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        scroll_offset = 0
        is_following = True  # auto-follow top of report (most-frequent first)
        is_paused = False
        is_selecting = False
        cursor_flow_idx = 0  # index into ordered_keys when selecting
        selected_keys: set[FlowKey] = set()

        ordered_keys: list[FlowKey] = []  # flow keys in display order (rebuilt each refresh)
        key_map: dict[int, FlowKey] = {}  # content_line_index -> FlowKey
        content_lines: list[str] = []
        last_refresh = 0.0

        while True:
            key = stdscr.getch()
            height, width = stdscr.getmaxyx()
            half_page = max(1, (height - HEADER_LINES) // 2)

            if key != -1:
                (
                    quit_sig,
                    is_paused,
                    is_selecting,
                    cursor_flow_idx,
                    scroll_offset,
                    is_following,
                    gen,
                ) = _handle_key(
                    key,
                    is_paused=is_paused,
                    is_selecting=is_selecting,
                    cursor_flow_idx=cursor_flow_idx,
                    ordered_keys=ordered_keys,
                    selected_keys=selected_keys,
                    scroll_offset=scroll_offset,
                    is_following=is_following,
                    half_page=half_page,
                    content_lines_len=len(content_lines),
                )
                if quit_sig:
                    if gen:
                        generate_flag = True
                        selected_keys_final.update(selected_keys)
                    break
                # Esc clears selections inside _handle_key via the returned
                # is_selecting=False, but the set is mutated in-place only for
                # toggle; for Esc we need to clear here when select was exited.
                if key == 27:
                    selected_keys.clear()

            now_mono = time.monotonic()

            # ---- Auto-refresh (skipped while paused) -------------------------
            if not is_paused and now_mono - last_refresh >= interval:
                last_refresh = now_mono

                # Auto-reconnect
                if not store.connected and proc_holder[0].poll() is not None:
                    if now_mono >= reconn.at:
                        try:
                            proc_holder[0] = _launch_hubble(hubble_cmd, store, stop_event)
                            reconn.reset()
                        except FileNotFoundError:
                            reconn.backoff(now_mono)

                flows = store.snapshot()
                _, flow_counts, total, matched, _ = _parse_flow_list(
                    flows, label_keys, verdicts, namespaces
                )

                buf = io.StringIO()
                ordered_keys = _print_report(
                    flow_counts, total, matched, file=buf, term_width=width
                )
                key_map = {DATA_ROW_OFFSET + i: fk for i, fk in enumerate(ordered_keys)}

                unknown_keys = _find_unknown_flows(flow_counts)
                if unknown_keys:
                    _print_unknown_warnings(unknown_keys, flow_counts, file=buf)

                buf.write(
                    "\nSpace pause  |  j/k line  |  d/u half-page"
                    "  |  g/G top/bottom  |  s select  |  q quit\n"
                )
                content_lines = buf.getvalue().splitlines()
                final_content = content_lines

                # Clamp cursor to valid range after data changes.
                if ordered_keys:
                    cursor_flow_idx = min(cursor_flow_idx, len(ordered_keys) - 1)
                else:
                    cursor_flow_idx = 0

            # ---- Clamp scroll / auto-follow ----------------------------------
            content_viewport = max(1, height - HEADER_LINES)
            max_scroll = max(0, len(content_lines) - content_viewport)

            if is_following:
                scroll_offset = 0
            else:
                scroll_offset = min(scroll_offset, max_scroll)
                if scroll_offset <= 0:
                    is_following = True  # scrolled back to top -- re-enable

            # In selection mode keep the cursor row visible.
            if is_selecting and ordered_keys:
                cursor_line = DATA_ROW_OFFSET + cursor_flow_idx
                if not is_following:
                    if cursor_line < scroll_offset:
                        scroll_offset = cursor_line
                    elif cursor_line >= scroll_offset + content_viewport:
                        scroll_offset = min(cursor_line - content_viewport + 1, max_scroll)

            # ---- Draw --------------------------------------------------------
            stdscr.erase()
            _draw_header(
                stdscr,
                width,
                cmd_display=cmd_display,
                interval=interval,
                store=store,
                capture_file=capture_file_name,
                is_paused=is_paused,
                is_selecting=is_selecting,
                selected_count=len(selected_keys),
                reconn=reconn,
                now_mono=now_mono,
            )
            _draw_content(
                stdscr,
                width,
                height,
                content_lines=content_lines,
                scroll_offset=scroll_offset,
                is_selecting=is_selecting,
                is_following=is_following,
                cursor_flow_idx=cursor_flow_idx,
                key_map=key_map,
                selected_keys=selected_keys,
                header_lines=HEADER_LINES,
                data_row_offset=DATA_ROW_OFFSET,
            )
            stdscr.refresh()
            time.sleep(0.05)  # ~20 fps -- keeps key input responsive

    try:
        curses.wrapper(_run)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        proc_holder[0].terminate()
        try:
            proc_holder[0].wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc_holder[0].kill()
        if capture_fh:
            capture_fh.close()

    # Print the last snapshot so the user is not left with a blank screen.
    if final_content:
        print()
        for line in final_content:
            print(line)

    # Generate policies from selected flows (triggered by Enter in select mode).
    if generate_flag and selected_keys_final:
        policies = _build_policies_from_flow_keys(selected_keys_final)
        sorted_policies = [(ns, app, rules) for (ns, app), rules in sorted(policies.items())]
        n_pol = len(sorted_policies)
        print(
            f"\nGenerating {n_pol} {'policy' if n_pol == 1 else 'policies'} "
            f"from {len(selected_keys_final)} selected flows...",
            file=sys.stderr,
        )
        if args.dry_run:
            _write_multi_doc_yaml(sorted_policies, sys.stdout)
        else:
            written = _write_policy_dir(sorted_policies, args.output_dir)
            print(
                f"Wrote {written} {'policy' if written == 1 else 'policies'} "
                f"to {os.path.realpath(args.output_dir)}",
                file=sys.stderr,
            )

    print("\nWatch mode stopped.", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hubble-audit2policy",
        description="Generate CiliumNetworkPolicy YAML from Hubble AUDIT flows.",
        epilog="""\
Capture flows with Hubble before running this tool:

  # Single namespace:
  hubble observe -P -n <namespace> --verdict AUDIT -o json -f > <namespace>-flows.json

  # All namespaces:
  hubble observe -P --all-namespaces --verdict AUDIT -o json -f > cluster-flows.json

Then generate policies:

  %(prog)s <namespace>-flows.json -o policies/
  %(prog)s cluster-flows.json --dry-run > all-policies.yaml
  %(prog)s cluster-flows.json --single-file policies/all.yaml
  %(prog)s cluster-flows.json --report
  %(prog)s cluster-flows.json --report --dry-run
  %(prog)s cluster-flows.json -n monitoring -n default -o policies/

Live monitoring mode (replaces watch -n1 ... --report-only):

  %(prog)s --watch                          # all namespaces, auto-detect hubble
  %(prog)s --watch -n default               # single namespace
  %(prog)s --watch --interval 5             # refresh every 5 seconds
  %(prog)s --watch --window 120             # rolling 2-minute view
  %(prog)s --watch --label-key k8s:name     # custom workload label
  %(prog)s flows.json --watch               # seed from file, then follow live
  %(prog)s --watch --hubble-cmd 'kubectl exec -n kube-system cilium-xyz -- hubble observe'

Capture while watching, then generate policies:

  %(prog)s --watch --capture-file session.jsonl
  %(prog)s session.jsonl -o policies/

Interactive flow selection (press s in watch mode):

  %(prog)s --watch --output-dir policies/
  # inside TUI: s to select, j/k to move, Space to toggle, Enter to generate
  %(prog)s --watch --dry-run   # preview selected policies on stdout

Loki backend (query flows stored in Grafana Loki):

  %(prog)s --from loki --loki-url http://loki:3100 --dry-run
  %(prog)s --from loki --loki-url http://loki:3100 -n kube-system -o policies/
  %(prog)s --from loki --loki-url http://loki:3100 --since 2h --until 30m
  %(prog)s --from loki --loki-url http://loki:3100 --loki-query '{namespace="hubble"}'
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "flows_file",
        nargs="?",
        default=None,
        help=(
            "Path to Hubble flows file (JSONL or JSON array). "
            "Required unless --watch is used (where it optionally seeds initial history)."
        ),
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=".",
        help="Directory to write policy YAML files (default: current directory)",
    )
    parser.add_argument(
        "-n",
        "--namespace",
        action="append",
        default=None,
        dest="namespaces",
        help="Only generate policies for this namespace (can be repeated)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated policies to stdout instead of writing files",
    )
    parser.add_argument(
        "--single-file",
        metavar="FILE",
        help="Write all policies to a single multi-document YAML file",
    )
    parser.add_argument(
        "--verdict",
        action="append",
        default=None,
        help="Only include flows with this verdict (can be repeated; default: all)",
    )
    parser.add_argument(
        "--label-key",
        action="append",
        default=None,
        dest="label_keys",
        help=(
            "Kubernetes label key used to identify workloads, "
            "prefixed with 'k8s:' (can be repeated; "
            "default: k8s:app, k8s:app.kubernetes.io/name)"
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a frequency report of unique observed flows to stderr",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Print the flow report and exit without generating policies",
    )
    parser.add_argument(
        "-w",
        "--watch",
        action="store_true",
        help=(
            "Interactive TUI mode with flow-frequency report, scrolling, "
            "and workload selection for policy generation. "
            "In live mode (default): spawns hubble observe and continuously "
            "refreshes. With --from loki: fetches historical flows from "
            "Loki and presents them in the same interactive TUI."
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Screen refresh interval for --watch mode (default: 2.0)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help=(
            "Rolling time window for --watch mode: only count flows received "
            "in the last N seconds (default: 0 = keep all flows)"
        ),
    )
    parser.add_argument(
        "--hubble-cmd",
        default=None,
        metavar="CMD",
        help=(
            "Override the hubble observe command used by --watch mode. "
            "Accepts a shell-quoted string, e.g. "
            "'kubectl exec -n kube-system <pod> -- hubble observe'. "
            "Default: auto-detect 'hubble' on PATH, fall back to kubectl exec."
        ),
    )
    parser.add_argument(
        "--capture-file",
        metavar="FILE",
        help=(
            "Write all flows received during --watch mode to FILE as JSONL. "
            "The file is created (or overwritten) at the start of each session. "
            "Use the file later to generate policies: "
            "%(prog)s FILE -o policies/"
        ),
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help=(
            "Skip live cluster enrichment. By default the tool queries "
            "cilium endpoint list / cilium endpoint get on each Cilium pod "
            "to resolve the authoritative security labels for every workload "
            "seen in the flows. Use this flag when kubectl is unavailable or "
            "you deliberately want to work offline."
        ),
    )

    # --- Loki backend ---
    loki_group = parser.add_argument_group(
        "Loki backend",
        "Fetch flows from a Grafana Loki instance instead of a local file.",
    )
    loki_group.add_argument(
        "--from",
        dest="source",
        choices=["file", "loki"],
        default="file",
        help="Flow source backend (default: file)",
    )
    loki_group.add_argument(
        "--loki-url",
        metavar="URL",
        help="Loki base URL, e.g. http://loki:3100",
    )
    loki_group.add_argument(
        "--loki-query",
        default='{app="hubble"}',
        metavar="LOGQL",
        help='LogQL stream selector (default: {app="hubble"})',
    )
    loki_group.add_argument(
        "--since",
        default="1h",
        metavar="DURATION",
        help="How far back to query, e.g. 30m, 2h, 1d (default: 1h)",
    )
    loki_group.add_argument(
        "--until",
        default="0s",
        metavar="DURATION",
        help="End of query window as duration before now (default: 0s = now)",
    )
    loki_group.add_argument(
        "--loki-limit",
        type=int,
        default=5000,
        metavar="N",
        help="Max entries per Loki request batch (default: 5000)",
    )
    loki_group.add_argument(
        "--loki-user",
        metavar="USER",
        help="Username for Loki HTTP Basic authentication",
    )
    loki_group.add_argument(
        "--loki-password",
        metavar="PASSWORD",
        help="Password for Loki HTTP Basic authentication (used with --loki-user)",
    )
    loki_group.add_argument(
        "--loki-token",
        metavar="TOKEN",
        help="Bearer token for Loki (Authorization: Bearer ...) header",
    )
    loki_group.add_argument(
        "--loki-tls-ca",
        metavar="PATH",
        help="Path to a PEM CA certificate for verifying the Loki server (self-signed certs)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=logging.DEBUG if args.verbose else logging.WARNING,
    )

    # Interactive watch mode with TUI.
    if args.watch:
        if args.source == "loki":
            _loki_watch_mode(args)
        else:
            _watch_mode(args)
        return

    verdicts: set[str] = {v.upper() for v in args.verdict} if args.verdict else set()
    namespaces = set(args.namespaces or [])
    label_keys = args.label_keys or DEFAULT_LABEL_KEYS

    # --- Select flow source ---
    if args.source == "loki":
        if not args.loki_url:
            parser.error("--loki-url is required when using --from loki")
        if args.loki_token and args.loki_user:
            parser.error("--loki-token and --loki-user are mutually exclusive")
        if args.loki_password and not args.loki_user:
            parser.error("--loki-password requires --loki-user")
        since_sec = _parse_duration(args.since)
        until_sec = _parse_duration(args.until)
        loki_iter = _read_flows_loki(
            args.loki_url,
            args.loki_query,
            since_sec,
            until_sec,
            args.loki_limit,
            loki_user=args.loki_user,
            loki_password=args.loki_password,
            loki_token=args.loki_token,
            loki_tls_ca=args.loki_tls_ca,
        )
        print(
            f"Querying Loki at {args.loki_url} "
            f"(query={args.loki_query!r}, since={args.since}, until={args.until}) ...",
            file=sys.stderr,
        )
        policies, flow_counts, total, matched, app_pods = parse_flows(
            "", label_keys, verdicts, namespaces, flow_iter=loki_iter
        )
    else:
        if not args.flows_file:
            parser.error("flows_file is required unless --watch or --from loki is used")
        if not os.path.isfile(args.flows_file):
            LOG.error("Flows file not found: %s", args.flows_file)
            sys.exit(EXIT_ERROR)
        policies, flow_counts, total, matched, app_pods = parse_flows(
            args.flows_file, label_keys, verdicts, namespaces
        )

    # --- Detect unidentified endpoints ---
    unknown_keys = _find_unknown_flows(flow_counts)
    has_unknowns = len(unknown_keys) > 0

    # --- Report modes (forced when unknowns exist) ---
    if args.report or args.report_only or has_unknowns:
        _print_report(flow_counts, total, matched)

    if has_unknowns:
        _print_unknown_warnings(unknown_keys, flow_counts)

    if args.report_only:
        sys.exit(EXIT_OK)

    if not policies:
        LOG.warning("No policies generated (parsed %d flows, %d matched)", total, matched)
        sys.exit(EXIT_NO_POLICIES)

    # --- Cluster enrichment: resolve authoritative Cilium security labels ---
    workload_labels: WorkloadLabels = {}
    if not args.no_enrich:
        all_pods: set[tuple[str, str]] = {pod for pods in app_pods.values() for pod in pods}
        if all_pods:
            endpoint_cache = build_endpoint_label_cache(all_pods)
            if endpoint_cache:
                enriched = 0
                for (ns, app), pods in app_pods.items():
                    for ns_p, pod_name in sorted(pods):
                        if (ns_p, pod_name) in endpoint_cache:
                            workload_labels[(ns, app)] = _security_labels_to_match_labels(
                                endpoint_cache[(ns_p, pod_name)]
                            )
                            enriched += 1
                            break
                print(
                    f"Cluster enrichment: {enriched}/{len(app_pods)} workload(s) "
                    f"enriched with real Cilium labels.",
                    file=sys.stderr,
                )
        else:
            print(
                "Cluster enrichment skipped: no pod names found in flow data "
                "(flows may pre-date the pod_name field). "
                "Use --no-enrich to silence this warning.",
                file=sys.stderr,
            )

    # Build sorted iteration for consistent output.
    sorted_policies: list[tuple[str, str, RuleSet]] = [
        (ns, app, rules) for (ns, app), rules in sorted(policies.items())
    ]

    # --- Dry-run: print to stdout ---
    if args.dry_run:
        _write_multi_doc_yaml(sorted_policies, sys.stdout, workload_labels=workload_labels)
        _print_summary(total, matched, len(sorted_policies))
        return

    # --- Single-file mode ---
    if args.single_file:
        out_dir = os.path.dirname(os.path.abspath(args.single_file))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.single_file, "w", encoding="utf-8") as fh:
            _write_multi_doc_yaml(sorted_policies, fh, workload_labels=workload_labels)
        _print_summary(total, matched, len(sorted_policies))
        print(f"Wrote {len(sorted_policies)} policies to {args.single_file}", file=sys.stderr)
        return

    # --- Multi-file mode (default) ---
    written = _write_policy_dir(sorted_policies, args.output_dir, workload_labels=workload_labels)
    _print_summary(total, matched, written)


if __name__ == "__main__":
    main()
