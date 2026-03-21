"""Tests for flow parsing: _apply_flow, _parse_flow_list, _read_flows, and file I/O."""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter, defaultdict
from typing import Any

import hubble_audit2policy as h


def _make_flow(
    src_ns: str = "default",
    src_app: str = "frontend",
    src_pod: str = "frontend-abc",
    dst_ns: str = "default",
    dst_app: str = "api",
    dst_pod: str = "api-xyz",
    port: int = 8080,
    proto: str = "TCP",
    verdict: str = "AUDIT",
    src_labels: list[str] | None = None,
    dst_labels: list[str] | None = None,
) -> dict[str, Any]:
    """Build a minimal Hubble flow dict for testing."""
    return {
        "verdict": verdict,
        "source": {
            "namespace": src_ns,
            "labels": src_labels or [f"k8s:app={src_app}"],
            "pod_name": src_pod,
        },
        "destination": {
            "namespace": dst_ns,
            "labels": dst_labels or [f"k8s:app={dst_app}"],
            "pod_name": dst_pod,
        },
        "l4": {proto: {"destination_port": port}},
    }


LABEL_KEYS = h.DEFAULT_LABEL_KEYS


class TestApplyFlow:
    def _run(
        self,
        flow: dict[str, Any],
        namespaces: set[str] | None = None,
    ) -> tuple[bool, dict[h.PolicyKey, h.RuleSet], Counter[h.FlowKey]]:
        policies: defaultdict[h.PolicyKey, h.RuleSet] = defaultdict(
            lambda: {"egress": set(), "ingress": set()}
        )
        flow_counts: Counter[h.FlowKey] = Counter()
        app_pods: defaultdict[h.PolicyKey, set[tuple[str, str]]] = defaultdict(set)
        hit = h._apply_flow(flow, LABEL_KEYS, namespaces or set(), policies, flow_counts, app_pods)
        return hit, dict(policies), flow_counts

    def test_basic_flow_creates_egress_and_ingress(self) -> None:
        hit, policies, counts = self._run(_make_flow())
        assert hit is True
        assert ("default", "frontend") in policies
        assert ("default", "api") in policies
        assert len(policies[("default", "frontend")]["egress"]) == 1
        assert len(policies[("default", "api")]["ingress"]) == 1

    def test_no_l4_returns_false(self) -> None:
        flow = _make_flow()
        flow["l4"] = {}
        hit, policies, _ = self._run(flow)
        assert hit is False
        assert len(policies) == 0

    def test_namespace_filter(self) -> None:
        hit, policies, _ = self._run(_make_flow(), namespaces={"monitoring"})
        assert hit is False
        assert len(policies) == 0

    def test_namespace_filter_partial_match(self) -> None:
        flow = _make_flow(src_ns="monitoring", src_app="prom", dst_ns="default", dst_app="api")
        hit, policies, _ = self._run(flow, namespaces={"monitoring"})
        assert hit is True
        assert ("monitoring", "prom") in policies
        assert ("default", "api") not in policies

    def test_reserved_entity_destination(self) -> None:
        flow = _make_flow(dst_labels=["reserved:world"], dst_ns="", dst_pod="")
        hit, policies, _ = self._run(flow)
        assert hit is True
        egress_rules = policies[("default", "frontend")]["egress"]
        assert any(r[1] == "entity:world" for r in egress_rules)

    def test_udp_protocol(self) -> None:
        flow = _make_flow(port=53, proto="UDP")
        flow["l4"] = {"UDP": {"destination_port": 53}}
        hit, policies, _ = self._run(flow)
        assert hit is True
        egress = policies[("default", "frontend")]["egress"]
        assert (("default", "api", 53, "UDP")) in egress


class TestParseFlowList:
    def test_basic_list(self) -> None:
        flows = [_make_flow(), _make_flow(port=443)]
        policies, counts, total, matched, app_pods = h._parse_flow_list(
            flows, LABEL_KEYS, set(), set()
        )
        assert total == 2
        assert matched == 2
        assert ("default", "frontend") in policies
        assert ("default", "api") in policies

    def test_verdict_filter(self) -> None:
        flows = [_make_flow(verdict="AUDIT"), _make_flow(verdict="FORWARDED")]
        _, _, total, matched, _ = h._parse_flow_list(flows, LABEL_KEYS, {"AUDIT"}, set())
        assert total == 2
        assert matched == 1

    def test_empty_list(self) -> None:
        policies, counts, total, matched, _ = h._parse_flow_list([], LABEL_KEYS, set(), set())
        assert total == 0
        assert matched == 0
        assert len(policies) == 0


class TestReadFlows:
    def test_jsonl_format(self) -> None:
        flows = [_make_flow(port=80), _make_flow(port=443)]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for flow in flows:
                f.write(json.dumps(flow) + "\n")
            path = f.name
        try:
            result = list(h._read_flows(path))
            assert len(result) == 2
            assert result[0][0] == 1  # lineno
            assert result[1][0] == 2
        finally:
            os.unlink(path)

    def test_json_array_format(self) -> None:
        flows = [_make_flow(port=80), _make_flow(port=443)]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(flows, f)
            path = f.name
        try:
            result = list(h._read_flows(path))
            assert len(result) == 2
        finally:
            os.unlink(path)

    def test_empty_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
        try:
            result = list(h._read_flows(path))
            assert len(result) == 0
        finally:
            os.unlink(path)

    def test_malformed_jsonl_skips_bad_lines(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps(_make_flow()) + "\n")
            f.write("NOT VALID JSON\n")
            f.write(json.dumps(_make_flow()) + "\n")
            path = f.name
        try:
            result = list(h._read_flows(path))
            assert len(result) == 2
        finally:
            os.unlink(path)

    def test_flow_envelope_unwrap(self) -> None:
        """parse_flows should unwrap the {"flow": {...}} envelope."""
        inner = _make_flow()
        wrapped = [{"flow": inner}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(wrapped, f)
            path = f.name
        try:
            policies, _, total, matched, _ = h.parse_flows(path, LABEL_KEYS, set(), set())
            assert total == 1
            assert matched == 1
            assert len(policies) > 0
        finally:
            os.unlink(path)


class TestWritePolicyDir:
    def test_writes_files(self) -> None:
        rules: h.RuleSet = {
            "egress": {("default", "db", 5432, "TCP")},
            "ingress": set(),
        }
        sorted_policies = [("default", "api", rules)]
        with tempfile.TemporaryDirectory() as tmpdir:
            written = h._write_policy_dir(sorted_policies, tmpdir)
            assert written == 1
            files = os.listdir(tmpdir)
            assert "default-api.yaml" in files

    def test_skips_unsanitizable(self) -> None:
        rules: h.RuleSet = {"egress": set(), "ingress": set()}
        sorted_policies = [("", "api", rules)]
        with tempfile.TemporaryDirectory() as tmpdir:
            written = h._write_policy_dir(sorted_policies, tmpdir)
            assert written == 0
