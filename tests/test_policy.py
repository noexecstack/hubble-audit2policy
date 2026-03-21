"""Tests for policy construction: consolidation, build_policy, and enrichment labels."""

from __future__ import annotations

import hubble_audit2policy as h


class TestConsolidateRules:
    def test_merges_ports_by_endpoint(self) -> None:
        rules: set[h.RuleTuple] = {
            ("default", "api", 80, "TCP"),
            ("default", "api", 443, "TCP"),
        }
        result = h._consolidate_rules(rules)
        assert len(result) == 1
        ns, app, ports = result[0]
        assert ns == "default"
        assert app == "api"
        assert ports == [(80, "TCP"), (443, "TCP")]

    def test_separate_endpoints(self) -> None:
        rules: set[h.RuleTuple] = {
            ("default", "api", 80, "TCP"),
            ("monitoring", "prometheus", 9090, "TCP"),
        }
        result = h._consolidate_rules(rules)
        assert len(result) == 2

    def test_empty_rules(self) -> None:
        assert h._consolidate_rules(set()) == []

    def test_sorted_output(self) -> None:
        rules: set[h.RuleTuple] = {
            ("z-ns", "z-app", 80, "TCP"),
            ("a-ns", "a-app", 80, "TCP"),
        }
        result = h._consolidate_rules(rules)
        assert result[0][0] == "a-ns"
        assert result[1][0] == "z-ns"


class TestBuildPolicy:
    def test_basic_egress_and_ingress(self) -> None:
        rules: h.RuleSet = {
            "egress": {("monitoring", "prometheus", 9090, "TCP")},
            "ingress": {("default", "frontend", 8080, "TCP")},
        }
        policy = h.build_policy("default", "api", rules)

        assert policy["apiVersion"] == "cilium.io/v2"
        assert policy["kind"] == "CiliumNetworkPolicy"
        assert policy["metadata"]["name"] == "allow-api"
        assert policy["metadata"]["namespace"] == "default"
        assert policy["spec"]["endpointSelector"]["matchLabels"]["app"] == "api"
        assert len(policy["spec"]["egress"]) == 1
        assert len(policy["spec"]["ingress"]) == 1

    def test_egress_only(self) -> None:
        rules: h.RuleSet = {
            "egress": {("", "entity:world", 443, "TCP")},
            "ingress": set(),
        }
        policy = h.build_policy("default", "api", rules)
        assert "egress" in policy["spec"]
        assert "ingress" not in policy["spec"]

    def test_ingress_only(self) -> None:
        rules: h.RuleSet = {
            "egress": set(),
            "ingress": {("default", "frontend", 8080, "TCP")},
        }
        policy = h.build_policy("default", "api", rules)
        assert "ingress" in policy["spec"]
        assert "egress" not in policy["spec"]

    def test_entity_egress(self) -> None:
        rules: h.RuleSet = {
            "egress": {("", "entity:world", 443, "TCP")},
            "ingress": set(),
        }
        policy = h.build_policy("default", "api", rules)
        egress_rule = policy["spec"]["egress"][0]
        assert egress_rule["toEntities"] == ["world"]
        assert "toEndpoints" not in egress_rule

    def test_entity_ingress(self) -> None:
        rules: h.RuleSet = {
            "egress": set(),
            "ingress": {("", "entity:host", 4240, "TCP")},
        }
        policy = h.build_policy("default", "api", rules)
        ingress_rule = policy["spec"]["ingress"][0]
        assert ingress_rule["fromEntities"] == ["host"]
        assert "fromEndpoints" not in ingress_rule

    def test_cross_namespace_label(self) -> None:
        rules: h.RuleSet = {
            "egress": {("monitoring", "prometheus", 9090, "TCP")},
            "ingress": set(),
        }
        policy = h.build_policy("default", "api", rules)
        to_ep = policy["spec"]["egress"][0]["toEndpoints"][0]["matchLabels"]
        assert to_ep["app"] == "prometheus"
        assert to_ep["k8s:io.kubernetes.pod.namespace"] == "monitoring"

    def test_same_namespace_no_extra_label(self) -> None:
        rules: h.RuleSet = {
            "egress": {("default", "db", 5432, "TCP")},
            "ingress": set(),
        }
        policy = h.build_policy("default", "api", rules)
        to_ep = policy["spec"]["egress"][0]["toEndpoints"][0]["matchLabels"]
        assert to_ep == {"app": "db"}

    def test_workload_labels_enrichment(self) -> None:
        rules: h.RuleSet = {
            "egress": set(),
            "ingress": {("default", "frontend", 8080, "TCP")},
        }
        wl: h.WorkloadLabels = {
            ("default", "api"): {"app": "api", "version": "v2"},
            ("default", "frontend"): {"app": "frontend", "tier": "web"},
        }
        policy = h.build_policy("default", "api", rules, workload_labels=wl)
        selector = policy["spec"]["endpointSelector"]["matchLabels"]
        assert selector == {"app": "api", "version": "v2"}
        from_ep = policy["spec"]["ingress"][0]["fromEndpoints"][0]["matchLabels"]
        assert from_ep == {"app": "frontend", "tier": "web"}

    def test_port_as_string(self) -> None:
        rules: h.RuleSet = {
            "egress": {("default", "db", 5432, "TCP")},
            "ingress": set(),
        }
        policy = h.build_policy("default", "api", rules)
        port_entry = policy["spec"]["egress"][0]["toPorts"][0]["ports"][0]
        assert port_entry["port"] == "5432"
        assert port_entry["protocol"] == "TCP"


class TestSecurityLabelsToMatchLabels:
    def test_basic_conversion(self) -> None:
        labels = ["k8s:app=nginx", "k8s:version=v1"]
        result = h._security_labels_to_match_labels(labels)
        assert result == {"app": "nginx", "version": "v1"}

    def test_excludes_namespace_labels(self) -> None:
        labels = [
            "k8s:app=nginx",
            "k8s:io.cilium.k8s.namespace.labels.team=platform",
        ]
        result = h._security_labels_to_match_labels(labels)
        assert "io.cilium.k8s.namespace.labels.team" not in result
        assert result == {"app": "nginx"}

    def test_excludes_cluster_label(self) -> None:
        labels = ["k8s:app=nginx", "k8s:io.cilium.k8s.policy.cluster=default"]
        result = h._security_labels_to_match_labels(labels)
        assert result == {"app": "nginx"}

    def test_excludes_reserved(self) -> None:
        labels = ["k8s:app=nginx", "reserved:host"]
        result = h._security_labels_to_match_labels(labels)
        assert result == {"app": "nginx"}

    def test_skips_no_equals(self) -> None:
        labels = ["k8s:app=nginx", "k8s:malformed"]
        result = h._security_labels_to_match_labels(labels)
        assert result == {"app": "nginx"}
