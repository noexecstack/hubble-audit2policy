"""Tests for helper functions: sanitize_name, label parsing, reserved identities."""

from __future__ import annotations

import hubble_audit2policy as h


class TestSanitizeName:
    def test_basic(self) -> None:
        assert h.sanitize_name("my-app") == "my-app"

    def test_strips_unsafe_chars(self) -> None:
        assert h.sanitize_name("../../etc/passwd") == "....etcpasswd"

    def test_preserves_dots_and_hyphens(self) -> None:
        assert h.sanitize_name("app.v2-beta") == "app.v2-beta"

    def test_none_returns_empty(self) -> None:
        assert h.sanitize_name(None) == ""

    def test_empty_string(self) -> None:
        assert h.sanitize_name("") == ""

    def test_unicode_stripped(self) -> None:
        assert h.sanitize_name("app_naïve") == "appnave"


class TestParseIdentityLabel:
    KEYS = ["k8s:app", "k8s:app.kubernetes.io/name"]

    def test_matches_first_key(self) -> None:
        labels = ["k8s:app=nginx"]
        assert h._parse_identity_label(labels, self.KEYS) == "nginx"

    def test_matches_fallback_key(self) -> None:
        labels = ["k8s:app.kubernetes.io/name=grafana"]
        assert h._parse_identity_label(labels, self.KEYS) == "grafana"

    def test_priority_order_respected(self) -> None:
        """Higher-priority key wins even if lower-priority label appears first."""
        labels = [
            "k8s:app.kubernetes.io/name=grafana",
            "k8s:app=nginx",
        ]
        assert h._parse_identity_label(labels, self.KEYS) == "nginx"

    def test_no_match_returns_none(self) -> None:
        labels = ["k8s:tier=backend"]
        assert h._parse_identity_label(labels, self.KEYS) is None

    def test_none_labels(self) -> None:
        assert h._parse_identity_label(None, self.KEYS) is None

    def test_empty_labels(self) -> None:
        assert h._parse_identity_label([], self.KEYS) is None

    def test_value_with_equals(self) -> None:
        labels = ["k8s:app=key=value"]
        assert h._parse_identity_label(labels, self.KEYS) == "key=value"


class TestParseReservedIdentity:
    def test_host(self) -> None:
        assert h._parse_reserved_identity(["reserved:host"]) == "host"

    def test_world(self) -> None:
        assert h._parse_reserved_identity(["reserved:world"]) == "world"

    def test_kube_apiserver(self) -> None:
        assert h._parse_reserved_identity(["reserved:kube-apiserver"]) == "kube-apiserver"

    def test_no_reserved(self) -> None:
        assert h._parse_reserved_identity(["k8s:app=nginx"]) is None

    def test_none_labels(self) -> None:
        assert h._parse_reserved_identity(None) is None

    def test_mixed_labels(self) -> None:
        labels = ["k8s:app=nginx", "reserved:ingress"]
        assert h._parse_reserved_identity(labels) == "ingress"
