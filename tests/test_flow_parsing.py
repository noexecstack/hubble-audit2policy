"""Tests for flow parsing: _apply_flow, _parse_flow_list, _read_flows, and file I/O."""

from __future__ import annotations

import argparse
import base64
import json
import os
import tempfile
from collections import Counter, defaultdict
from typing import Any
from unittest import mock

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


class TestParseDuration:
    def test_seconds(self) -> None:
        assert h._parse_duration("30s") == 30.0

    def test_minutes(self) -> None:
        assert h._parse_duration("5m") == 300.0

    def test_hours(self) -> None:
        assert h._parse_duration("2h") == 7200.0

    def test_days(self) -> None:
        assert h._parse_duration("1d") == 86400.0

    def test_bare_number_as_seconds(self) -> None:
        assert h._parse_duration("3600") == 3600.0

    def test_whitespace_tolerance(self) -> None:
        assert h._parse_duration("  10m  ") == 600.0

    def test_invalid_raises(self) -> None:
        import pytest

        with pytest.raises(argparse.ArgumentTypeError):
            h._parse_duration("abc")

    def test_fractional(self) -> None:
        assert h._parse_duration("1.5h") == 5400.0


class TestParseTimestamp:
    def test_full_iso(self) -> None:
        import datetime

        dt = h._parse_timestamp("2026-03-27T20:00:00")
        assert dt == datetime.datetime(2026, 3, 27, 20, 0, 0)

    def test_utc_z_suffix(self) -> None:
        import datetime

        dt = h._parse_timestamp("2026-03-27T20:00:00Z")
        assert dt == datetime.datetime(
            2026, 3, 27, 20, 0, 0, tzinfo=datetime.timezone.utc
        )

    def test_date_only(self) -> None:
        import datetime

        dt = h._parse_timestamp("2026-03-27")
        assert dt == datetime.datetime(2026, 3, 27, 0, 0, 0)

    def test_with_offset(self) -> None:
        import datetime

        dt = h._parse_timestamp("2026-03-27T20:00:00+02:00")
        assert dt.utcoffset() == datetime.timedelta(hours=2)

    def test_invalid_raises(self) -> None:
        import pytest

        with pytest.raises(argparse.ArgumentTypeError):
            h._parse_timestamp("not-a-date")

    def test_whitespace_tolerance(self) -> None:
        import datetime

        dt = h._parse_timestamp("  2026-03-27T10:00:00  ")
        assert dt == datetime.datetime(2026, 3, 27, 10, 0, 0)


class TestParseTimeArg:
    def test_relative_duration(self) -> None:
        import time

        before = time.time() - 3600
        result = h._parse_time_arg("1h")
        after = time.time() - 3600
        assert before <= result <= after

    def test_absolute_timestamp(self) -> None:
        result = h._parse_time_arg("2026-03-27T00:00:00Z")
        # 2026-03-27 00:00:00 UTC
        assert abs(result - 1774569600.0) < 1.0

    def test_date_only(self) -> None:
        result = h._parse_time_arg("2026-03-27")
        # Should resolve to midnight UTC
        assert abs(result - 1774569600.0) < 1.0

    def test_zero_duration_means_now(self) -> None:
        import time

        before = time.time()
        result = h._parse_time_arg("0s")
        after = time.time()
        assert before <= result <= after


class TestParseFlowsWithIterator:
    """parse_flows accepts a flow_iter to decouple from file I/O."""

    def test_flow_iter_bypasses_file(self) -> None:
        flow = _make_flow(port=80)
        it = iter([(1, flow)])
        policies, _, total, matched, _ = h.parse_flows("", LABEL_KEYS, set(), set(), flow_iter=it)
        assert total == 1
        assert matched == 1
        assert len(policies) > 0

    def test_flow_iter_envelope_unwrap(self) -> None:
        inner = _make_flow(port=443)
        it = iter([(1, {"flow": inner})])
        policies, _, total, matched, _ = h.parse_flows("", LABEL_KEYS, set(), set(), flow_iter=it)
        assert total == 1
        assert matched == 1

    def test_flow_iter_empty(self) -> None:
        it = iter([])
        policies, _, total, matched, _ = h.parse_flows("", LABEL_KEYS, set(), set(), flow_iter=it)
        assert total == 0
        assert len(policies) == 0


class TestReadFlowsLoki:
    """Test _read_flows_loki with mocked HTTP responses."""

    @staticmethod
    def _loki_response(flows: list[dict[str, Any]]) -> bytes:
        """Build a minimal Loki query_range JSON response."""
        values = [[str(i * 1_000_000_000), json.dumps(f)] for i, f in enumerate(flows, 1)]
        body = {
            "status": "success",
            "data": {"result": [{"stream": {}, "values": values}]},
        }
        return json.dumps(body).encode()

    def test_basic_fetch(self) -> None:
        flows = [_make_flow(port=80), _make_flow(port=443)]
        resp_bytes = self._loki_response(flows)

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = resp_bytes
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 2
            assert result[0][1]["l4"]["TCP"]["destination_port"] == 80
            assert result[1][1]["l4"]["TCP"]["destination_port"] == 443

    def test_error_response(self) -> None:
        body = json.dumps({"status": "error", "message": "bad query"}).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 0

    def test_connection_error(self) -> None:
        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = OSError("connection refused")
            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 0

    def test_malformed_json_skipped(self) -> None:
        values = [
            ["1000000000", json.dumps(_make_flow(port=80))],
            ["2000000000", "NOT-JSON"],
            ["3000000000", json.dumps(_make_flow(port=443))],
        ]
        body = json.dumps(
            {
                "status": "success",
                "data": {"result": [{"stream": {}, "values": values}]},
            }
        ).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 2

    def test_pagination(self) -> None:
        """When a batch returns exactly `limit` entries, a follow-up request is made."""
        flow_a = _make_flow(port=80)
        flow_b = _make_flow(port=443)

        page1 = json.dumps(
            {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {},
                            "values": [
                                ["1000000000", json.dumps(flow_a)],
                            ],
                        }
                    ]
                },
            }
        ).encode()
        page2 = json.dumps(
            {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {},
                            "values": [
                                ["2000000000", json.dumps(flow_b)],
                            ],
                        }
                    ]
                },
            }
        ).encode()
        # Empty final page signals end of data.
        page3 = json.dumps(
            {
                "status": "success",
                "data": {"result": []},
            }
        ).encode()

        responses = []
        for page in [page1, page2, page3]:
            resp = mock.MagicMock()
            resp.read.return_value = page
            resp.__enter__ = mock.Mock(return_value=resp)
            resp.__exit__ = mock.Mock(return_value=False)
            responses.append(resp)

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.side_effect = responses
            # limit=1 forces pagination after each entry.
            result = list(
                h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0, limit=1)
            )
            assert len(result) == 2
            assert result[0][1]["l4"]["TCP"]["destination_port"] == 80
            assert result[1][1]["l4"]["TCP"]["destination_port"] == 443
            # Should have made 3 requests: page1 + page2 + empty page3.
            assert mock_open.call_count == 3

    def test_multiple_streams(self) -> None:
        """Loki may return multiple streams; all should be consumed."""
        body = json.dumps(
            {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {"pod": "a"},
                            "values": [
                                ["1000000000", json.dumps(_make_flow(port=80))],
                            ],
                        },
                        {
                            "stream": {"pod": "b"},
                            "values": [
                                ["2000000000", json.dumps(_make_flow(port=443))],
                            ],
                        },
                    ]
                },
            }
        ).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 2

    def test_query_params_forwarded(self) -> None:
        """Verify the LogQL query and direction are included in the request URL."""
        body = json.dumps(
            {
                "status": "success",
                "data": {"result": []},
            }
        ).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            list(h._read_flows_loki("http://loki:3100", '{namespace="hubble"}', 7200, 0, limit=100))
            req = mock_open.call_args[0][0]
            url = req.full_url
            assert "/loki/api/v1/query_range?" in url
            assert "namespace" in url
            assert "FORWARD" in url

    def test_empty_log_lines_skipped(self) -> None:
        body = json.dumps(
            {
                "status": "success",
                "data": {
                    "result": [
                        {
                            "stream": {},
                            "values": [
                                ["1000000000", ""],
                                ["2000000000", "   "],
                                ["3000000000", json.dumps(_make_flow(port=80))],
                            ],
                        }
                    ]
                },
            }
        ).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            result = list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            assert len(result) == 1


class TestLokiEndToEnd:
    """End-to-end: Loki response -> parse_flows -> policies."""

    def test_loki_flows_produce_policies(self) -> None:
        flows = [
            _make_flow(src_app="web", dst_app="api", port=8080),
            _make_flow(src_app="api", dst_app="db", port=5432),
        ]
        values = [[str(i * 1_000_000_000), json.dumps(f)] for i, f in enumerate(flows, 1)]
        body = json.dumps(
            {
                "status": "success",
                "data": {"result": [{"stream": {}, "values": values}]},
            }
        ).encode()

        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = body
            mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
            mock_resp.__exit__ = mock.Mock(return_value=False)
            mock_open.return_value = mock_resp

            loki_iter = h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0)
            policies, _, total, matched, _ = h.parse_flows(
                "", LABEL_KEYS, set(), set(), flow_iter=loki_iter
            )
            assert total == 2
            assert matched == 2
            # Should have policies for web, api, and db.
            apps = {app for _, app in policies}
            assert "web" in apps
            assert "api" in apps
            assert "db" in apps


class TestLokiAuth:
    """Test Loki authentication modes in _read_flows_loki."""

    @staticmethod
    def _empty_loki_response() -> bytes:
        return json.dumps({"status": "success", "data": {"result": []}}).encode()

    def _mock_urlopen(self) -> mock.MagicMock:
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = self._empty_loki_response()
        mock_resp.__enter__ = mock.Mock(return_value=mock_resp)
        mock_resp.__exit__ = mock.Mock(return_value=False)
        return mock_resp

    def test_bearer_token(self) -> None:
        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._mock_urlopen()
            list(
                h._read_flows_loki(
                    "http://loki:3100",
                    '{app="hubble"}',
                    3600,
                    0,
                    loki_token="my-secret-token",
                )
            )
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") == "Bearer my-secret-token"

    def test_basic_auth(self) -> None:
        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._mock_urlopen()
            list(
                h._read_flows_loki(
                    "http://loki:3100",
                    '{app="hubble"}',
                    3600,
                    0,
                    loki_user="admin",
                    loki_password="s3cret",
                )
            )
            req = mock_open.call_args[0][0]
            expected = "Basic " + base64.b64encode(b"admin:s3cret").decode("ascii")
            assert req.get_header("Authorization") == expected

    def test_basic_auth_no_password(self) -> None:
        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._mock_urlopen()
            list(
                h._read_flows_loki(
                    "http://loki:3100",
                    '{app="hubble"}',
                    3600,
                    0,
                    loki_user="admin",
                )
            )
            req = mock_open.call_args[0][0]
            expected = "Basic " + base64.b64encode(b"admin:").decode("ascii")
            assert req.get_header("Authorization") == expected

    def test_no_auth_header_by_default(self) -> None:
        with mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open:
            mock_open.return_value = self._mock_urlopen()
            list(h._read_flows_loki("http://loki:3100", '{app="hubble"}', 3600, 0))
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") is None

    def test_tls_ca_cert(self) -> None:
        with (
            mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open,
            mock.patch("hubble_audit2policy.ssl.create_default_context") as mock_ctx,
        ):
            mock_open.return_value = self._mock_urlopen()
            list(
                h._read_flows_loki(
                    "https://loki:3100",
                    '{app="hubble"}',
                    3600,
                    0,
                    loki_tls_ca="/path/to/ca.pem",
                )
            )
            mock_ctx.assert_called_once_with(cafile="/path/to/ca.pem")
            # The context should be passed to urlopen.
            _, kwargs = mock_open.call_args
            assert kwargs.get("context") is mock_ctx.return_value

    def test_tls_ca_with_bearer(self) -> None:
        """TLS CA and bearer token can be combined."""
        with (
            mock.patch("hubble_audit2policy.urllib.request.urlopen") as mock_open,
            mock.patch("hubble_audit2policy.ssl.create_default_context") as mock_ctx,
        ):
            mock_open.return_value = self._mock_urlopen()
            list(
                h._read_flows_loki(
                    "https://loki:3100",
                    '{app="hubble"}',
                    3600,
                    0,
                    loki_token="tok",
                    loki_tls_ca="/path/to/ca.pem",
                )
            )
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") == "Bearer tok"
            mock_ctx.assert_called_once_with(cafile="/path/to/ca.pem")

    def test_build_loki_ssl_context_none(self) -> None:
        assert h._build_loki_ssl_context(None) is None
        assert h._build_loki_ssl_context("") is None

    def test_build_loki_ssl_context_returns_ctx(self) -> None:
        with mock.patch("hubble_audit2policy.ssl.create_default_context") as mock_ctx:
            ctx = h._build_loki_ssl_context("/path/to/ca.pem")
            mock_ctx.assert_called_once_with(cafile="/path/to/ca.pem")
            assert ctx is mock_ctx.return_value
