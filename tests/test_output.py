"""Tests for output helpers, display functions, watch-mode key handling, and error paths."""

from __future__ import annotations

import argparse
import io
from collections import Counter

import pytest
import yaml

import hubble_audit2policy as h

# ---------------------------------------------------------------------------
# _dump_yaml / _write_multi_doc_yaml
# ---------------------------------------------------------------------------


class TestDumpYaml:
    def test_basic_roundtrip(self) -> None:
        policy = h.build_policy(
            "default", "web", {"egress": {("default", "api", 8080, "TCP")}, "ingress": set()}
        )
        buf = io.StringIO()
        h._dump_yaml(policy, buf)
        loaded = yaml.safe_load(buf.getvalue())
        assert loaded["metadata"]["name"] == "allow-web"
        assert loaded["metadata"]["namespace"] == "default"

    def test_preserves_key_order(self) -> None:
        policy = h.build_policy(
            "ns", "app", {"egress": {("ns", "peer", 443, "TCP")}, "ingress": set()}
        )
        buf = io.StringIO()
        h._dump_yaml(policy, buf)
        text = buf.getvalue()
        api_pos = text.index("apiVersion")
        kind_pos = text.index("kind")
        meta_pos = text.index("metadata")
        assert api_pos < kind_pos < meta_pos


class TestWriteMultiDocYaml:
    def test_two_policies_separated_by_doc_marker(self) -> None:
        policies = [
            ("ns1", "app1", {"egress": {("ns1", "peer", 80, "TCP")}, "ingress": set()}),
            ("ns2", "app2", {"egress": set(), "ingress": {("ns2", "src", 443, "TCP")}}),
        ]
        buf = io.StringIO()
        h._write_multi_doc_yaml(policies, buf)
        text = buf.getvalue()
        docs = list(yaml.safe_load_all(text))
        assert len(docs) == 2
        assert docs[0]["metadata"]["name"] == "allow-app1"
        assert docs[1]["metadata"]["name"] == "allow-app2"

    def test_single_policy_no_separator(self) -> None:
        policies = [
            ("ns", "app", {"egress": {("ns", "peer", 80, "TCP")}, "ingress": set()}),
        ]
        buf = io.StringIO()
        h._write_multi_doc_yaml(policies, buf)
        assert "---" not in buf.getvalue()


# ---------------------------------------------------------------------------
# _find_unknown_flows
# ---------------------------------------------------------------------------


class TestFindUnknownFlows:
    def test_detects_unknown_source(self) -> None:
        counts: Counter[h.FlowKey] = Counter()
        key: h.FlowKey = ("ns", "unknown", "ns", "app", 80, "TCP")
        counts[key] = 3
        result = h._find_unknown_flows(counts)
        assert key in result

    def test_detects_unknown_destination(self) -> None:
        counts: Counter[h.FlowKey] = Counter()
        key: h.FlowKey = ("ns", "app", "ns", "unknown", 80, "TCP")
        counts[key] = 1
        result = h._find_unknown_flows(counts)
        assert key in result

    def test_ignores_known_flows(self) -> None:
        counts: Counter[h.FlowKey] = Counter()
        key: h.FlowKey = ("ns", "web", "ns", "api", 80, "TCP")
        counts[key] = 5
        assert h._find_unknown_flows(counts) == []


# ---------------------------------------------------------------------------
# _print_unknown_warnings
# ---------------------------------------------------------------------------


class TestPrintUnknownWarnings:
    def test_contains_warning_and_hint(self) -> None:
        counts: Counter[h.FlowKey] = Counter()
        key: h.FlowKey = ("ns", "unknown", "ns", "api", 80, "TCP")
        counts[key] = 2
        buf = io.StringIO()
        h._print_unknown_warnings([key], counts, file=buf)
        text = buf.getvalue()
        assert "WARNING" in text
        assert "--label-key" in text
        assert "x2" in text


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_singular_policy(self) -> None:
        buf = io.StringIO()
        h._print_summary(10, 5, 1, file=buf)
        text = buf.getvalue()
        assert "1 policy" in text
        assert "policies" not in text

    def test_plural_policies(self) -> None:
        buf = io.StringIO()
        h._print_summary(100, 50, 3, file=buf)
        assert "3 policies" in buf.getvalue()

    def test_counts_present(self) -> None:
        buf = io.StringIO()
        h._print_summary(42, 17, 5, file=buf)
        text = buf.getvalue()
        assert "42" in text
        assert "17" in text


# ---------------------------------------------------------------------------
# _trunc
# ---------------------------------------------------------------------------


class TestTrunc:
    def test_short_string_unchanged(self) -> None:
        assert h._trunc("hello", 10) == "hello"

    def test_exact_width_unchanged(self) -> None:
        assert h._trunc("12345", 5) == "12345"

    def test_long_string_truncated(self) -> None:
        result = h._trunc("abcdefghij", 7)
        assert result == "abcd..."
        assert len(result) == 7

    def test_uses_ascii_ellipsis(self) -> None:
        result = h._trunc("a" * 20, 10)
        assert result.endswith("...")
        assert "\u2026" not in result


# ---------------------------------------------------------------------------
# _print_report
# ---------------------------------------------------------------------------


class TestPrintReport:
    def _make_counts(self) -> Counter[h.FlowKey]:
        counts: Counter[h.FlowKey] = Counter()
        counts[("ns", "web", "ns", "api", 8080, "TCP")] = 10
        counts[("ns", "api", "ns", "db", 5432, "TCP")] = 5
        return counts

    def test_returns_keys_in_frequency_order(self) -> None:
        counts = self._make_counts()
        buf = io.StringIO()
        keys = h._print_report(counts, 15, 15, file=buf, term_width=120)
        assert len(keys) == 2
        # Most common first
        assert keys[0] == ("ns", "web", "ns", "api", 8080, "TCP")
        assert keys[1] == ("ns", "api", "ns", "db", 5432, "TCP")

    def test_output_contains_header_and_data(self) -> None:
        counts = self._make_counts()
        buf = io.StringIO()
        h._print_report(counts, 15, 15, file=buf, term_width=120)
        text = buf.getvalue()
        assert "FLOW REPORT" in text
        assert "COUNT" in text
        assert "SOURCE" in text
        assert "DESTINATION" in text
        assert "8080" in text
        assert "5432" in text

    def test_empty_counts(self) -> None:
        counts: Counter[h.FlowKey] = Counter()
        buf = io.StringIO()
        keys = h._print_report(counts, 0, 0, file=buf, term_width=80)
        assert keys == []
        assert "FLOW REPORT" in buf.getvalue()

    def test_narrow_terminal_does_not_crash(self) -> None:
        counts = self._make_counts()
        buf = io.StringIO()
        keys = h._print_report(counts, 15, 15, file=buf, term_width=40)
        assert len(keys) == 2


# ---------------------------------------------------------------------------
# _ReconnectState
# ---------------------------------------------------------------------------


class TestReconnectState:
    def test_initial_values(self) -> None:
        rs = h._ReconnectState()
        assert rs.delay == 2.0
        assert rs.at == 0.0

    def test_reset(self) -> None:
        rs = h._ReconnectState()
        rs.delay = 32.0
        rs.reset()
        assert rs.delay == 2.0

    def test_backoff_doubles(self) -> None:
        rs = h._ReconnectState()
        rs.backoff(100.0)
        assert rs.at == 102.0
        assert rs.delay == 4.0

    def test_backoff_caps_at_max(self) -> None:
        rs = h._ReconnectState()
        for _ in range(20):
            rs.backoff(0.0)
        assert rs.delay == 60.0


# ---------------------------------------------------------------------------
# _handle_key
# ---------------------------------------------------------------------------


_DEFAULT_KEY_ARGS = {
    "is_paused": False,
    "is_selecting": False,
    "cursor_flow_idx": 0,
    "ordered_keys": [],
    "selected_keys": set(),
    "scroll_offset": 0,
    "is_following": True,
    "half_page": 10,
    "content_lines_len": 50,
}


class TestHandleKey:
    def _call(self, key: int, **overrides: object) -> tuple[object, ...]:
        kw = {**_DEFAULT_KEY_ARGS, **overrides}
        return h._handle_key(key, **kw)  # type: ignore[arg-type]

    def test_quit_q(self) -> None:
        result = self._call(ord("q"))
        assert result[0] is True  # quit signal

    def test_quit_ctrl_c(self) -> None:
        result = self._call(3)
        assert result[0] is True

    def test_space_toggles_pause(self) -> None:
        result = self._call(ord(" "), is_paused=False)
        assert result[1] is True  # is_paused

    def test_space_unpauses(self) -> None:
        result = self._call(ord(" "), is_paused=True)
        assert result[1] is False

    def test_j_scrolls_down(self) -> None:
        result = self._call(ord("j"), scroll_offset=5)
        assert result[4] == 6  # scroll_offset

    def test_k_scrolls_up(self) -> None:
        result = self._call(ord("k"), scroll_offset=5, is_following=False)
        assert result[4] == 4

    def test_g_jumps_to_top(self) -> None:
        result = self._call(ord("g"), scroll_offset=20, is_following=False)
        assert result[4] == 0  # scroll_offset
        assert result[5] is True  # is_following

    def test_s_enters_select_mode(self) -> None:
        keys: list[h.FlowKey] = [("ns", "a", "ns", "b", 80, "TCP")]
        result = self._call(ord("s"), ordered_keys=keys)
        assert result[2] is True  # is_selecting

    def test_s_noop_when_no_keys(self) -> None:
        result = self._call(ord("s"), ordered_keys=[])
        assert result[0] is None  # no-op
        assert result[2] is False  # still not selecting

    def test_enter_generates_when_selecting(self) -> None:
        keys: list[h.FlowKey] = [("ns", "a", "ns", "b", 80, "TCP")]
        selected: set[h.FlowKey] = {keys[0]}
        result = self._call(ord("\r"), is_selecting=True, ordered_keys=keys, selected_keys=selected)
        assert result[0] is True  # quit
        assert result[6] is True  # generate_flag

    def test_unknown_key_returns_none(self) -> None:
        result = self._call(ord("z"))
        assert result[0] is None  # no-op


# ---------------------------------------------------------------------------
# Error path tests
# ---------------------------------------------------------------------------


class TestParseDurationErrors:
    def test_invalid_unit(self) -> None:
        with pytest.raises(argparse.ArgumentTypeError):
            h._parse_duration("5x")

    def test_empty_string(self) -> None:
        with pytest.raises(argparse.ArgumentTypeError):
            h._parse_duration("")

    def test_letters_only(self) -> None:
        with pytest.raises(argparse.ArgumentTypeError):
            h._parse_duration("abc")


class TestReadFlowsErrors:
    def test_nonexistent_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            list(h._read_flows("/tmp/nonexistent_hubble_flows_12345.jsonl"))

    def test_completely_malformed_file(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not json at all\n")
            f.write("{totally broken\n")
            path = f.name
        try:
            result = list(h._read_flows(path))
            assert result == []
        finally:
            import os

            os.unlink(path)
