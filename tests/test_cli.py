"""Tests for CLI entry point: argument validation, dry-run output, and exit codes."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any
from unittest import mock

import pytest
import yaml

import hubble_audit2policy as h


def _make_flow(
    src_app: str = "frontend",
    dst_app: str = "api",
    port: int = 8080,
) -> dict[str, Any]:
    """Minimal Hubble flow dict for CLI tests."""
    return {
        "verdict": "AUDIT",
        "source": {
            "namespace": "default",
            "labels": [f"k8s:app={src_app}"],
            "pod_name": f"{src_app}-abc",
        },
        "destination": {
            "namespace": "default",
            "labels": [f"k8s:app={dst_app}"],
            "pod_name": f"{dst_app}-xyz",
        },
        "l4": {"TCP": {"destination_port": port}},
    }


def _write_flows_file(flows: list[dict[str, Any]]) -> str:
    """Write flows to a temp JSONL file and return the path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for flow in flows:
        f.write(json.dumps(flow) + "\n")
    f.close()
    return f.name


class TestCliFileMode:
    def test_dry_run_prints_yaml(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with mock.patch("sys.argv", ["hubble-audit2policy", path, "--dry-run", "--no-enrich"]):
                buf = _capture_stdout(h.main)
            docs = list(yaml.safe_load_all(buf))
            assert len(docs) >= 1
            assert docs[0]["kind"] == "CiliumNetworkPolicy"
        finally:
            os.unlink(path)

    def test_output_dir_writes_files(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with mock.patch(
                    "sys.argv",
                    ["hubble-audit2policy", path, "-o", tmpdir, "--no-enrich"],
                ):
                    h.main()
                files = os.listdir(tmpdir)
                assert any(f.endswith(".yaml") for f in files)
        finally:
            os.unlink(path)

    def test_single_file_mode(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                outfile = os.path.join(tmpdir, "all.yaml")
                with mock.patch(
                    "sys.argv",
                    ["hubble-audit2policy", path, "--single-file", outfile, "--no-enrich"],
                ):
                    h.main()
                assert os.path.isfile(outfile)
                with open(outfile) as f:
                    docs = list(yaml.safe_load_all(f))
                assert len(docs) >= 1
        finally:
            os.unlink(path)

    def test_report_only_exits_ok(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with mock.patch(
                "sys.argv",
                ["hubble-audit2policy", path, "--report-only", "--no-enrich"],
            ):
                with pytest.raises(SystemExit) as exc_info:
                    h.main()
                assert exc_info.value.code == h.EXIT_OK
        finally:
            os.unlink(path)

    def test_namespace_filter(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with mock.patch(
                "sys.argv",
                ["hubble-audit2policy", path, "--dry-run", "--no-enrich", "-n", "nonexistent"],
            ):
                with pytest.raises(SystemExit) as exc_info:
                    h.main()
                assert exc_info.value.code == h.EXIT_NO_POLICIES
        finally:
            os.unlink(path)

    def test_verdict_filter(self) -> None:
        path = _write_flows_file([_make_flow()])
        try:
            with mock.patch(
                "sys.argv",
                [
                    "hubble-audit2policy",
                    path,
                    "--dry-run",
                    "--no-enrich",
                    "--verdict",
                    "FORWARDED",
                ],
            ):
                with pytest.raises(SystemExit) as exc_info:
                    h.main()
                assert exc_info.value.code == h.EXIT_NO_POLICIES
        finally:
            os.unlink(path)

    def test_empty_file_exits_no_policies(self) -> None:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        f.close()
        try:
            with mock.patch(
                "sys.argv",
                ["hubble-audit2policy", f.name, "--dry-run", "--no-enrich"],
            ):
                with pytest.raises(SystemExit) as exc_info:
                    h.main()
                assert exc_info.value.code == h.EXIT_NO_POLICIES
        finally:
            os.unlink(f.name)

    def test_nonexistent_file_exits_error(self) -> None:
        with mock.patch(
            "sys.argv",
            ["hubble-audit2policy", "/tmp/no_such_hubble_file_12345.jsonl", "--no-enrich"],
        ):
            with pytest.raises(SystemExit) as exc_info:
                h.main()
            assert exc_info.value.code == h.EXIT_ERROR


class TestCliArgValidation:
    def test_missing_flows_file_errors(self) -> None:
        with mock.patch("sys.argv", ["hubble-audit2policy"]):
            with pytest.raises(SystemExit) as exc_info:
                h.main()
            assert exc_info.value.code == 2  # argparse error

    def test_loki_without_url_errors(self) -> None:
        with mock.patch("sys.argv", ["hubble-audit2policy", "--from", "loki"]):
            with pytest.raises(SystemExit) as exc_info:
                h.main()
            assert exc_info.value.code == 2

    def test_loki_token_and_user_mutual_exclusion(self) -> None:
        with mock.patch(
            "sys.argv",
            [
                "hubble-audit2policy",
                "--from",
                "loki",
                "--loki-url",
                "http://loki:3100",
                "--loki-token",
                "tok",
                "--loki-user",
                "admin",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                h.main()
            assert exc_info.value.code == 2

    def test_loki_password_without_user_errors(self) -> None:
        with mock.patch(
            "sys.argv",
            [
                "hubble-audit2policy",
                "--from",
                "loki",
                "--loki-url",
                "http://loki:3100",
                "--loki-password",
                "secret",
            ],
        ):
            with pytest.raises(SystemExit) as exc_info:
                h.main()
            assert exc_info.value.code == 2


class TestCliBuildParser:
    def test_version_flag(self) -> None:
        parser = h._build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["-V"])
        assert exc_info.value.code == 0

    def test_defaults(self) -> None:
        parser = h._build_parser()
        args = parser.parse_args(["flows.json"])
        assert args.flows_file == "flows.json"
        assert args.output_dir == "."
        assert args.source == "file"
        assert args.dry_run is False
        assert args.watch is False
        assert args.no_enrich is False
        assert args.verbose is False


def _capture_stdout(func: object) -> str:
    """Call func and return everything it wrote to stdout."""
    from io import StringIO

    buf = StringIO()
    with mock.patch("sys.stdout", buf):
        try:
            func()  # type: ignore[operator]
        except SystemExit:
            pass
    return buf.getvalue()
