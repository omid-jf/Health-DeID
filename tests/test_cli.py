from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import health_deid.cli as cli
from health_deid.models.export import ExportResult
from health_deid.pipeline.control import RetryResult
from health_deid.pipeline.precheck import (
    BackendCostEstimate,
    CostEstimate,
    PrecheckIssue,
    PrecheckResult,
)

runner = CliRunner()


def _report(status: str = "completed") -> dict[str, object]:
    return {
        "run": {"run_id": "run-1", "status": status},
        "records": {"denominator": 2, "counts": {"ready": 2}},
        "usage": {
            "backends": [
                {
                    "backend_id": "sonnet_4_6",
                    "provenance": "this_run",
                    "attempts": 2,
                    "request_count": 2,
                    "actual_cost_usd": 0.123,
                }
            ]
        },
        "errors": {
            "items": [
                {
                    "record_id": "R2",
                    "stage_name": "detection",
                    "message": "example failure",
                    "resolved": False,
                }
            ]
        },
    }


class FakeHandle:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_id = "run-1"
        self.calls: list[tuple[str, object]] = []

    def execute(self) -> FakeHandle:
        self.calls.append(("execute", None))
        return self

    def resume(self) -> FakeHandle:
        self.calls.append(("resume", None))
        return self

    def status(self) -> dict[str, object]:
        return _report()

    def retry(self, **kwargs: object) -> RetryResult:
        self.calls.append(("retry", kwargs))
        return RetryResult(("R2",), ("detection", "transformation", "finalization"))

    def revise(self, config: Path, **kwargs: object) -> FakeHandle:
        self.calls.append(("revise", {"config": config, **kwargs}))
        child = FakeHandle(self.run_dir.parent / "child")
        child.run_id = "child-run"
        return child

    def export(self, **kwargs: object) -> ExportResult:
        self.calls.append(("export", kwargs))
        timestamp = datetime(2026, 7, 31, tzinfo=UTC)
        return ExportResult(
            export_id="export-1",
            output_path=Path(kwargs["output_path"]),
            format=kwargs["format"],  # type: ignore[arg-type]
            mode=kwargs["mode"],  # type: ignore[arg-type]
            selected_columns=kwargs["selected_columns"],  # type: ignore[arg-type]
            record_count=2,
            output_sha256="a" * 64,
            created_at=timestamp,
            finished_at=timestamp,
        )


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    config = tmp_path / "config.yaml"
    config.write_text("config_version: 1\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return config, run_dir


def test_check_prints_precheck_estimate_json_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, _ = _paths(tmp_path)
    estimate = CostEstimate(
        active_record_count=2,
        backends=(
            BackendCostEstimate(
                backend_id="medical",
                backend="aws_comprehend_medical",
                request_count=3,
                input_characters=213,
                billable_100_character_units=3,
                estimated_input_cost_usd=0.05,
                estimated_output_cost_usd=0.0,
                estimated_total_cost_usd=0.05,
            ),
        ),
        estimated_input_cost_usd=0.05,
        estimated_output_cost_usd=0.0,
        estimated_total_cost_usd=0.05,
    )
    ready = PrecheckResult(
        (PrecheckIssue("info", "ready", "ready"),),
        record_count=2,
        cost_estimate=estimate,
    )
    monkeypatch.setattr(cli, "precheck", lambda path: ready)

    plain = runner.invoke(cli.app, ["check", str(config)])
    assert plain.exit_code == 0
    assert "Precheck estimate: $0.050000" in plain.output
    assert "medical: 3 request(s), $0.050000" in plain.output
    as_json = runner.invoke(cli.app, ["check", str(config), "--json"])
    assert '"estimated_total_cost_usd": 0.05' in as_json.output

    blocked = PrecheckResult((PrecheckIssue("error", "bad", "blocked", "input"),))
    monkeypatch.setattr(cli, "precheck", lambda path: blocked)
    failed = runner.invoke(cli.app, ["check", str(config)])
    assert failed.exit_code == 1
    assert "ERROR [input]: blocked" in failed.output


def test_run_status_resume_and_retry_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir = _paths(tmp_path)
    handle = FakeHandle(run_dir)
    ready = PrecheckResult((PrecheckIssue("info", "ready", "ready"),), record_count=2)
    monkeypatch.setattr(cli, "precheck", lambda path: ready)
    monkeypatch.setattr(cli, "create_run", lambda path, check_precheck: handle)
    monkeypatch.setattr(cli, "open_run", lambda path: handle)

    result = runner.invoke(cli.app, ["run", str(config)])
    assert result.exit_code == 0
    assert handle.calls[0][0] == "execute"
    assert "Status: completed" in result.output

    plain = runner.invoke(cli.app, ["status", str(run_dir), "--errors"])
    assert "actual_cost=$0.123000" in plain.output
    assert "example failure" in plain.output
    as_json = runner.invoke(cli.app, ["status", str(run_dir), "--json"])
    assert '"run_id": "run-1"' in as_json.output

    assert runner.invoke(cli.app, ["resume", str(run_dir)]).exit_code == 0
    retried = runner.invoke(cli.app, ["retry", str(run_dir), "--stage", "detection", "--failed"])
    assert retried.exit_code == 0
    assert "Retried 1 record(s)" in retried.output


def test_revise_export_and_ui_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, run_dir = _paths(tmp_path)
    handle = FakeHandle(run_dir)
    monkeypatch.setattr(cli, "open_run", lambda path: handle)

    revised = runner.invoke(
        cli.app,
        [
            "revise",
            str(run_dir),
            str(config),
            "--reason",
            "new settings",
            "--no-execute",
        ],
    )
    assert revised.exit_code == 0
    assert "Created revised run child-run" in revised.output
    assert "health-deid resume" in revised.output

    output = tmp_path / "result.jsonl"
    exported = runner.invoke(
        cli.app,
        [
            "export",
            str(run_dir),
            str(output),
            "--format",
            "jsonl",
            "--mode",
            "all_records",
            "--column",
            "record_id",
        ],
    )
    assert exported.exit_code == 0
    assert "Exported 2 record(s)" in exported.output

    launches: list[tuple[object, dict[str, object]]] = []
    monkeypatch.setattr(
        cli,
        "launch_ui",
        lambda run_path, **kwargs: launches.append((run_path, kwargs)),
    )
    opened = runner.invoke(
        cli.app,
        [
            "ui",
            str(run_dir),
            "--reviewer",
            "Reviewer",
            "--runs-dir",
            str(tmp_path / "runs"),
            "--no-open-browser",
        ],
    )
    assert opened.exit_code == 0
    assert launches[0][0] == run_dir
    assert launches[0][1]["reviewer_id"] == "Reviewer"


def test_cli_reports_service_errors_and_has_only_the_supported_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir = _paths(tmp_path)
    monkeypatch.setattr(cli, "precheck", lambda path: (_ for _ in ()).throw(ValueError("bad")))
    failed = runner.invoke(cli.app, ["check", str(config)])
    assert failed.exit_code == 1
    assert "Error: bad" in failed.output

    monkeypatch.setattr(cli, "open_run", lambda path: (_ for _ in ()).throw(RuntimeError()))
    failed = runner.invoke(cli.app, ["status", str(run_dir)])
    assert failed.exit_code == 1
    assert "Error: RuntimeError" in failed.output

    help_result = runner.invoke(cli.app, ["--help"])
    assert help_result.exit_code == 0
    version_result = runner.invoke(cli.app, ["--version"])
    assert version_result.exit_code == 0
    assert version_result.output.strip() == "Health-DeID 1.0.0"
    for command in ("ui", "check", "run", "status", "resume", "retry", "revise", "export"):
        assert command in help_result.output
    assert "derive" not in help_result.output


def test_status_formatting_without_optional_sections() -> None:
    report = _report()
    report["records"]["counts"] = {}  # type: ignore[index]
    report["usage"] = {"backends": []}
    report["errors"] = {"items": []}
    text = cli._status_text(report, Path("run"))  # type: ignore[arg-type]
    assert "Record states" not in text
    assert cli._money(None) == "not priced"
    with pytest.raises(BaseException) as raised:
        cli._fail(RuntimeError())
    assert getattr(raised.value, "exit_code", None) == 1


def test_remaining_command_success_and_error_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, run_dir = _paths(tmp_path)
    handle = FakeHandle(run_dir)
    ready = PrecheckResult((PrecheckIssue("info", "ready", "ready"),))
    blocked = PrecheckResult((PrecheckIssue("error", "blocked", "stop"),))

    monkeypatch.setattr(cli, "precheck", lambda path: blocked)
    assert runner.invoke(cli.app, ["run", str(config)]).exit_code == 1

    monkeypatch.setattr(cli, "precheck", lambda path: ready)
    monkeypatch.setattr(cli, "open_run", lambda path: handle)
    executed = runner.invoke(
        cli.app,
        ["revise", str(run_dir), str(config), "--reason", "new settings"],
    )
    assert executed.exit_code == 0
    assert "Status: completed" in executed.output

    def failing(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise ValueError("service failed")

    monkeypatch.setattr(cli, "create_run", failing)
    assert "service failed" in runner.invoke(cli.app, ["run", str(config)]).output
    monkeypatch.setattr(cli, "open_run", failing)
    for arguments in (
        ["resume", str(run_dir)],
        ["retry", str(run_dir), "--failed"],
        ["revise", str(run_dir), str(config), "--reason", "change"],
        ["export", str(run_dir), str(tmp_path / "out.jsonl")],
    ):
        result = runner.invoke(cli.app, arguments)
        assert result.exit_code == 1
        assert "service failed" in result.output

    monkeypatch.setattr(cli, "launch_ui", failing)
    ui_result = runner.invoke(
        cli.app,
        ["ui", "--reviewer", "Reviewer", "--no-open-browser"],
    )
    assert ui_result.exit_code == 1
    assert "service failed" in ui_result.output

    report = _report()
    backend = report["usage"]["backends"][0]  # type: ignore[index]
    backend["actual_cost_usd"] = None
    backend["provenance"] = "reused_from_parent"
    assert "Reused usage" in cli._status_text(report, run_dir)  # type: ignore[arg-type]
