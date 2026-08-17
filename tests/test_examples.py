from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import load_config
from health_deid.models.export import ExportRequest
from health_deid.models.review import ReviewDecision, ReviewStructuredEvent
from health_deid.pipeline.engine import PipelineEngine
from health_deid.pipeline.exports import ExportService
from health_deid.pipeline.reporting import LiveReportService
from health_deid.pipeline.review import ReviewService
from health_deid.storage.reviews import ReviewRepository

EXAMPLE_CONFIGS = Path("examples/configs")
NOW = datetime(2026, 8, 4, 18, 0, tzinfo=UTC)


def test_all_example_configurations_load() -> None:
    paths = sorted(EXAMPLE_CONFIGS.glob("*.yaml"))

    assert [path.name for path in paths] == [
        "01_comprehend_default.yaml",
        "02_sonnet46_default.yaml",
        "03_hybrid_with_rules.yaml",
        "04_rules_only.yaml",
        "05_full_validation_review.yaml",
        "06_surrogates_and_date_shift.yaml",
        "07_revised_full_date_redaction.yaml",
        "08_review_all_without_validation.yaml",
        "09_embedded_rules_structured_fields.yaml",
        "10_structured_field_review_export.yaml",
        "11_revised_detector_reuse.yaml",
        "12_sonnet46_adaptive_reasoning.yaml",
        "13_cancer_notes_end_to_end.yaml",
    ]
    loaded = {path.name: load_config(path) for path in paths}
    for path in paths:
        config = loaded[path.name]
        assert config.input.path.is_file()
        if config.rules.rules_path is not None:
            assert config.rules.rules_path.is_file()
    example_3 = loaded["03_hybrid_with_rules.yaml"]
    example_11 = loaded["11_revised_detector_reuse.yaml"]
    assert example_11.detection == example_3.detection
    example_12 = loaded["12_sonnet46_adaptive_reasoning.yaml"]
    detector = example_12.detection.detectors[0]
    assert detector.backend == "aws_bedrock"
    assert detector.reasoning_effort == "medium"
    example_13 = loaded["13_cancer_notes_end_to_end.yaml"]
    rows = [
        json.loads(line) for line in example_13.input.path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 15
    assert {row["patient_id"] for row in rows} == {f"P{index:03d}" for index in range(1, 6)}
    for patient_id in {row["patient_id"] for row in rows}:
        note_types = [row["note_type"] for row in rows if row["patient_id"] == patient_id]
        assert note_types.count("progress_note") == 2
        assert note_types.count("discharge_summary") == 1


@pytest.mark.parametrize(
    ("filename", "expected_status"),
    [
        ("04_rules_only.yaml", "completed"),
        ("08_review_all_without_validation.yaml", "awaiting_review"),
        ("09_embedded_rules_structured_fields.yaml", "completed"),
        ("10_structured_field_review_export.yaml", "awaiting_review"),
    ],
)
def test_no_aws_examples_run_end_to_end(
    tmp_path: Path,
    filename: str,
    expected_status: str,
) -> None:
    config = load_config(EXAMPLE_CONFIGS / filename)
    run = config.run.model_copy(update={"output_dir": tmp_path / filename.removesuffix(".yaml")})
    engine = PipelineEngine.create(config.model_copy(update={"run": run}), timestamp=NOW)

    engine.execute()

    assert engine.store.read_run_status() == expected_status
    if filename in {
        "08_review_all_without_validation.yaml",
        "10_structured_field_review_export.yaml",
    }:
        expected_ids = (
            ["S001", "S002"]
            if filename == "10_structured_field_review_export.yaml"
            else ["N001", "N002", "N003", "N004", "N005", "N006"]
        )
        assert ReviewRepository(engine.store).queue() == [
            *expected_ids,
        ]
    if filename == "09_embedded_rules_structured_fields.yaml":
        rows = engine.store.read_input_records()
        assert [row.record_id for row in rows] == ["S001", "S002"]
        final = engine.transformations.current_rendering("S001", "final").rendered_text
        metadata = json.loads(str(engine.store.read_record("S001")["final_metadata_json"]))
        assert final == "[R_NAME] was seen on [R_DATE]/[R_DATE]/2026. Record [R_ID] was updated."
        assert metadata == {
            "medical_record_number": "[R_ID]",
            "note_type": "progress_note",
            "patient_name": "[R_NAME]",
            "service_date": "2026-[R_DATE]-[R_DATE]",
        }


def test_structured_review_example_applies_override_reports_time_and_exports_raw(
    tmp_path: Path,
) -> None:
    config = load_config(EXAMPLE_CONFIGS / "10_structured_field_review_export.yaml")
    run = config.run.model_copy(update={"output_dir": tmp_path / "structured-review"})
    engine = PipelineEngine.create(config.model_copy(update={"run": run}), timestamp=NOW)
    engine.execute()
    service = ReviewService(engine.store)

    first = service.record("S001")
    assert {
        item["column_name"]: item["deidentified_value"] for item in first.structured_fields
    } == {
        "medical_record_number": "[R_ID]",
        "patient_name": "[R_NAME]",
        "service_date": "2026-[R_DATE]-[R_DATE]",
    }
    service.decide(
        ReviewDecision(
            decision_id="structured-correction",
            record_id="S001",
            basis_plan_revision=first.plan_revision,
            disposition="corrected",
            reviewer_id="Example Reviewer",
            decided_at=NOW + timedelta(seconds=42),
            review_seconds=42,
            structured_events=[
                ReviewStructuredEvent(
                    event_id="patient-name-override",
                    column_name="patient_name",
                    category=PhiCategory.NAME,
                    original_value="Alice Example",
                    replacement_value="Patient Alpha",
                )
            ],
        )
    )
    second = service.record("S002")
    service.decide(
        ReviewDecision(
            decision_id="structured-approval",
            record_id="S002",
            basis_plan_revision=second.plan_revision,
            disposition="approved_unchanged",
            reviewer_id="Example Reviewer",
            decided_at=NOW + timedelta(seconds=60),
            review_seconds=18,
        )
    )

    engine.resume()

    first_metadata = json.loads(str(engine.store.read_record("S001")["final_metadata_json"]))
    assert first_metadata["patient_name"] == "Patient Alpha"
    report = LiveReportService(engine.store).build()
    assert [item["record_id"] for item in report["review"]["records"]] == ["S001", "S002"]
    assert [item["review_seconds"] for item in report["review"]["records"]] == [42, 18]
    audit = LiveReportService(engine.store).record_audit("S001")
    assert audit["review_structured_events"][0]["replacement_value"] == "Patient Alpha"

    output = tmp_path / "structured-review.jsonl"
    ExportService(engine.store).export(
        ExportRequest(
            output_path=output,
            format="jsonl",
            selected_columns=[
                "record_id",
                "final_text",
                "patient_name",
                "raw_patient_name",
            ],
        ),
        created_at=NOW + timedelta(minutes=2),
    )
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["patient_name"] == "Patient Alpha"
    assert rows[0]["raw_patient_name"] == "Alice Example"
