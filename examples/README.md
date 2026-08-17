# Health-DeID examples

These thirteen configurations use fictional records. Run commands from the
repository root after:

```bash
uv sync --locked
```

AWS examples use boto3's normal credential chain. Confirm the active identity
before making paid calls:

```bash
aws sts get-caller-identity
```

## Scenarios

| Config | Purpose | External calls |
| --- | --- | --- |
| `01_comprehend_default.yaml` | Comprehend Medical and default handling | Comprehend |
| `02_sonnet46_default.yaml` | Sonnet 4.6 structured detection | Bedrock |
| `03_hybrid_with_rules.yaml` | Both detectors plus local rules | Comprehend + Bedrock |
| `04_rules_only.yaml` | Local rules and the full workflow | None |
| `05_full_validation_review.yaml` | Hybrid detection, validation, review-all | Comprehend + Bedrock |
| `06_surrogates_and_date_shift.yaml` | List/Faker replacements and date shift | Comprehend |
| `07_revised_full_date_redaction.yaml` | Revised scenario 3 policy | Reuses detectors |
| `08_review_all_without_validation.yaml` | Review every record without validation | None |
| `09_embedded_rules_structured_fields.yaml` | Embedded rules and structured PHI | None |
| `10_structured_field_review_export.yaml` | Structured overrides and export | None |
| `11_revised_detector_reuse.yaml` | Second detector-reuse acceptance case | Reuses detectors |
| `12_sonnet46_adaptive_reasoning.yaml` | Sonnet 4.6 medium reasoning | Bedrock |
| `13_cancer_notes_end_to_end.yaml` | Fifteen full cancer notes through every stage | Comprehend + Bedrock |

## Run and inspect

```bash
uv run health-deid check examples/configs/04_rules_only.yaml
uv run health-deid run examples/configs/04_rules_only.yaml
uv run health-deid status <run-directory>
uv run health-deid status <run-directory> --json
uv run health-deid status <run-directory> --errors
```

Paid examples run the same way:

```bash
uv run health-deid run examples/configs/01_comprehend_default.yaml
uv run health-deid run examples/configs/02_sonnet46_default.yaml
uv run health-deid run examples/configs/03_hybrid_with_rules.yaml
uv run health-deid run examples/configs/13_cancer_notes_end_to_end.yaml
```

Scenario 13 contains two progress notes and one discharge summary for each of
five fictional patients. It enables both detectors, local rules, synthetic
replacement, date shifting, validation, review-all, and four parallel workers.

## UI and review

```bash
uv run health-deid ui --reviewer "Reviewer Name" --runs-dir example-runs
```

The home page lists immediate run directories under `example-runs`. Open
scenario 5, 8, or 10 to approve, correct, exclude, or save records for later.
When every required record has a decision, complete review to resume
final de-identification.

## Structured fields

Scenarios 9 and 10 map:

- `patient_name` to `NAME`
- `service_date` to `DATE`
- `medical_record_number` to `ID`

Mapped fields use the same category policy as source text. The review page
shows the original, configured action, output preview, and any reviewer override.

## Replacements and dates

Scenario 6 uses a custom list for names, Faker for identifiers, and one
whole-week date shift per entity:

```bash
uv run health-deid run examples/configs/06_surrogates_and_date_shift.yaml
```

Records `N001` and `N002` share an entity ID, so they reuse the same date
offset and entity-consistent replacements.

## Revised runs

Complete scenario 3, then create a revised run with scenario 7 or 11:

```bash
uv run health-deid revise <scenario-3-run-directory> \
  examples/configs/07_revised_full_date_redaction.yaml \
  --reason "test full date redaction"

uv run health-deid revise <scenario-3-run-directory> \
  examples/configs/11_revised_detector_reuse.yaml \
  --reason "verify detector reuse"
```

Both configurations match scenario 3's input and detectors, so completed paid
detector work is copied into the child. Rules and every downstream stage run
again. If those reuse requirements do not match, add `--rerun-detection` only
when a new paid pass is intended.

## Export

```bash
uv run health-deid export <run-directory> \
  <run-directory>/exports/final.jsonl \
  --format jsonl \
  --mode ready_only \
  --column record_id \
  --column entity_id \
  --column final_text \
  --column service_date
```

`ready_only` contains records with current final output. `all_records`
preserves original size and adds operational status.

## Python API

```bash
uv run python examples/scripts/run_via_python.py \
  examples/configs/04_rules_only.yaml

uv run python examples/scripts/run_via_python.py \
  examples/configs/02_sonnet46_default.yaml --precheck-only
```
