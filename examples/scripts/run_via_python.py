from __future__ import annotations

import argparse
import json
from pathlib import Path

from health_deid import create_run, precheck


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Precheck and optionally execute one health-deid example."
    )
    parser.add_argument("config", type=Path, help="Pipeline YAML file.")
    parser.add_argument(
        "--precheck-only",
        action="store_true",
        help="Validate without creating a run or making backend calls.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    check = precheck(args.config)
    print(json.dumps(check.as_dict(), indent=2, default=str))
    if not check.ok:
        return 1
    if args.precheck_only:
        return 0

    handle = create_run(args.config, check_precheck=False)
    print(f"Created: {handle.run_dir}")
    handle.execute()
    report = handle.status()
    print(json.dumps(report, indent=2, default=str))

    run_status = str(report["run"]["status"])
    if run_status == "awaiting_review":
        print(f"Review required: uv run health-deid ui {handle.run_dir}")
        return 0

    result = handle.export(
        output_path=handle.context.exports_dir / "final.jsonl",
        format="jsonl",
        mode="ready_only",
        selected_columns=[
            "record_id",
            "entity_id",
            "final_text",
            "service_date",
            "note_type",
            "deid_status",
        ],
    )
    print(f"Exported {result.record_count} records to {result.output_path}")
    print(f"SHA-256: {result.output_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
