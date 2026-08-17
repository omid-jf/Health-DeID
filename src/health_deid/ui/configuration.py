"""Translate setup and revision forms into one validated configuration model."""

from __future__ import annotations

import json
import secrets
from typing import Any

import yaml
from flask import render_template, request
from werkzeug.datastructures import MultiDict

from health_deid.backends.rules import RulesFile
from health_deid.backends.runtime import AWS_MAX_RETRIES, AWS_RETRY_MODE
from health_deid.core.taxonomy import PhiCategory
from health_deid.models.config import PipelineConfig
from health_deid.models.policy import (
    CustomListSurrogate,
    DateShiftSurrogate,
    TransformationAction,
    TransformationPolicy,
)
from health_deid.pipeline.context import RunContext
from health_deid.pipeline.precheck import PrecheckResult
from health_deid.pipeline.revision import RevisionPlan
from health_deid.ui.route_helpers import state
from health_deid.ui.state import SetupDraft


def render_configuration(
    draft: SetupDraft,
    *,
    form: dict[str, Any] | None = None,
    result: PrecheckResult | None = None,
) -> str:
    columns = [column.name for column in draft.preview.columns]
    values = _setup_defaults(draft, columns)
    if form is not None:
        values.update(form)
    return render_template(
        "ui/setup_configure.html",
        draft=draft,
        columns=columns,
        categories=list(PhiCategory),
        form=values,
        result=result,
        aws_retry_mode=AWS_RETRY_MODE,
        aws_max_retries=AWS_MAX_RETRIES,
    )


def config_from_form(draft: SetupDraft) -> PipelineConfig:
    form = request.form
    rules = (
        _rules_from_form(form, fallback=draft.rules_payload)
        if form.get("rules_enabled") == "yes"
        else None
    )
    payload = {
        "config_version": 1,
        "run": {
            "name": form.get("run_name") or None,
            "output_dir": state().runs_dir,
        },
        "input": _input_from_form(form, draft),
        "policy": policy_from_form(form, secrets_by_category=draft.surrogate_secrets),
        "detection": _detection_from_form(form),
        "rules": _rules_config(form, rules),
        "validation": _validation_from_form(form),
        "review": _review_from_form(form),
    }
    return PipelineConfig.model_validate(payload)


def revised_config_from_form(context: RunContext, base: PipelineConfig) -> PipelineConfig:
    form = request.form
    rules = (
        _rules_from_form(form, fallback=_configured_rules_payload(base))
        if form.get("rules_enabled") == "yes"
        else None
    )
    input_payload = base.input.model_dump(mode="python")
    input_payload["structured_phi_columns"] = _structured_columns(form, base.input.metadata_columns)
    payload = {
        "config_version": 1,
        "run": {
            "name": form.get("run_name") or None,
            "output_dir": state().runs_dir,
            "parent_run_id": context.run_id,
        },
        "input": input_payload,
        "policy": policy_from_form(form, base_config=base),
        "detection": _detection_from_form(form),
        "rules": _rules_config(form, rules),
        "validation": _validation_from_form(form),
        "review": _review_from_form(form),
    }
    return PipelineConfig.model_validate(payload)


def embedded_rules(draft: SetupDraft) -> RulesFile:
    return _rules_from_form(request.form, fallback=draft.rules_payload)


def rules_payload(config: PipelineConfig) -> dict[str, object]:
    if not config.rules.enabled:
        return {"rules": []}
    if config.rules.embedded is not None:
        return config.rules.embedded.model_dump(mode="json")
    assert config.rules.rules_path is not None
    raw = yaml.safe_load(config.rules.rules_path.read_text(encoding="utf-8"))
    return RulesFile.model_validate(raw).model_dump(mode="json")


def policy_from_form(
    form: MultiDict[str, str],
    *,
    base_config: PipelineConfig | None = None,
    secrets_by_category: dict[str, str] | None = None,
) -> TransformationPolicy:
    categories: dict[str, object] = {}
    defaults = TransformationPolicy()
    for category in PhiCategory:
        method = form.get(f"replacement:{category.value}") or _policy_method(defaults, category)
        item: dict[str, object]
        if method in {"retain", "redact"}:
            item = {"action": method}
        elif method in {"year_only", "age_90_plus"}:
            item = {"action": "generalize", "generalization": method}
        elif method == "date_shift":
            item = {
                "action": "surrogate",
                "surrogate": {
                    "method": "date_shift",
                    "consistency": "entity",
                    "minimum_weeks": _integer(form.get("date_minimum_weeks"), -52),
                    "maximum_weeks": _integer(form.get("date_maximum_weeks"), 52),
                    "fallback": form.get("date_fallback", "year_only"),
                    "secret_reference": _secret_reference(
                        form,
                        category,
                        base_config=base_config,
                        defaults=secrets_by_category,
                    ),
                },
            }
        elif method == "custom_list":
            values = [
                value.strip()
                for value in form.get(f"custom_values:{category.value}", "").splitlines()
                if value.strip()
            ]
            item = {
                "action": "surrogate",
                "surrogate": {
                    "method": "custom_list",
                    "consistency": form.get(f"consistency:{category.value}", "entity"),
                    "values": values,
                    "secret_reference": _secret_reference(
                        form,
                        category,
                        base_config=base_config,
                        defaults=secrets_by_category,
                    ),
                },
            }
        else:
            item = {
                "action": "surrogate",
                "surrogate": {
                    "method": "faker",
                    "consistency": form.get(f"consistency:{category.value}", "entity"),
                    "secret_reference": _secret_reference(
                        form,
                        category,
                        base_config=base_config,
                        defaults=secrets_by_category,
                    ),
                },
            }
        categories[category.value] = item
    return TransformationPolicy.model_validate({"policy_version": 1, "categories": categories})


def policy_form(policy: TransformationPolicy) -> dict[str, object]:
    output: dict[str, object] = {}
    for category, category_policy in policy.categories.items():
        output[f"replacement:{category.value}"] = _policy_method(policy, category)
        replacement = category_policy.surrogate
        if replacement is None:
            continue
        output[f"secret_reference:{category.value}"] = replacement.secret_reference
        output[f"consistency:{category.value}"] = replacement.consistency.value
        if isinstance(replacement, CustomListSurrogate):
            output[f"custom_values:{category.value}"] = "\n".join(replacement.values)
        elif isinstance(replacement, DateShiftSurrogate):
            assert isinstance(replacement, DateShiftSurrogate)
            output.update(
                {
                    "date_minimum_weeks": str(replacement.minimum_weeks),
                    "date_maximum_weeks": str(replacement.maximum_weeks),
                    "date_fallback": replacement.fallback.value,
                }
            )
    return output


def render_settings(
    context: RunContext,
    config: PipelineConfig,
    *,
    form: dict[str, Any] | None = None,
    plan: RevisionPlan | None = None,
) -> str:
    values = _form_from_config(config)
    if form is not None:
        values.update(form)
    return render_template(
        "ui/settings.html",
        context=context,
        config=config,
        categories=list(PhiCategory),
        columns=config.input.metadata_columns,
        form=values,
        plan=plan,
        aws_retry_mode=AWS_RETRY_MODE,
        aws_max_retries=AWS_MAX_RETRIES,
    )


def _setup_defaults(draft: SetupDraft, columns: list[str]) -> dict[str, Any]:
    record, entity, text = _infer_columns(columns)
    for category in PhiCategory:
        draft.surrogate_secrets.setdefault(category.value, f"literal:{secrets.token_hex(32)}")
    values: dict[str, Any] = {
        "run_name": "",
        "record_id_column": record,
        "entity_id_column": entity,
        "text_column": text,
        "metadata_columns": [column for column in columns if column not in {record, entity, text}],
        "structured_columns": [],
        "detectors": [],
        "comprehend_region": "us-east-1",
        "comprehend_confidence": "0.0",
        "comprehend_cost": "0.0014",
        "bedrock_region": "us-east-1",
        "bedrock_confidence": "0.0",
        "bedrock_reasoning": "none",
        "bedrock_input_cost": "3.0",
        "bedrock_output_cost": "15.0",
        "workers": "2",
        "rules_enabled": False,
        "rules_json": json.dumps(draft.rules_payload or {"rules": []}),
        "validation_enabled": False,
        "validation_region": "us-east-1",
        "validation_input_cost": "0.15",
        "validation_output_cost": "0.60",
        "validation_workers": "2",
        "review_mode": "none",
        "date_minimum_weeks": "-52",
        "date_maximum_weeks": "52",
        "date_fallback": "year_only",
    }
    values.update(policy_form(TransformationPolicy()))
    if draft.config_payload is not None:
        imported = PipelineConfig.model_validate(draft.config_payload)
        values.update(_form_from_config(imported))
        configured = _configured_rules_payload(imported)
        if configured is not None:
            draft.rules_payload = configured
            values["rules_json"] = json.dumps(configured)
    return values


def _form_from_config(config: PipelineConfig) -> dict[str, Any]:
    detectors = [
        "comprehend" if item.backend == "aws_comprehend_medical" else "sonnet"
        for item in config.detection.detectors
    ]
    values: dict[str, Any] = {
        "run_name": config.run.name or "",
        "record_id_column": config.input.record_id_column,
        "entity_id_column": config.input.entity_id.column or "__record_id__",
        "text_column": config.input.text_column,
        "metadata_columns": config.input.metadata_columns,
        "structured_columns": list(config.input.structured_phi_columns),
        "detectors": detectors,
        "comprehend_region": "us-east-1",
        "comprehend_confidence": "0.0",
        "comprehend_cost": "0.0014",
        "bedrock_region": "us-east-1",
        "bedrock_confidence": "0.0",
        "bedrock_reasoning": "none",
        "bedrock_input_cost": "3.0",
        "bedrock_output_cost": "15.0",
        "workers": str(config.detection.execution.workers),
        "rules_enabled": config.rules.enabled,
        "rules_json": json.dumps(_configured_rules_payload(config) or {"rules": []}),
        "validation_enabled": config.validation.enabled,
        "validation_region": config.validation.region_name or "",
        "validation_input_cost": _optional(config.validation.input_cost_per_million_tokens),
        "validation_output_cost": _optional(config.validation.output_cost_per_million_tokens),
        "validation_workers": str(config.validation.execution.workers),
        "review_mode": (
            "all"
            if config.review.enabled and config.review.review_scope == "all"
            else "findings"
            if config.review.enabled
            else "none"
        ),
        "date_minimum_weeks": "-52",
        "date_maximum_weeks": "52",
        "date_fallback": "year_only",
    }
    for column, category in config.input.structured_phi_columns.items():
        values[f"structured_category:{column}"] = category.value
    for detector in config.detection.detectors:
        if detector.backend == "aws_comprehend_medical":
            values.update(
                {
                    "comprehend_region": detector.region_name or "",
                    "comprehend_confidence": str(detector.min_confidence),
                    "comprehend_cost": _optional(detector.cost_per_100_characters_usd),
                }
            )
        else:
            values.update(
                {
                    "bedrock_region": detector.region_name or "",
                    "bedrock_confidence": str(detector.min_confidence),
                    "bedrock_reasoning": detector.reasoning_effort,
                    "bedrock_input_cost": _optional(detector.input_cost_per_million_tokens),
                    "bedrock_output_cost": _optional(detector.output_cost_per_million_tokens),
                }
            )
    values.update(policy_form(config.policy))
    return values


def _input_from_form(form: MultiDict[str, str], draft: SetupDraft) -> dict[str, object]:
    record = form.get("record_id_column", "")
    entity = form.get("entity_id_column", "")
    metadata = list(dict.fromkeys(form.getlist("metadata_columns")))
    return {
        "kind": "text_records",
        "path": draft.source_path,
        "format": draft.preview.format,
        "record_id_column": record,
        "entity_id": (
            {"source": "record_id"}
            if entity in {"", "__record_id__", record}
            else {"source": "column", "column": entity}
        ),
        "text_column": form.get("text_column", ""),
        "metadata_columns": metadata,
        "structured_phi_columns": _structured_columns(form, metadata),
        "text_normalization": "ftfy_default",
    }


def _structured_columns(form: MultiDict[str, str], metadata_columns: list[str]) -> dict[str, str]:
    return {
        column: form.get(f"structured_category:{column}", "UNMAPPED")
        for column in form.getlist("structured_columns")
        if column in metadata_columns
    }


def _detection_from_form(form: MultiDict[str, str]) -> dict[str, object]:
    detectors: list[dict[str, object]] = []
    selected = set(form.getlist("detectors"))
    if "comprehend" in selected:
        detectors.append(
            {
                "backend": "aws_comprehend_medical",
                "region_name": form.get("comprehend_region") or None,
                "min_confidence": _float(form.get("comprehend_confidence"), 0.0),
                "cost_per_100_characters_usd": _optional_float(form.get("comprehend_cost")),
            }
        )
    if "sonnet" in selected:
        detectors.append(
            {
                "backend": "aws_bedrock",
                "region_name": form.get("bedrock_region") or None,
                "min_confidence": _float(form.get("bedrock_confidence"), 0.0),
                "reasoning_effort": form.get("bedrock_reasoning", "none"),
                "input_cost_per_million_tokens": _optional_float(form.get("bedrock_input_cost")),
                "output_cost_per_million_tokens": _optional_float(form.get("bedrock_output_cost")),
            }
        )
    return {
        "enabled": bool(detectors),
        "detectors": detectors,
        "execution": {"workers": _integer(form.get("workers"), 2)},
    }


def _validation_from_form(form: MultiDict[str, str]) -> dict[str, object]:
    enabled = form.get("validation_enabled") == "yes"
    return {
        "enabled": enabled,
        "region_name": form.get("validation_region") or None,
        "input_cost_per_million_tokens": _optional_float(form.get("validation_input_cost")),
        "output_cost_per_million_tokens": _optional_float(form.get("validation_output_cost")),
        "execution": {"workers": _integer(form.get("validation_workers"), 2)},
    }


def _review_from_form(form: MultiDict[str, str]) -> dict[str, object]:
    mode = form.get("review_mode", "none")
    validation = form.get("validation_enabled") == "yes"
    enabled = validation or mode != "none"
    return {
        "enabled": enabled,
        "review_scope": "all" if mode == "all" else "effective_validation_failures",
    }


def _rules_from_form(form: MultiDict[str, str], *, fallback: dict[str, object] | None) -> RulesFile:
    raw = form.get("rules_json")
    payload = json.loads(raw) if raw else fallback or {"rules": []}
    return RulesFile.model_validate(payload)


def _rules_config(
    form: MultiDict[str, str],
    rules: RulesFile | None,
) -> dict[str, object]:
    enabled = form.get("rules_enabled") == "yes"
    return {
        "enabled": enabled,
        **({"embedded": rules.model_dump(mode="json")} if rules is not None else {}),
    }


def _configured_rules_payload(config: PipelineConfig) -> dict[str, object] | None:
    try:
        return rules_payload(config) if config.rules.enabled else None
    except (OSError, ValueError, yaml.YAMLError):
        return None


def _secret_reference(
    form: MultiDict[str, str],
    category: PhiCategory,
    *,
    base_config: PipelineConfig | None,
    defaults: dict[str, str] | None,
) -> str:
    supplied = form.get(f"secret_reference:{category.value}")
    if supplied:
        return supplied
    if base_config is not None:
        replacement = base_config.policy.categories[category].surrogate
        if replacement is not None:
            return replacement.secret_reference
    if defaults is not None:
        return defaults.setdefault(category.value, f"literal:{secrets.token_hex(32)}")
    return f"literal:{secrets.token_hex(32)}"


def _policy_method(policy: TransformationPolicy, category: PhiCategory) -> str:
    item = policy.categories[category]
    if item.action in {TransformationAction.RETAIN, TransformationAction.REDACT}:
        return item.action.value
    if item.action is TransformationAction.GENERALIZE:
        assert item.generalization is not None
        return item.generalization.value
    assert item.surrogate is not None
    return item.surrogate.method


def _infer_columns(columns: list[str]) -> tuple[str, str, str]:
    if not columns:
        return "", "", ""
    record = next((name for name in columns if "id" in name.casefold()), columns[0])
    text = next(
        (name for name in columns if "text" in name.casefold() or "note" in name.casefold()),
        columns[-1],
    )
    entity = next(
        (
            name
            for name in columns
            if name not in {record, text}
            and ("patient" in name.casefold() or "entity" in name.casefold())
        ),
        record,
    )
    return record, entity, text


def _integer(value: str | None, default: int) -> int:
    return default if value in {None, ""} else int(value)


def _float(value: str | None, default: float) -> float:
    return default if value in {None, ""} else float(value)


def _optional_float(value: str | None) -> float | None:
    return None if value in {None, ""} else float(value)


def _optional(value: object) -> str:
    return "" if value is None else str(value)


__all__ = [
    "config_from_form",
    "embedded_rules",
    "policy_form",
    "policy_from_form",
    "render_configuration",
    "render_settings",
    "revised_config_from_form",
    "rules_payload",
]
