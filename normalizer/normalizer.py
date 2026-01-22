"""Normalization logic for security events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping

from normalizer.mappings import SOURCES, SchemaMap, required_fields


class NormalizationError(ValueError):
    """Raised when normalization fails due to invalid input."""


@dataclass(frozen=True)
class NormalizationResult:
    source: str
    schema: str
    normalized: SchemaMap


def normalize_event(event: Mapping[str, Any], source: str, schema: str) -> NormalizationResult:
    mapping = SOURCES.get(source)
    if not mapping:
        raise NormalizationError(f"Unknown source '{source}'.")

    schema_key = _normalize_schema(schema)
    if schema_key == "ecs":
        normalized = mapping.ecs(event)
    elif schema_key == "oscf":
        normalized = mapping.oscf(event)
    else:
        raise NormalizationError(f"Unknown schema '{schema}'. Use ecs or oscf.")

    normalized = _prune_empty(normalized)
    return NormalizationResult(source=source, schema=schema_key, normalized=normalized)


def normalize_events(
    events: Iterable[Mapping[str, Any]],
    source: str,
    schema: str,
    *,
    strict: bool = False,
) -> List[SchemaMap]:
    results: List[SchemaMap] = []
    for event in events:
        _validate_event(event, strict=strict)
        result = normalize_event(event, source=source, schema=schema)
        results.append(result.normalized)
    return results


def normalize_event_auto(event: Mapping[str, Any], schema: str, *, strict: bool = False) -> NormalizationResult:
    _validate_event(event, strict=strict)
    source = event.get("device_type") or event.get("source") or event.get("observer_type")
    if not source:
        raise NormalizationError("Event is missing device type for auto detection.")
    return normalize_event(event, source=source, schema=schema)


def _normalize_schema(schema: str) -> str:
    schema_key = schema.lower()
    if schema_key == "ocsf":
        return "oscf"
    return schema_key


def _validate_event(event: Mapping[str, Any], *, strict: bool) -> None:
    if not strict:
        return
    missing = []
    for field in required_fields():
        if not event.get(field):
            missing.append(field)
    if missing:
        raise NormalizationError(f"Event is missing required fields: {', '.join(missing)}.")


def _prune_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            pruned = _prune_empty(item)
            if pruned is not None and pruned != {} and pruned != []:
                cleaned[key] = pruned
        return cleaned
    if isinstance(value, list):
        cleaned_list = [_prune_empty(item) for item in value]
        cleaned_list = [item for item in cleaned_list if item is not None and item != {}]
        return cleaned_list
    return value
