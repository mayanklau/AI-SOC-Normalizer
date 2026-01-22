"""Normalization logic for security events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

from normalizer.mappings import SOURCES, SchemaMap


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

    schema_key = schema.lower()
    if schema_key == "ecs":
        normalized = mapping.ecs(event)
    elif schema_key == "oscf":
        normalized = mapping.oscf(event)
    else:
        raise NormalizationError(f"Unknown schema '{schema}'. Use ecs or oscf.")

    return NormalizationResult(source=source, schema=schema_key, normalized=normalized)


def normalize_events(
    events: Iterable[Mapping[str, Any]],
    source: str,
    schema: str,
) -> List[SchemaMap]:
    results: List[SchemaMap] = []
    for event in events:
        result = normalize_event(event, source=source, schema=schema)
        results.append(result.normalized)
    return results


def normalize_event_auto(event: Mapping[str, Any], schema: str) -> NormalizationResult:
    source = event.get("device_type") or event.get("source") or event.get("observer_type")
    if not source:
        raise NormalizationError("Event is missing device type for auto detection.")
    return normalize_event(event, source=source, schema=schema)
