"""Command line interface for the AI-SOC normalizer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable, List, Mapping

from normalizer.mappings import list_sources
from normalizer.normalizer import NormalizationError, normalize_event_auto, normalize_events


def _load_events(path: Path | None) -> Iterable[Mapping[str, Any]]:
    if path:
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = json.loads(input())

    if isinstance(payload, list):
        return payload
    return [payload]


def _write_output(events: List[Mapping[str, Any]]) -> None:
    print(json.dumps(events, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize security events to ECS or OSCF.")
    parser.add_argument(
        "--schema",
        choices=["ecs", "oscf"],
        default="ecs",
        help="Output schema to emit.",
    )
    parser.add_argument(
        "--source",
        choices=list(list_sources()) + ["auto"],
        default="auto",
        help="Source type (firewall, endpoint, ids) or auto detection.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="Path to JSON event or array of events. Reads stdin if omitted.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        events = list(_load_events(args.input))
        if args.source == "auto":
            normalized = [normalize_event_auto(event, args.schema).normalized for event in events]
        else:
            normalized = normalize_events(events, source=args.source, schema=args.schema)
    except (NormalizationError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return

    _write_output(normalized)


if __name__ == "__main__":
    main()
