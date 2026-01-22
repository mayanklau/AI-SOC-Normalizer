"""Command line interface for the AI-SOC normalizer."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterable, List, Mapping

from normalizer.mappings import list_sources
from normalizer.normalizer import NormalizationError, normalize_event_auto, normalize_events


logger = logging.getLogger(__name__)


def _load_events(path: Path | None, *, ndjson: bool) -> Iterable[Mapping[str, Any]]:
    if path:
        raw = path.read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()

    if ndjson:
        events = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            events.append(json.loads(line))
        return events

    payload = json.loads(raw)
    if isinstance(payload, list):
        return payload
    return [payload]


def _write_output(events: List[Mapping[str, Any]], output: Path | None) -> None:
    payload = json.dumps(events, indent=2, sort_keys=True)
    if output:
        output.write_text(payload + "\n", encoding="utf-8")
        return
    print(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize security events to ECS or OSCF.")
    parser.add_argument(
        "--schema",
        choices=["ecs", "oscf", "ocsf"],
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
    parser.add_argument(
        "--ndjson",
        action="store_true",
        help="Read newline-delimited JSON (one event per line).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write normalized output to a file instead of stdout.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if required fields are missing.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR).",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(message)s")
    try:
        events = list(_load_events(args.input, ndjson=args.ndjson))
        if args.source == "auto":
            normalized = [
                normalize_event_auto(event, args.schema, strict=args.strict).normalized
                for event in events
            ]
        else:
            normalized = normalize_events(
                events,
                source=args.source,
                schema=args.schema,
                strict=args.strict,
            )
    except (NormalizationError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
        return

    _write_output(normalized, args.output)


if __name__ == "__main__":
    main()
