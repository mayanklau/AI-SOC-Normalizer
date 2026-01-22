"""Mapping definitions for ECS and OSCF normalization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping


SchemaMap = Dict[str, Any]
Transformer = Callable[[Mapping[str, Any]], SchemaMap]
REQUIRED_FIELDS = ("event_time", "action")


@dataclass(frozen=True)
class SourceMapping:
    name: str
    ecs: Transformer
    oscf: Transformer


def _get(event: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = event.get(key)
        if value not in (None, ""):
            return value
    return default


def _base_event(event: Mapping[str, Any]) -> SchemaMap:
    return {
        "event_time": _get(event, "event_time", "@timestamp", "timestamp"),
        "device_type": _get(event, "device_type", "observer_type", "product"),
        "event_action": _get(event, "action", "event_action"),
    }


def firewall_to_ecs(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "@timestamp": base["event_time"],
        "event": {
            "action": base["event_action"],
            "category": ["network"],
            "kind": "event",
        },
        "source": {"ip": _get(event, "src_ip", "source_ip")},
        "destination": {"ip": _get(event, "dst_ip", "destination_ip")},
        "network": {"bytes": _get(event, "bytes", "network_bytes")},
        "rule": {"name": _get(event, "rule", "policy")},
        "observer": {"type": "firewall"},
    }


def firewall_to_oscf(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "time": base["event_time"],
        "activity": base["event_action"],
        "category": "network",
        "src": {"ip": _get(event, "src_ip", "source_ip")},
        "dst": {"ip": _get(event, "dst_ip", "destination_ip")},
        "traffic": {"bytes": _get(event, "bytes", "network_bytes")},
        "policy": {"name": _get(event, "rule", "policy")},
        "device": {"type": "firewall"},
    }


def endpoint_to_ecs(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "@timestamp": base["event_time"],
        "event": {
            "action": base["event_action"],
            "category": ["process"],
            "kind": "event",
        },
        "host": {"name": _get(event, "hostname", "host")},
        "user": {"name": _get(event, "user", "username")},
        "process": {
            "name": _get(event, "process", "process_name"),
            "executable": _get(event, "path", "process_path"),
        },
        "observer": {"type": "endpoint"},
    }


def endpoint_to_oscf(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "time": base["event_time"],
        "activity": base["event_action"],
        "category": "process",
        "host": {"name": _get(event, "hostname", "host")},
        "user": {"name": _get(event, "user", "username")},
        "process": {
            "name": _get(event, "process", "process_name"),
            "path": _get(event, "path", "process_path"),
        },
        "device": {"type": "endpoint"},
    }


def ids_to_ecs(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "@timestamp": base["event_time"],
        "event": {
            "action": base["event_action"],
            "category": ["intrusion_detection"],
            "kind": "alert",
        },
        "source": {"ip": _get(event, "src_ip", "source_ip")},
        "destination": {"ip": _get(event, "dst_ip", "destination_ip")},
        "rule": {"name": _get(event, "signature", "rule")},
        "threat": {
            "name": _get(event, "threat", "signature"),
            "severity": _get(event, "severity"),
        },
        "observer": {"type": "ids"},
    }


def ids_to_oscf(event: Mapping[str, Any]) -> SchemaMap:
    base = _base_event(event)
    return {
        "time": base["event_time"],
        "activity": base["event_action"],
        "category": "intrusion_detection",
        "alert": {
            "name": _get(event, "signature", "rule"),
            "severity": _get(event, "severity"),
        },
        "src": {"ip": _get(event, "src_ip", "source_ip")},
        "dst": {"ip": _get(event, "dst_ip", "destination_ip")},
        "device": {"type": "ids"},
    }


SOURCES: Dict[str, SourceMapping] = {
    "firewall": SourceMapping("firewall", firewall_to_ecs, firewall_to_oscf),
    "endpoint": SourceMapping("endpoint", endpoint_to_ecs, endpoint_to_oscf),
    "ids": SourceMapping("ids", ids_to_ecs, ids_to_oscf),
}


def list_sources() -> Iterable[str]:
    return SOURCES.keys()


def required_fields() -> Iterable[str]:
    return REQUIRED_FIELDS
