import pytest

from normalizer.normalizer import NormalizationError, normalize_event_auto, normalize_events


def test_normalize_firewall_ecs():
    event = {
        "event_time": "2024-06-01T12:00:00Z",
        "action": "allow",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "bytes": 256,
        "device_type": "firewall",
    }
    results = normalize_events([event], source="firewall", schema="ecs", strict=True)
    assert results[0]["event"]["action"] == "allow"
    assert results[0]["source"]["ip"] == "10.0.0.1"


def test_normalize_auto_ocsf_alias():
    event = {
        "event_time": "2024-06-01T12:00:00Z",
        "action": "exec",
        "device_type": "endpoint",
        "process": "bash",
    }
    result = normalize_event_auto(event, schema="ocsf", strict=True)
    assert result.schema == "oscf"
    assert result.normalized["device"]["type"] == "endpoint"


def test_strict_validation_missing_fields():
    event = {"device_type": "ids"}
    with pytest.raises(NormalizationError):
        normalize_events([event], source="ids", schema="ecs", strict=True)
