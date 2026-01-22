# AI-SOC Normalizer

This repository contains a lightweight event normalizer that ingests security telemetry from
multiple sources (firewall, endpoint, IDS) and emits a consistent schema using either the
Elastic Common Schema (ECS) or the OSCF framework.

## Features
- Simple JSON-in/JSON-out normalization pipeline.
- Pluggable mappings for different device types.
- ECS or OSCF output selection.
- CLI for batch normalization from stdin or files.

## Quick start
```bash
python -m normalizer.cli --schema ecs --source firewall --input example_events.json
```

Normalize newline-delimited JSON with strict validation:
```bash
python -m normalizer.cli --schema ocsf --source auto --ndjson --strict --input events.ndjson
```

## Example
Input event:
```json
{
  "device_type": "firewall",
  "event_time": "2024-06-01T12:00:00Z",
  "src_ip": "10.10.10.10",
  "dst_ip": "172.16.0.5",
  "action": "allow",
  "rule": "egress-web",
  "bytes": 1512
}
```

Normalized ECS output:
```json
{
  "@timestamp": "2024-06-01T12:00:00Z",
  "event": {
    "action": "allow",
    "category": ["network"],
    "kind": "event"
  },
  "network": {
    "bytes": 1512
  },
  "rule": {
    "name": "egress-web"
  },
  "source": {
    "ip": "10.10.10.10"
  },
  "destination": {
    "ip": "172.16.0.5"
  },
  "observer": {
    "type": "firewall"
  }
}
```

## Supported sources
- `firewall`
- `endpoint`
- `ids`

## Extending mappings
Edit `normalizer/mappings.py` to add a new source mapping or expand existing ones.
