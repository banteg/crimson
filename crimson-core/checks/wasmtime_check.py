"""Load the exact Node/Worker core.wasm in Python and check every snapshot.

An optional desktop-host feasibility probe, not a renderer or public verifier.
Run with uv run --with wasmtime==49.0.0 python crimson-core/checks/wasmtime_check.py.
"""

import argparse
import hashlib
import json
import struct
from importlib.metadata import version
from pathlib import Path

import wasmtime

CORE = Path(__file__).resolve().parents[1]


CONFIG_BYTES = 260


SMOKE = {"rush-evade", "survival-hunt-highlander-ranked", "survival-relative-keyboard", "quest-point-click-ranked", "quest-settings"}


def decode(data):
    if len(data) < CONFIG_BYTES:
        raise ValueError("Truncated config")
    records = []
    offset = CONFIG_BYTES
    while offset < len(data):
        if len(data) - offset < 24:
            raise ValueError("Truncated tick")
        count = struct.unpack_from("<I", data, offset + 20)[0]
        size = 24 + count * 8
        if count > 16 or len(data) - offset < size:
            raise ValueError("Invalid commands")
        records.append(data[offset : offset + size])
        offset += size
    return data[:CONFIG_BYTES], records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=CORE / "build")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    wasm = args.build / "wasm/core.wasm"
    report = json.loads((args.build / "report.json").read_text())
    engine = wasmtime.Engine()
    module = wasmtime.Module.from_file(engine, str(wasm))
    if module.imports:
        raise ValueError("Probe expects the import-free core")
    store = wasmtime.Store(engine)
    exports = wasmtime.Instance(store, module, []).exports(store)
    exports["_initialize"](store)
    memory = exports["memory"]
    pointers = {name: exports["portable_" + name](store) for name in ("config", "input", "commands", "output")}
    snapshot_fields = sum(g["count"] * len(g["fields"]) for g in json.loads((CORE / "schema.json").read_text()))

    def init(config):
        memory.write(store, config, pointers["config"])
        if not exports["portable_init"](store, *struct.unpack_from("<4I", config)):
            raise ValueError("Rejected config")

    def step(record):
        memory.write(store, record[:20], pointers["input"])
        count = struct.unpack_from("<I", record, 20)[0]
        memory.write(store, record[24:], pointers["commands"])
        if not exports["portable_step_many"](store, count):
            raise ValueError("Rejected tick")

    def snapshot():
        count = exports["portable_snapshot"](store)
        if count != snapshot_fields:
            raise ValueError("Unknown snapshot schema")
        return memory.read(store, pointers["output"], pointers["output"] + count * 4)

    results = []
    # Use the same instance across all runs; repeat each A after a different B.
    other, other_records = decode((args.build / "fixtures/rush-idle.rsi").read_bytes())
    # One run per mode, policy and control family is enough to show the module runs the same here.
    for case in (case for case in report["cases"] if case["name"] in SMOKE):
        config, records = decode((args.build / "fixtures" / (case["name"] + ".rsi")).read_bytes())
        init(config)
        digest = hashlib.sha256(snapshot())
        for record in records:
            step(record)
            digest.update(snapshot())
        last = snapshot()
        final_digest = hashlib.sha256(last).hexdigest()
        if digest.hexdigest() != case["sha256"] or final_digest != case["final_sha256"]:
            raise ValueError(f"Wasmtime differs from native/Node: {case['name']}")
        init(other)
        for record in other_records[:200]:
            step(record)
        init(config)
        for record in records:
            step(record)
        if last != snapshot():
            raise ValueError(f"Wasmtime A/B/A reset differs: {case['name']}")
        results.append({"name": case["name"], "ticks": len(records), "sha256": digest.hexdigest()})
    if len(results) != len(SMOKE):
        raise ValueError("Smoke runs missing from the matrix report")
    result = {
        "wasmtime_version": version("wasmtime"),
        "module_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(),
        "cases": len(results),
        "ticks": sum(case["ticks"] for case in results),
        "fields_per_snapshot": snapshot_fields,
        "comparison": "every snapshot hash matches native/Node",
        "reset": "all Wasmtime A/B/A passed",
        "linear_memory_mib": memory.data_len(store) / 1048576,
        "results": results,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "results"}, indent=2))


if __name__ == "__main__":
    main()
