"""Sharding retains the complete corpus and rejects partial or overlapping merged reports."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch):
    checks = Path(__file__).resolve().parents[1] / "crimson-core/checks"
    monkeypatch.syspath_prepend(str(checks))
    spec = importlib.util.spec_from_file_location("core_gate", checks / "gate.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_stream_occurs_in_exactly_one_deterministic_shard(gate) -> None:
    streams = [SimpleNamespace(name=f"s{i}", ticks=[None] * n) for i, n in enumerate([100, 70, 40, 30, 20, 10, 5])]
    for count in range(1, len(streams) + 1):
        shards = [gate.shard_streams(streams, i, count) for i in range(1, count + 1)]
        assert sorted(s.name for shard in shards for s in shard) == sorted(s.name for s in streams)
        assert shards == [gate.shard_streams(list(reversed(streams)), i, count) for i in range(1, count + 1)]


def test_merge_requires_complete_disjoint_reports_and_keeps_failures(gate, tmp_path: Path) -> None:
    def report(name: str, streams: dict, unsupported: dict | None = None) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps({"streams": streams, "unsupported": unsupported or {}}))
        return path

    first = report("first.json", {"a": {"agree": True}})
    second = report("second.json", {"b": {"agree": False}})
    result = gate.merge_reports([first, second], {"a", "b"}, {})
    assert result["total"] == 2 and result["agree"] == 1
    with pytest.raises(ValueError, match="missing"):
        gate.merge_reports([first], {"a", "b"}, {})
    with pytest.raises(ValueError, match="duplicate"):
        gate.merge_reports([first, first], {"a"}, {})
    with pytest.raises(ValueError, match="unexpected"):
        gate.merge_reports([first, second], {"a"}, {})
    mismatch = report("mismatch.json", {"b": {"agree": True}}, {"fixture": "unsupported"})
    with pytest.raises(ValueError, match="unsupported fixtures differ"):
        gate.merge_reports([first, mismatch], {"a", "b"}, {})
