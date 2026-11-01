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
        if count == 2:
            assert sorted(sum(len(stream.ticks) for stream in shard) for shard in shards) == [135, 140]


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


def test_manifest_requires_declared_replays_and_every_checkpoint(gate, tmp_path) -> None:
    from msgspec.structs import replace

    from crimson.replay.checkpoints import dump_checkpoints_file, load_checkpoints_file

    name = "quest-1.1-rules2.crd"
    source = gate.ROOT / "tests/fixtures/replays" / name
    sidecar = tmp_path / (name + ".chk")
    (tmp_path / "manifest.json").write_text(json.dumps({name: "every_tick"}))
    with pytest.raises(ValueError, match="missing.*quest-1.1"):
        gate.load_streams(tmp_path, tmp_path)
    (tmp_path / name).write_bytes(source.read_bytes())
    with pytest.raises(ValueError, match=r"missing.*\.chk"):
        gate.load_streams(tmp_path, tmp_path)
    sidecar.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="checkpoints must use the zstd envelope"):
        gate.load_streams(tmp_path, tmp_path)
    points = load_checkpoints_file(source.with_suffix(".crd.chk"))
    dump_checkpoints_file(sidecar, replace(points, checkpoints=points.checkpoints[:-1]))
    with pytest.raises(ValueError, match="checkpoint for every replay tick"):
        gate.load_streams(tmp_path, tmp_path)
    sidecar.unlink()
    (tmp_path / "manifest.json").write_text(json.dumps({name: "result_only"}))
    streams, unsupported = gate.load_streams(tmp_path, tmp_path)
    assert [stream.name for stream in streams] == [name] and not unsupported
    (tmp_path / "unlisted.crd").write_bytes(source.read_bytes())
    with pytest.raises(ValueError, match="unexpected.*unlisted"):
        gate.load_streams(tmp_path, tmp_path)


def test_quest_coverage_counts_agreeing_runs_under_their_build_and_policy(gate) -> None:
    from crimson.cl_build import ClBuild
    from crimson.quests.level import QuestLevel

    streams = []
    results = {}
    for name, build, bugs, outcome, agree in [
        ("win", ClBuild.V1_9_93, False, "quest_completed", True),
        ("loss", ClBuild.V1_9_93, True, "death", True),
        ("partial", ClBuild.V1_9_8, False, "incomplete", True),
        ("diverged", ClBuild.V1_9_93, False, "death", False),
    ]:
        spec = SimpleNamespace(cl_build=build, quest_level=QuestLevel(4, 10), preserve_bugs=bugs)
        streams.append(SimpleNamespace(name=name, run_spec=lambda spec=spec: spec))
        results[name] = {"agree": agree, "python_result": {"outcome": outcome}}
    summary = gate.quest_outcomes(streams, results)
    edition93, edition8 = summary.split("## 1.9.8")
    assert "| 4.10 | 1 | 0 | 0 | 0 | 1 | 0 |" in edition93
    assert "| 4.10 | 0 | 0 | 1 | 0 | 0 | 0 |" in edition8
