"""Verify the used/unused pointer-copy lowering split without changing C2 decisions."""

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import source_controls

HERE = Path(__file__).resolve().parent
CONSUMERS = HERE.parent / "vc6-timeline-consumers-2026-09-11"
sys.path.insert(0, str(CONSUMERS))
spec = importlib.util.spec_from_file_location("consumer_trace", CONSUMERS / "trace.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
r = t.r


def analyze(snapshots, source, expected_stores):
    lines = source.splitlines()
    line = next(i for i, text in enumerate(lines) if "for (" in text) - next(
        i for i, text in enumerate(lines) if "void quest_spawn_timeline_update" in text
    )
    selected = [[n for n in nodes if n["line"] == line] for nodes in snapshots]
    assert not any(n["op"] == 0x190 for n in selected[0])
    intrinsic = next(n for n in selected[1] if n["op"] == 0x190)
    assert any(n["id"] == intrinsic["id"] and n["op"] == 0x190 for n in selected[4])
    assert not any(n["op"] == 0x190 for n in selected[5])
    stores = [n for n in selected[5] if n["op"] == 1 and n["dst"][0][2] & 255 == 2]
    assert len(stores) == expected_stores
    retained = []
    promoted = []
    for store in stores:
        node_id = store["id"]
        symbol = store["dst"][0][5]
        after = next(n for n in snapshots[7] if n["id"] == node_id)
        assert after["dst"][0][5] == symbol
        if after["dst"][0][2] & 255 == 2:
            for nodes in snapshots[5:]:
                current = next(n for n in nodes if n["id"] == node_id)
                assert current["op"] == 1 and current["dst"][0][2] & 255 == 2
                assert current["dst"][0][5] == symbol
                assert not any(op[5] == symbol for n in nodes for op in n["src"])
            retained.append({"node_id": node_id, "destination_symbol": symbol})
        else:
            assert after["dst"][0][2] & 255 == 1
            promoted.append({"node_id": node_id, "destination_symbol": symbol})
    assert len(promoted) == 1
    assert len(retained) == expected_stores - 1
    return {
        "source_relative_line": line,
        "copy_intrinsic_created_during_global_optimization": True,
        "intrinsic_node_id": intrinsic["id"],
        "memory_stores_after_lowering": len(stores),
        "promoted_at_26d75": promoted,
        "unused_memory_store_retained_through_pre_336f4": retained,
        "phases": [{"phase": t.old.PHASES[i], "nodes": nodes} for i, nodes in enumerate(selected)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--capture-dll", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = t.match.load_scratch_config(t.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    source = (config.directory / config.source).read_text()
    assert r.sha(source.encode()) == source_controls.probes.SOURCE_SHA
    assert r.sha((r.COMPILER / "Bin/C2.DLL").read_bytes()) == t.old.C2_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    sources = dict(source_controls.all_sources(source))
    # The imported analyzer assumes canonical field-load placement. Keep all of
    # its capture/COFF/stream checks and assert the copy-specific history above.
    t.analyze = lambda *args: {}
    records = []
    with patch.dict(
        os.environ,
        {
            "MSVC_VER": "msvc6.5",
            "CRIMSON_MSVC_ROOT": str(r.COMPILER),
            "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
            "WIBO": str(r.WIBO),
            "CRIMSON_IL_BACKEND": r.windows_path(r.COMPILER / "Bin/C2.DLL"),
        },
    ):
        for name, count in [
            ("memory/bytes-loop-relative", 1),
            ("pair/same-loop-last-relative", 2),
            ("shape/body-copy-relative", 2),
        ]:
            text = sources[name]
            row, snapshots = t.trace(config, out, name, text, args.capture_dll.resolve())
            findings = analyze(snapshots, text, count)
            listing = (out / name / "candidate.asm").read_text().splitlines()
            if count == 2:
                slot = "0x10" if name.startswith("shape/") else "0x14"
                sequence = ["lea edi, dword [esi+0xc]", f"mov dword [esp+{slot}], edi", f"mov dword [esp+{slot}], ebx"]
                start = listing.index(sequence[0])
                assert listing[start : start + 3] == sequence
                findings["adjacent_pointer_overwrite"] = {"start_index": start, "instructions": sequence}
            records.append({"verified": row, "findings": findings})
            print(name, "verified", flush=True)
    (out / "results.json").write_text(json.dumps({"c2_sha256": t.old.C2_SHA, "controls": records}, indent=2) + "\n")


if __name__ == "__main__":
    main()
