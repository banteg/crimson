"""Observe and reproduce the canonical overlay's VC6 stack-coloring groups."""

import argparse
import copy
import importlib.util
import json
import os
import shutil
import struct
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parent / "vc6-intermediate-replay-2026-09-09"
spec = importlib.util.spec_from_file_location("vc6_replay", REPLAY / "verify.py")
replay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(replay)


def signed(value):
    return value - 2**32 if value & 2**31 else value


def decode(data):
    pos = 0

    def words(n):
        nonlocal pos
        row = struct.unpack_from(f"<{n}I", data, pos)
        pos += n * 4
        return row

    (phase, n, head) = words(3)
    assert phase == 0 and 0 < n <= 16384
    symbols = []
    for index in range(n):
        row = words(39)
        blocks = [words(3) for _ in range(row[38])]
        conflicts = [start + bit for start, _, mask in blocks for bit in range(32) if mask & (1 << bit)]
        assert all(0 <= conflict < n for conflict in conflicts)
        symbols.append(
            {"index": index, "pointer": row[0], "before": row[1:22], "descriptor": row[22:38], "conflicts": conflicts},
        )
    assert words(2) == (1, n)
    for symbol in symbols:
        row = words(38)
        assert row[0] == symbol["pointer"]
        symbol["after"] = row[1:22]
        symbol["final_descriptor"] = row[22:38]
    assert pos == len(data), "Unexpected extra function or incomplete trace"
    pointers = {symbol["pointer"]: symbol for symbol in symbols}
    order = []
    while head:
        symbol = pointers[head]
        assert symbol["index"] not in order
        order.append(symbol["index"])
        head = symbol["before"][11]
    assert len(order) == n
    return symbols, order


def reproduce(symbols, order):
    # VC6 4b617 first seeds parameter buckets, then 4bae6 searches local
    # buckets backwards. Both directed conflict tests are necessary.
    assert [s["before"][1] & 255 for s in symbols].count(5) == 0
    groups = []
    for index in order:
        symbol = symbols[index]
        size = symbol["before"][8]
        conflicts = set(symbol["conflicts"])
        for group in reversed(groups):
            if (
                size <= 2 * group["size"]
                and index not in group["conflicts"]
                and not conflicts.intersection(group["members"])
            ):
                group["members"].append(index)
                group["conflicts"].update(conflicts)
                group["size"] = max(size, group["size"])
                break
        else:
            groups.append({"size": size, "members": [index], "conflicts": conflicts})
    # The observed /O2 overlay follows the ascending bucket allocation path.
    # Compute offsets from bucket sizes, then check against observed descriptors.
    offset = -sum((g["size"] + 3) & ~3 for g in groups)
    checked = 0
    for number, group in enumerate(groups):
        group.pop("conflicts")
        group["index"] = number
        group["offset"] = offset
        for index in group["members"]:
            symbol = symbols[index]
            if symbol["before"][1] & 255 == 4:
                assert signed(symbol["final_descriptor"][3]) == offset, (index, offset, symbol["final_descriptor"][3])
                checked += 1
        offset += (group["size"] + 3) & ~3
    assert offset == 0 and checked > 0
    return groups, checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--source", type=Path, help="Observe a overlay source control using the canonical compiler configuration",
    )
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    helper = out / "helper"
    helper.mkdir(exist_ok=True)
    environment = {
        "MSVC_VER": "msvc6.5",
        "CRIMSON_MSVC_ROOT": str(replay.COMPILER),
        "CRIMSON_MATCH_INCLUDE_OVERLAY": "",
        "WIBO": str(replay.WIBO),
        "CRIMSON_IL_BACKEND": replay.windows_path(replay.COMPILER / "Bin/C2.DLL"),
    }
    with patch.dict(os.environ, environment):
        shutil.copyfile(REPLAY / "capture.c", helper / "capture.c")
        replay.compile_driver(helper, "capture.c", "capture.obj")
        replay.link(helper, "capture.dll", "capture.obj", dll=True)
        if args.source:
            config = replay.match.load_scratch_config(replay.match.DEFAULT_MATCH_ROOT / "scratches/player_render_overlays")
            source_dir = out / "source"
            source_dir.mkdir(exist_ok=True)
            (source_dir / config.source).write_bytes(args.source.read_bytes())
            with patch.object(replay.match, "load_scratch_config", return_value=replace(config, directory=source_dir)):
                capture = replay.verify_function("player_render_overlays", out, helper / "capture.dll")
        else:
            capture = replay.verify_function("player_render_overlays", out, helper / "capture.dll")
        baseline = out / "player_render_overlays/replay"
        observer = out / "observer"
        observer.mkdir(exist_ok=True)
        shutil.copyfile(baseline / "replay_settings.h", observer / "replay_settings.h")
        shutil.copyfile(HERE / "observer.c", observer / "observer.c")
        replay.compile_driver(observer, "observer.c", "observer.obj")
        replay.link(observer, "observer.exe", "observer.obj")
        (observer / "replay.obj").unlink(missing_ok=True)
        replay.run([replay.WIBO, "observer.exe"], observer)
    normal = replay.normalized_coff(baseline / "replay.obj")
    assert normal == replay.normalized_coff(observer / "replay.obj")
    trace = (observer / "phases.bin").read_bytes()
    symbols, order = decode(trace)
    groups, checked = reproduce(symbols, order)
    corrupted = copy.deepcopy(symbols)
    local = next(s for s in corrupted if s["before"][1] & 255 == 4)
    local["final_descriptor"] = list(local["final_descriptor"])
    local["final_descriptor"][3] ^= 4
    try:
        reproduce(corrupted, order)
    except AssertionError:
        pass
    else:
        raise AssertionError("Changed descriptor offset was accepted")
    try:
        decode(trace[:-4])
    except (AssertionError, struct.error):
        pass
    else:
        raise AssertionError("Truncated trace was accepted")
    stable = [
        {
            "index": s["index"],
            "kind": s["before"][1] & 255,
            "size": s["before"][8],
            "use_count": s["before"][13],
            "frontend_id": s["descriptor"][10] if s["before"][0] else None,
            "initial_offset": signed(s["descriptor"][3]) if s["before"][0] else None,
            "final_offset": signed(s["final_descriptor"][3]) if s["before"][0] else None,
            "conflicts": s["conflicts"],
        }
        for s in symbols
    ]
    result = {
        "schema_version": 1,
        "kind": "vc6-overlay-stack-coloring-observer",
        "verified": True,
        "limitations": "Observes this source and compiler only; the greedy model is scoped to the observed overlay allocation path. No original-source identity, semantic equivalence, or additional exact function is claimed.",
        "source_hashes": {name: replay.sha((HERE / name).read_bytes()) for name in ("verify_stack.py", "observer.c")},
        "backend_sha256": replay.sha((replay.COMPILER / "Bin/C2.DLL").read_bytes()),
        "capture": capture,
        "observed_coff_equal_except_timestamp": True,
        "observed_coff_sha256": replay.sha(normal),
        "trace_sha256": replay.sha(trace),
        "symbol_count": len(symbols),
        "descriptor_offsets_checked": checked,
        "changed_offset_rejected": True,
        "truncated_trace_rejected": True,
        "allocation_order": order,
        "groups": groups,
        "symbols": stable,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        f"Verified identical COFF; {len(symbols)} symbols, {len(groups)} groups, {checked} predicted descriptor offsets",
    )


if __name__ == "__main__":
    main()
