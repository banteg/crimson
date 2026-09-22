"""Observe timeline locals, implicit aliases, and every allocated stack offset."""

import argparse
import copy
import json
import struct
from pathlib import Path
from unittest.mock import patch

from controls import HERE, build, load, sha

from crimson import match_c2 as c2

stack = load("timeline_stack", HERE.parent / "highscore-filter-storage-2026-09-22/verify.py")
CASES = ("end-pointer", "pair", "guard", "separate-input")


def profile():
    stock = c2.load_profile()
    return dict(
        stock,
        hooks=stock["hooks"][:12]
        + [
            {"site": 0x33CDE, "target": 0x4B617, "return": False},
            {"site": 0x5840F, "target": 0x34032, "return": False},
        ],
    )


def observer(settings):
    source = stack.observer(settings)
    edits = {
        "static void __cdecl observe(": (HERE / "aliases.c.in").read_text() + "\nstatic void __cdecl observe(",
        "source_use(phase,node,side,op);": "source_use(phase,node,side,op); alias_use(phase,node,side,op);",
        "    graph_file = CreateFileA(": (
            '    alias_file = CreateFileA("aliases.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            "    if(alias_file==INVALID_HANDLE_VALUE)ExitProcess(79);\n    graph_file = CreateFileA("
        ),
        "    CloseHandle(graph_file);": "    CloseHandle(alias_file);\n    CloseHandle(graph_file);",
    }
    for old, new in edits.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    return source


def decode_aliases(data, symbols, events):
    assert len(data) % 40 == 0
    records = [struct.unpack_from("<10I", data, pos) for pos in range(0, len(data), 40)]
    groups = []
    for record in records:
        if record[8] == 0:
            assert record[9] == 0xFFFFFFFF
            groups.append({"header": record, "members": []})
        else:
            assert groups and groups[-1]["header"][:8] == record[:8]
            index = record[9]
            assert index < len(symbols) and symbols[index]["pointer"] == record[8]
            assert index not in groups[-1]["members"]
            groups[-1]["members"].append(index)
    # Independently enumerate every kind-6/11 operand from the complete IR
    # snapshots. Kind 6's alias handle is an eighth word absent from those
    # snapshots; the observer reads +1c explicitly. Kind 11 uses common +14.
    (boundary,) = [event for event in events if event["site_rva"] == 0x33CDE]
    expected = []
    for node in boundary["nodes"]:
        for side, key in enumerate(("src", "dst")):
            for operand in node[key]:
                if operand["kind"] in (6, 11):
                    expected.append((node, side, operand))
    assert len(groups) == len(expected) and groups
    for group, (node, side, operand) in zip(groups, expected, strict=True):
        header = group["header"]
        assert header[:4] == (node["id"], node["line"], node["op"], side)
        assert header[5:7] == (operand["kind"], operand["raw"][4])
        if operand["kind"] == 11:
            assert header[7] == operand["raw"][5]
    return groups


def copied_index(symbols):
    candidates = [s["index"] for s in symbols if s["before"][13] == 1 and s["before"][8] in (4, 8)]
    (index,) = candidates
    return index


def check_alias_memberships(name, groups, symbols):
    owner = copied_index(symbols)
    owner_uses = [g for g in groups if owner in g["members"]]
    if name in ("end-pointer", "separate-input"):
        assert len(owner_uses) == 4
        assert {(g["header"][5], g["header"][3]) for g in owner_uses} == {(6, 0), (11, 0), (11, 1)}
    else:
        assert name in ("pair", "guard") and not owner_uses
    return owner_uses


def verify(name, out):
    row, cfg, _obj = build(name, out / "controls")
    settings = profile()
    directory = out / "traces" / name
    with patch.object(c2, "load_profile", lambda: settings), patch.object(c2, "observer_source", observer):
        receipt = c2.trace(cfg.directory, directory)
    assert receipt["whole_coff_equal_except_timestamp"]
    assert row["normalized_coff_sha256"] == sha(c2.replay.normalized_coff(directory / "observed/replay.obj"))
    data = (directory / "observed/graph.bin").read_bytes()
    symbols, order = stack.hud.decode(data)
    prediction = stack.predict(symbols, order)
    checked = stack.check_offsets(symbols, prediction)
    assert row["frame"] == prediction["frame_size"]
    alias_data = (directory / "observed/aliases.bin").read_bytes()
    events = c2.read_verified(directory)
    groups = decode_aliases(alias_data, symbols, events)
    owner_uses = check_alias_memberships(name, groups, symbols)
    owner = copied_index(symbols)
    assert symbols[owner]["before"][8] == (8 if name == "pair" else 4)
    raw_uses = (directory / "observed/uses.bin").read_bytes()
    assert len(raw_uses) % 24 == 0
    uses = [struct.unpack_from("<6I", raw_uses, i) for i in range(0, len(raw_uses), 24)]
    owner_direct = [u for u in uses if u[0] == symbols[owner]["pointer"]]
    assert len(owner_direct) == 1 and owner_direct[0][4] == 1
    shared = next(g for g in prediction["groups"] if owner in g["members"])
    assert shared["members"] == ([owner] if owner_uses else [0, owner])
    lines = (cfg.directory / cfg.source).read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if "void quest_spawn_timeline_update" in line)
    stable = []
    for symbol in symbols:
        direct = sorted({u[2] for u in uses if u[0] == symbol["pointer"]})
        stable.append(
            {
                "index": symbol["index"],
                "size": symbol["before"][8],
                "explicit_uses": symbol["before"][13],
                "flags": hex(symbol["before"][1]),
                "conflicts": symbol["conflicts"],
                "offset": stack.hud.signed(symbol["final_descriptor"][3]),
                "source_lines": [start + line + 1 for line in direct],
                "source": [lines[start + line] for line in direct],
            },
        )
    negatives = {
        "truncated_graph": stack.rejected(lambda: stack.hud.decode(data[:-4])),
        "truncated_alias_record": stack.rejected(lambda: decode_aliases(alias_data[:-4], symbols, events)),
        "omitted_alias_operand": stack.rejected(lambda: decode_aliases(alias_data[40:], symbols, events)),
    }
    corrupted_alias = bytearray(alias_data)
    member_pos = next(pos for pos in range(0, len(alias_data), 40) if struct.unpack_from("<I", alias_data, pos + 32)[0])
    (old_index,) = struct.unpack_from("<I", alias_data, member_pos + 36)
    struct.pack_into("<I", corrupted_alias, member_pos + 36, (old_index + 1) % len(symbols))
    negatives["changed_alias_index"] = stack.rejected(lambda: decode_aliases(corrupted_alias, symbols, events))
    corrupted = copy.deepcopy(symbols)
    corrupted[owner]["final_descriptor"] = list(corrupted[owner]["final_descriptor"])
    corrupted[owner]["final_descriptor"][3] ^= 4
    negatives["changed_offset"] = stack.rejected(lambda: stack.check_offsets(corrupted, prediction))
    if owner_uses:
        bad_groups = copy.deepcopy(groups)
        next(g for g in bad_groups if owner in g["members"])["members"].remove(owner)
        negatives["omitted_copied_alias"] = stack.rejected(lambda: check_alias_memberships(name, bad_groups, symbols))
        corrupted = copy.deepcopy(symbols)
        corrupted[0]["conflicts"].remove(owner)
        corrupted[owner]["conflicts"].remove(0)
        negatives["ignored_copy_spread_conflict"] = stack.rejected(
            lambda: stack.check_offsets(symbols, stack.predict(corrupted, order)),
        )
    result = {
        "control": name,
        "build": row,
        "capture": receipt,
        "graph_sha256": sha(data),
        "alias_sha256": sha(alias_data),
        "direct_uses_sha256": sha(raw_uses),
        "offsets_checked": checked,
        "copied_index": owner,
        "allocation_order": order,
        **prediction,
        "symbols": stable,
        "negative_controls": negatives,
        "alias_operands": [
            {
                "source_line": start + g["header"][1] + 1,
                "opcode": g["header"][2],
                "side": g["header"][3],
                "kind": g["header"][5],
                "flags": hex(g["header"][6]),
                "handle": g["header"][7],
                "members": g["members"],
            }
            for g in groups
        ],
    }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in CASES:
        rows.append(verify(name, args.out))
        print(f"{name}: verified alias membership and every stack offset", flush=True)
    result = {
        "kind": "timeline-copy-alias-observer",
        "verified": True,
        "limitations": "Pinned compiler observations for four diagnostic source witnesses. No original-source recovery, runtime proof, or additional exact function.",
        "source_hashes": {
            name: sha((HERE / name).read_bytes())
            for name in ("verify.py", "aliases.c.in", "controls.py", "witness.cpp")
        },
        "controls": rows,
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
