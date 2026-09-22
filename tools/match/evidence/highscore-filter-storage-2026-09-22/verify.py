"""Observe and predict the highscore witnesses' complete VC6 stack allocation."""

import argparse
import copy
import importlib.util
import json
import struct
from pathlib import Path
from unittest.mock import patch

from controls import build, sha

from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
HUD = HERE.parent / "hud-stack-coloring-2026-09-10" / "verify.py"
spec = importlib.util.spec_from_file_location("hud_graph", HUD)
hud = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hud)
ORIGINAL_OBSERVER = c2.observer_source
CONTROLS = (
    "row-plus-widget-labels",
    "label-x-before-version",
    "byte-full-version",
    "label-after-int-version",
    "player-items-before-date",
)


def observer(profile):
    source = ORIGINAL_OBSERVER(profile)
    edits = {
        "static HANDLE trace_file;": "static HANDLE trace_file;\n" + (HERE / "observer.c.in").read_text(),
        "    node = first;": "    if (phase == 12) graph(0);\n    if (phase == 13) graph(1);\n    node = first;",
        "for (j=0;j<7;++j) record[at+1+k*23+j]=*(unsigned long *)(op+j*4);": (
            "for (j=0;j<7;++j) record[at+1+k*23+j]=*(unsigned long *)(op+j*4);\n"
            "                    source_use(phase,node,side,op);"
        ),
        "base = (unsigned char *)invoke - INVOKE_RVA;": (
            "base = (unsigned char *)invoke - INVOKE_RVA;\n    compiler_base = base;"
        ),
        "    trace_file = CreateFileA(": (
            '    graph_file = CreateFileA("graph.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            '    use_file = CreateFileA("uses.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            "    if (graph_file == INVALID_HANDLE_VALUE || use_file == INVALID_HANDLE_VALUE) ExitProcess(88);\n"
            "    trace_file = CreateFileA("
        ),
        "    CloseHandle(trace_file);": (
            "    CloseHandle(graph_file);\n    CloseHandle(use_file);\n    CloseHandle(trace_file);"
        ),
    }
    for old, new in edits.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    return source


def sort_groups(groups, low, high):
    """C2+61bf0: middle pivot, strict greater comparison, no stable tie rule."""
    while low < high:
        middle = (low + high) // 2
        groups[low], groups[middle] = groups[middle], groups[low]
        pivot = low
        for index in range(low + 1, high + 1):
            if groups[index]["density"] > groups[low]["density"]:
                pivot += 1
                groups[index], groups[pivot] = groups[pivot], groups[index]
        groups[low], groups[pivot] = groups[pivot], groups[low]
        sort_groups(groups, low, pivot - 1)
        low = pivot + 1


def predict(symbols, order, *, sorting="native", padding=True):
    """Scoped to observed zero-parameter, reverse-allocation highscore path."""
    assert set(order) == set(range(len(symbols))) and len(order) == len(symbols)
    assert all(s["before"][1] & 255 in (3, 4) for s in symbols)
    assert all(s["before"][8] in (1, 4, 8, 16, 20) for s in symbols)
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
                group["uses"] += symbol["before"][13]
                break
        else:
            groups.append(
                {
                    "size": size,
                    "members": [index],
                    "conflicts": conflicts,
                    "uses": symbol["before"][13],
                },
            )
    raw_size = sum(g["size"] for g in groups)
    for index, group in enumerate(groups):
        group["creation_index"] = index
        group["density"] = group["uses"] * 1000 // group["size"]
        group["conflicts"] = sorted(group["conflicts"])
    if raw_size > 128:
        if sorting == "native":
            sort_groups(groups, 0, len(groups) - 1)
        elif sorting == "stable":
            groups.sort(key=lambda g: -g["density"])
        else:
            assert sorting == "disabled"
    offset = 0
    for group in reversed(groups):
        offset -= group["size"]
        if padding:
            offset &= ~(min(group["size"], 4) - 1)
        group["offset"] = offset
    return {"raw_size": raw_size, "frame_size": (-offset + 3) & ~3, "groups": groups}


def check_offsets(symbols, prediction):
    checked = 0
    for group in prediction["groups"]:
        for index in group["members"]:
            symbol = symbols[index]
            if symbol["before"][1] & 255 == 4:
                actual = hud.signed(symbol["final_descriptor"][3])
            else:
                assert symbol["after"][1] & 0x2000
                actual = hud.signed(symbol["after"][10])
            assert actual == group["offset"], (index, actual, group["offset"])
            checked += 1
    assert checked == len(symbols)
    return checked


def rejected(call):
    try:
        call()
    except (AssertionError, struct.error):
        return True
    raise AssertionError("Corrupted model or trace was accepted")


def verify(name, out):
    cfg, _, body, _ = build(name, out / "controls")
    profile = c2.load_profile()
    profile = dict(
        profile,
        hooks=profile["hooks"][:12]
        + [
            {"site": 0x33CDE, "target": 0x4B617, "return": False},
            {"site": 0x5840F, "target": 0x34032, "return": False},
        ],
    )
    trace_dir = out / name
    with patch.object(c2, "load_profile", lambda: profile), patch.object(c2, "observer_source", observer):
        receipt = c2.trace(cfg.directory, trace_dir)
    raw = (trace_dir / "observed/graph.bin").read_bytes()
    symbols, order = hud.decode(raw)
    prediction = predict(symbols, order)
    checked = check_offsets(symbols, prediction)
    # This body starts with mov al,[hardcore]; sub esp,imm32. Validate the
    # allocation independently against emitted instructions, not trace offsets.
    assert body.data[:1] == b"\xa0" and body.data[5:7] == b"\x81\xec"
    assert struct.unpack_from("<I", body.data, 7)[0] == prediction["frame_size"]
    corrupted = copy.deepcopy(symbols)
    local = next(s for s in corrupted if s["before"][1] & 255 == 4)
    local["final_descriptor"] = list(local["final_descriptor"])
    local["final_descriptor"][3] ^= 4
    negatives = {
        "changed_offset": rejected(lambda: check_offsets(corrupted, prediction)),
        "truncated_trace": rejected(lambda: hud.decode(raw[:-4])),
        "omitted_large_frame_sort": rejected(
            lambda: check_offsets(symbols, predict(symbols, order, sorting="disabled")),
        ),
        "omitted_byte_padding": rejected(lambda: check_offsets(symbols, predict(symbols, order, padding=False))),
    }
    if name == "row-plus-widget-labels":
        negatives["stable_tie_sort"] = rejected(
            lambda: check_offsets(symbols, predict(symbols, order, sorting="stable")),
        )
    else:
        # These witnesses do not distinguish the native and stable tie rules.
        check_offsets(symbols, predict(symbols, order, sorting="stable"))
    use_data = (trace_dir / "observed/uses.bin").read_bytes()
    assert len(use_data) % 24 == 0
    uses = [struct.unpack_from("<6I", use_data, pos) for pos in range(0, len(use_data), 24)]
    source = (cfg.directory / cfg.source).read_text().splitlines()
    start = next(i for i, line in enumerate(source) if "void highscore_screen_update" in line)
    stable = []
    for symbol in symbols:
        lines = sorted({u[2] for u in uses if u[0] == symbol["pointer"]})
        assert all(0 <= start + line < len(source) for line in lines)
        stable.append(
            {
                "index": symbol["index"],
                "kind": symbol["before"][1] & 255,
                "size": symbol["before"][8],
                "uses": symbol["before"][13],
                "conflicts": symbol["conflicts"],
                "source_lines": [start + line + 1 for line in lines],
                "source": [source[start + line] for line in lines],
            },
        )
    return {
        "control": name,
        "capture": receipt,
        "graph_sha256": sha(raw),
        "uses_sha256": sha(use_data),
        "offsets_checked": checked,
        "negative_controls": negatives,
        "allocation_order": order,
        **prediction,
        "symbols": stable,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    results = []
    for name in CONTROLS:
        result = verify(name, args.out)
        results.append(result)
        print(
            f"{name}: verified {result['offsets_checked']} offsets "
            f"and {len(result['negative_controls'])} negative controls",
            flush=True,
        )
    result = {
        "kind": "highscore-filter-storage-observer",
        "verified": True,
        "limitations": (
            "Compiler allocation proof for five source witnesses only. No original-source identity, "
            "whole-UI execution equivalence, canonical promotion or additional exact match. "
            "Source lines are diagnostic attribution, not recovered native variable identities."
        ),
        "source_hashes": {
            name: sha((HERE / name).read_bytes())
            for name in (
                "verify.py",
                "observer.c.in",
                "controls.py",
                "controls.json",
            )
        },
        "graph_decoder_sha256": sha(HUD.read_bytes()),
        "controls": results,
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
