"""Prove coupled angle/input propagation; modified replays are diagnostics only."""

import argparse
import copy
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

from controls import COFF_SHA, FRAME_MAP, HERE, SOURCE_SHA, build, inspect, sha, sources, write_json

from crimson import match_c2 as c2

ORIGINAL_OBSERVER = c2.observer_source
ROLES = ("input-X", "input-Y", "heading")
EXPECTED_COFF = (
    COFF_SHA,
    COFF_SHA,
    COFF_SHA,
    COFF_SHA,
    "51f37d9b479e559837581a49fadaaaa29f2b5583b353221750f45f5b8a33a714",
    "a698a84e3567e1dabfaac129dee51e840393248aee025f418538a5e51fd95d0b",
    "134d80bd7b5f186047cddaded8adc31d4a4aaf5624d382a518062b32dfa305ac",
    "533b54257871f15a02ad69c35b20c5942be6cc4e5cb790892d5843c2992cb706",
)


def profile():
    stock = c2.load_profile()
    return dict(
        stock,
        hooks=stock["hooks"][:12]
        + [
            {"site": 0x11F08, "target": 0x11786, "return": True},
            {"site": 0x1273E, "target": 0x1D548, "return": False},
            {"site": 0x12794, "target": 0x211E, "return": False},
            {"site": 0x1315A, "target": 0x11AFA, "return": True},
            {"site": 0x12713, "target": 0x42AD4, "return": True},
            {"site": 0x125D8, "target": 0x42AD4, "return": True},
            {"site": 0x42B47, "target": 0x2771, "return": True},
            {"site": 0x42B65, "target": 0x2771, "return": True},
            {"site": 0x42B0A, "target": 0x2771, "return": True},
        ],
    )


def observer(settings, mask=0):
    assert 0 <= mask < 8
    source = ORIGINAL_OBSERVER(settings)
    edits = {
        "static void __cdecl observe(": (
            f"#define DENY_MASK {mask}\n" + (HERE / "observe.c.in").read_text() + "\nstatic void __cdecl observe("
        ),
        "    if (phase < 12) saved_function = registers[6];": (
            "    if((phase>=16&&phase<=20)||(phase>=116&&phase<=120))"
            "{conflict_watch(phase,registers);return;}\n"
            "    if(phase==15)angle_init(saved_function);\n"
            "    if(phase==12||phase==112||phase==13||phase==14){angle_watch(phase,registers);return;}\n"
            "    if (phase < 12) saved_function = registers[6];"
        ),
        "    write_block(&phase, 4);": (
            "    count=0;\n"
            "    for(node=first;node;node=*(unsigned long *)node)"
            " {unsigned long line=*(unsigned short *)(node+0x10);if(line>=160&&line<=185)++count;}\n"
            "    write_block(&phase, 4);"
        ),
        "        for (j=0;j<742;++j) record[j]=0;": (
            "        {unsigned long line=*(unsigned short *)(node+0x10);if(line<160||line>185)continue;}\n"
            "        for (j=0;j<742;++j) record[j]=0;"
        ),
        "    trace_file = CreateFileA(": (
            '    conflict_file=CreateFileA("conflict.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            "    if(conflict_file==INVALID_HANDLE_VALUE)ExitProcess(87);\n"
            '    angle_file=CreateFileA("angle.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            "    if(angle_file==INVALID_HANDLE_VALUE)ExitProcess(83);\n    trace_file = CreateFileA("
        ),
        "    CloseHandle(trace_file);": (
            "    CloseHandle(conflict_file);\n    CloseHandle(angle_file);\n    CloseHandle(trace_file);"
        ),
    }
    for old, new in edits.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    return source


def records(data, words):
    assert len(data) % (words * 4) == 0
    return [struct.unpack_from(f"<{words}I", data, offset) for offset in range(0, len(data), words * 4)]


def boundary(events, phase):
    (event,) = [e for e in events if e["phase"] == phase]
    assert event["function_ordinal"] == 0
    return event["nodes"]


def angle_order(nodes):
    return [
        n["line"]
        for n in nodes
        if n["flags"] & 0x40000000
        and ((n["line"] == 171 and n["op"] == 0x190) or (n["line"] in (173, 174) and n["op"] == 0x16D))
    ]


def check_angle(data, events, mask):
    rows = records(data, 13)
    before, after = boundary(events, 15), boundary(events, 115)
    definitions = [n for n in before if n["line"] == 171 and n["op"] == 0x15B]
    assert len(definitions) == 3
    for role, (row, node) in enumerate(zip(rows[:3], definitions, strict=True)):
        assert row[0] == 15 and row[1] == node["id"] and row[12] == role
        assert row[3:5] == (171, 0x15B) and row[6] == node["dst"][0]["raw"][5]
        assert node["dst"][0]["kind"] == 2 and node["flags"] & 0x40000000
    # Identify X/Y by their complete load/address producer chain, not arena values.
    loads = []
    for node in definitions[:2]:
        (load,) = [n for n in before if n["dst"] and n["dst"][0]["raw"][5] == node["src"][0]["raw"][5]]
        assert load["op"] == 0x15D and load["src"][0]["kind"] == 6
        loads.append(load)
    assert [o["kind"] for o in loads[0]["src"]] == [6, 2]
    assert [o["kind"] for o in loads[1]["src"]] == [6, 1]
    (add,) = [n for n in before if n["dst"] and n["dst"][0]["raw"][5] == loads[1]["src"][1]["raw"][5]]
    assert add["op"] == 0x16D and add["src"][0]["raw"][5] == loads[0]["src"][1]["raw"][5]
    assert add["src"][1]["kind"] == 7 and add["src"][1]["raw"][3] == 4
    expected = [(phase, role) for role in (1, 0, 2) for phase in (12, 112)]
    moved = [2] if mask < 4 else [r for r in (0, 1) if not mask & (1 << r)]
    expected += [(phase, role) for role in moved for phase in (13, 14)]
    assert [(r[0], r[12]) for r in rows[3:]] == expected
    for row in rows[3:]:
        role = row[12]
        assert row[1] == definitions[role]["id"] and row[6] == definitions[role]["dst"][0]["raw"][5]
        assert row[3:6] == (171, 0x15B, 2) and row[7] == 1
        if row[0] == 112:
            assert row[10] == 1 and row[11] == int(not mask & (1 << role))
        if row[0] in (12, 112, 13):
            use = next(n for n in before if n["id"] == row[2])
            assert row[9] == use["op"] == (0x15A if role == 2 else 0x15F)
            assert use["line"] == (181 if role == 2 else 171)
    # Deleted IR storage can be recycled immediately for a conversion node.
    # Match the assignment opcode and symbol, never pointer absence alone.
    remaining = {
        n["dst"][0]["raw"][5]
        for n in after
        if n["line"] == 171 and n["op"] == 0x15B and n["dst"] and n["dst"][0]["kind"] == 2
    }
    assert [r for r, n in enumerate(definitions) if n["dst"][0]["raw"][5] not in remaining] == sorted(moved)
    assert angle_order(before) == [171, 173, 174]
    assert angle_order(after) == ([173, 174, 171] if mask < 4 else [171, 173, 174])
    return definitions, loads, {"moved_definitions": [ROLES[r] for r in moved], "after_order": angle_order(after)}


def check_conflicts(data, events, mask, definitions, loads):
    rows = records(data, 26)
    pending, returns = {}, []
    for row in rows:
        phase, role = row[:2]
        assert role in range(3)
        if phase in range(16, 21):
            assert phase not in pending and row[5] == 0
            pending[phase] = row
        else:
            assert phase in range(116, 121) and phase - 100 in pending
            entry = pending.pop(phase - 100)
            assert row[1:5] == entry[1:5] and row[6:] == entry[6:] and row[5] in (0, 1)
            returns.append(row)
    assert not pending
    order = ([2] if mask < 4 else []) + [r for r in (0, 1) if not mask & (1 << r)]
    outer = [r for r in returns if r[0] <= 117]
    first = [r for r in outer if r[0] == 116]
    assert [r[1] for r in first] == order
    expected = []
    for row in first:
        role = row[1]
        expected.append((116, role, 1))
        # C2 skips the crossing scan when definition.next is already the use.
        if row[4] != row[3]:
            expected.append((117, role, int(role == 2 or mask >= 4)))
    assert [(r[0], r[1], r[5]) for r in outer] == expected
    for row in outer:
        assert row[2] == definitions[row[1]]["id"]
    positive = [r for r in returns if r[0] >= 118 and r[5]]
    expected_roles = [r for r in (0, 1) if not mask & (1 << r)] if mask < 4 else []
    assert [r[1] for r in positive] == expected_roles
    before = boundary(events, 15)
    stores = [n for n in before if n["line"] == 174 and n["op"] == 0x15B]
    (store,) = stores
    for row in positive:
        assert row[0] == 118 and row[2] == store["id"] and row[3:5] == (174, 0x15B)
        assert row[9] & 255 == 2 and row[12] == store["dst"][0]["raw"][5]
        assert row[19] & 255 == 6 and row[20] == loads[row[1]]["src"][0]["raw"][3]
    return {
        "operand_comparisons": sum(r[0] >= 118 for r in returns),
        "outer_results": [{"phase": r[0], "role": ROLES[r[1]], "result": r[5]} for r in outer],
        "conflicting_position_store": [
            {"role": ROLES[r[1]], "line": r[3], "opcode": hex(r[4]), "operand_kinds": [r[9] & 255, r[19] & 255]}
            for r in positive
        ],
    }


def check(directory, events, mask):
    definitions, loads, angle = check_angle((directory / "angle.bin").read_bytes(), events, mask)
    conflicts = check_conflicts((directory / "conflict.bin").read_bytes(), events, mask, definitions, loads)
    return {**angle, **conflicts}


def rejected(callback):
    try:
        callback()
    except (AssertionError, ValueError, StopIteration, KeyError):
        return True
    raise AssertionError("Corrupt evidence was accepted")


def negatives(directory, events):
    angle = (directory / "angle.bin").read_bytes()
    conflict = (directory / "conflict.bin").read_bytes()
    definitions, loads, _ = check_angle(angle, events, 0)
    acheck = lambda data: check_angle(data, events, 0)
    ccheck = lambda data: check_conflicts(data, events, 0, definitions, loads)
    changed_role = bytearray(angle)
    struct.pack_into("<I", changed_role, 48, 1)
    changed_return = bytearray(conflict)
    index = next(i for i, r in enumerate(records(conflict, 26)) if r[0] == 117 and r[5] == 0)
    struct.pack_into("<I", changed_return, index * 104 + 20, 1)
    changed_events = copy.deepcopy(events)
    for node in boundary(changed_events, 15):
        if node["line"] == 174 and node["op"] == 0x15B:
            node["dst"][0]["raw"][5] ^= 4
    return {
        "truncated_angle": rejected(lambda: acheck(angle[:-4])),
        "omitted_eligibility": rejected(lambda: acheck(angle[: 4 * 52] + angle[5 * 52 :])),
        "changed_role": rejected(lambda: acheck(changed_role)),
        "truncated_conflict": rejected(lambda: ccheck(conflict[:-4])),
        "changed_conflict_return": rejected(lambda: ccheck(changed_return)),
        "wrong_position_symbol": rejected(lambda: check_conflicts(conflict, changed_events, 0, definitions, loads)),
        "wrong_denial_mask": rejected(lambda: check_angle(angle, events, 4)),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    settings = profile()
    controls = []
    baseline_cfg = None
    for name, source in sources():
        row, cfg, _obj = build(name, source, out / "controls")
        controls.append(row)
        if name == "baseline":
            baseline_cfg = cfg
        print(f"stock {name}: verified source, object, references and frame map", flush=True)
    assert baseline_cfg is not None
    preserved = out / "preserving"
    with patch.object(c2, "load_profile", lambda: settings), patch.object(c2, "observer_source", observer):
        receipt = c2.trace(baseline_cfg.directory, preserved)
    events = c2.read_verified(preserved)
    assert receipt["whole_coff_equal_except_timestamp"]
    assert sha(c2.replay.normalized_coff(preserved / "observed/replay.obj")) == COFF_SHA
    preserving_decisions = check(preserved / "observed", events, 0)
    negative_results = negatives(preserved / "observed", events)
    modes = []
    for mask in range(8):
        directory = out / f"diagnostic-{mask}"
        directory.mkdir()
        shutil.copyfile(preserved / "replay/replay_settings.h", directory / "replay_settings.h")
        (directory / "observer.c").write_text(observer(settings, mask))
        with c2.compiler_environment():
            c2.replay.compile_driver(directory, "observer.c", "observer.obj")
            c2.replay.link(directory, "observer.exe", "observer.obj")
            c2.replay.run([c2.replay.WIBO, "observer.exe"], directory)
        # Deliberately modified output is decoded directly, never certified as preserving.
        observed = c2.decode_trace((directory / "phases.bin").read_bytes(), settings)
        decisions = check(directory, observed, mask)
        info = inspect(baseline_cfg, directory / "replay.obj", directory)
        assert info["normalized_coff_sha256"] == EXPECTED_COFF[mask]
        window = info["angle_windows"]["candidate"]
        fpatan = window.index("fpatan")
        assert ("fxch st(0), st(1)" in window[:fpatan]) == (mask < 4 or mask == 5)
        denied = [ROLES[r] for r in range(3) if mask & (1 << r)]
        modes.append({"deny_mask": mask, "denied": denied, **decisions, **info})
        print(f"diagnostic {mask}: verified decisions, alias conflicts, object and frame map", flush=True)
    result = {
        "kind": "player-angle-propagation-evidence",
        "verified": True,
        "source_sha256": SOURCE_SHA,
        "source_hashes": {
            p.name: sha(p.read_bytes())
            for p in (HERE / "controls.py", HERE / "verify.py", HERE / "observe.c.in", FRAME_MAP)
        },
        "limitations": "No canonical change or new match. Seven masks deliberately change C2 eligibility results. Frame checks are static; runtime equivalence is not claimed for these diagnostics or changed stock controls.",
        "preserving_manifest": receipt,
        "preserving_decisions": preserving_decisions,
        "negative_controls": negative_results,
        "stock_controls": controls,
        "diagnostic_modes": modes,
    }
    write_json(out / "results.json", result)


if __name__ == "__main__":
    main()
