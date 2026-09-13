"""Diagnostic player_update ESP propagation with explicit direct-call cleanup."""

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ROOT = Path(sys.argv[1])
header_path = REPO / "tools/match/include/grim2d_cpp.h"

expected = json.loads((HERE / "controls.json").read_text())["build"]["dependencies"]["tools/match/include/grim2d_cpp.h"]
assert hashlib.sha256(header_path.read_bytes()).hexdigest() == expected
header = header_path.read_text()
methods = re.findall(r"virtual\s+([^;]+);", header, re.DOTALL)
slots = {}
for i, method in enumerate(methods):
    name, args = re.search(r"(grim_\w+)\((.*?)\)", method, re.DOTALL).groups()
    pop = (
        0
        if "..." in args
        else sum(16 if "grim_config_value_t" in a else 4 for a in args.split(",") if a.strip() not in ("void", ""))
    )
    slots[i * 4] = (name, pop)
# These direct calls use caller cleanup in this pinned function. The two
# vector methods below pop their arguments; ECX carries the vec2_sub receiver.
cdecl = {
    "player_start_reload",
    "player_heading_approach_target",
    "vec2_length",
    "player_apply_move_with_spawn_avoidance",
    "input_aim_pov_left_active",
    "input_aim_pov_right_active",
    "fx_spawn_sprite",
    "fx_spawn_particle",
    "fx_spawn_particle_slow",
    "fx_spawn_secondary_projectile",
    "projectile_spawn",
    "player_take_damage",
    "effect_spawn",
    "effect_spawn_blood_splatter",
    "perk_count_get",
    "sfx_play_panned",
    "input_primary_just_pressed",
    "crt_ftol",
    "ftol",
    "crt_rand",
    "rand",
}
summary = {}
for kind in ["native", "candidate"]:
    lines = json.loads((ROOT / (kind + ".json")).read_text())
    offsets = {x["offset"]: i for i, x in enumerate(lines)}
    states = {0: 0}
    todo = [0]
    bad = []
    while todo:
        i = todo.pop()
        n = lines[i]
        depth = states[i]
        t = n["text"]
        new = depth
        if t.startswith("push "):
            new += 4
        if t.startswith("pop "):
            new -= 4
        m = re.fullmatch(r"(add|sub) esp, (0x[0-9a-f]+)", t)
        if m:
            new += int(m[2], 0) * (1 if m[1] == "sub" else -1)
        elif re.match(r"\w+ esp(?:,|$)", t) and t != "push esp":
            raise ValueError(f"unsupported ESP instruction: {t}")
        if t.startswith("call "):
            names = {k[5:] for r in n["masked_references"] for k in r["keys"] if k.startswith("name:")}
            m = re.fullmatch(r"call dword \[\w+\+(0x[0-9a-f]+)\]", t)
            if m:
                name, pop = slots[int(m[1], 0)]
                new -= pop
            elif "Sleep" in names:
                new -= 4
            elif {"vec2_sub", "D3DXVec2Normalize"}.intersection(names):
                new -= 8
            elif t != "call ADDR" or not cdecl.intersection(names):
                raise ValueError(f"unknown call cleanup: {t}, {sorted(names)}")
        branch = re.fullmatch(r"j\w+ L([0-9a-f]+)", t)
        successors = [] if t.startswith("ret") else [i + 1] if i + 1 < len(lines) else []
        if branch:
            if t.startswith("jmp "):
                successors = []
            successors.append(offsets[int(branch[1], 16)])
        if t.startswith("jmp ") and not branch:
            raise ValueError(t)
        for j in successors:
            if j not in states:
                states[j] = new
                todo.append(j)
            elif states[j] != new:
                bad.append((i, j, states[j], new))
    summary[kind] = {
        "instructions": len(lines),
        "reached": len(states),
        "conflicts": bad,
        "returns": [[i, states[i]] for i, n in enumerate(lines) if n["text"].startswith("ret")],
    }
    print(json.dumps({"kind": kind, **summary[kind]}))
    assert not bad and len(states) == len(lines)
    assert all(states[i] == 0 for i, row in enumerate(lines) if row["text"].startswith("ret"))
    annotated = []
    for i, n in enumerate(lines):
        t = re.sub(
            r"\[esp(?P<disp>[+-]0x[0-9a-f]+)?\]",
            lambda m, depth=states[i]: "[FRAME" + format(int(m["disp"] or "0", 0) - depth, "+d") + "]",
            n["text"],
        )
        refs = ",".join(x["text"] for x in n["masked_references"])
        annotated.append(f"{n['address']:08x} {t}" + (" ; " + refs if refs else ""))
    (ROOT / (kind + "-frame.asm")).write_text("\n".join(annotated) + "\n")
    (ROOT / (kind + "-depths.json")).write_text(json.dumps(states, indent=2) + "\n")

(ROOT / "frame-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
