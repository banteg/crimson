"""Diagnostic ESP propagation for this function, using the verified Grim ABI."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
header = Path("tools/match/include/grim2d_cpp.h").read_text()
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
for kind in ["native", "candidate"]:
    lines = json.loads((ROOT / (kind + ".json")).read_text())
    offsets = {x["offset"]: i for i, x in enumerate(lines)}
    states = {0: 0}
    todo = [0]
    edges = {}
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
        if t.startswith("call "):
            m = re.fullmatch(r"call dword \[\w+\+(0x[0-9a-f]+)\]", t)
            if m:
                name, pop = slots[int(m[1], 0)]
                new -= pop
            elif any("name:Sleep" in x["keys"] for x in n["masked_references"]):
                new -= 4
        branch = re.fullmatch(r"j\w+ L([0-9a-f]+)", t)
        successors = [] if t.startswith("ret") else [i + 1] if i + 1 < len(lines) else []
        if branch:
            if t.startswith("jmp "):
                successors = []
            successors.append(offsets[int(branch[1], 16)])
        if t.startswith("jmp ") and not branch:
            raise ValueError(t)
        edges[i] = successors
        for j in successors:
            if j not in states:
                states[j] = new
                todo.append(j)
            elif states[j] != new:
                bad.append((i, j, states[j], new))
    print(
        kind,
        "reached",
        len(states),
        "total",
        len(lines),
        "conflicts",
        bad[:10],
        "returns",
        [(i, states[i]) for i, n in enumerate(lines) if n["text"].startswith("ret")],
    )
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
