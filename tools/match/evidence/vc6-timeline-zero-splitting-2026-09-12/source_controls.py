"""Stock-source controls for zero lifetime, allocation ordering, and four-byte returns."""

import argparse
import hashlib
import itertools
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "vc6-timeline-decomposition-2026-09-12"))
import source_controls as sc

p = sc.probes


def lifetime(base, w, hoisted):
    cases = []
    for b, s in [("witness", w), ("canonical", base)]:
        cases.append((b + "/control", s))
        for loc, needle in [
            ("pre-outer", "    do {\n        quest_timeline_vec2_t offset"),
            ("pre-entry", "    quest_spawn_entry_t *entry ="),
            ("pre-zero", "    quest_timeline_vec2_t zero_offset"),
        ]:
            for resetwhere in ["before-reload", "after-reload", "after-clears"]:
                z = s.replace("        int spawn_index = 0;\n", "").replace(
                    needle,
                    "    int spawn_index = 0;\n" + needle,
                )
                clear = "        entry->count = 0;\n        creatures_any_active_flag = 0;"
                new = {
                    "before-reload": "        spawn_index = 0;\n        entry_count = quest_spawn_count;",
                    "after-reload": "        entry_count = quest_spawn_count;\n        spawn_index = 0;",
                }
                if resetwhere == "after-clears":
                    z = z.replace(clear, clear + "\n        spawn_index = 0;")
                else:
                    z = z.replace("        entry_count = quest_spawn_count;", new[resetwhere])
                z = z.replace(
                    "entry->count = 0;",
                    "entry->count = spawn_index;" if resetwhere != "after-clears" else "entry->count = 0;",
                ).replace(
                    "creatures_any_active_flag = 0;",
                    "creatures_any_active_flag = spawn_index;"
                    if resetwhere != "after-clears"
                    else "creatures_any_active_flag = 0;",
                )
                cases.append((b + "/" + loc + "-" + resetwhere, z))
        for resetwhere in ["before-reload", "after-reload", "after-if"]:
            z = s
            if resetwhere == "after-if":
                z = z.replace(
                    "        }\n\n        entry_count",
                    "        }\n        spawn_index = 0;\n\n        entry_count",
                )
            else:
                z = z.replace(
                    "        entry_count = quest_spawn_count;",
                    ("        spawn_index = 0;\n" if resetwhere == "before-reload" else "")
                    + "        entry_count = quest_spawn_count;"
                    + ("\n        spawn_index = 0;" if resetwhere == "after-reload" else ""),
                )
            z = z.replace("entry->count = 0;", "entry->count = spawn_index;").replace(
                "creatures_any_active_flag = 0;",
                "creatures_any_active_flag = spawn_index;",
            )
            cases.append((b + "/local-" + resetwhere, z))
    return cases


def ordering(base, w, hoisted):
    s = hoisted
    cases = []
    old = "    int entry_count = quest_spawn_count;\n    int entry_index = 0;"
    for order in itertools.permutations(["count", "index", "spawn"]):
        block = {
            "count": "    int entry_count = quest_spawn_count;",
            "index": "    int entry_index = 0;",
            "spawn": "    int spawn_index = 0;",
        }
        z = s.replace("    int spawn_index = 0;\n", "").replace(old, "\n".join(block[x] for x in order))
        cases.append(("init-" + "-".join(order), z))
    for declorder in itertools.permutations(["count", "index", "spawn", "timeline"]):
        decl = {
            "count": "    int entry_count;",
            "index": "    int entry_index;",
            "spawn": "    int spawn_index;",
            "timeline": "    int timeline;",
        }
        z = (
            s.replace(
                "    unsigned char creatures_none_active",
                "\n".join(decl[x] for x in declorder) + "\n    unsigned char creatures_none_active",
            )
            .replace("int entry_count =", "entry_count =")
            .replace("int entry_index =", "entry_index =")
            .replace("int spawn_index =", "spawn_index =")
            .replace("int timeline =", "timeline =")
        )
        cases.append(("declarations-" + "-".join(declorder), z))
    # Change outer phi construction while preserving the same reset.
    for loop in ["for", "while", "goto"]:
        z = s
        if loop == "for":
            z = z.replace(
                "    do {\n        quest_timeline_vec2_t offset",
                "    for (;;) {\n        quest_timeline_vec2_t offset",
            ).replace("    } while (true);", "    }")
        if loop == "while":
            z = z.replace(
                "    do {\n        quest_timeline_vec2_t offset",
                "    while (true) {\n        quest_timeline_vec2_t offset",
            ).replace("    } while (true);", "    }")
        if loop == "goto":
            z = z.replace(
                "    do {\n        quest_timeline_vec2_t offset",
                "outer_loop:\n    {\n        quest_timeline_vec2_t offset",
            ).replace("    } while (true);", "    }\n    goto outer_loop;")
        cases.append(("outer-" + loop, z))
    return cases


def split(base, w, hoisted):
    s = hoisted
    cases = []
    for label, z in [("canonical", base), ("witness", w), ("hoisted", s)]:
        for typ in ["int", "const int"]:
            t = z.replace(
                "        entry_count = quest_spawn_count;",
                "        " + typ + " next_count = quest_spawn_count;",
            ).replace("entry_index >= entry_count - 1", "entry_index >= next_count - 1")
            cases.append((label + "/count-" + typ.replace(" ", "-"), t))
            for cursor in ["pre", "post"]:
                y = t.replace(
                    "        ++entry_index;\n        ++entry;",
                    (
                        "        ++entry;\n        ++entry_index;"
                        if cursor == "pre"
                        else "        entry++;\n        entry_index++;"
                    ),
                )
                cases.append((label + "/count-" + typ.replace(" ", "-") + "-cursor-" + cursor, y))
        for sign in ["unsigned int", "long", "short"]:
            t = (
                z.replace("int entry_count =", "const " + sign + " entry_count =")
                .replace("        entry_count = quest_spawn_count;", "        int next_count = quest_spawn_count;")
                .replace("entry_index >= entry_count - 1", "entry_index >= next_count - 1")
            )
            # Keep signed-int behavior; unsigned/short are diagnostics only.
            cases.append((label + "/type-" + sign.replace(" ", "-"), t))
    return cases


def hints(base, w, hoisted):
    s = hoisted
    cases = []
    for target in ["entry_count", "entry_index", "timeline", "spawn_index", "entry", "trigger_cursor"]:
        for kind in ["register", "const"]:
            decl = {
                "entry_count": "int entry_count",
                "entry_index": "int entry_index",
                "timeline": "int timeline",
                "spawn_index": "int spawn_index",
                "entry": "quest_spawn_entry_t *entry",
                "trigger_cursor": "int *trigger_cursor",
            }[target]
            if kind == "const" and target not in ["timeline"]:
                continue
            z = s.replace(decl, kind + " " + decl)
            cases.append((kind + "-" + target, z))
    # A distinct stall counter local, preserving all reads/writes and ordering.
    for b, original in [("witness", w), ("hoisted", s)]:
        for mode in ["local", "register"]:
            z = original.replace(
                "    unsigned char creatures_none_active",
                "    "
                + ("register " if mode == "register" else "")
                + "int stall_time;\n    unsigned char creatures_none_active",
            )
            z = (
                z.replace(
                    "        quest_spawn_stall_timer_ms += frame_dt_ms;",
                    "        stall_time = quest_spawn_stall_timer_ms + frame_dt_ms;",
                )
                .replace("        quest_spawn_stall_timer_ms = 0;", "        stall_time = 0;")
                .replace("    int entry_count =", "    quest_spawn_stall_timer_ms = stall_time;\n    int entry_count =")
                .replace("quest_spawn_stall_timer_ms > 3000", "stall_time > 3000")
            )
            cases.append((b + "-" + mode + "-stall", z))
    return cases


def returns(base, w, hoisted):
    cases = []
    for copy in ["implicit", "member", "bytes"]:
        for dtor in [False, True]:
            ctor = {
                "implicit": "",
                "member": "pointer_cursor(const pointer_cursor &v):p(v.p) {}",
                "bytes": "pointer_cursor(const pointer_cursor &v) { for(unsigned int k=0;k<sizeof *this;++k)((unsigned char*)this)[k]=((const unsigned char*)&v)[k]; }",
            }[copy]
            helper = (
                "struct pointer_cursor { int *p; pointer_cursor(int *v):p(v) {} "
                + ctor
                + (" ~pointer_cursor() {} " if dtor else "")
                + " pointer_cursor operator--(int) { pointer_cursor old(*this); --p; return old; } pointer_cursor &operator++() { ++p; return *this; } pointer_cursor clone() const { return *this; } };\n"
            )
            for action in ["postfix", "clone", "copy-temp", "return-used"]:
                body = {
                    "postfix": "pointer_cursor cursor(&entry->template_id); cursor--; ++cursor; int *template_id=cursor.p;",
                    "clone": "pointer_cursor cursor(&entry->template_id); cursor.clone(); int *template_id=cursor.p;",
                    "copy-temp": "pointer_cursor cursor(&entry->template_id); { pointer_cursor discarded(cursor); } int *template_id=cursor.p;",
                    "return-used": "pointer_cursor cursor(&entry->template_id); int *template_id=cursor.clone().p;",
                }[action]
                z = (
                    base.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;')
                    .replace("int *template_id = &entry->template_id;", body)
                    .replace("entry->heading", "((float *)template_id)[-1]")
                )
                cases.append((copy + ("-dtor" if dtor else "") + "/" + action, z))
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    c = sc.match.load_scratch_config(sc.match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    base = (c.directory / c.source).read_text()
    w = (HERE.parent / "vc6-timeline-pointer-home-2026-09-12/witness.cpp").read_text()
    assert hashlib.sha256(base.encode()).hexdigest() == p.SOURCE_SHA
    assert hashlib.sha256(w.encode()).hexdigest() == sc.WITNESS_SHA
    assert c.compiler == "msvc6.5" and c.cflags == "/O2 /GB /W3 /GR-"
    life = lifetime(base, w, None)
    hoisted = dict(life)["witness/pre-outer-before-reload"]
    cases = []
    for name, generator in [
        ("lifetime", lifetime),
        ("ordering", ordering),
        ("split", split),
        ("hints", hints),
        ("returns", returns),
    ]:
        cases.extend((name + "/" + label, source) for label, source in generator(base, w, hoisted))
    out = args.out.resolve()

    def build(item):
        name, source = item
        row, _, _ = p.build(c, out, name, source)
        lines = (out / name / "candidate.asm").read_text().splitlines()
        row.update(sc.features(lines))
        row["initial_count_compares_ebx"] = any(x.startswith("cmp ") and x.endswith(", ebx") for x in lines[:22])
        row["outer_count_compares_ebx"] = "cmp eax, ebx" in lines
        print(name, row["ratio"], flush=True)
        return row

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(build, cases))
    assert len(rows) == 121 and all(not row["body_byte_exact"] for row in rows)
    by_label = {row["label"]: row for row in rows}
    canonical = by_label["lifetime/canonical/control"]
    assert canonical["instructions"] == 113 and canonical["prefix"] == 51
    assert canonical["references_ok"] == 13 and canonical["reference_problems"] == 0
    assert all(row["ratio"] <= canonical["ratio"] for row in rows)
    positive = by_label["lifetime/witness/pre-outer-before-reload"]
    assert positive["instructions"] == 115 and positive["native_pointer_triplet"]
    assert positive["frame"] == "sub esp, 0x20" and positive["reference_problems"] == 0
    assert all(
        positive[key]
        for key in [
            "initial_count_compares_ebx",
            "scan_count_cmp_zero",
            "outer_count_compares_ebx",
            "clear_count_via_ebx",
            "clear_active_via_bl",
        ]
    )
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
