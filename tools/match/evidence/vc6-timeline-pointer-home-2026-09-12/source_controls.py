"""Reproduce the stock VC6 pointer-home witness and bounded source ablations."""

import argparse
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "vc6-timeline-consumers-2026-09-11"))
import mine
import probes

from crimson import match


def memory_variants(s):
    decl = "int *template_id = &entry->template_id;"
    cases = {
        "memmove": (
            "int *selected = &entry->template_id; int *template_id; memmove(&template_id, &selected, sizeof template_id);",
            "",
        ),
        "bytes-roundtrip": (
            "int *selected = &entry->template_id; unsigned char bytes[sizeof selected]; memcpy(bytes, &selected, sizeof selected); int *template_id; memcpy(&template_id, bytes, sizeof template_id);",
            "",
        ),
        "split-2-2": (
            "int *selected = &entry->template_id; int *template_id; memcpy(&template_id, &selected, 2); memcpy((char *)&template_id + 2, (char *)&selected + 2, 2);",
            "",
        ),
        "split-3-1": (
            "int *selected = &entry->template_id; int *template_id; memcpy(&template_id, &selected, 3); memcpy((char *)&template_id + 3, (char *)&selected + 3, 1);",
            "",
        ),
        "bytes-unrolled": (
            "int *selected = &entry->template_id; int *template_id; "
            + " ".join(
                "((unsigned char *)&template_id)[" + str(i) + "] = ((unsigned char *)&selected)[" + str(i) + "];"
                for i in range(4)
            ),
            "",
        ),
        "bytes-loop": (
            "int *selected = &entry->template_id; int *template_id; for (unsigned int k = 0; k != sizeof template_id; ++k) ((unsigned char *)&template_id)[k] = ((unsigned char *)&selected)[k];",
            "",
        ),
    }
    for second in ["int", "float", "double"]:
        helper = "struct pointer_pair { int *p; " + second + " extra; };\n"
        for mode in ["assign", "memcpy", "memmove"]:
            copy = (
                "pointer_pair copied = selected;"
                if mode == "assign"
                else "pointer_pair copied; " + mode + "(&copied, &selected, sizeof copied);"
            )
            cases[second + "-pair-" + mode] = (
                "pointer_pair selected = { &entry->template_id, 0 }; " + copy + " int *template_id = copied.p;",
                helper,
            )
    for packing in [1, 2]:
        helper = (
            "#pragma pack(push, "
            + str(packing)
            + ")\nstruct packed_pointer { char pad; int *p; };\n#pragma pack(pop)\n"
        )
        for mode in ["assign", "memcpy"]:
            copy = (
                "packed_pointer copied = selected;"
                if mode == "assign"
                else "packed_pointer copied; memcpy(&copied, &selected, sizeof copied);"
            )
            cases["packed-" + str(packing) + "-" + mode] = (
                "packed_pointer selected = { 0, &entry->template_id }; " + copy + " int *template_id = copied.p;",
                helper,
            )
    for name, (body, helper) in cases.items():
        for relative in [False, True]:
            src = "#include <string.h>\n" + s.replace(
                'extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;',
            ).replace(decl, body)
            if relative:
                src = src.replace("entry->heading", "((float *)template_id)[-1]")
            yield name + ("-relative" if relative else ""), src


def loop_variants(s):
    decl = "int *template_id = &entry->template_id;"
    loop = "for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
    for kind, fields, init in [
        ("pair", "int *p; int extra;", "&entry->template_id, 0"),
        ("float", "int *p; float extra;", "&entry->template_id, 0"),
        ("double", "int *p; double extra;", "&entry->template_id, 0"),
        ("reversed", "int extra; int *p;", "0, &entry->template_id"),
    ]:
        helper = "struct pointer_holder { " + fields + " };\n"
        for scope in [False, True]:
            body = "pointer_holder selected = { " + init + " }; pointer_holder copied; " + loop
            body = (
                ("int *template_id; { " + body + " template_id = copied.p; }")
                if scope
                else body + " int *template_id = copied.p;"
            )
            for relative in [False, True]:
                src = s.replace(decl, body).replace(
                    'extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;',
                )
                if relative:
                    src = src.replace("entry->heading", "((float *)template_id)[-1]")
                yield kind + ("-scoped" if scope else "") + ("-relative" if relative else ""), src
    for name, lp in [
        ("signed-less", loop.replace("unsigned int", "int").replace("!= sizeof copied", "< 4")),
        ("unsigned-less", loop.replace("!= sizeof copied", "< sizeof copied")),
        (
            "reverse",
            loop.replace("unsigned int k = 0; k != sizeof copied; ++k", "int k = sizeof copied - 1; k >= 0; --k"),
        ),
        (
            "while",
            "unsigned int k = 0; while (k != sizeof copied) { ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; ++k; }",
        ),
    ]:
        body = "int *selected = &entry->template_id; int *copied; " + lp + " int *template_id = copied;"
        for relative in [False, True]:
            src = s.replace(decl, body)
            if relative:
                src = src.replace("entry->heading", "((float *)template_id)[-1]")
            yield name + ("-relative" if relative else ""), src


def pair_variants(s):
    decl = "int *template_id = &entry->template_id;"
    loop = "for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
    helper = "struct pointer_pair { int *first; int *last; };\n"
    for second in ["same", "count"]:
        value = "&entry->template_id" if second == "same" else "&entry->count"
        for mode in ["loop", "memcpy", "assign"]:
            for used in ["first", "last"]:
                init = (
                    "{ &entry->template_id, " + value + " }"
                    if used == "first"
                    else "{ " + value + ", &entry->template_id }"
                )
                copy = (
                    loop
                    if mode == "loop"
                    else ("memcpy(&copied, &selected, sizeof copied);" if mode == "memcpy" else "copied = selected;")
                )
                body = (
                    "int *template_id; { pointer_pair selected = "
                    + init
                    + "; pointer_pair copied; "
                    + copy
                    + " template_id = copied."
                    + used
                    + "; }"
                )
                for relative in [False, True]:
                    src = "#include <string.h>\n" + s.replace(decl, body).replace(
                        'extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;',
                    )
                    if relative:
                        src = src.replace("entry->heading", "((float *)template_id)[-1]")
                    yield second + "-" + mode + "-" + used + ("-relative" if relative else ""), src


def shape_variants(s):
    decl = "int *template_id = &entry->template_id;"
    loop = "for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
    helper = "struct pointer_pair { int *first; int *last; };\n"
    init = "pointer_pair selected = { &entry->template_id, &entry->template_id };"
    styles = [
        ("less", init, loop.replace("!= sizeof copied", "< sizeof copied")),
        ("signed", init, loop.replace("unsigned int", "int").replace("!= sizeof copied", "< 8")),
        (
            "reverse",
            init,
            loop.replace("unsigned int k = 0; k != sizeof copied; ++k", "int k = sizeof copied - 1; k >= 0; --k"),
        ),
        (
            "body-forward",
            "pointer_pair selected; selected.first = &entry->template_id; selected.last = &entry->template_id;",
            loop,
        ),
        (
            "body-reverse",
            "pointer_pair selected; selected.last = &entry->template_id; selected.first = &entry->template_id;",
            loop,
        ),
        (
            "body-copy",
            "pointer_pair selected; selected.last = &entry->template_id; selected.first = selected.last;",
            loop,
        ),
        (
            "while",
            init,
            "unsigned int k = 0; while (k != sizeof copied) { ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; ++k; }",
        ),
        (
            "do",
            init,
            "unsigned int k = 0; do { ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; ++k; } while (k < sizeof copied);",
        ),
    ]
    for name, initial, copy in styles:
        for relative in [False, True]:
            body = "int *template_id; { " + initial + " pointer_pair copied; " + copy + " template_id = copied.last; }"
            src = s.replace(decl, body).replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;')
            if relative:
                src = src.replace("entry->heading", "((float *)template_id)[-1]")
            yield name + ("-relative" if relative else ""), src


def scalar_variants(s):
    decl = "int *template_id = &entry->template_id;"
    loop = "for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
    for style in ["outer", "scoped", "direct", "memcpy", "assign"]:
        copy = (
            loop
            if style not in ["memcpy", "assign"]
            else ("memcpy(&copied, &selected, sizeof copied);" if style == "memcpy" else "copied = selected;")
        )
        body = "int *selected = &entry->template_id; int *copied; " + copy + " int *template_id = selected;"
        if style == "scoped":
            body = (
                "int *template_id; { int *selected = &entry->template_id; int *copied; "
                + copy
                + " template_id = selected; }"
            )
        if style == "direct":
            body = decl + " { int *copied; " + copy.replace("selected", "template_id") + " }"
        for relative in [False, True]:
            src = "#include <string.h>\n" + s.replace(decl, body)
            if relative:
                src = src.replace("entry->heading", "((float *)template_id)[-1]")
            yield style + ("-relative" if relative else ""), src


def lifetime_variants(s):
    decl = "            int *template_id = &entry->template_id;\n"
    helper = "struct pointer_pair { int *first; int *last; };\n"
    copy = "int *template_id; { pointer_pair selected; selected.last = &entry->template_id; selected.first = selected.last; pointer_pair copied; for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; template_id = copied.last; }"
    base = s.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;').replace(
        "entry->heading", "((float *)template_id)[-1]",
    )
    offset = "        quest_timeline_vec2_t offset = zero_offset;\n"
    guard = "        if (entry->count > 0) {\n"
    for site in [
        "before-offset",
        "after-offset",
        "before-offset-guarded",
        "offset-in-guard-before",
        "offset-in-guard-after",
    ]:
        t = base.replace(decl, "")
        if site == "before-offset":
            t = t.replace(offset, "        " + copy + "\n" + offset)
        if site == "after-offset":
            t = t.replace(offset, offset + "        " + copy + "\n")
        if site == "before-offset-guarded":
            guarded = copy.replace("int *template_id; {", "int *template_id; if (entry->count > 0) {")
            t = t.replace(offset, "        " + guarded + "\n" + offset)
        if site.startswith("offset-in-guard"):
            t = t.replace(offset, "")
            inside = (
                ("            " + copy + "\n" + offset)
                if site.endswith("after")
                else (offset + "            " + copy + "\n")
            )
            t = t.replace(guard, guard + inside)
        yield site, t
    # Reuse the consumed object field directly instead of extracting a scalar.
    for name, init in [
        ("same", "selected.first = &entry->template_id; selected.last = &entry->template_id;"),
        ("copy", "selected.last = &entry->template_id; selected.first = selected.last;"),
    ]:
        body = (
            "pointer_pair selected; "
            + init
            + " pointer_pair copied; for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
        )
        t = (
            base.replace(decl, "            " + body + "\n")
            .replace("*template_id,", "*copied.last,")
            .replace("((float *)template_id)[-1]", "((float *)copied.last)[-1]")
        )
        yield "direct-field-" + name, t


FAMILIES = {
    "memory": memory_variants,
    "loop": loop_variants,
    "pair": pair_variants,
    "shape": shape_variants,
    "scalar": scalar_variants,
    "lifetime": lifetime_variants,
}


def all_sources(source):
    yield "baseline", source
    for family, generate in FAMILIES.items():
        for label, text in generate(source):
            yield family + "/" + label, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    source = (config.directory / config.source).read_text()
    assert hashlib.sha256(source.encode()).hexdigest() == probes.SOURCE_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    out = args.out.resolve()

    def run(item):
        name, text = item
        row, _, _ = probes.build(config, out, name, text)
        lines = (out / name / "candidate.asm").read_text().splitlines()
        row.update(mine.screen(lines))
        print(name, row["ratio"], row["instructions"], flush=True)
        return row

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(run, all_sources(source)))
    assert len(rows) == 120 and all(not r["body_byte_exact"] for r in rows)
    by_name = {r["label"]: r for r in rows}
    baseline = by_name["baseline"]["instruction_text_sha256"]
    for name in ["pair/same-memcpy-last-relative", "pair/same-assign-last-relative", "scalar/scoped-relative"]:
        assert by_name[name]["instruction_text_sha256"] == baseline
    witness = by_name["shape/body-copy-relative"]
    assert witness["instructions"] == 115 and witness["references_ok"] == 12 and witness["reference_problems"] == 0
    assert witness["same_block_stack_overwrites"] == [
        {"first_index": 54, "second_index": 55, "context": ["mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]},
    ]
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
