"""Reproduce independent source controls for zero lifetime, layout, and copy induction."""

import argparse
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "vc6-timeline-consumers-2026-09-11"))
import probes

from crimson import match

WITNESS_SHA = "5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9"


def zero_variants(source):
    yield "control", source
    for location in ["before-count", "after-index", "entry"]:
        s = source.replace("        int spawn_index = 0;\n", "")
        if location == "before-count":
            s = s.replace(
                "    int entry_count = quest_spawn_count;",
                "    int spawn_index = 0;\n    int entry_count = quest_spawn_count;",
            )
        elif location == "after-index":
            s = s.replace("    int entry_index = 0;", "    int entry_index = 0;\n    int spawn_index = 0;")
        else:
            s = s.replace(
                "    unsigned char creatures_none_active",
                "    int spawn_index = 0;\n    unsigned char creatures_none_active",
            )
        for shared in [False, True]:
            t = s.replace(
                "        entry->count = 0;",
                "        spawn_index = 0;\n        entry->count = " + ("spawn_index" if shared else "0") + ";",
            )
            if shared:
                t = t.replace(
                    "        creatures_any_active_flag = 0;",
                    "        creatures_any_active_flag = spawn_index;",
                )
            yield location + ("-shared" if shared else "-reset"), t
            if shared and location == "before-count":
                t = (
                    t.replace("entry_count <= 0", "entry_count <= spawn_index")
                    .replace("trigger_cursor[1] > 0", "trigger_cursor[1] > spawn_index")
                    .replace("entry->count > 0", "entry->count > spawn_index")
                    .replace("            spread = 0;", "            spread = spawn_index;")
                )
                yield "shared-comparisons", t


def features(lines):
    triple = ["lea edi, dword [esi+0xc]", "mov dword [esp+0x10], edi", "mov dword [esp+0x10], ebx"]
    return {
        "frame": next(x for x in lines if x.startswith("sub esp,")),
        "native_pointer_triplet": any(lines[i : i + 3] == triple for i in range(len(lines) - 2)),
        "heading_through_edi": "mov eax, dword [edi+-0x4]" in lines,
        "id_through_edi": "mov edx, dword [edi]" in lines,
        "initial_count_cmp_zero": "cmp edi, ebx" in lines,
        "scan_count_cmp_zero": "cmp dword [eax+0x4], ebx" in lines,
        "clear_count_via_ebx": "mov dword [esi+0x14], ebx" in lines,
        "clear_active_via_bl": "mov byte [ADDR], bl" in lines,
    }


def layout_variants(s):
    decl = "int *template_id = &entry->template_id;"
    cases = []
    helper = "union pointer_word { int *p; unsigned long bits; unsigned char bytes[4]; };\n"
    for read in ["pointer", "bits", "memcpy"]:
        extract = {
            "pointer": "int *template_id = copied.p;",
            "bits": "int *template_id = (int *)copied.bits;",
            "memcpy": "int *template_id; memcpy(&template_id, copied.bytes, sizeof template_id);",
        }[read]
        body = (
            "pointer_word selected; selected.p = &entry->template_id; pointer_word copied; for (unsigned int k=0; k<sizeof copied; ++k) copied.bytes[k] = selected.bytes[k]; "
            + extract
        )
        cases.append(("union-" + read, helper, body))
    for size in [4, 8]:
        body = (
            "int *selected = &entry->template_id; unsigned char copied["
            + str(size)
            + "]; for (unsigned int k=0; k<sizeof selected; ++k) copied[k] = ((unsigned char *)&selected)[k]; int *template_id; memcpy(&template_id, copied, sizeof template_id);"
        )
        cases.append(("byte-array-" + str(size), "", body))
    for value in ["array", "nested", "base"]:
        if value == "array":
            helper = ""
            body = "int *selected[2]; selected[1] = &entry->template_id; selected[0] = selected[1]; int *copied[2]; for (unsigned int k=0; k<sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; int *template_id = copied[1];"
        else:
            helper = "struct pointer_cell { int *p; };\n" + (
                "struct pointer_pair { pointer_cell first; pointer_cell last; };\n"
                if value == "nested"
                else "struct pointer_pair : pointer_cell { int *last; };\n"
            )
            first = "first.p" if value == "nested" else "p"
            last = "last.p" if value == "nested" else "last"
            body = (
                "pointer_pair selected; selected."
                + last
                + " = &entry->template_id; selected."
                + first
                + " = selected."
                + last
                + "; pointer_pair copied; for (unsigned int k=0; k<sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k]; int *template_id = copied."
                + last
                + ";"
            )
        cases.append((value, helper, body))
    for name, helper, body in cases:
        src = "#include <string.h>\n" + s.replace(
            'extern "C" int frame_dt_ms;',
            helper + 'extern "C" int frame_dt_ms;',
        ).replace(decl, body).replace("entry->heading", "((float *)template_id)[-1]")
        yield name, src


def counter_variants(s):
    old = "for (unsigned int k = 0; k != sizeof copied; ++k) ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];"
    assert old in s
    loops = {
        "countdown-index": "for (unsigned int k = sizeof copied; k != 0; --k) ((unsigned char *)&copied)[sizeof copied-k] = ((unsigned char *)&selected)[sizeof copied-k];",
        "countdown-pointers": "unsigned int n=sizeof copied; unsigned char *d=(unsigned char *)&copied; const unsigned char *p=(const unsigned char *)&selected; while (n) { *d++ = *p++; --n; }",
        "countdown-do": "unsigned int n=sizeof copied; unsigned char *d=(unsigned char *)&copied; const unsigned char *p=(const unsigned char *)&selected; do { *d++ = *p++; } while (--n);",
        "pointer-end": "unsigned char *d=(unsigned char *)&copied; const unsigned char *p=(const unsigned char *)&selected; while (d != (unsigned char *)&copied + sizeof copied) { *d++ = *p++; }",
        "source-end": "unsigned char *d=(unsigned char *)&copied; const unsigned char *p=(const unsigned char *)&selected; while (p != (const unsigned char *)&selected + sizeof selected) { *d++ = *p++; }",
        "pointer-less": "unsigned char *d=(unsigned char *)&copied; const unsigned char *p=(const unsigned char *)&selected; while (d < (unsigned char *)&copied + sizeof copied) { *d++ = *p++; }",
    }
    for name, loop in loops.items():
        yield name, s.replace(old, loop)


def sources(canonical, witness):
    for base, base_text in [("canonical", canonical), ("witness", witness)]:
        for label, text in zero_variants(base_text):
            yield "zero/" + base + "/" + label, text
    for label, text in layout_variants(canonical):
        yield "layout/" + label, text
    for label, text in counter_variants(witness):
        yield "counter/" + label, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    canonical = (config.directory / config.source).read_text()
    witness = (HERE.parent / "vc6-timeline-pointer-home-2026-09-12/witness.cpp").read_text()
    assert hashlib.sha256(canonical.encode()).hexdigest() == probes.SOURCE_SHA
    assert hashlib.sha256(witness.encode()).hexdigest() == WITNESS_SHA
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    out = args.out.resolve()

    def run(item):
        name, text = item
        row, _, _ = probes.build(config, out, name, text)
        row.update(features((out / name / "candidate.asm").read_text().splitlines()))
        print(name, row["ratio"], row["frame"], row["native_pointer_triplet"], flush=True)
        return row

    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(run, sources(canonical, witness)))
    assert len(rows) == 30 and all(not row["body_byte_exact"] for row in rows)
    by_label = {row["label"]: row for row in rows}
    witness_hash = by_label["zero/witness/control"]["instruction_text_sha256"]
    for label in ["layout/array", "layout/nested", "layout/base", "counter/countdown-pointers", "counter/countdown-do"]:
        assert by_label[label]["instruction_text_sha256"] == witness_hash
    for label in ["union-pointer", "union-bits", "union-memcpy", "byte-array-4", "byte-array-8"]:
        row = by_label["layout/" + label]
        assert row["frame"] == "sub esp, 0x1c" and not row["native_pointer_triplet"]
    assert all(row["ratio"] <= by_label["zero/canonical/control"]["ratio"] for row in rows)
    (out / "results.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
