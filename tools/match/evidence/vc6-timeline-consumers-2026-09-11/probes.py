"""Bounded source hypotheses from the GPT Pro timeline consultation."""

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"


def variants(source):
    declaration = "int *template_id = &entry->template_id;"
    for copy in (False, True):
        for relative in (False, True):
            new = "int *template_id; { int *selected = &entry->template_id; "
            new += "memcpy(&template_id, &selected, sizeof template_id);" if copy else "template_id = selected;"
            new += " }"
            text = source.replace(declaration, new)
            if copy:
                text = "#include <string.h>\n" + text
            if relative:
                text = text.replace("entry->heading", "((float *)template_id)[-1]")
            label = f"{'memcpy' if copy else 'assignment'}-{'relative' if relative else 'entry'}"
            yield label, text, None, ""
            if copy:
                yield label + "-nointrinsic", text, None, " /Oi-"

    # Bind the pointer expression itself, rather than an existing named pointer.
    start = source.index("            " + declaration)
    end = source.index("\n        }\n\n        entry_count", start)
    body = source[start:end].replace("            " + declaration + "\n", "")
    for reference in (False, True):
        param = "const P &template_id" if reference else "P template_id"
        helper = (
            "template<class P> static __inline void spawn_selected(quest_spawn_entry_t *entry, "
            + param
            + ", quest_timeline_vec2_t &offset) {\n    int spawn_index = 0;\n"
            + body
            + "\n}\n\n"
        )
        text = source[:start] + "            spawn_selected(entry, &entry->template_id, offset);" + source[end:]
        text = text.replace("        int spawn_index = 0;\n", "")
        text = text.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;')
        yield "generic-" + ("const-ref" if reference else "value"), text, None, ""

    # Overlay the actual embedded field type; do not cast an int object into a class.
    header = (match.REPO_ROOT / "third_party/headers/crimsonland_types.h").read_text()
    begin = header.index("typedef struct quest_spawn_entry_t {")
    finish = header.index("} quest_spawn_entry_t;", begin)
    record = header[begin:finish]
    assert record.count("    int template_id;") == 1
    wrapped = (
        header[:begin]
        + "struct quest_id_t { int value; int get() const { return value; } };\n"
        + record.replace("    int template_id;", "    quest_id_t template_id;")
        + header[finish:]
    )
    for direct in (False, True):
        text = source.replace(declaration, "const quest_id_t *template_id = &entry->template_id;")
        text = text.replace("*template_id,", "entry->template_id.get()," if direct else "template_id->get(),")
        if direct:
            text = text.replace("            const quest_id_t *template_id = &entry->template_id;\n", "")
        checks = (
            "#include <stddef.h>\n"
            "typedef char id_size_check[sizeof(quest_id_t)==4 ? 1 : -1];\n"
            "typedef char entry_size_check[sizeof(quest_spawn_entry_t)==24 ? 1 : -1];\n"
            "typedef char id_offset_check[offsetof(quest_spawn_entry_t,template_id)==12 ? 1 : -1];\n"
            "typedef char heading_offset_check[offsetof(quest_spawn_entry_t,heading)==8 ? 1 : -1];\n"
        )
        text = text.replace('extern "C" int frame_dt_ms;', checks + 'extern "C" int frame_dt_ms;')
        yield "embedded-id-" + ("direct" if direct else "pointer"), text, wrapped, ""


def build(config, out, label, source, header=None, extra_flags=""):
    directory = out / label
    directory.mkdir(parents=True, exist_ok=True)
    (directory / config.source).write_text(source)
    if header is not None:
        (directory / "crimsonland_types.h").write_text(header)
    candidate = replace(
        config,
        directory=directory,
        cflags=config.cflags + extra_flags,
        include_overlay=directory if header is not None else None,
    )
    obj = match.compile_scratch(candidate, force=True)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    (directory / "candidate.asm").write_text("\n".join(result.candidate_lines) + "\n")
    data = bytearray(obj.read_bytes())
    data[4:8] = bytes(4)
    row = {
        "label": label,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "header_sha256": hashlib.sha256(header.encode()).hexdigest() if header is not None else None,
        "cflags": candidate.cflags,
        "normalized_coff_sha256": hashlib.sha256(data).hexdigest(),
        "instruction_text_sha256": hashlib.sha256("\n".join(result.candidate_lines).encode()).hexdigest(),
        "ratio": result.ratio,
        "instructions": len(result.candidate_lines),
        "prefix": result.prefix_instructions,
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "body_byte_exact": result.body_byte_exact,
    }
    (directory / "result.json").write_text(json.dumps(row, indent=2) + "\n")
    return row, candidate, obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    source = (config.directory / config.source).read_text()
    assert hashlib.sha256(source.encode()).hexdigest() == SOURCE_SHA
    rows = []
    for label, text, header, flags in [("baseline", source, None, ""), *variants(source)]:
        row, _, _ = build(config, args.out.resolve(), label, text, header, flags)
        rows.append(row)
        print(label, row["ratio"], row["instructions"], row["references_ok"], row["reference_problems"], flush=True)
    assert len(rows) == 11 and all(not row["body_byte_exact"] for row in rows)
    by_label = {row["label"]: row for row in rows}
    baseline = by_label["baseline"]["instruction_text_sha256"]
    for name in (
        "assignment-entry",
        "assignment-relative",
        "memcpy-entry",
        "memcpy-relative",
        "embedded-id-pointer",
        "embedded-id-direct",
    ):
        assert by_label[name]["instruction_text_sha256"] == baseline
        assert by_label[name]["instructions"] == 113 and by_label[name]["references_ok"] == 13
        assert by_label[name]["reference_problems"] == 0
    assert (
        by_label["generic-value"]["instruction_text_sha256"] == by_label["generic-const-ref"]["instruction_text_sha256"]
    )
    assert by_label["generic-value"]["instruction_text_sha256"] != baseline
    for name in ("memcpy-entry-nointrinsic", "memcpy-relative-nointrinsic"):
        assert by_label[name]["instructions"] == 123 and by_label[name]["ratio"] < by_label["baseline"]["ratio"]
    (args.out / "results.json").write_text(
        json.dumps(
            {
                "source_sha256": SOURCE_SHA,
                "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "results": rows,
            },
            indent=2,
        )
        + "\n",
    )


if __name__ == "__main__":
    main()
