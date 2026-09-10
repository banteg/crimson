"""Generate the bounded 2026-09-11 timeline source experiments as a mutation plan."""

import argparse
import hashlib
import json
from itertools import product
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="destination JSON mutation plan")
args = parser.parse_args()
s = Path(__file__).with_name("scratch.cpp").read_text()
expected_source_sha256 = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
if hashlib.sha256(s.encode()).hexdigest() != expected_source_sha256:
    raise SystemExit("Canonical source changed; review the mutation recipes before replay.")
variants = {}


def add(name, source):
    if name in variants:
        raise ValueError(f"Duplicate variant: {name}")
    variants[name] = source


# Derive the spawn operands from the quest table index rather than the entry cursor.
for where in ["template", "heading", "both", "all", "position", "count"]:
    t = s
    if where in ["template", "both", "all"]:
        t = t.replace("&entry->template_id", "&quest_spawn_table[entry_index].template_id")
    if where in ["heading", "both", "all"]:
        t = t.replace("entry->heading", "quest_spawn_table[entry_index].heading")
    if where in ["position", "all"]:
        t = t.replace("entry->position", "quest_spawn_table[entry_index].position")
    if where in ["count", "all"]:
        t = t.replace("entry->count", "quest_spawn_table[entry_index].count")
    add("indexed-" + where, t)
# Express the spawn loop using its primary index and let strength reduction form spread.
for loop in ["while", "for", "for-multiply", "do-multiply"]:
    t = s
    if loop == "while":
        t = t.replace("            do {", "            while (spawn_index < entry->count) {").replace(
            "            } while (spawn_index < entry->count);",
            "            }",
        )
    if loop.startswith("for"):
        t = t.replace(
            "            do {",
            "            for (; spawn_index < entry->count; ++spawn_index, spread += 0x28) {",
        ).replace(
            "                ++spawn_index;\n                spread += 0x28;\n            } while (spawn_index < entry->count);",
            "            }",
        )
    if "multiply" in loop:
        t = t.replace("(float)spread", "(float)(spawn_index * 40)")
    add("loop-" + loop, t)
# Reference-based field access is an ordinary C++ binding.
add(
    "reference-template",
    s.replace("int *template_id = &entry->template_id", "int &template_id = entry->template_id").replace(
        "*template_id,",
        "template_id,",
    ),
)
# Fully indexed source: allow VC6 to select induction cursors itself.
a = (
    s.replace("    quest_spawn_entry_t *entry = &quest_spawn_table[entry_index];\n", "")
    .replace("        ++entry;\n", "")
    .replace("entry[1].trigger_time_ms", "quest_spawn_table[entry_index+1].trigger_time_ms")
    .replace("entry->", "quest_spawn_table[entry_index].")
)
add("fully-indexed", a)
for name, base in [("indexed", a), ("pointer", s)]:
    for scan in ["direct", "entry-pointer"]:
        if scan == "direct":
            t = (
                base.replace("    int *trigger_cursor = &quest_spawn_table[0].trigger_time_ms;\n", "")
                .replace("trigger_cursor[1]", "quest_spawn_table[entry_index].count")
                .replace("trigger_cursor[0]", "quest_spawn_table[entry_index].trigger_time_ms")
                .replace("        trigger_cursor += sizeof(quest_spawn_entry_t) / sizeof(int);\n", "")
            )
        else:
            t = (
                base.replace(
                    "int *trigger_cursor = &quest_spawn_table[0].trigger_time_ms",
                    "quest_spawn_entry_t *trigger_cursor = quest_spawn_table",
                )
                .replace("trigger_cursor[1]", "trigger_cursor->count")
                .replace("trigger_cursor[0]", "trigger_cursor->trigger_time_ms")
                .replace("trigger_cursor += sizeof(quest_spawn_entry_t) / sizeof(int)", "++trigger_cursor")
            )
        add(name + "-scan-" + scan, t)
# The most direct scalar record shape with scan and nested indexed for loops.
for base_name, base in [("fully-indexed", a), ("pointer", s)]:
    for mode in ["outer-for", "outer-while", "outer-end-test", "inner-for-no-guard"]:
        t = base
        if mode == "outer-for":
            t = (
                t.replace(
                    "    do {\n        quest_timeline_vec2_t offset",
                    "    for (; entry_index < entry_count; ++entry_index) {\n        quest_timeline_vec2_t offset",
                )
                .replace("        ++entry_index;\n        ++entry;", "        ++entry;")
                .replace("        ++entry_index;\n    } while (true);", "    }")
                .replace("    } while (true);", "    }")
            )
        if mode == "outer-while":
            t = t.replace(
                "    do {\n        quest_timeline_vec2_t offset",
                "    while (entry_index < entry_count) {\n        quest_timeline_vec2_t offset",
            ).replace("    } while (true);", "    }")
        if mode == "outer-end-test":
            t = t.replace("    } while (true);", "    } while (entry_index < entry_count);")
        if mode == "inner-for-no-guard":
            t = (
                t.replace(
                    "        if ("
                    + ("quest_spawn_table[entry_index]." if base_name == "fully-indexed" else "entry->")
                    + "count > 0) {",
                    "        {",
                )
                .replace(
                    "            do {",
                    "            for (; spawn_index < "
                    + ("quest_spawn_table[entry_index]." if base_name == "fully-indexed" else "entry->")
                    + "count; ++spawn_index, spread += 40) {",
                )
                .replace(
                    "                ++spawn_index;\n                spread += 0x28;\n            } while (spawn_index < "
                    + ("quest_spawn_table[entry_index]." if base_name == "fully-indexed" else "entry->")
                    + "count);",
                    "            }",
                )
            )
        add(base_name + "-" + mode, t)
# Inline the positive-count spawn body separately from the count guard.
beg = s.index("            int *template_id = &entry->template_id;")
end = s.index("\n        }\n\n        entry_count", beg)
body = s[beg:end]
for ptr_mode, offset_mode, heading_mode in product(
    ["pointer", "reference", "indirect"],
    ["ref", "value"],
    ["entry", "reference"],
):
    head = (
        "int *template_id"
        if ptr_mode == "pointer"
        else ("int *&template_id" if ptr_mode == "reference" else "int **template_pointer")
    )
    param = (
        head
        + ", quest_spawn_entry_t *entry, quest_timeline_vec2_t "
        + ("&" if offset_mode == "ref" else "")
        + "offset, int &spawn_index"
    )
    if heading_mode == "reference":
        param += ", const float &heading"
    b = body.replace("            int *template_id = &entry->template_id;\n", "")
    if ptr_mode == "indirect":
        b = b.replace("*template_id,", "**template_pointer,")
    if heading_mode == "reference":
        b = b.replace("entry->heading", "heading")
    helper = "static __inline void spawn_positive_entry(" + param + ")\n{\n" + b + "\n}\n\n"
    call = (
        "            int *template_id = &entry->template_id;\n            spawn_positive_entry("
        + ("&template_id" if ptr_mode == "indirect" else "template_id")
        + ", entry, offset, spawn_index"
        + (", entry->heading" if heading_mode == "reference" else "")
        + ");"
    )
    t = s[:beg] + call + s[end:]
    add(
        "positive-helper-" + ptr_mode + "-" + offset_mode + "-" + heading_mode,
        t.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;'),
    )
# Explicit pointer value object copying can leave different frontend address lifetimes.
for kind in ["copy", "assign", "copy-dtor", "assign-dtor"]:
    for relative in [False, True]:
        cls = (
            "struct template_ref { int *p; template_ref(int *v) : p(v) {} template_ref(const template_ref &v) : p(v.p) {} template_ref &operator=(const template_ref &v) { p=v.p; return *this; } "
            + ("~template_ref() {}" if "dtor" in kind else "")
            + " };\n"
        )
        decl = "template_ref ref(&entry->template_id); template_ref template_id" + (
            "(ref);" if kind.startswith("copy") else "(0); template_id = ref;"
        )
        t = s.replace("int *template_id = &entry->template_id;", decl).replace("*template_id,", "*template_id.p,")
        if relative:
            t = t.replace("entry->heading", "((float *)template_id.p)[-1]")
        add(
            "copy-object-" + kind + "-" + str(relative),
            t.replace('extern "C" int frame_dt_ms;', cls + 'extern "C" int frame_dt_ms;'),
        )
# Early postincrement cursor: processing the previous record while holding next.
for stage in ["before-offset", "before-guard", "after-pointer", "after-spawn"]:
    for decl in ["entry", "template-relative"]:
        t = s
        if stage == "before-offset":
            point = t.index("        quest_timeline_vec2_t offset = zero_offset;")
        if stage == "before-guard":
            point = t.index("        if (entry->count > 0)")
        if stage == "after-pointer":
            point = t.index("            int spread;")
        if stage == "after-spawn":
            point = t.index("        entry_count = quest_spawn_count;")
        before, after = t[:point], t[point:]
        after = (
            after.replace("entry[1].trigger_time_ms", "entry[0].trigger_time_ms")
            .replace("entry->", "entry[-1].")
            .replace("        ++entry;\n", "")
        )
        if stage == "after-pointer":
            # The cursor advances on both sides of the positive count guard.
            after = after.replace(
                "        }\n\n        entry_count",
                "        } else {\n            ++entry;\n        }\n\n        entry_count",
                1,
            )
        t = before + "        ++entry;\n" + after
        if decl == "template-relative":
            t = t.replace("entry[-1].heading", "((float *)template_id)[-1]").replace(
                "entry->heading",
                "((float *)template_id)[-1]",
            )
        add("advance-" + stage + "-" + decl, t)
# A loop-local current entry, with next-entry cursor advanced immediately.
for stage in ["before-offset", "after-offset", "after-guard"]:
    t = s.replace(
        "    quest_spawn_entry_t *entry = &quest_spawn_table[entry_index];",
        "    quest_spawn_entry_t *next_entry = &quest_spawn_table[entry_index];",
    )
    t = t.replace("        ++entry;\n", "")
    t = t.replace(
        "        quest_timeline_vec2_t offset = zero_offset;",
        "        quest_spawn_entry_t *entry = next_entry;\n        quest_timeline_vec2_t offset = zero_offset;",
    )
    if stage == "before-offset":
        t = t.replace("*entry = next_entry;", "*entry = next_entry++;")
    if stage == "after-offset":
        t = t.replace("        int spawn_index = 0;", "        ++next_entry;\n        int spawn_index = 0;")
    if stage == "after-guard":
        t = t.replace("            int spread;", "            ++next_entry;\n            int spread;").replace(
            "        }\n\n        entry_count",
            "        } else {\n            ++next_entry;\n        }\n\n        entry_count",
            1,
        )
    add("next-cursor-" + stage, t)
for stage in ["loop-top", "before-vector", "before-call", "conditional-arms", "call-accessor"]:
    for heading in ["entry", "relative"]:
        t = s.replace("            int *template_id = &entry->template_id;\n", "")
        decl = "                int *template_id = &entry->template_id;\n"
        if stage == "loop-top":
            t = t.replace("            do {\n", "            do {\n" + decl)
        if stage == "before-vector":
            t = t.replace(
                "                quest_timeline_vec2_t pos(",
                decl + "                quest_timeline_vec2_t pos(",
            )
        if stage == "before-call":
            t = t.replace("                creature_spawn_template(", decl + "                creature_spawn_template(")
        if stage == "conditional-arms":
            t = (
                t.replace("            do {\n", "            do {\n                int *template_id;\n")
                .replace(
                    "                    offset.y = (float)spread;",
                    "                    template_id = &entry->template_id;\n                    offset.y = (float)spread;",
                )
                .replace(
                    "                    offset.x = (float)spread;",
                    "                    template_id = &entry->template_id;\n                    offset.x = (float)spread;",
                )
            )
        if stage == "call-accessor":
            t = t.replace(
                "            do {\n",
                "            do {\n" + decl.replace("&entry->template_id", "template_field(entry)"),
            )
            t = t.replace(
                'extern "C" int frame_dt_ms;',
                'static __inline int *template_field(quest_spawn_entry_t *entry) { return &entry->template_id; }\nextern "C" int frame_dt_ms;',
            )
        if heading == "relative":
            t = t.replace("entry->heading", "((float *)template_id)[-1]")
        add("inner-pointer-" + stage + "-" + heading, t)
# Whole routine and grouped-dispatch inlining boundaries.
for qualifier in ["__inline", "__forceinline"]:
    t = s.replace(
        'extern "C" void quest_spawn_timeline_update(void)',
        "static " + qualifier + " void timeline_update_impl(void)",
    )
    t += '\nextern "C" void quest_spawn_timeline_update(void) { timeline_update_impl(); }\n'
    add("whole-inline-" + qualifier, t)
a = s.index("    quest_timeline_vec2_t zero_offset")
for countparam in ["int", "int &"]:
    for indexparam in ["int", "int &"]:
        body = s[a : s.rindex("}")]
        helper = (
            "static __inline void spawn_trigger_group("
            + countparam
            + " entry_count, "
            + indexparam
            + " entry_index) {\n"
            + body
            + "}\n\n"
        )
        t = s[:a] + "    spawn_trigger_group(entry_count, entry_index);\n}\n"
        t = t.replace(
            'extern "C" void quest_spawn_timeline_update(void)',
            helper + 'extern "C" void quest_spawn_timeline_update(void)',
        )
        add("group-inline-count" + str("&" in countparam) + "-index" + str("&" in indexparam), t)
# Local scalar types and explicit cached field liveness at the positive guard.
for name, old, new in [
    (
        "unsigned-template",
        "int *template_id = &entry->template_id",
        "unsigned int *template_id = (unsigned int *)&entry->template_id",
    ),
    (
        "enum-template",
        "int *template_id = &entry->template_id",
        "timeline_template_id *template_id = (timeline_template_id *)&entry->template_id",
    ),
    ("unsigned-index", "int spawn_index = 0", "unsigned int spawn_index = 0"),
    ("long-spread", "int spread;", "long spread;"),
    ("unsigned-spread", "int spread;", "unsigned int spread;"),
]:
    t = s.replace(old, new)
    if name == "enum-template":
        t = t.replace(
            'extern "C" int frame_dt_ms;',
            'enum timeline_template_id { timeline_template_zero = 0 };\nextern "C" int frame_dt_ms;',
        )
    if name == "unsigned-index":
        t = t.replace("spawn_index < entry->count", "(int)spawn_index < entry->count")
    if name == "unsigned-spread":
        t = t.replace("(float)spread", "(float)(int)spread")
    add("types-" + name, t)
# Aggregate spawn state: scalar-replacement and local object lifetime boundary.
for fields in ["pointer-spread", "pointer-index", "pointer-spread-index", "pointer-offset", "all"]:
    for constructor in ["pod", "constructor"]:
        members = "int *template_id; "
        if "spread" in fields or fields == "all":
            members += "int spread; "
        if "index" in fields or fields == "all":
            members += "int spawn_index; "
        if "offset" in fields or fields == "all":
            members += "quest_timeline_vec2_t offset; "
        mapped = ["template_id"]
        if "spread" in fields or fields == "all":
            mapped += ["spread"]
        if "index" in fields or fields == "all":
            mapped += ["spawn_index"]
        if "offset" in fields or fields == "all":
            mapped += ["offset"]
        initializers = [
            x + "(" + {"template_id": "ptr", "spread": "0", "spawn_index": "0", "offset": "zero"}[x] + ")"
            for x in mapped
        ]
        ctor = "spawn_state(int *ptr, const quest_timeline_vec2_t &zero) : " + ", ".join(initializers) + " {}"
        # vec2 has no default ctor, so states containing it require a constructor.
        if "offset" in mapped and constructor == "pod":
            continue
        cls = "struct spawn_state { " + members + (ctor if constructor == "constructor" else "") + " };\n"
        t = s
        t = t.replace(
            "        quest_timeline_vec2_t offset = zero_offset;",
            "        "
            + (
                "spawn_state state(&entry->template_id, zero_offset);"
                if constructor == "constructor"
                else "spawn_state state;\n        state.template_id = &entry->template_id;\n"
                + ("\n".join("        state." + x + " = 0;" for x in mapped if x != "template_id"))
            )
            + "\n        quest_timeline_vec2_t offset = zero_offset;",
        )
        t = t.replace("            int *template_id = &entry->template_id;\n", "")
        if "spread" in mapped:
            t = t.replace("            int spread;\n\n            spread = 0;\n", "")
        if "spawn_index" in mapped:
            t = t.replace("        int spawn_index = 0;\n", "")
        if "offset" in mapped:
            t = t.replace("        quest_timeline_vec2_t offset = zero_offset;\n", "")
        # Only replace scalar uses, not state initialization.
        t = t.replace("*template_id,", "*state.template_id,")
        if "spread" in mapped:
            t = t.replace("(float)spread", "(float)state.spread").replace("spread += 0x28", "state.spread += 0x28")
        if "spawn_index" in mapped:
            t = (
                t.replace("spawn_index & 1", "state.spawn_index & 1")
                .replace("++spawn_index", "++state.spawn_index")
                .replace("spawn_index < entry->count", "state.spawn_index < entry->count")
            )
        if "offset" in mapped:
            t = t.replace("offset.x", "state.offset.x").replace("offset.y", "state.offset.y")
        for relative in [False, True]:
            z = t.replace("entry->heading", "((float *)state.template_id)[-1]") if relative else t
            add(
                "state-" + fields + "-" + constructor + "-" + str(relative),
                z.replace('extern "C" int frame_dt_ms;', cls + 'extern "C" int frame_dt_ms;'),
            )
for form in ["ref", "const-ref", "ptr-ref", "ptr-ptr", "member-ref", "member-ptr-ref"]:
    t = s
    if form in ["ref", "const-ref"]:
        helper = (
            "static __inline "
            + ("const " if form == "const-ref" else "")
            + "int &template_value(int *p) { return *p; }\n"
        )
        t = t.replace("*template_id,", "template_value(template_id),")
    elif form in ["ptr-ref", "ptr-ptr"]:
        helper = (
            "static __inline int *&template_pointer(int *&p) { return p; }\n"
            if form == "ptr-ref"
            else "static __inline int **template_pointer(int **p) { return p; }\n"
        )
        t = t.replace(
            "*template_id,",
            "*template_pointer(template_id)," if form == "ptr-ref" else "**template_pointer(&template_id),",
        )
    else:
        helper = (
            "struct template_handle { int *p; template_handle(int *v):p(v) {} "
            + ("int &value() { return *p; }" if form == "member-ref" else "int *&pointer() { return p; }")
            + " };\n"
        )
        t = t.replace(
            "int *template_id = &entry->template_id;",
            "template_handle template_id(&entry->template_id);",
        ).replace("*template_id,", "template_id.value()," if form == "member-ref" else "*template_id.pointer(),")
    add("return-" + form, t.replace('extern "C" int frame_dt_ms;', helper + 'extern "C" int frame_dt_ms;'))

plan = {
    "schema": 1,
    "sites": [
        {
            "name": "source-boundary",
            "find": s,
            "replacements": [{"name": name, "text": text} for name, text in variants.items()],
        },
    ],
}
args.output.write_text(json.dumps(plan, indent=2) + "\n")
print(f"Wrote {len(variants)} source controls to {args.output}")
