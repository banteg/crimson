"""Generate the bounded 2026-09-12 timeline source-shape controls as one mutation plan.

Ten families probe whether ordinary C++ spellings reproduce the native interior
template-id pointer (`lea edi, [esi+0xc]`) and its immediately overwritten stack
home: inline call wrappers, non-POD return temporaries, memory-class holders,
by-value pointer parameters, out-parameters, multi-word aggregates, short-lived
scoped holders, pointers derived from sibling fields, `this`-anchored sub-object
methods, and redefined base copies.
"""

import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="destination JSON mutation plan")
args = parser.parse_args()
s = Path(__file__).with_name("scratch.cpp").read_text()
expected_source_sha256 = "a448391479030f257a8e5626e795be585674e2b4ec3e0fdb5e95ff9a08ff44d9"
if hashlib.sha256(s.encode()).hexdigest() != expected_source_sha256:
    raise SystemExit("Canonical source changed; review the mutation recipes before replay.")
variants = {}


def batch_wrap(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    CALL = (
        "                creature_spawn_template(\n"
        "                    *template_id,\n"
        "                    (const vec2f_t *)&pos,\n"
        "                    entry->heading);\n"
    )
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    assert CALL in s and PTR_DECL in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def drop_ptr(text):
        return text.replace(PTR_DECL, "")

    # --- Inlined wrapper around creature_spawn_template with reference/pointer parameters.
    POS_PARAM = {
        "posref": ("const quest_timeline_vec2_t &pos", "(const vec2f_t *)&pos", "pos"),
        "posptr": ("const quest_timeline_vec2_t *pos", "(const vec2f_t *)pos", "&pos"),
    }
    TID_PARAM = {
        "cref": ("const int &template_id", "template_id", "entry->template_id"),
        "ref": ("int &template_id", "template_id", "entry->template_id"),
        "cptr": ("const int *template_id", "*template_id", "&entry->template_id"),
        "ptr": ("int *template_id", "*template_id", "&entry->template_id"),
    }
    HEAD_PARAM = {
        "val": ("float heading", "heading", "entry->heading"),
        "cref": ("const float &heading", "heading", "entry->heading"),
    }
    for tk, (tdecl, tuse, targ) in TID_PARAM.items():
        for pk, (pdecl, puse, parg) in POS_PARAM.items():
            for hk, (hdecl, huse, harg) in HEAD_PARAM.items():
                helper = (
                    "static __inline void spawn_creature(" + tdecl + ", " + pdecl + ", " + hdecl + ")\n"
                    "{\n"
                    "    creature_spawn_template(" + tuse + ", " + puse + ", " + huse + ");\n"
                    "}\n\n"
                )
                call = "                spawn_creature(" + targ + ", " + parg + ", " + harg + ");\n"
                add("wrap-" + tk + "-" + pk + "-" + hk, prepend(drop_ptr(s).replace(CALL, call), helper))

    # Wrapper receiving the temporary vector expression directly.
    for tk in ["cref", "cptr"]:
        tdecl, tuse, targ = TID_PARAM[tk]
        helper = (
            "static __inline void spawn_creature(" + tdecl + ", const quest_timeline_vec2_t &pos, float heading)\n"
            "{\n"
            "    creature_spawn_template(" + tuse + ", (const vec2f_t *)&pos, heading);\n"
            "}\n\n"
        )
        t = drop_ptr(s).replace(
            "                quest_timeline_vec2_t pos(\n"
            "                    offset.x + entry->position.x,\n"
            "                    offset.y + entry->position.y);\n" + CALL,
            "                spawn_creature(" + targ + ",\n"
            "                    offset + *(const quest_timeline_vec2_t *)&entry->position,\n"
            "                    entry->heading);\n",
        )
        add("wrap-" + tk + "-vecexpr", prepend(t, helper))

    # Wrapper reading heading relative to the reference parameter.
    helper = (
        "static __inline void spawn_creature(const int &template_id, const quest_timeline_vec2_t &pos)\n"
        "{\n"
        "    creature_spawn_template(template_id, (const vec2f_t *)&pos, ((const float *)&template_id)[-1]);\n"
        "}\n\n"
    )
    add(
        "wrap-cref-relative-heading",
        prepend(drop_ptr(s).replace(CALL, "                spawn_creature(entry->template_id, pos);\n"), helper),
    )

    # --- Array-decay views: template_id is the first element of an int triple.
    VIEW = (
        "struct quest_spawn_row_t {\n    float pos_x;\n    float pos_y;\n    float heading;\n    int meta[3];\n};\n\n"
    )
    for form in ["decay", "elem0", "array-ptr"]:
        t = s
        if form == "decay":
            t = t.replace(PTR_DECL, "            int *template_id = ((quest_spawn_row_t *)entry)->meta;\n")
        elif form == "elem0":
            t = t.replace(PTR_DECL, "            int *template_id = &((quest_spawn_row_t *)entry)->meta[0];\n")
        else:
            t = t.replace(
                PTR_DECL,
                "            int (*template_id)[3] = &((quest_spawn_row_t *)entry)->meta;\n",
            ).replace(
                "*template_id,",
                "(*template_id)[0],",
            )
        add("array-" + form, prepend(t, VIEW))

    # --- Conversion-operator ID object overlay.
    IDVIEW = (
        "struct quest_spawn_id_object_t {\n"
        "    int value;\n"
        "    operator int() const { return value; }\n"
        "};\n\n"
        "struct quest_spawn_view_t {\n"
        "    vec2f_t position;\n"
        "    float heading;\n"
        "    quest_spawn_id_object_t template_id;\n"
        "    int trigger_time_ms;\n"
        "    int count;\n"
        "};\n\n"
    )
    for form in ["direct", "ref", "ptr"]:
        t = drop_ptr(s)
        if form == "direct":
            t = t.replace("*template_id,", "((quest_spawn_view_t *)entry)->template_id,")
        elif form == "ref":
            t = t.replace(
                "            int spread;\n",
                "            const quest_spawn_id_object_t &template_id = ((quest_spawn_view_t *)entry)->template_id;\n            int spread;\n",
            ).replace("*template_id,", "template_id,")
        else:
            t = t.replace(
                "            int spread;\n",
                "            const quest_spawn_id_object_t *template_id = &((quest_spawn_view_t *)entry)->template_id;\n            int spread;\n",
            )
        add("idobj-" + form, prepend(t, IDVIEW))

    # --- Derived and sibling pointers.
    add(
        "derived-heading-ptr-outer",
        s.replace(PTR_DECL, PTR_DECL + "            float *heading = (float *)template_id - 1;\n").replace(
            "entry->heading);",
            "*heading);",
        ),
    )
    add(
        "derived-heading-ptr-inner",
        s.replace(
            "                creature_spawn_template(\n",
            "                float *heading = (float *)template_id - 1;\n                creature_spawn_template(\n",
        ).replace("entry->heading);", "*heading);"),
    )
    add(
        "sibling-heading-ptr",
        s.replace(PTR_DECL, PTR_DECL + "            float *heading = &entry->heading;\n").replace(
            "entry->heading);",
            "*heading);",
        ),
    )
    add(
        "entry-reference",
        s.replace(
            "        quest_timeline_vec2_t offset = zero_offset;\n",
            "        quest_spawn_entry_t &e = *entry;\n        quest_timeline_vec2_t offset = zero_offset;\n",
        ).replace(PTR_DECL, "            int *template_id = &e.template_id;\n"),
    )
    add(
        "char-offsetof",
        prepend(
            s.replace(
                PTR_DECL,
                "            int *template_id = (int *)((char *)entry + offsetof(quest_spawn_entry_t, template_id));\n",
            ),
            "#include <stddef.h>\n",
        ),
    )
    add(
        "function-scope-pointer",
        s.replace(
            "    int entry_count = quest_spawn_count;\n",
            "    int *template_id;\n    int entry_count = quest_spawn_count;\n",
        ).replace(PTR_DECL, "            template_id = &entry->template_id;\n"),
    )
    add(
        "for-init-pointer",
        s.replace(
            PTR_DECL + "            int spread;\n\n            spread = 0;\n            do {\n",
            "            int spread = 0;\n            for (int *template_id = &entry->template_id;;) {\n",
        ).replace(
            "                ++spawn_index;\n                spread += 0x28;\n            } while (spawn_index < entry->count);\n",
            "                ++spawn_index;\n                spread += 0x28;\n                if (spawn_index >= entry->count) {\n                    break;\n                }\n            }\n",
        ),
    )


def batch_rettemp(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    CALL = (
        "                creature_spawn_template(\n"
        "                    *template_id,\n"
        "                    (const vec2f_t *)&pos,\n"
        "                    entry->heading);\n"
    )
    assert PTR_DECL in s and CALL in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    # --- Non-POD wrapper returned by value from an inline accessor (hidden-pointer return temp).
    REF_CLASS = "struct spawn_ref_t {\n    int *p;\n    spawn_ref_t(int *v) : p(v) {}\n};\n\n"
    ACCESSORS = {
        "free": "static __inline spawn_ref_t template_ref(quest_spawn_entry_t *e) { return spawn_ref_t(&e->template_id); }\n\n",
        "free-named": "static __inline spawn_ref_t template_ref(quest_spawn_entry_t *e) { spawn_ref_t r(&e->template_id); return r; }\n\n",
    }
    for ak, acc in ACCESSORS.items():
        # temp dies immediately; scalar pointer keeps value
        add(
            "ret-" + ak + "-scalar",
            prepend(s.replace(PTR_DECL, "            int *template_id = template_ref(entry).p;\n"), REF_CLASS + acc),
        )
        # named object lives through loop
        add(
            "ret-" + ak + "-object",
            prepend(
                s.replace(PTR_DECL, "            spawn_ref_t template_id = template_ref(entry);\n").replace(
                    "*template_id,",
                    "*template_id.p,",
                ),
                REF_CLASS + acc,
            ),
        )
        # const ref bound to the temporary
        add(
            "ret-" + ak + "-constref",
            prepend(
                s.replace(PTR_DECL, "            const spawn_ref_t &template_id = template_ref(entry);\n").replace(
                    "*template_id,",
                    "*template_id.p,",
                ),
                REF_CLASS + acc,
            ),
        )

    # Member accessor on an overlay entry class returning non-POD by value.
    VIEW = (
        "struct spawn_ref_t {\n"
        "    int *p;\n"
        "    spawn_ref_t(int *v) : p(v) {}\n"
        "};\n\n"
        "struct quest_entry_view_t {\n"
        "    vec2f_t position;\n"
        "    float heading;\n"
        "    int template_id;\n"
        "    int trigger_time_ms;\n"
        "    int count;\n"
        "    spawn_ref_t spawn_ref() { return spawn_ref_t(&template_id); }\n"
        "};\n\n"
    )
    add(
        "ret-member-scalar",
        prepend(
            s.replace(PTR_DECL, "            int *template_id = ((quest_entry_view_t *)entry)->spawn_ref().p;\n"),
            VIEW,
        ),
    )

    # --- Temporary class object constructed in place with the pointer, method used in loop.
    TEMP_CLASS = (
        "struct spawn_ref_t {\n"
        "    int *p;\n"
        "    spawn_ref_t(int *v) : p(v) {}\n"
        "    int id() const { return *p; }\n"
        "};\n\n"
    )
    add(
        "temp-ctor-scalar",
        prepend(
            s.replace(PTR_DECL, "            int *template_id = spawn_ref_t(&entry->template_id).p;\n"),
            TEMP_CLASS,
        ),
    )
    add(
        "temp-ctor-object",
        prepend(
            s.replace(PTR_DECL, "            spawn_ref_t template_id(&entry->template_id);\n").replace(
                "*template_id,",
                "template_id.id(),",
            ),
            TEMP_CLASS,
        ),
    )
    add(
        "temp-ctor-copyinit",
        prepend(
            s.replace(PTR_DECL, "            spawn_ref_t template_id = spawn_ref_t(&entry->template_id);\n").replace(
                "*template_id,",
                "template_id.id(),",
            ),
            TEMP_CLASS,
        ),
    )
    add(
        "temp-ctor-assign",
        prepend(
            s.replace(
                PTR_DECL,
                "            spawn_ref_t template_id(0);\n            template_id = spawn_ref_t(&entry->template_id);\n",
            ).replace(
                "*template_id,",
                "template_id.id(),",
            ),
            TEMP_CLASS,
        ),
    )

    # --- Whole-loop helper taking reference-to-pointer bound to an rvalue (materialized temporary).
    beg = s.index(PTR_DECL)
    end = s.index("\n        }\n\n        entry_count", beg)
    body = s[beg + len(PTR_DECL) : end]
    for pk, pdecl, puse in [
        ("ptr-constref", "int *const &template_id", "*template_id"),
        ("cptr-constref", "const int *const &template_id", "*template_id"),
        ("ref-struct-constref", "const spawn_ref_t &ref", "*ref.p"),
        ("struct-value", "spawn_ref_t ref", "*ref.p"),
        ("struct-value-pod", "spawn_pod_t ref", "*ref.p"),
    ]:
        b = body.replace("*template_id,", puse + ",")
        helper = (
            "static __inline void spawn_group("
            + pdecl
            + ", quest_spawn_entry_t *entry, quest_timeline_vec2_t &offset, int &spawn_index)\n"
            "{\n" + b + "\n}\n\n"
        )
        arg = "&entry->template_id"
        if "struct" in pk and "pod" not in pk:
            helper = REF_CLASS + helper
            arg = "spawn_ref_t(&entry->template_id)"
        if "pod" in pk:
            helper = "struct spawn_pod_t { int *p; };\n\n" + helper
            arg = "ref"
        call = "            spawn_group(" + arg + ", entry, offset, spawn_index);"
        if "pod" in pk:
            call = "            spawn_pod_t ref = { &entry->template_id };\n" + call
        add("group-" + pk, prepend(s[:beg] + call + s[end:], helper))

    # --- Whole-loop helper: pointer param by value, but helper also declares spread after.
    for pk, pdecl in [("ptr", "int *template_id"), ("cptr", "const int *template_id")]:
        helper = (
            "static __inline void spawn_group("
            + pdecl
            + ", quest_spawn_entry_t *entry, quest_timeline_vec2_t &offset, int &spawn_index)\n"
            "{\n" + body + "\n}\n\n"
        )
        add(
            "group-" + pk + "-value",
            prepend(
                s[:beg] + "            spawn_group(&entry->template_id, entry, offset, spawn_index);" + s[end:],
                helper,
            ),
        )

    # --- Address of the pointer variable escapes into a dead local (address-taken pointer).
    add(
        "addr-taken-dead",
        s.replace(
            PTR_DECL,
            PTR_DECL + "            int **template_id_ref = &template_id;\n            (void)template_id_ref;\n",
        ),
    )
    add(
        "addr-taken-ref",
        s.replace(PTR_DECL, PTR_DECL + "            int *&template_id_ref = template_id;\n").replace(
            "*template_id,",
            "*template_id_ref,",
        ),
    )

    # --- Pointer stored into a struct field of a local aggregate declared before the loop, scalar used later.
    add(
        "aggregate-init-scalar",
        prepend(
            s.replace(
                PTR_DECL,
                "            spawn_pod_t ref = { &entry->template_id };\n            int *template_id = ref.p;\n",
            ),
            "struct spawn_pod_t { int *p; };\n\n",
        ),
    )
    add(
        "aggregate-init-use",
        prepend(
            s.replace(PTR_DECL, "            spawn_pod_t ref = { &entry->template_id };\n").replace(
                "*template_id,",
                "*ref.p,",
            ),
            "struct spawn_pod_t { int *p; };\n\n",
        ),
    )


def batch_memclass(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    assert PTR_DECL in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def use(text, expr, heading=None):
        t = text.replace("*template_id,", expr + ",")
        if heading is not None:
            t = t.replace("entry->heading);", heading + ");")
        return t

    # diagnostic only: volatile pointer
    add("diag-volatile-ptr", s.replace(PTR_DECL, "            int *volatile template_id = &entry->template_id;\n"))
    add(
        "diag-volatile-ptr-relative",
        use(
            s.replace(PTR_DECL, "            int *volatile template_id = &entry->template_id;\n"),
            "*template_id",
            "((float *)template_id)[-1]",
        ),
    )

    # arrays are memory-class
    add("array1", use(s.replace(PTR_DECL, "            int *fields[1] = { &entry->template_id };\n"), "*fields[0]"))
    add(
        "array1-relative",
        use(
            s.replace(PTR_DECL, "            int *fields[1] = { &entry->template_id };\n"),
            "*fields[0]",
            "((float *)fields[0])[-1]",
        ),
    )
    add(
        "array2-heading-template",
        use(
            s.replace(PTR_DECL, "            void *fields[2] = { &entry->heading, &entry->template_id };\n"),
            "*(int *)fields[1]",
            "*(float *)fields[0]",
        ),
    )

    # address taken and used through the double pointer
    add(
        "addr-used-both",
        use(
            s.replace(PTR_DECL, PTR_DECL + "            int **fields = &template_id;\n"),
            "**fields",
            "((float *)*fields)[-1]",
        ),
    )
    add(
        "addr-used-template",
        use(s.replace(PTR_DECL, PTR_DECL + "            int **fields = &template_id;\n"), "**fields"),
    )

    # union
    add(
        "union-ptr",
        prepend(
            use(
                s.replace(
                    PTR_DECL,
                    "            spawn_word_t template_id;\n            template_id.p = &entry->template_id;\n",
                ),
                "*template_id.p",
            ),
            "union spawn_word_t { int *p; unsigned int u; };\n\n",
        ),
    )

    # wrapper class with operator*, operator[]
    WRAP = (
        "struct spawn_cursor_t {\n"
        "    int *p;\n"
        "    spawn_cursor_t(int *v) : p(v) {}\n"
        "    int operator*() const { return *p; }\n"
        "    float heading() const { return ((const float *)p)[-1]; }\n"
        "};\n\n"
    )
    add(
        "wrapclass-deref",
        prepend(
            use(s.replace(PTR_DECL, "            spawn_cursor_t template_id(&entry->template_id);\n"), "*template_id"),
            WRAP,
        ),
    )
    add(
        "wrapclass-deref-heading",
        prepend(
            use(
                s.replace(PTR_DECL, "            spawn_cursor_t template_id(&entry->template_id);\n"),
                "*template_id",
                "template_id.heading()",
            ),
            WRAP,
        ),
    )

    # pointer modified in loop (post-increment then re-decrement) -> induction candidate
    add(
        "ptr-bump-restore",
        s.replace(
            "                ++spawn_index;\n                spread += 0x28;\n",
            "                ++spawn_index;\n                spread += 0x28;\n                template_id += 0;\n",
        ),
    )

    # pointer declared before the count guard (outer scope) with heading relative
    add(
        "outer-scope-relative",
        use(
            s.replace(PTR_DECL, "").replace(
                "        int spawn_index = 0;\n",
                "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
            ),
            "*template_id",
            "((float *)template_id)[-1]",
        ),
    )

    # pointer used after the inner loop too (clear count via pointer)
    add(
        "ptr-clears-count",
        s.replace("        entry->count = 0;\n", "        template_id[2] = 0;\n")
        .replace(PTR_DECL, "")
        .replace(
            "        int spawn_index = 0;\n",
            "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
        ),
    )
    add(
        "ptr-clears-count-relative",
        use(
            s.replace("        entry->count = 0;\n", "        template_id[2] = 0;\n")
            .replace(PTR_DECL, "")
            .replace(
                "        int spawn_index = 0;\n",
                "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
            ),
            "*template_id",
            "((float *)template_id)[-1]",
        ),
    )
    # pointer used in the trigger comparison too
    add(
        "ptr-trigger-compare",
        s.replace(
            "        if (entry->trigger_time_ms != entry[1].trigger_time_ms) {",
            "        if (template_id[1] != template_id[7]) {",
        )
        .replace(PTR_DECL, "")
        .replace(
            "        int spawn_index = 0;\n",
            "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
        ),
    )

    # spread derived from pointer difference (silly but exercises pointer-int slot)
    add(
        "spread-from-ptr",
        s.replace("            spread = 0;\n", "            spread = (int)(template_id - &entry->template_id);\n"),
    )

    # the pointer captured into a struct with the index (spawn state), pointer relative heading
    STATE = "struct spawn_state_t { int *template_id; int spawn_index; };\n\n"
    add(
        "state-ptr-index",
        prepend(
            use(
                s.replace("        int spawn_index = 0;\n", "        spawn_state_t st;\n        st.spawn_index = 0;\n")
                .replace(PTR_DECL, "            st.template_id = &entry->template_id;\n")
                .replace("spawn_index & 1", "st.spawn_index & 1")
                .replace("++spawn_index", "++st.spawn_index")
                .replace("spawn_index < entry->count", "st.spawn_index < entry->count"),
                "*st.template_id",
            ),
            STATE,
        ),
    )


def batch_byvalue(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    GUARD = "        if (entry->count > 0) {\n"
    CLEAR = "        entry->count = 0;\n"
    TRIG = "        if (entry->trigger_time_ms != entry[1].trigger_time_ms) {"
    assert PTR_DECL in s and GUARD in s and CLEAR in s and TRIG in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def with_heading(body, mode):
        if mode == "relative":
            return body.replace("entry->heading", "((float *)template_id)[-1]")
        return body

    def caller_uses(t, uses):
        if "clear" in uses:
            t = t.replace(CLEAR, "        template_id[2] = 0;\n")
        if "trig" in uses:
            t = t.replace(TRIG, "        if (template_id[1] != template_id[7]) {")
        if "count" in uses:
            t = t.replace(GUARD, "        if (template_id[2] > 0) {\n")
        return t

    # Move pointer decl to the outer loop body so caller uses after the guard are in scope.
    OUTER = s.replace(PTR_DECL, "").replace(
        "        int spawn_index = 0;\n",
        "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
    )
    obeg = OUTER.index("            int spread;\n")
    oend = OUTER.index("\n        }\n\n        entry_count", obeg)
    OBODY = OUTER[obeg:oend]

    # A. inline helper, by-value pointer param, caller retains uses.
    for hm in ["entry", "relative"]:
        for uses in ["clear", "trig", "clear+trig", "count+clear", "count+clear+trig"]:
            helper = (
                "static __inline void spawn_group(int *template_id, quest_spawn_entry_t *entry, "
                "quest_timeline_vec2_t &offset, int &spawn_index)\n{\n" + with_heading(OBODY, hm) + "\n}\n\n"
            )
            t = OUTER[:obeg] + "            spawn_group(template_id, entry, offset, spawn_index);" + OUTER[oend:]
            add("A-" + hm + "-" + uses.replace("+", "_"), prepend(caller_uses(t, uses), helper))

    # A2. same but no caller uses (control), pointer declared outer.
    for hm in ["entry", "relative"]:
        helper = (
            "static __inline void spawn_group(int *template_id, quest_spawn_entry_t *entry, "
            "quest_timeline_vec2_t &offset, int &spawn_index)\n{\n" + with_heading(OBODY, hm) + "\n}\n\n"
        )
        t = OUTER[:obeg] + "            spawn_group(template_id, entry, offset, spawn_index);" + OUTER[oend:]
        add("A2-" + hm + "-none", prepend(t, helper))

    # B. this-anchored method on a meta overlay at template_id.
    for hm in ["entry", "this"]:
        for uses in ["none", "clear", "count+clear"]:
            body = OBODY.replace("*template_id,", "template_id,").replace(
                "spawn_index < entry->count",
                "spawn_index < count",
            )
            if hm == "this":
                body = body.replace("entry->heading", "((const float *)this)[-1]")
            cls = (
                "struct spawn_meta_t {\n"
                "    int template_id;\n"
                "    int trigger_time_ms;\n"
                "    int count;\n"
                "    void spawn_group(quest_spawn_entry_t *entry, quest_timeline_vec2_t &offset, int &spawn_index)\n"
                "    {\n" + body + "\n    }\n"
                "};\n\n"
            )
            t = OUTER.replace(
                "        int *template_id = &entry->template_id;\n",
                "        spawn_meta_t *meta = (spawn_meta_t *)&entry->template_id;\n",
            )
            t = (
                t[: t.index("            int spread;\n")]
                + "            meta->spawn_group(entry, offset, spawn_index);"
                + t[t.index("\n        }\n\n        entry_count") :]
            )
            if "clear" in uses:
                t = t.replace(CLEAR, "        meta->count = 0;\n")
            if "count" in uses:
                t = t.replace(GUARD, "        if (meta->count > 0) {\n")
            add("B-" + hm + "-" + uses.replace("+", "_"), prepend(t, cls))

    # C. declaration list.
    add(
        "C-decl-list",
        s.replace(
            PTR_DECL + "            int spread;\n\n            spread = 0;\n",
            "            int *template_id = &entry->template_id, spread = 0;\n",
        ),
    )

    # D. two inline helpers both receiving the pointer by value.
    for hm in ["entry", "relative"]:
        helper = (
            "static __inline void spawn_group(int *template_id, quest_spawn_entry_t *entry, "
            "quest_timeline_vec2_t &offset, int &spawn_index)\n{\n" + with_heading(OBODY, hm) + "\n}\n\n"
            "static __inline void clear_group(int *template_id)\n{\n    template_id[2] = 0;\n}\n\n"
        )
        t = OUTER[:obeg] + "            spawn_group(template_id, entry, offset, spawn_index);" + OUTER[oend:]
        t = t.replace(CLEAR, "        clear_group(template_id);\n")
        add("D-" + hm, prepend(t, helper))

    # E. pointer passed by value to a helper that spawns ONE creature (inner call), caller keeps loop.
    for hm in ["entry", "relative"]:
        hexpr = "((float *)template_id)[-1]" if hm == "relative" else "entry->heading"
        helper = (
            "static __inline void spawn_one(int *template_id, quest_spawn_entry_t *entry, const quest_timeline_vec2_t &pos)\n"
            "{\n    creature_spawn_template(*template_id, (const vec2f_t *)&pos, " + hexpr + ");\n}\n\n"
        )
        t = s.replace(
            "                creature_spawn_template(\n                    *template_id,\n                    (const vec2f_t *)&pos,\n                    entry->heading);\n",
            "                spawn_one(template_id, entry, pos);\n",
        )
        for uses in ["none", "clear"]:
            u = t
            if uses == "clear":
                u = (
                    u.replace(PTR_DECL, "")
                    .replace(
                        "        int spawn_index = 0;\n",
                        "        int spawn_index = 0;\n        int *template_id = &entry->template_id;\n",
                    )
                    .replace(CLEAR, "        template_id[2] = 0;\n")
                )
            add("E-" + hm + "-" + uses, prepend(u, helper))


def batch_outparam(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    assert PTR_DECL in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def rel(t):
        return t.replace("entry->heading", "((float *)template_id)[-1]")

    # 1. out-parameter by pointer
    for hm in ["entry", "relative"]:
        for order in ["decl-then-call", "decl-init-call"]:
            helper = "static __inline void spawn_params(quest_spawn_entry_t *e, int **template_id)\n{\n    *template_id = &e->template_id;\n}\n\n"
            decl = "            int *template_id;\n            spawn_params(entry, &template_id);\n"
            if order == "decl-init-call":
                decl = "            int *template_id = 0;\n            spawn_params(entry, &template_id);\n"
            t = s.replace(PTR_DECL, decl)
            if hm == "relative":
                t = rel(t)
            add(f"outptr-{hm}-{order}", prepend(t, helper))

    # 2. out-parameter by reference
    for hm in ["entry", "relative"]:
        helper = "static __inline void spawn_params(quest_spawn_entry_t *e, int *&template_id)\n{\n    template_id = &e->template_id;\n}\n\n"
        t = s.replace(PTR_DECL, "            int *template_id;\n            spawn_params(entry, template_id);\n")
        if hm == "relative":
            t = rel(t)
        add(f"outref-{hm}", prepend(t, helper))

    # 3. out-parameter that also returns something used (count)
    for hm in ["entry", "relative"]:
        helper = "static __inline int spawn_params(quest_spawn_entry_t *e, int **template_id)\n{\n    *template_id = &e->template_id;\n    return e->count;\n}\n\n"
        t = s.replace(
            "        if (entry->count > 0) {\n" + PTR_DECL,
            "        int *template_id;\n        if (spawn_params(entry, &template_id) > 0) {\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"outptr-count-{hm}", prepend(t, helper))

    # 4. struct with assignment-body constructor (store through this)
    for hm in ["entry", "relative"]:
        for style in ["body", "init"]:
            ctor = "spawn_ref_t(int *v) { p = v; }" if style == "body" else "spawn_ref_t(int *v) : p(v) {}"
            cls = "struct spawn_ref_t {\n    int *p;\n    " + ctor + "\n};\n\n"
            t = s.replace(
                PTR_DECL,
                "            spawn_ref_t ref(&entry->template_id);\n            int *template_id = ref.p;\n",
            )
            if hm == "relative":
                t = rel(t)
            add(f"ctor-{style}-{hm}", prepend(t, cls))

    # 5. struct with a set() method (store through this), object then used via .p
    for hm in ["entry", "relative"]:
        cls = "struct spawn_ref_t {\n    int *p;\n    void set(int *v) { p = v; }\n};\n\n"
        t = s.replace(
            PTR_DECL,
            "            spawn_ref_t ref;\n            ref.set(&entry->template_id);\n            int *template_id = ref.p;\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"setmethod-{hm}", prepend(t, cls))
        t2 = s.replace(PTR_DECL, "            spawn_ref_t ref;\n            ref.set(&entry->template_id);\n").replace(
            "*template_id,",
            "*ref.p,",
        )
        if hm == "relative":
            t2 = t2.replace("entry->heading", "((float *)ref.p)[-1]")
        add(f"setmethod-use-{hm}", prepend(t2, cls))

    # 6. out-parameter helper that fills a small struct with two pointers (heading, template)
    for style in ["ptrs", "struct-ret"]:
        if style == "ptrs":
            helper = (
                "static __inline void spawn_params(quest_spawn_entry_t *e, float **heading, int **template_id)\n"
                "{\n    *heading = &e->heading;\n    *template_id = &e->template_id;\n}\n\n"
            )
            t = s.replace(
                PTR_DECL,
                "            float *heading;\n            int *template_id;\n            spawn_params(entry, &heading, &template_id);\n",
            ).replace(
                "entry->heading);",
                "*heading);",
            )
        else:
            helper = (
                "struct spawn_params_t { float *heading; int *template_id; };\n\n"
                "static __inline void spawn_params(quest_spawn_entry_t *e, spawn_params_t *out)\n"
                "{\n    out->heading = &e->heading;\n    out->template_id = &e->template_id;\n}\n\n"
            )
            t = s.replace(
                PTR_DECL,
                "            spawn_params_t params;\n            spawn_params(entry, &params);\n            int *template_id = params.template_id;\n",
            ).replace(
                "entry->heading);",
                "*params.heading);",
            )
        add(f"outparams-{style}", prepend(t, helper))

    # 7. pointer assigned via inline helper that writes through pointer AND caller uses variable in loop w/ heading relative,
    #    pointer declared at outer scope (before the guard).
    for hm in ["entry", "relative"]:
        helper = "static __inline void spawn_params(quest_spawn_entry_t *e, int **template_id)\n{\n    *template_id = &e->template_id;\n}\n\n"
        t = s.replace(PTR_DECL, "").replace(
            "        int spawn_index = 0;\n",
            "        int spawn_index = 0;\n        int *template_id;\n        spawn_params(entry, &template_id);\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"outptr-outer-{hm}", prepend(t, helper))

    # 8. Out-parameter inside the guard, but written *after* spread decl (order within block)
    helper = "static __inline void spawn_params(quest_spawn_entry_t *e, int **template_id)\n{\n    *template_id = &e->template_id;\n}\n\n"
    add(
        "outptr-after-spread-decl",
        prepend(
            s.replace(
                PTR_DECL + "            int spread;\n\n            spread = 0;\n",
                "            int *template_id;\n            int spread;\n\n            spawn_params(entry, &template_id);\n            spread = 0;\n",
            ),
            helper,
        ),
    )
    add(
        "outptr-after-spread-init",
        prepend(
            s.replace(
                PTR_DECL + "            int spread;\n\n            spread = 0;\n",
                "            int *template_id;\n            int spread;\n\n            spread = 0;\n            spawn_params(entry, &template_id);\n",
            ),
            helper,
        ),
    )


def batch_multiword(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    SPREAD = "            int spread;\n\n            spread = 0;\n"
    assert PTR_DECL in s and SPREAD in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def rel(t, expr):
        return t.replace("entry->heading", expr)

    # 1. two-pointer struct
    add(
        "two-ptr-both-stored",
        prepend(
            s.replace(
                PTR_DECL,
                "            spawn_cursor_t c;\n            c.template_id = &entry->template_id;\n            c.heading = &entry->heading;\n",
            )
            .replace("*template_id,", "*c.template_id,")
            .replace("entry->heading);", "*c.heading);"),
            "struct spawn_cursor_t { int *template_id; float *heading; };\n\n",
        ),
    )
    add(
        "two-ptr-one-stored",
        prepend(
            s.replace(
                PTR_DECL,
                "            spawn_cursor_t c;\n            c.template_id = &entry->template_id;\n",
            ).replace(
                "*template_id,",
                "*c.template_id,",
            ),
            "struct spawn_cursor_t { int *template_id; float *heading; };\n\n",
        ),
    )
    add(
        "two-ptr-one-stored-relative",
        prepend(
            rel(
                s.replace(
                    PTR_DECL,
                    "            spawn_cursor_t c;\n            c.template_id = &entry->template_id;\n",
                ).replace(
                    "*template_id,",
                    "*c.template_id,",
                ),
                "((float *)c.template_id)[-1]",
            ),
            "struct spawn_cursor_t { int *template_id; float *heading; };\n\n",
        ),
    )
    # 2. pointer + spread struct, both orders
    for order in ["ptr-first", "spread-first"]:
        cls = (
            "struct spawn_state_t { int *template_id; int spread; };\n\n"
            if order == "ptr-first"
            else "struct spawn_state_t { int spread; int *template_id; };\n\n"
        )
        t = s.replace(
            PTR_DECL + SPREAD,
            "            spawn_state_t st;\n            st.template_id = &entry->template_id;\n            st.spread = 0;\n",
        )
        t = (
            t.replace("*template_id,", "*st.template_id,")
            .replace("(float)spread", "(float)st.spread")
            .replace("spread += 0x28", "st.spread += 0x28")
        )
        add("ptr-spread-" + order, prepend(t, cls))
        add("ptr-spread-" + order + "-relative", prepend(rel(t, "((float *)st.template_id)[-1]"), cls))
    # 3. pointer + offset struct (offset copy-inited from zero)
    cls = (
        "struct spawn_state_t {\n"
        "    int *template_id;\n"
        "    quest_timeline_vec2_t offset;\n"
        "    spawn_state_t(int *id, const quest_timeline_vec2_t &zero) : template_id(id), offset(zero) {}\n"
        "};\n\n"
    )
    t = (
        s.replace("        quest_timeline_vec2_t offset = zero_offset;\n", "")
        .replace(
            PTR_DECL,
            "",
        )
        .replace(
            "        int spawn_index = 0;\n",
            "        int spawn_index = 0;\n        spawn_state_t st(&entry->template_id, zero_offset);\n",
        )
    )
    t = (
        t.replace("*template_id,", "*st.template_id,")
        .replace("offset.x", "st.offset.x")
        .replace("offset.y", "st.offset.y")
    )
    add("ptr-offset-ctor", prepend(t, cls))
    # 4. pointer array of 2, one stored / both stored
    add(
        "ptr-array2-one",
        s.replace(PTR_DECL, "            int *fields[2];\n            fields[0] = &entry->template_id;\n").replace(
            "*template_id,",
            "*fields[0],",
        ),
    )
    add(
        "ptr-array2-both",
        s.replace(
            PTR_DECL,
            "            int *fields[2];\n            fields[0] = &entry->template_id;\n            fields[1] = &entry->count;\n",
        )
        .replace("*template_id,", "*fields[0],")
        .replace("spawn_index < entry->count", "spawn_index < *fields[1]"),
    )
    add(
        "ptr-array2-init",
        s.replace(PTR_DECL, "            int *fields[2] = { &entry->template_id, &entry->count };\n")
        .replace("*template_id,", "*fields[0],")
        .replace("spawn_index < entry->count", "spawn_index < *fields[1]"),
    )
    # 5. pointer + int struct with ctor and getter (class-like)
    cls = (
        "struct spawn_ref_t {\n"
        "    int *p;\n"
        "    int n;\n"
        "    spawn_ref_t(int *v) : p(v), n(0) {}\n"
        "    int id() const { return *p; }\n"
        "};\n\n"
    )
    add(
        "ptr-int-class",
        prepend(
            s.replace(PTR_DECL, "            spawn_ref_t ref(&entry->template_id);\n").replace(
                "*template_id,",
                "ref.id(),",
            ),
            cls,
        ),
    )
    # 6. pointer pair class (begin/end iterator style)
    cls = (
        "struct spawn_range_t {\n"
        "    int *first;\n"
        "    int *last;\n"
        "    spawn_range_t(int *a, int *b) : first(a), last(b) {}\n"
        "};\n\n"
    )
    add(
        "ptr-range-class",
        prepend(
            s.replace(PTR_DECL, "            spawn_range_t r(&entry->template_id, &entry->count);\n")
            .replace("*template_id,", "*r.first,")
            .replace("spawn_index < entry->count", "spawn_index < *r.last"),
            cls,
        ),
    )
    # 7. double-word: pointer + pointer-to-entry
    add(
        "ptr-entry-struct",
        prepend(
            s.replace(
                PTR_DECL,
                "            spawn_cursor_t c;\n            c.entry = entry;\n            c.template_id = &entry->template_id;\n",
            )
            .replace("*template_id,", "*c.template_id,")
            .replace("entry->heading);", "c.entry->heading);"),
            "struct spawn_cursor_t { quest_spawn_entry_t *entry; int *template_id; };\n\n",
        ),
    )
    # 8. pointer stored in an 8-byte struct that is then copied to a second struct (like offset = zero_offset)
    cls = "struct spawn_pair_t { int *template_id; int spread; };\n\n"
    t = s.replace(
        PTR_DECL + SPREAD,
        "            spawn_pair_t init;\n            init.template_id = &entry->template_id;\n            init.spread = 0;\n            spawn_pair_t st = init;\n",
    )
    t = (
        t.replace("*template_id,", "*st.template_id,")
        .replace("(float)spread", "(float)st.spread")
        .replace("spread += 0x28", "st.spread += 0x28")
    )
    add("pair-copy", prepend(t, cls))
    # 9. 8-byte struct: pointer + float heading cached
    cls = "struct spawn_args_t { int *template_id; float heading; };\n\n"
    t = s.replace(
        PTR_DECL,
        "            spawn_args_t a;\n            a.template_id = &entry->template_id;\n            a.heading = entry->heading;\n",
    )
    t = t.replace("*template_id,", "*a.template_id,").replace("entry->heading);", "a.heading);")
    add("ptr-heading-cached", prepend(t, cls))
    # 10. long long / double-word scalar holding pointer bits (memory-class by size)
    add(
        "ptr-in-int64",
        s.replace(
            PTR_DECL,
            "            __int64 raw = (__int64)(int)&entry->template_id;\n            int *template_id = (int *)(int)raw;\n",
        ),
    )


def batch_shortlived(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    SPREAD = "            int spread;\n\n            spread = 0;\n"
    assert PTR_DECL in s and SPREAD in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def rel(t):
        return t.replace("entry->heading", "((float *)template_id)[-1]")

    # 8-byte aggregate holder in a nested scope; scalar pointer extracted, aggregate dies.
    for size in [8, 12]:
        members = "int *p; int pad0;" if size == 8 else "int *p; int pad0; int pad1;"
        for style in ["pod-scope", "ctor-scope", "pod-noscope"]:
            cls = (
                "struct spawn_holder_t { "
                + members
                + (" spawn_holder_t(int *v) : p(v) {}" if "ctor" in style else "")
                + " };\n\n"
            )
            if style == "pod-scope":
                decl = "            int *template_id;\n            {\n                spawn_holder_t h;\n                h.p = &entry->template_id;\n                template_id = h.p;\n            }\n"
            elif style == "ctor-scope":
                decl = "            int *template_id;\n            {\n                spawn_holder_t h(&entry->template_id);\n                template_id = h.p;\n            }\n"
            else:
                decl = "            spawn_holder_t h;\n            h.p = &entry->template_id;\n            int *template_id = h.p;\n"
            for hm in ["entry", "relative"]:
                t = s.replace(PTR_DECL, decl)
                if hm == "relative":
                    t = rel(t)
                add(f"holder{size}-{style}-{hm}", prepend(t, cls))

    # address-taken pointer in nested scope (memory-class), copied to scalar, scope ends.
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            int *template_id;\n            {\n                int *p = &entry->template_id;\n                int **pp = &p;\n                template_id = *pp;\n            }\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"addr-scope-{hm}", t)

    # out-param helper writing into a memory home then copied.
    for hm in ["entry", "relative"]:
        helper = "static __inline void take(int **out, int *v)\n{\n    *out = v;\n}\n\n"
        t = s.replace(
            PTR_DECL,
            "            int *template_id;\n            {\n                int *p;\n                take(&p, &entry->template_id);\n                template_id = p;\n            }\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"outparam-scope-{hm}", prepend(t, helper))

    # 8-byte holder as inline helper by-value parameter (temp copy dies after call)
    for hm in ["entry", "relative"]:
        cls = "struct spawn_holder_t { int *p; int n; };\n\n"
        helper = "static __inline int *unwrap(spawn_holder_t h)\n{\n    return h.p;\n}\n\n"
        t = s.replace(
            PTR_DECL,
            "            spawn_holder_t h;\n            h.p = &entry->template_id;\n            h.n = 0;\n            int *template_id = unwrap(h);\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"unwrap8-{hm}", prepend(t, cls + helper))
        t2 = s.replace(
            PTR_DECL,
            "            spawn_holder_t h = { &entry->template_id, 0 };\n            int *template_id = unwrap(h);\n",
        )
        if hm == "relative":
            t2 = rel(t2)
        add(f"unwrap8-agg-{hm}", prepend(t2, cls + helper))

    # by-value struct returned from inline (8 bytes: hidden return slot)
    for hm in ["entry", "relative"]:
        cls = "struct spawn_holder_t { int *p; int n; };\n\n"
        helper = "static __inline spawn_holder_t wrap(quest_spawn_entry_t *e)\n{\n    spawn_holder_t h;\n    h.p = &e->template_id;\n    h.n = e->count;\n    return h;\n}\n\n"
        t = s.replace(PTR_DECL, "            int *template_id = wrap(entry).p;\n")
        if hm == "relative":
            t = rel(t)
        add(f"wrap8-ret-{hm}", prepend(t, cls + helper))
        t2 = s.replace(PTR_DECL, "            spawn_holder_t h = wrap(entry);\n            int *template_id = h.p;\n")
        if hm == "relative":
            t2 = rel(t2)
        add(f"wrap8-named-{hm}", prepend(t2, cls + helper))

    # pointer stored in a memory-class variable that IS spread's declared object: union of {int *p; int spread;}
    for hm in ["entry", "relative"]:
        t = (
            s.replace(
                PTR_DECL + SPREAD,
                "            spawn_word_t w;\n            w.p = &entry->template_id;\n            int *template_id = w.p;\n            w.spread = 0;\n",
            )
            .replace("(float)spread", "(float)w.spread")
            .replace("spread += 0x28", "w.spread += 0x28")
        )
        if hm == "relative":
            t = rel(t)
        add(f"union-slot-{hm}", prepend(t, "union spawn_word_t { int *p; int spread; };\n\n"))

    # The reference variable form: int& used for id, heading relative through &ref
    add(
        "ref-relative",
        s.replace(PTR_DECL, "            int &template_id = entry->template_id;\n")
        .replace("*template_id,", "template_id,")
        .replace("entry->heading);", "((float *)&template_id)[-1]);"),
    )
    add(
        "ref-scope-copy",
        s.replace(
            PTR_DECL,
            "            int *template_id;\n            {\n                int &r = entry->template_id;\n                template_id = &r;\n            }\n",
        ),
    )
    # pointer to pointer param: helper stores the pointer to caller memory then caller reads it later? (double)


def batch_derived(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    GUARD = "        if (entry->count > 0) {\n"
    assert PTR_DECL in s and GUARD in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    def heading_via(t, expr):
        return t.replace("entry->heading);", expr + ");")

    # 1. derived from heading pointer
    for hm in ["entry", "hptr", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            float *heading = &entry->heading;\n            int *template_id = (int *)(heading + 1);\n",
        )
        if hm == "hptr":
            t = heading_via(t, "*heading")
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-heading-{hm}", t)
    # 2. derived from position pointer
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            float *pos = &entry->position.x;\n            int *template_id = (int *)(pos + 3);\n",
        )
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-pos-{hm}", t)
    # 3. derived from int view of entry
    for hm in ["entry", "relative"]:
        t = s.replace(PTR_DECL, "            int *words = (int *)entry;\n            int *template_id = words + 3;\n")
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-words-{hm}", t)
        t2 = s.replace(PTR_DECL, "            int *words = (int *)entry;\n            int *template_id = &words[3];\n")
        if hm == "relative":
            t2 = heading_via(t2, "((float *)template_id)[-1]")
        add(f"from-words-index-{hm}", t2)
    # 4. derived from count pointer (used as guard too)
    for hm in ["entry", "relative"]:
        t = s.replace(
            GUARD + PTR_DECL,
            "        int *count = &entry->count;\n        if (*count > 0) {\n            int *template_id = count - 2;\n",
        )
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-count-{hm}", t)
        t2 = s.replace(
            GUARD + PTR_DECL,
            "        int *count = &entry->count;\n        if (*count > 0) {\n            int *template_id = count - 2;\n",
        ).replace(
            "spawn_index < entry->count",
            "spawn_index < *count",
        )
        if hm == "relative":
            t2 = heading_via(t2, "((float *)template_id)[-1]")
        add(f"from-count-loop-{hm}", t2)
    # 5. derived from trigger pointer (scan cursor style)
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            int *trigger = &entry->trigger_time_ms;\n            int *template_id = trigger - 1;\n",
        )
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-trigger-{hm}", t)
    # 6. ternary definition
    for hm in ["entry", "relative"]:
        t = s.replace(
            GUARD + PTR_DECL,
            "        int *template_id = entry->count > 0 ? &entry->template_id : 0;\n        if (template_id) {\n",
        )
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"ternary-{hm}", t)
        t2 = s.replace(
            GUARD + PTR_DECL,
            "        int *template_id = 0;\n        if (entry->count > 0) {\n            template_id = &entry->template_id;\n",
        )
        if hm == "relative":
            t2 = heading_via(t2, "((float *)template_id)[-1]")
        add(f"null-outer-{hm}", t2)
    # 7. pointer used after the guard as well (clear count via pointer or check)
    for hm in ["entry", "relative"]:
        t = s.replace(
            GUARD + PTR_DECL,
            "        int *template_id = 0;\n        if (entry->count > 0) {\n            template_id = &entry->template_id;\n",
        ).replace(
            "        entry->count = 0;\n",
            "        if (template_id) {\n            template_id[2] = 0;\n        }\n",
        )
        if hm == "relative":
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"null-outer-clear-{hm}", t)
    # 8. pointer plus zero / identity ops
    add("plus-zero", s.replace(PTR_DECL, "            int *template_id = &entry->template_id + 0;\n"))
    add("index-zero", s.replace(PTR_DECL, "            int *template_id = &(&entry->template_id)[0];\n"))
    add("deref-addr", s.replace(PTR_DECL, "            int *template_id = &*&entry->template_id;\n"))
    # 9. pointer from entry_index-based table access but entry also used (dual IV)
    add(
        "table-index-template",
        s.replace(PTR_DECL, "            int *template_id = &quest_spawn_table[entry_index].template_id;\n"),
    )
    # 10. derived from heading pointer, heading pointer declared outside guard
    for hm in ["hptr", "relative"]:
        t = s.replace(PTR_DECL, "            int *template_id = (int *)(heading + 1);\n").replace(
            "        int spawn_index = 0;\n",
            "        int spawn_index = 0;\n        float *heading = &entry->heading;\n",
        )
        if hm == "hptr":
            t = heading_via(t, "*heading")
        else:
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-heading-outer-{hm}", t)
    # 11. struct view pointer {heading, template_id} derived from entry, template ptr derived from view
    for hm in ["view", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            spawn_meta_t *meta = (spawn_meta_t *)&entry->heading;\n            int *template_id = &meta->template_id;\n",
        )
        if hm == "view":
            t = heading_via(t, "meta->heading")
        else:
            t = heading_via(t, "((float *)template_id)[-1]")
        add(f"from-meta-{hm}", prepend(t, "struct spawn_meta_t { float heading; int template_id; };\n\n"))


def batch_thisview(s, add):
    ANCHOR = 'extern "C" int frame_dt_ms;'
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    CALL = (
        "                creature_spawn_template(\n"
        "                    *template_id,\n"
        "                    (const vec2f_t *)&pos,\n"
        "                    entry->heading);\n"
    )
    assert PTR_DECL in s and CALL in s

    def prepend(text, helper):
        return text.replace(ANCHOR, helper + ANCHOR)

    # (a) {heading, template_id} view at offset 8, method spawn(pos)
    for decl_pos in ["inner", "outer"]:
        for pos_kind in ["cref", "ptr"]:
            pdecl = "const quest_timeline_vec2_t &pos" if pos_kind == "cref" else "const quest_timeline_vec2_t *pos"
            parg = "pos" if pos_kind == "cref" else "&pos"
            puse = "(const vec2f_t *)&pos" if pos_kind == "cref" else "(const vec2f_t *)pos"
            cls = (
                "struct spawn_meta_t {\n"
                "    float heading;\n"
                "    int template_id;\n"
                "    void spawn(" + pdecl + ") const\n"
                "    {\n        creature_spawn_template(template_id, " + puse + ", heading);\n    }\n"
                "};\n\n"
            )
            t = s.replace(CALL, "                meta->spawn(" + parg + ");\n")
            if decl_pos == "inner":
                t = t.replace(PTR_DECL, "            spawn_meta_t *meta = (spawn_meta_t *)&entry->heading;\n")
            else:
                t = t.replace(PTR_DECL, "").replace(
                    "        int spawn_index = 0;\n",
                    "        int spawn_index = 0;\n        spawn_meta_t *meta = (spawn_meta_t *)&entry->heading;\n",
                )
            add(f"a-heading-view-{decl_pos}-{pos_kind}", prepend(t, cls))

    # (a2) same view but method non-const, and via reference object instead of pointer
    cls = (
        "struct spawn_meta_t {\n"
        "    float heading;\n"
        "    int template_id;\n"
        "    void spawn(const quest_timeline_vec2_t &pos)\n"
        "    {\n        creature_spawn_template(template_id, (const vec2f_t *)&pos, heading);\n    }\n"
        "};\n\n"
    )
    add(
        "a2-heading-view-ref",
        prepend(
            s.replace(CALL, "                meta.spawn(pos);\n").replace(
                PTR_DECL,
                "            spawn_meta_t &meta = *(spawn_meta_t *)&entry->heading;\n",
            ),
            cls,
        ),
    )

    # (b) {template_id, trigger, count} view at offset 0xc, method spawn(pos, heading) / heading from this[-1]
    for hm in ["param", "relative"]:
        hdecl = ", float heading" if hm == "param" else ""
        hexpr = "heading" if hm == "param" else "((const float *)this)[-1]"
        cls = (
            "struct spawn_meta_t {\n"
            "    int template_id;\n"
            "    int trigger_time_ms;\n"
            "    int count;\n"
            "    void spawn(const quest_timeline_vec2_t &pos" + hdecl + ") const\n"
            "    {\n        creature_spawn_template(template_id, (const vec2f_t *)&pos, " + hexpr + ");\n    }\n"
            "};\n\n"
        )
        harg = ", entry->heading" if hm == "param" else ""
        t = s.replace(CALL, "                meta->spawn(pos" + harg + ");\n").replace(
            PTR_DECL,
            "            spawn_meta_t *meta = (spawn_meta_t *)&entry->template_id;\n",
        )
        add(f"b-template-view-{hm}", prepend(t, cls))

    # (c) whole-entry overlay class with a method taking `this` = entry (control)
    cls = (
        "struct spawn_entry_view_t {\n"
        "    quest_timeline_vec2_t position;\n"
        "    float heading;\n"
        "    int template_id;\n"
        "    int trigger_time_ms;\n"
        "    int count;\n"
        "    void spawn(const quest_timeline_vec2_t &pos) const\n"
        "    {\n        creature_spawn_template(template_id, (const vec2f_t *)&pos, heading);\n    }\n"
        "};\n\n"
    )
    add(
        "c-entry-view-method",
        prepend(
            s.replace(CALL, "                ((spawn_entry_view_t *)entry)->spawn(pos);\n").replace(PTR_DECL, ""),
            cls,
        ),
    )

    # (d) heading-view method that also does the spawn loop (this = esi+8), count via entry param
    BEG = s.index(PTR_DECL)
    END = s.index("\n        }\n\n        entry_count", BEG)
    BODY = s[BEG + len(PTR_DECL) : END]
    body = BODY.replace(
        "                creature_spawn_template(\n                    *template_id,\n                    (const vec2f_t *)&pos,\n                    entry->heading);\n",
        "                creature_spawn_template(template_id, (const vec2f_t *)&pos, heading);\n",
    )
    cls = (
        "struct spawn_meta_t {\n"
        "    float heading;\n"
        "    int template_id;\n"
        "    void spawn_group(quest_spawn_entry_t *entry, quest_timeline_vec2_t &offset, int &spawn_index)\n"
        "    {\n" + body + "\n    }\n"
        "};\n\n"
    )
    t = s[:BEG] + "            ((spawn_meta_t *)&entry->heading)->spawn_group(entry, offset, spawn_index);" + s[END:]
    add("d-heading-view-group", prepend(t, cls))

    # (e) template-view method with the loop, heading relative, count via entry (this = esi+0xc)
    body_e = BODY.replace(
        "                creature_spawn_template(\n                    *template_id,\n                    (const vec2f_t *)&pos,\n                    entry->heading);\n",
        "                creature_spawn_template(template_id, (const vec2f_t *)&pos, ((const float *)this)[-1]);\n",
    )
    cls = (
        "struct spawn_meta_t {\n"
        "    int template_id;\n"
        "    int trigger_time_ms;\n"
        "    int count;\n"
        "    void spawn_group(quest_spawn_entry_t *entry, quest_timeline_vec2_t &offset, int &spawn_index)\n"
        "    {\n" + body_e + "\n    }\n"
        "};\n\n"
    )
    t = (
        s[:BEG]
        + "            ((spawn_meta_t *)&entry->template_id)->spawn_group(entry, offset, spawn_index);"
        + s[END:]
    )
    add("e-template-view-group-relative", prepend(t, cls))

    # (f) accessor methods on the heading view (getters), pointer named
    cls = (
        "struct spawn_meta_t {\n"
        "    float heading;\n"
        "    int template_id;\n"
        "    int id() const { return template_id; }\n"
        "    float dir() const { return heading; }\n"
        "};\n\n"
    )
    t = s.replace(
        CALL,
        "                creature_spawn_template(meta->id(), (const vec2f_t *)&pos, meta->dir());\n",
    ).replace(
        PTR_DECL,
        "            spawn_meta_t *meta = (spawn_meta_t *)&entry->heading;\n",
    )
    add("f-heading-view-getters", prepend(t, cls))
    cls2 = (
        "struct spawn_meta_t {\n"
        "    int template_id;\n"
        "    int trigger_time_ms;\n"
        "    int count;\n"
        "    int id() const { return template_id; }\n"
        "    float dir() const { return ((const float *)this)[-1]; }\n"
        "};\n\n"
    )
    t = s.replace(
        CALL,
        "                creature_spawn_template(meta->id(), (const vec2f_t *)&pos, meta->dir());\n",
    ).replace(
        PTR_DECL,
        "            spawn_meta_t *meta = (spawn_meta_t *)&entry->template_id;\n",
    )
    add("f-template-view-getters", prepend(t, cls2))


def batch_basecopy(s, add):
    PTR_DECL = "            int *template_id = &entry->template_id;\n"
    GUARD = "        if (entry->count > 0) {\n"
    TAIL = "                ++spawn_index;\n                spread += 0x28;\n"
    assert PTR_DECL in s and GUARD in s and TAIL in s

    def rel(t):
        return t.replace("entry->heading", "((float *)template_id)[-1]")

    for hm in ["entry", "relative"]:
        for redefine in ["inc", "null", "plus1", "table", "inc-loop-end", "inc-after-call"]:
            decl = "            quest_spawn_entry_t *cur = entry;\n            int *template_id = &cur->template_id;\n"
            if redefine == "inc":
                decl += "            ++cur;\n"
            elif redefine == "null":
                decl += "            cur = 0;\n"
            elif redefine == "plus1":
                decl += "            cur = entry + 1;\n"
            elif redefine == "table":
                decl += "            cur = &quest_spawn_table[entry_index + 1];\n"
            t = s.replace(PTR_DECL, decl)
            if redefine == "inc-loop-end":
                t = t.replace(TAIL, TAIL + "                ++cur;\n")
            if redefine == "inc-after-call":
                t = t.replace(
                    "                ++spawn_index;\n",
                    "                ++cur;\n                ++spawn_index;\n",
                )
            if hm == "relative":
                t = rel(t)
            add(f"cur-{redefine}-{hm}", t)

    # copy base declared outside the guard, redefined inside
    for hm in ["entry", "relative"]:
        t = s.replace(
            GUARD + PTR_DECL,
            "        quest_spawn_entry_t *cur = entry;\n        if (entry->count > 0) {\n            int *template_id = &cur->template_id;\n            ++cur;\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"cur-outer-inc-{hm}", t)

    # cur used for the inner-loop condition after being advanced (live use)
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            quest_spawn_entry_t *cur = entry;\n            int *template_id = &cur->template_id;\n            ++cur;\n",
        ).replace("spawn_index < entry->count", "spawn_index < cur[-1].count")
        if hm == "relative":
            t = rel(t)
        add(f"cur-inc-cond-{hm}", t)

    # cur is the *next* entry pointer used later in the trigger comparison
    for hm in ["entry", "relative"]:
        t = s.replace(
            GUARD + PTR_DECL,
            "        quest_spawn_entry_t *next = entry;\n        if (entry->count > 0) {\n            int *template_id = &next->template_id;\n            ++next;\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"next-inc-{hm}", t)
        t2 = (
            s.replace(
                GUARD + PTR_DECL,
                "        quest_spawn_entry_t *next = entry;\n        if (entry->count > 0) {\n            int *template_id = &next->template_id;\n            ++next;\n",
            )
            .replace("        } else {\n", "        } else {\n")
            .replace(
                "        }\n\n        entry_count = quest_spawn_count;",
                "        } else {\n            ++next;\n        }\n\n        entry_count = quest_spawn_count;",
            )
            .replace("entry[1].trigger_time_ms", "next->trigger_time_ms")
        )
        if hm == "relative":
            t2 = rel(t2)
        add(f"next-inc-used-{hm}", t2)

    # the pointer copied from another pointer temp (two-step) with the temp redefined
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            int *field = &entry->template_id;\n            int *template_id = field;\n            ++field;\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"field-copy-inc-{hm}", t)
        t2 = s.replace(
            PTR_DECL,
            "            int *field = &entry->template_id;\n            int *template_id = field;\n            field = 0;\n",
        )
        if hm == "relative":
            t2 = rel(t2)
        add(f"field-copy-null-{hm}", t2)

    # pointer as an int-array element cursor: int *fields = (int*)entry; template_id = fields + 3; fields += 6;
    for hm in ["entry", "relative"]:
        t = s.replace(
            PTR_DECL,
            "            int *fields = (int *)entry;\n            int *template_id = fields + 3;\n            fields += 6;\n",
        )
        if hm == "relative":
            t = rel(t)
        add(f"fields-inc-{hm}", t)

    # entry itself copy-redefined via the index (same value): entry = &quest_spawn_table[entry_index];
    for hm in ["entry", "relative"]:
        t = s.replace(PTR_DECL, PTR_DECL + "            entry = &quest_spawn_table[entry_index];\n")
        if hm == "relative":
            t = rel(t)
        add(f"entry-reassign-same-{hm}", t)


for tag, batch in [
    ("wrap", batch_wrap),
    ("rettemp", batch_rettemp),
    ("memclass", batch_memclass),
    ("byvalue", batch_byvalue),
    ("outparam", batch_outparam),
    ("multiword", batch_multiword),
    ("shortlived", batch_shortlived),
    ("derived", batch_derived),
    ("thisview", batch_thisview),
    ("basecopy", batch_basecopy),
]:

    def add(name, text, tag=tag):
        key = tag + "-" + name
        if key in variants:
            raise ValueError(f"Duplicate variant: {key}")
        variants[key] = text

    batch(s, add)

plan = {
    "schema": 1,
    "sites": [
        {
            "name": "source-shape",
            "find": s,
            "replacements": [{"name": name, "text": text} for name, text in variants.items()],
        },
    ],
}
args.output.write_text(json.dumps(plan, indent=2) + "\n")
print(f"Wrote {len(variants)} source controls to {args.output}")
