"""Index-family spawn-group grid: which spellings give the 1.9.8 body, and does any give native's pointer."""

import argparse
import itertools
import json
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import compare

INDEX = "quest_spawn_table[entry_index]"
BODY = """spawn_entries:
    quest_timeline_vec2_t zero_offset(0.0f, 0.0f);
    do {{
{top}        quest_timeline_vec2_t offset = zero_offset;
        int spawn_index = 0;
        if ({guard} > 0) {{
{block}            int spread;

            spread = 0;
            do {{
{loop}                if ({x} < 0.0f
                    || (float)terrain_texture_width < {x}) {{
                    offset.y = (float)spread;
                    if (spawn_index & 1) {{
                        offset.y = -offset.y;
                    }}
                }} else {{
                    offset.x = (float)spread;
                    if (spawn_index & 1) {{
                        offset.x = -offset.x;
                    }}
                }}

                quest_timeline_vec2_t pos(
                    offset.x + {x},
                    offset.y + {y});
                creature_spawn_template(
                    {template},
                    (const vec2f_t *)&pos,
                    {heading});

                ++spawn_index;
                spread += 0x28;
            }} while (spawn_index < {count});
        }}

        entry_count = quest_spawn_count;
        {zero} = 0;
        creatures_any_active_flag = 0;
        if (entry_index >= entry_count - 1) {{
            return;
        }}
        if ({trigger} != {next_trigger}) {{
            return;
        }}
        ++entry_index;
    }} while (true);
}}
"""


def spawn_part(entry, pointer, place, heading, x, y, count, guard, zero, trigger):
    """entry t/b/n: entry re-derived at the group top, in the positive-count block, or absent.
    pointer 0/i/e: no template pointer, from the index, from entry; place t/b/l: group top, block, spawn loop.
    heading e/i/p: entry, index, ((float *)template_id)[-1]; x e/i/l/m: entry, index, float local from either.
    The remaining sites choose e (entry) or i (index)."""
    sites = (x if x in "ei" else "i", y, count, guard, zero, trigger)
    if entry == "n" and ("e" in sites or pointer == "e" or heading == "e" or x == "l"):
        return None
    if entry == "b" and "e" in (guard, zero, trigger):
        return None
    if pointer == "0" and (heading == "p" or place != "t"):
        return None
    if pointer == "e" and entry == "b" and place == "t":
        return None

    def field(mode, name):
        return f"entry->{name}" if mode == "e" else f"{INDEX}.{name}"

    entry_decl = "quest_spawn_entry_t *entry = &quest_spawn_table[entry_index];\n"
    pointer_decl = {"0": "", "i": f"int *template_id = &{INDEX}.template_id;\n", "e": "int *template_id = &entry->template_id;\n"}[pointer]
    top = ("        " + entry_decl if entry == "t" else "") + ("        " + pointer_decl if pointer_decl and place == "t" else "")
    block = ("            " + entry_decl if entry == "b" else "") + ("            " + pointer_decl if pointer_decl and place == "b" else "")
    loop = "                " + pointer_decl if pointer_decl and place == "l" else ""
    x_expr = field(x, "position.x")
    if x in "lm":
        loop += f"                float x = {field('e' if x == 'l' else 'i', 'position.x')};\n"
        x_expr = "x"
    return BODY.format(
        top=top, block=block, loop=loop, x=x_expr, y=field(y, "position.y"),
        template="*template_id" if pointer != "0" else f"{INDEX}.template_id",
        heading={"e": "entry->heading", "i": f"{INDEX}.heading", "p": "((float *)template_id)[-1]"}[heading],
        count=field(count, "count"), guard=field(guard, "count"), zero=field(zero, "count"),
        trigger=field(trigger, "trigger_time_ms"),
        next_trigger=("entry[1]" if trigger == "e" else "quest_spawn_table[entry_index + 1]") + ".trigger_time_ms",
    )


def anchor(lines):
    """Field offset of the group cursor: native reads count at [esi+0x14] (anchor 0), 1.9.8 at [esi] (0x14)."""
    for index, line in enumerate(lines):
        if re.fullmatch(r"lea esi, \[e\w\w\*8 \+ IMAGE\]", line):
            count = re.fullmatch(r"mov e\w\w, dword ptr \[esi(?: ([+-]) (0x[0-9a-f]+|\d+))?\]", lines[index + 1])
            if count:
                offset = int(count[2] or "0", 0)
                return 0x14 - (-offset if count[1] == "-" else offset)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", type=Path, required=True, help="output directory of historical.py")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    prefix = (compare.SCRATCH / "scratch.cpp").read_text().partition("spawn_entries:\n")[0]
    targets = {version: (args.history / f"{version}.asm").read_text().splitlines() for _, version in compare.BUILDS}
    cases, seen = {}, set()
    for choice in itertools.product("tbn", "0ie", "tbl", "eip", "eilm", "ei", "ei", "ei", "ei", "ei"):
        body = spawn_part(*choice)
        if body and body not in seen:
            seen.add(body)
            cases["".join(choice)] = prefix + body

    def run(item):
        name, text = item
        with tempfile.TemporaryDirectory(dir=args.out) as work:
            source = Path(work) / f"{name}.cpp"
            source.write_text(text)
            listings = {compiler: compare.listing(source, compiler, Path(work)) for compiler, _ in compare.BUILDS}
        return name, {
            "exact_1_9_8": listings["msvc6.5pp"] == targets["1.9.8"],
            "exact_1_9_93": listings["msvc6.5"] == targets["1.9.93"],
            "anchor_8966": anchor(listings["msvc6.5"]),
            "pointer_lea_8966": any(re.fullmatch(r"lea e\w\w, \[esi \+ 0xc\]", line) for line in listings["msvc6.5"]),
        }

    with ThreadPoolExecutor(args.jobs) as pool:
        results = dict(pool.map(run, cases.items()))
    summary = {
        "variants": len(results),
        "exact_1_9_8": sum(r["exact_1_9_8"] for r in results.values()),
        "exact_1_9_8_with_native_anchor_8966": sum(r["exact_1_9_8"] and r["anchor_8966"] == 0 for r in results.values()),
        "exact_1_9_93": sum(r["exact_1_9_93"] for r in results.values()),
        "pointer_lea_8966": sum(r["pointer_lea_8966"] for r in results.values()),
    }
    (args.out / "grid.json").write_text(json.dumps({"summary": summary, "results": results}, indent=1) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
