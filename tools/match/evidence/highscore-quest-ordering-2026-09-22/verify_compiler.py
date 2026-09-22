"""Prove the quest edit changes row ordering through a generated-symbol hash."""

import argparse
import json
import shutil
import struct
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from controls import HERE, WITNESS, build, sha, sources

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

ORIGINAL_OBSERVER = c2.observer_source
STOCK = ("selector", "predicate", "quest-limit-reference", "quest-arm-indices", WITNESS)
EXPECTED_IDS = dict(zip(STOCK, (0xB2A, 0xB28, 0xB29, 0xB28, 0xB27), strict=True))


def lines(source):
    rows = source.splitlines()
    start = next(i for i, s in enumerate(rows) if "void highscore_screen_update" in s)
    zero = next(i for i, s in enumerate(rows) if "int prefix_length = 0;" in s) - start
    two = next(i for i, s in enumerate(rows) if "prefix_length = 2;" in s) - start
    additions = []
    for i, s in enumerate(rows):
        if "score_line_items[score_count] + prefix_length," in s:
            end = next(j for j in range(i, len(rows)) if rows[j].rstrip().endswith(");"))
            additions.append(end - start)
    assert len(additions) == 3
    return zero, two, additions


def profile():
    p = c2.load_profile()
    return dict(
        p,
        hooks=p["hooks"][:12]
        + [
            {"site": 0xDA8D, "target": 0xF584, "return": True},
            {"site": 0xD8EA, "target": 0xF584, "return": True},
            {"site": 0xD8FF, "target": 0xF584, "return": True},
            {"site": 0x2FE5F, "target": 0x32F7C, "return": True},
            {"site": 0x330C2, "target": 0x251D, "return": True},
        ],
    )


def observer(p, source, force=0, expected=0):
    zero, _, additions = lines(source)
    defines = f"#define PREFIX_LINE {zero}\n#define FORCE_KEY {force}\n#define EXPECT_KEY {expected}\n"
    defines += "".join(f"#define ROW_LINE_{i} {v}\n" for i, v in enumerate(additions))
    s = ORIGINAL_OBSERVER(p).replace(
        "static HANDLE trace_file;", "static HANDLE trace_file;\n" + defines + (HERE / "watch.c.in").read_text(),
    )
    # The sort hooks also run before the first function. Never dereference a
    # saved function before the standard function-entry hook has observed one.
    s = s.replace(
        "    function = (unsigned long *)saved_function;",
        "    if(phase>=12 && !saved_function)return;\n    function = (unsigned long *)saved_function;",
    )
    s = s.replace(
        "    node = first;", "    watch(phase,registers,first);\n    if(phase>=12)return;\n    node = first;", 1,
    )
    s = s.replace(
        "base = (unsigned char *)invoke - INVOKE_RVA;",
        "base = (unsigned char *)invoke - INVOKE_RVA;\n    c2base=(unsigned long)base;",
    )
    opens = "".join(
        f'    {name}_file=CreateFileA("{name}.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
        f"    if({name}_file==INVALID_HANDLE_VALUE)ExitProcess(81);\n"
        for name in ("order", "alloc", "change")
    )
    s = s.replace("    trace_file = CreateFileA(", opens + "    trace_file = CreateFileA(")
    closes = "".join(f"    CloseHandle({name}_file);\n" for name in ("order", "alloc", "change"))
    closes += "    if(key_changes!=(FORCE_KEY?6:0))ExitProcess(87);\n"
    return s.replace("    CloseHandle(trace_file);", closes + "    CloseHandle(trace_file);")


def records(data, width):
    assert len(data) % (width * 4) == 0
    return [struct.unpack_from(f"<{width}I", data, i) for i in range(0, len(data), width * 4)]


def ordering(data, additions, symbol_id, force=0):
    rows = records(data, 90)
    assert len(rows) == 36
    expected_key = 0x10000 | ((7 + (symbol_id << 14)) & 0xFFFF)
    result = []
    for line in additions:
        selected = [r for r in rows if r[3] == line]
        assert [r[0] for r in selected] == [14, 14, 114, 114, 13, 13, 113, 113, 12, 12, 112, 112]
        assert len({r[1] for r in selected}) == 1
        for at in range(0, len(selected), 2):
            pair = selected[at : at + 2]
            assert [r[4] for r in pair] == [0, 1]
            assert {r[8] & 255 for r in pair} == {2, 6}
            memory = next(r for r in pair if r[8] & 255 == 6)
            prefix = next(r for r in pair if r[8] & 255 == 2)
            assert memory[7] == 0x14C and memory[15] == 0 and memory[17] == 0
            assert memory[36] & 255 == 2 and memory[47] & 255 == 3
            assert memory[51] == 0 and memory[53] == symbol_id
            assert prefix[19] & 255 == 4 and prefix[23] == 0 and prefix[25] == 27
            assert prefix[9] == 0x10360
            natural = pair[0][0] in (14, 12) or not force
            assert memory[9] == (expected_key if natural else force)
            if pair[0][0] == 14:
                assert [r[8] & 255 for r in pair] == [6, 2]
            else:
                wanted = [6, 2] if (force or expected_key) > 0x10360 else [2, 6]
                assert [r[8] & 255 for r in pair] == wanted
            result.append(
                {"line": line, "phase": pair[0][0], "kinds": [r[8] & 255 for r in pair], "keys": [r[9] for r in pair]},
            )
    return {"generated_base_id": symbol_id, "natural_memory_key": expected_key, "prefix_key": 0x10360, "sorts": result}


def allocation(data, base, source, memory_first):
    rows = records(data, 35)
    zero, two, additions = lines(source)
    ids = {r[1] for r in rows if r[0] == 200 and r[5] == zero and r[4] == 1}
    assert len(ids) == 1
    selected = [r for r in rows if r[1] in ids]
    before = [r for r in selected if r[0] == 12]
    after = [r for r in selected if r[0] == 112]
    choices = [r for r in selected if r[0] == 113]
    assert len(before) == len(after) == 1 and len(choices) == 7
    assert len({r[2] for r in selected}) == 1
    assert [r[3] for r in choices] == [1, 2, 3, 7, 8, 4, 6]
    b, a = before[0], after[0]
    users = [(r[5], r[6], r[4]) for r in selected if r[0] == 200]
    wanted = [(zero, 1, 1), (two, 1, 1)]
    for line in additions:
        wanted.append((line, 0x2D, 0))
        if not memory_first:
            wanted.extend(((line, 0x2D, 1), (line, 0xD, 0)))
    assert users == wanted
    assert (b[1], b[9], b[21], a[10] - base) == ((6, 106, 20, 0xAC880) if memory_first else (1, 274, 44, 0xAC97C))
    assert Counter(r[0] for r in rows)[12] == Counter(r[0] for r in rows)[112] == 170
    return {
        "ordinal": b[1],
        "priority": b[9],
        "cost": b[21],
        "register_rva": a[10] - base,
        "users": users,
        "choices": [{"register": r[3], "eligible": r[4], "costs": r[26:35]} for r in choices],
        "total_allocations": 170,
    }


def read(out, source, symbol_id, force=0):
    base = struct.unpack_from("<3I", (out / "phases.bin").read_bytes())[2]
    order = ordering((out / "order.bin").read_bytes(), lines(source)[2], symbol_id, force)
    alloc = allocation((out / "alloc.bin").read_bytes(), base, source, (force or order["natural_memory_key"]) > 0x10360)
    changes = records((out / "change.bin").read_bytes(), 4)
    assert changes == (
        [(phase, line, order["natural_memory_key"], force) for line in lines(source)[2] for phase in (14, 12)]
        if force
        else []
    )
    return {
        "ordering": order,
        "allocation": alloc,
        "changed_keys": changes,
        "coff_sha256": sha(replay.normalized_coff(out / "replay.obj")),
        "trace_hashes": {n: sha((out / n).read_bytes()) for n in ("order.bin", "alloc.bin", "change.bin")},
    }


def lowering(events, source, memory_first):
    zero, _, additions = lines(source)
    results = {}
    for phase in (4, 5, 10):
        event = next(e for e in events if e["phase"] == phase and e["function_ordinal"] == 0)
        definition = [n for n in event["nodes"] if n["line"] == zero and len(n["dst"]) == 1]
        assert len(definition) == 1 and definition[0]["dst"][0]["kind"] == 1
        symbol = definition[0]["dst"][0]["raw"][5]
        uses = []
        for node in event["nodes"]:
            if node["line"] not in additions:
                continue
            for index, operand in enumerate(node["src"]):
                if operand["kind"] == 1 and operand["raw"][5] == symbol:
                    uses.append((node["line"], node["op"] & 0xFFFF, index, [o["kind"] for o in node["src"]]))
        shape = (0x2D, 1, [1, 1]) if memory_first else ((0x2D, 0, [1, 6, 1]) if phase == 4 else (1, 0, [1]))
        assert uses == [(line, *shape) for line in additions]
        results[phase] = uses
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    root = parser.parse_args().out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    p = profile()
    results = {}
    for name in STOCK:
        cfg, _, _, _, _ = build(name, root / "controls")
        source = sources()[name][0]
        out = root / name
        with (
            patch.object(c2, "load_profile", lambda: p),
            patch.object(
                c2,
                "observer_source",
                lambda q, source=source: observer(q, source),
            ),
        ):
            receipt = c2.trace(cfg.directory, out)
        results[name] = read(out / "observed", source, EXPECTED_IDS[name])
        results[name]["lowering"] = lowering(
            c2.read_verified(out), source, results[name]["ordering"]["natural_memory_key"] > 0x10360,
        )
        results[name].update(
            source_sha256=receipt["source_sha256"],
            whole_coff_equal_except_timestamp=receipt["whole_coff_equal_except_timestamp"],
            missing_stream_rejected=receipt["missing_stream_rejected"],
        )
        results[name]["capture_manifest_sha256"] = sha((out / "manifest.json").read_bytes())
        print("Verified preserving trace", name, flush=True)
    for name, force in (("predicate", 0x18007), ("selector", 0x10007)):
        out = root / (name + "-force-key")
        out.mkdir()
        source = sources()[name][0]
        shutil.copyfile(root / name / "replay/replay_settings.h", out / "replay_settings.h")
        natural = results[name]["ordering"]["natural_memory_key"]
        (out / "observer.c").write_text(observer(p, source, force, natural))
        with c2.compiler_environment():
            replay.compile_driver(out, "observer.c", "observer.obj")
            replay.link(out, "observer.exe", "observer.obj")
            replay.run([replay.WIBO, "observer.exe"], out)
        results[out.name] = read(out, source, EXPECTED_IDS[name], force)
        print("Verified scoped key intervention", name, flush=True)
    assert results["predicate-force-key"]["coff_sha256"] == results["quest-limit-reference"]["coff_sha256"]
    assert (
        results["selector-force-key"]["coff_sha256"]
        == "05552a274b93076586b25cce144c94afd8e9647ee92709e4c7149ce47dd5875e"
    )
    data = (root / "predicate/observed/order.bin").read_bytes()
    rejected = []
    for label, bad in [("truncated-order-record", data[:-1]), ("omitted-sort-return", data[:-720])]:
        try:
            ordering(bad, lines(sources()["predicate"][0])[2], EXPECTED_IDS["predicate"])
        except AssertionError:
            rejected.append(label)
        else:
            raise AssertionError(label)
    bad = bytearray(data)
    struct.pack_into("<I", bad, 9 * 4, 0x18007)
    try:
        ordering(bad, lines(sources()["predicate"][0])[2], EXPECTED_IDS["predicate"])
    except AssertionError:
        rejected.append("wrong-ordering-key")
    else:
        raise AssertionError("Accepted wrong key")
    result = {
        "schema": 1,
        "scope": "causal-compiler-evidence-not-full-function-match",
        "c2_sha256": p["c2_sha256"],
        "hooks": p["hooks"],
        "results": results,
        "corruptions_rejected": rejected,
        "dependency_hashes": {
            str(path.relative_to(c2.match.REPO_ROOT)): sha(path.read_bytes())
            for path in (Path(c2.__file__), Path(replay.__file__), c2.ASSETS / "observer.c.in")
        },
        "input_hashes": {
            n: sha((HERE / n).read_bytes())
            for n in ("controls.py", "controls.json", "verify_compiler.py", "watch.c.in")
        },
    }
    (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
