"""Locate expression merging and independently deny the two reuse decisions."""

import argparse
import copy
import json
import shutil
import struct
from pathlib import Path
from unittest.mock import patch

from controls import HERE, build, measure, sha, sources

from crimson import match_c2 as c2
from crimson import match_c2_replay as replay

ORIGINAL_OBSERVER = c2.observer_source


def observer(profile, deny=0):
    source = ORIGINAL_OBSERVER(profile)
    predicate = "(*(unsigned short *)(node+0x10)>=390 && *(unsigned short *)(node+0x10)<=430)"
    edits = {
        "static HANDLE trace_file;": (
            f"static HANDLE trace_file;\n#define DENY_MASK {deny}\n" + (HERE / "watch.c.in").read_text()
        ),
        "    node = first;": (
            "    if (!watched_function) watched_function = saved_function;\n"
            "    if (saved_function == watched_function) watch(phase, registers);\n"
            "    if (phase == 13 || phase == 113 || phase == 14) return;\n"
            "    node = first;"
        ),
        "while (node && count < MAX_NODES) { ++count; node = *(unsigned long *)node; }": (
            "j = 0;\n    while (node && j++ < MAX_NODES) {\n"
            f"        if {predicate} ++count;\n        node = *(unsigned long *)node;\n    }}"
        ),
        "for (j=0;j<742;++j) record[j]=0;": (f"if (!{predicate}) continue;\n        for (j=0;j<742;++j) record[j]=0;"),
        "base = (unsigned char *)invoke - INVOKE_RVA;": (
            "base = (unsigned char *)invoke - INVOKE_RVA;\n    c2base=(unsigned long)base;"
        ),
        "    trace_file = CreateFileA(": (
            '    watch_file=CreateFileA("choices.bin",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);\n'
            "    if (watch_file==INVALID_HANDLE_VALUE) ExitProcess(85);\n    trace_file = CreateFileA("
        ),
        "    CloseHandle(trace_file);": "    CloseHandle(watch_file);\n    CloseHandle(trace_file);",
    }
    for old, new in edits.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    return source


def floating_adds(event, line):
    return [
        n
        for n in event["nodes"]
        if n["line"] == line and n["op"] == 0x16D and len(n["src"]) == 2 and n["src"][1]["kind"] == 9
    ]


def merging(events):
    selected = [e for e in events if e["function_ordinal"] == 0 and e["phase"] in (12, 112)]
    assert [e["phase"] for e in selected] == [12, 112]
    result = []
    for label, widget in ((399, 401), (421, 426)):
        destinations = []
        for event in selected:
            pair = [floating_adds(event, line) for line in (label, widget)]
            assert all(len(v) == 1 and len(v[0]["dst"]) == 1 for v in pair)
            dst = [v[0]["dst"][0] for v in pair]
            if event["phase"] == 12:
                assert all(d["kind"] == 1 for d in dst)
                assert dst[0]["raw"][6] != dst[1]["raw"][6]
            else:
                assert all(d["kind"] == 2 for d in dst)
                assert dst[0]["raw"][5] == dst[1]["raw"][5] != 0
            destinations.append([d["kind"] for d in dst])
        result.append(
            {
                "label_line": label,
                "widget_line": widget,
                "destination_kinds": destinations,
                "distinct_temporaries_before": True,
                "same_expression_after": True,
            },
        )
    return result


def decisions(raw, deny):
    assert len(raw) % 44 == 0
    rows = [list(struct.unpack_from("<11I", raw, i)) for i in range(0, len(raw), 44)]
    expected = []
    for line, mask in ((401, 1), (426, 2)):
        expected += [(13, line), (113, line)]
        if not deny & mask:
            expected.append((14, line))
    assert [(r[0], r[1]) for r in rows] == expected
    result = []
    for line, before, mask in ((401, 32768, 1), (426, 2, 2)):
        group = [r for r in rows if r[1] == line]
        assert all(r[2] == 0x16D and r[4] == 3 and r[9] == 0 and r[10] != 0 for r in group)
        assert all(r[3] == group[0][3] and r[7:11] == group[0][7:11] for r in group)
        ret = group[1]
        assert before == 1 << (ret[7] & 31)
        assert ret[5] == before and ret[6] == (0 if deny & mask else before)
        assert all(r[5] == r[6] for r in group if r[0] != 113)
        result.append(
            {
                "line": line,
                "bit_index": ret[7],
                "before": ret[5],
                "after": ret[6],
                "deleted": any(r[0] == 14 for r in group),
                "optimizer_phase": ret[4],
            },
        )
    return result


def rejected(call):
    try:
        call()
    except (AssertionError, IndexError, KeyError, struct.error):
        return True
    raise AssertionError("Corrupted evidence was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    root = parser.parse_args().out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    cfg, _, _, _, _ = build("baseline", root / "controls")
    assert sha(sources()["baseline"][0].encode()) == "ffc2226e2ec54cefaf4a2fde09fd1f379342b105f9162a418b49f5d0ce1fa6c7"
    p = c2.load_profile()
    p = dict(
        p,
        hooks=p["hooks"][:12]
        + [
            {"site": 0x13189, "target": 0x11209, "return": True},
            {"site": 0x9739, "target": 0x251D, "return": True},
            {"site": 0x97A4, "target": 0x210E, "return": False},
        ],
    )
    out = root / "preserving"
    with patch.object(c2, "load_profile", lambda: p), patch.object(c2, "observer_source", observer):
        receipt = c2.trace(cfg.directory, out)
    events = c2.read_verified(out)
    merge = merging(events)
    print("Verified preserving trace and expression merging", flush=True)
    results = {}
    for deny in range(4):
        folder = out / "observed" if deny == 0 else root / f"deny-{deny}"
        if deny:
            folder.mkdir()
            shutil.copyfile(out / "replay/replay_settings.h", folder / "replay_settings.h")
            (folder / "observer.c").write_text(observer(p, deny))
            with c2.compiler_environment():
                replay.compile_driver(folder, "observer.c", "observer.obj")
                replay.link(folder, "observer.exe", "observer.obj")
                replay.run([replay.WIBO, "observer.exe"], folder)
        raw = (folder / "choices.bin").read_bytes()
        choices = decisions(raw, deny)
        body, _, metrics = measure(folder / "replay.obj", cfg, folder)
        assert body.data[5:7] == b"\x81\xec"
        frame = struct.unpack_from("<I", body.data, 7)[0]
        assert (metrics["instructions"], frame) == [(2005, 132), (2004, 132), (2004, 128), (2003, 128)][deny]
        assert not metrics["exact"] and not metrics["body_byte_exact"]
        results[str(deny)] = {
            "choices": choices,
            "frame": frame,
            **metrics,
            "choices_sha256": sha(raw),
            "coff_sha256": sha(replay.normalized_coff(folder / "replay.obj")),
        }
        print("Verified availability mask", deny, flush=True)
    raw = (out / "observed/choices.bin").read_bytes()
    corruptions = {"truncated-record": rejected(lambda: decisions(raw[:-1], 0))}
    for name, offset, value in (
        ("wrong-line", 4, 402),
        ("wrong-opcode", 8, 0x16E),
        ("wrong-phase", 16, 2),
        ("unavailable-expression", 40, 0),
        ("wrong-return", 44 + 24, 0),
    ):
        bad = bytearray(raw)
        struct.pack_into("<I", bad, offset, value)
        corruptions[name] = rejected(lambda bad=bad: decisions(bad, 0))
    damaged = copy.deepcopy(events)
    event = next(e for e in damaged if e["function_ordinal"] == 0 and e["phase"] == 112)
    floating_adds(event, 401)[0]["dst"][0]["raw"][5] ^= 4
    corruptions["different-expression-owner"] = rejected(lambda: merging(damaged))
    result = {
        "schema": 1,
        "scope": "diagnostic-compiler-intervention-not-a-source-match",
        "c2_sha256": p["c2_sha256"],
        "source_sha256": receipt["source_sha256"],
        "whole_coff_equal_except_timestamp": receipt["whole_coff_equal_except_timestamp"],
        "missing_stream_rejected": receipt["missing_stream_rejected"],
        "merging": merge,
        "results": results,
        "corruptions_rejected": corruptions,
        "input_hashes": {
            n: sha((HERE / n).read_bytes())
            for n in ("controls.py", "controls.json", "watch.c.in", "verify_compiler.py")
        },
    }
    (root / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
