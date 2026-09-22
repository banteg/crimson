"""Temporarily prune one copied local's implicit alias membership during allocation.

This intentionally changes a pinned compiler decision. Its output must never
be installed as a candidate or used as source-match evidence.
"""

import argparse
import json
import shutil
import struct
from pathlib import Path

from controls import HERE, TRIPLET, build, sha
from verify import copied_index, decode_aliases, observer, profile, stack

from crimson import match
from crimson import match_c2 as c2


def source(enable):
    settings = profile()
    settings = dict(
        settings,
        hooks=settings["hooks"][:12]
        + [
            {"site": 0x33C7E, "target": 0x4AC4C, "return": False},
            *settings["hooks"][12:],
        ],
    )
    text = observer(settings)
    edits = {
        "static void __cdecl observe(": (
            f"#define ENABLE_PRUNE {int(enable)}\n"
            + (HERE / "prune.c.in").read_text()
            + "\nstatic void __cdecl observe("
        ),
        "    if (phase < 12) saved_function = registers[6];": (
            "    if(phase==12){prune_aliases();return;}\n    if(phase>=13)--phase;\n"
            "    if (phase < 12) saved_function = registers[6];"
        ),
        "        write_block(record,sizeof(record));\n    }": (
            "        write_block(record,sizeof(record));\n    }\n    if(phase==12)restore_aliases();"
        ),
    }
    for old, new in edits.items():
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


def inspect_output(cfg, obj):
    result = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    lines = list(result.candidate_lines)
    pointer = lines.index("lea edi, dword [esi+0xc]")
    call = lines.index("call ADDR")
    frame = int(next(line.split(", ")[1] for line in lines if line.startswith("sub esp,")), 0)
    return {
        "normalized_coff_sha256": sha(c2.replay.normalized_coff(obj)),
        "metrics": c2.replay.function_metrics(cfg, obj),
        "frame": frame,
        "pointer_window": lines[pointer : pointer + 3],
        "argument_window": lines[call - 12 : call + 1],
    }, lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verified", type=Path, required=True, help="Output of this package's preserving verify.py")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    preserved = args.verified / "traces/end-pointer"
    # Validate capture, input hashes and pinned compiler through the existing
    # verifier before replaying anything. Derive settings from this fresh run.
    c2.read_verified(preserved)
    row, cfg, _obj = build("end-pointer", args.out / "controls")
    assert sha(c2.replay.normalized_coff(preserved / "observed/replay.obj")) == row["normalized_coff_sha256"]
    baseline_symbols, baseline_order = stack.hud.decode((preserved / "observed/graph.bin").read_bytes())
    copied = copied_index(baseline_symbols)
    rows = []
    for enable in (False, True):
        name = "pruned" if enable else "preserving"
        out = args.out / name
        out.mkdir()
        shutil.copyfile(preserved / "replay/replay_settings.h", out / "replay_settings.h")
        (out / "observer.c").write_text(source(enable))
        with c2.compiler_environment():
            c2.replay.compile_driver(out, "observer.c", "observer.obj")
            c2.replay.link(out, "observer.exe", "observer.obj")
            c2.replay.run([c2.replay.WIBO, "observer.exe"], out)
        data = (out / "graph.bin").read_bytes()
        symbols, order = stack.hud.decode(data)
        prediction = stack.predict(symbols, order)
        checked = stack.check_offsets(symbols, prediction)
        raw_aliases = (out / "aliases.bin").read_bytes()
        assert struct.unpack("<2I", raw_aliases[-8:]) == (0x50524E31, int(enable))
        # Raw arena identities stay within their replay. This trace's phase
        # records use the same normalized 0..13 phase numbers as the preserving
        # capture, but are decoded directly, not presented as a c2 receipt.
        observed = c2.decode_trace((out / "phases.bin").read_bytes(), profile())
        groups = decode_aliases(raw_aliases[:-8], symbols, observed)
        owner = copied_index(symbols)
        assert owner == copied and order == baseline_order
        assert bool([g for g in groups if owner in g["members"]]) != enable
        expected_conflicts = [list(s["conflicts"]) for s in baseline_symbols]
        if enable:
            expected_conflicts[owner] = [2, 3, 4]
            for index in (0, 2, 4):
                expected_conflicts[index].remove(owner)
        assert [s["conflicts"] for s in symbols] == expected_conflicts
        info, lines = inspect_output(cfg, out / "replay.obj")
        assert prediction["frame_size"] == info["frame"] == (28 if enable else 32)
        if enable:
            assert info["pointer_window"] == TRIPLET
            assert info["normalized_coff_sha256"] != row["normalized_coff_sha256"]
        else:
            assert info["normalized_coff_sha256"] == row["normalized_coff_sha256"]
        assert not info["metrics"]["exact"] and not info["metrics"]["body_byte_exact"]
        (out / "candidate.asm").write_text("\n".join(lines) + "\n")
        rows.append(
            {
                "mode": name,
                "edited_and_restored_alias_links": int(enable),
                "offsets_checked": checked,
                "graph_sha256": sha(data),
                "alias_sha256": sha(raw_aliases),
                "conflicts": expected_conflicts,
                "prediction": prediction,
                **info,
            },
        )
        print(f"{name}: verified frame {info['frame']}, alias membership, ordered stores and all offsets", flush=True)
    result = {
        "kind": "timeline-copy-alias-diagnostic",
        "verified": True,
        "limitations": "One deliberate compiler intervention. Aliases restored before grouping returns to later passes. No stock-source recovery, runtime equivalence, or new match is claimed; argument scheduling still changes.",
        "source_hashes": {
            name: sha((HERE / name).read_bytes())
            for name in ("diagnostic.py", "prune.c.in", "verify.py", "aliases.c.in")
        },
        "modes": rows,
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
