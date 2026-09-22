"""Stock-source controls for Fire Cough angle storage and argument staging."""

import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from crimson import match
from crimson import match_c2 as c2

HERE = Path(__file__).resolve().parent
SOURCE_SHA = "c982bef1d0b1aa82f7aa2f2488fbe0df72959e8d9ffa31f9a69f89762234a72c"
COFF_SHA = "f52730071393c62f8b16673ec2fe4b5a70546db0f9c147abfb441e1b78efa1f0"
FRAME_MAP = HERE.parent / "player-frame-controls-2026-09-14/frame_map.py"
NEUTRAL = ("own-array", "own-struct", "own-union", "double-atan2f", "scalar-argument-subtract")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sources():
    cfg = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    source = (cfg.directory / cfg.source).read_text()
    assert sha(source.encode()) == SOURCE_SHA
    angle = "atan2f(shot_delta[1], shot_delta[0])"
    expr = angle + " - 1.5707964f"
    old = "float shot_heading = " + expr + ";"
    arg = "                shot_heading,"
    assert source.count(old) == source.count(arg) == 1
    yield "baseline", source
    variants = {
        "own-array": ("float shot_heading[1] = {" + expr + "};", "shot_heading[0]"),
        "own-struct": (
            "struct shot_angle_t { float value; }; shot_angle_t shot_heading = {" + expr + "};",
            "shot_heading.value",
        ),
        "own-union": (
            "union { float value; unsigned bits; } shot_heading; shot_heading.value = " + expr + ";",
            "shot_heading.value",
        ),
        "double-atan2f": ("double shot_heading = " + expr + ";", "shot_heading"),
        "scalar-argument-subtract": ("float shot_heading = " + angle + ";", "shot_heading - 1.5707964f"),
        "scratch-member": ("scratch_pos.x = " + expr + ";", "scratch_pos.x"),
        "member-argument-subtract": ("scratch_pos.x = " + angle + ";", "scratch_pos.x - 1.5707964f"),
        "reference-argument-subtract": (
            "const float &shot_heading = " + angle + ";",
            "shot_heading - 1.5707964f",
        ),
    }
    for name, (declaration, argument) in variants.items():
        yield name, source.replace(old, declaration).replace(arg, "                " + argument + ",")


def inspect(cfg, obj, out):
    result = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    for kind, rows in (("native", result.target_disassembly), ("candidate", result.candidate_disassembly)):
        write_json(out / (kind + ".json"), [asdict(row) for row in rows])
    subprocess.run([sys.executable, str(FRAME_MAP), str(out)], check=True, capture_output=True)
    windows = {}
    for kind in ("native", "candidate"):
        lines = (out / (kind + "-frame.asm")).read_text().splitlines()
        start = next(i for i, line in enumerate(lines) if "call ADDR ;" in line and "vec2_sub" in line)
        end = next(
            i for i in range(start + 1, len(lines)) if "call ADDR ;" in lines[i] and "projectile_spawn" in lines[i]
        )
        windows[kind] = [line[9:] for line in lines[start : end + 1]]
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    audit = result.masked_operand_audit
    row = {
        "normalized_coff_sha256": sha(c2.replay.normalized_coff(obj)),
        "body_sha256": sha(body.data),
        "instructions": len(result.candidate_lines),
        "target_instructions": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "references": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "ratio": result.ratio,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "frames": json.loads((out / "frame-summary.json").read_text()),
        "angle_windows": windows,
    }
    assert not row["exact"] and not row["body_byte_exact"]
    return row


def build(name, source, out):
    original = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    directory = out / name
    directory.mkdir(parents=True, exist_ok=False)
    (directory / original.source).write_text(source)
    (directory / "scratch.conf").write_bytes((original.directory / "scratch.conf").read_bytes())
    cfg = match.load_scratch_config(directory)
    obj = match.compile_scratch(cfg, force=True)
    row = {"name": name, "source_sha256": sha(source.encode()), **inspect(cfg, obj, directory)}
    if name == "baseline" or name in NEUTRAL:
        assert row["normalized_coff_sha256"] == COFF_SHA
    write_json(directory / "result.json", row)
    return row, cfg, obj
