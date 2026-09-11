"""Replay native Sharpshooter ownership and laser coordinate rounding."""

import argparse
import importlib.util
import itertools
import json
import math
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10" / "verify.py"
SPEC = importlib.util.spec_from_file_location("plasma_probe", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match = probe.match
OWNER = "player_state_table[0].perk_counts[perk_id_sharpshooter]"
SCREEN = "projectile_render_vec2_t start_screen = start_pos;\n            start_screen += camera_offset;"


def execute(program, native, count, perks, headings, health, alpha, glow):
    players = tuple(
        (i, x, y, health[i], headings[i], perks[i]) for i, (x, y) in enumerate(((100.0, 150.0), (220.0, 210.0)))
    )
    return probe.run(program, native, None, 0.4, alpha, glow, player_count=count, player_rows=players)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path, help="Replay a historical source with the canonical build configuration")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert probe.unicorn.__version__ == "2.1.4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / probe.FUNCTION)
    if args.source is not None:
        source_dir = out / "source"
        source_dir.mkdir(exist_ok=True)
        (source_dir / config.source).write_bytes(args.source.read_bytes())
        config = replace(config, directory=source_dir)
    source = (config.directory / config.source).read_text()
    current = probe.Program(config)
    assert source.count(OWNER) == 1 and source.count(SCREEN) == 1
    md = probe.capstone.Cs(probe.capstone.CS_ARCH_X86, probe.capstone.CS_MODE_32)
    instructions = {
        i.address: i
        for i in md.disasm(current.image.function_bytes(current.native_start, current.native_end), current.native_start)
    }
    expected = {
        0x422E90: ("mov", f"ecx, dword ptr [{hex(current.address('perk_id_sharpshooter'))}]"),
        0x422EA8: ("mov", f"eax, dword ptr [ecx*4 + {hex(current.address('player_state_table') + 0xB8)}]"),
        0x422DEB: ("fld", "dword ptr [esp + 0x48]"),
        0x422DEF: ("fadd", "st(1)"),
        0x422DF1: ("fstp", "dword ptr [esp + 0x48]"),
        0x422E1E: ("fld", "dword ptr [esp + 0x48]"),
        0x422E22: ("fadd", f"dword ptr [{hex(current.address('camera_offset_y'))}]"),
        0x422E28: ("fst", "dword ptr [esp + 0x14]"),
        0x422E2C: ("fstp", "dword ptr [esp + 0x100]"),
    }
    operations = []
    for address, operation in expected.items():
        ins = instructions[address]
        assert (ins.mnemonic, ins.op_str) == operation
        operations.append(
            {"address": hex(address), "bytes": bytes(ins.bytes).hex(), "instruction": " ".join(operation)},
        )
    defects = {}
    for name in ("owner", "rounding", "previous"):
        text = source
        if name in ("owner", "previous"):
            text = text.replace(OWNER, "player->perk_counts[perk_id_sharpshooter]")
        if name in ("rounding", "previous"):
            text = text.replace(
                SCREEN,
                "projectile_render_vec2_t start_screen =\n                camera_offset + start_pos;",
            )
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(text)
        defects[name] = probe.Program(replace(config, directory=directory))
    assert (
        probe.sha((defects["previous"].config.directory / config.source).read_bytes())
        == "45282781bf6a17603dba64ad58dbfddd925c391bfcc5c694c96bb85450d6472e"
    )
    fixtures = list(
        itertools.product(
            (1, 2),
            ((0, 0), (1, 0), (0, 1), (1, 1)),
            ((0.0, 0.0), (0.3, 0.7), (-2.4, 4.0)),
            ((100.0, 100.0), (0.0, 100.0), (100.0, -1.0)),
            (0.2, 0.7, 1.5),
            (0, 1),
        ),
    )
    fixtures += [(0, (1, 1), (0.3, 0.7), (100.0, 100.0), a, g) for a, g in itertools.product((0.2, 0.7, 1.5), (0, 1))]
    rows = []
    for fixture in fixtures:
        native = execute(current, True, *fixture)
        candidate = execute(current, False, *fixture)
        assert native["calls"] == candidate["calls"], fixture
        for key in ("state_sha256", "player_state_sha256", "creature_state_sha256"):
            assert native[key] == candidate[key], (fixture, key)
        count, perks, _, health, _, _ = fixture
        quads = [args for name, args in native["calls"] if name == "grim_draw_quad_points"]
        assert len(quads) == (sum(h > 0 for h in health[:count]) if perks[0] else 0), fixture
        rows.append(
            {
                "fixture": fixture,
                "laser_quads": len(quads),
                "call_trace_sha256": probe.sha(json.dumps(native["calls"]).encode()),
                "projectile_state_sha256": native["state_sha256"],
                "player_state_sha256": native["player_state_sha256"],
                "native_instructions_exercised": native["coverage"],
                "candidate_instructions_exercised": candidate["coverage"],
            },
        )
    negatives = []
    for name, program in defects.items():
        cases = (
            [(1, (1, 0), (0.3, 0.7), (100.0, 100.0), 0.7, 0)]
            if name == "rounding"
            else [
                (2, perks, (0.3, 0.7), health, 0.7, 0)
                for perks, health in (((1, 0), (100.0, 100.0)), ((0, 1), (100.0, 100.0)), ((1, 0), (0.0, 100.0)))
            ]
        )
        for fixture in cases:
            native = execute(current, True, *fixture)
            wrong = execute(program, False, *fixture)
            assert native["calls"] != wrong["calls"]
            nq = [a for n, a in native["calls"] if n == "grim_draw_quad_points"]
            wq = [a for n, a in wrong["calls"] if n == "grim_draw_quad_points"]
            if name == "rounding":
                assert nq[0][1] == 0x42E22EC0 and wq[0][1] == 0x42E22EC1
            else:
                assert len(nq) != len(wq)
            negatives.append({"defect": name, "fixture": fixture, "native": native["calls"], "wrong": wrong["calls"]})
    # Independent rounding oracle for the single-player fixture above.
    heading = probe.f32(0.3) - probe.f32(1.5707964) - probe.f32(0.150915)
    y = 150.0 + math.sin(heading) * 15.0
    width = probe.f32(math.sin(probe.f32(0.3)) * probe.f32(1.1))
    rounded = probe.bits(probe.f32(y) - 21.75 - width)
    extended = probe.bits(y - 21.75 - width)
    assert (rounded, extended) == (0x42E22EC0, 0x42E22EC1)
    result = current.result
    previous = defects["previous"].result
    assert (
        result.ratio > previous.ratio
        and result.masked_operand_audit.problem_count < previous.masked_operand_audit.problem_count
    )
    assert not result.exact and not result.body_byte_exact
    record = {
        "schema_version": 1,
        "kind": "native-sharpshooter-laser-owner-and-rounding",
        "new_source_matches": 0,
        "source_sha256": probe.sha(source.encode()),
        "verifier_sha256": probe.sha(Path(__file__).read_bytes()),
        "engine_sha256": probe.sha(ENGINE.read_bytes()),
        "unicorn_version": probe.unicorn.__version__,
        "image_sha256": probe.sha(match.default_image_path().read_bytes()),
        "native_body_sha256": probe.sha(current.image.function_bytes(current.native_start, current.native_end)),
        "candidate_object_sha256": probe.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": probe.sha(current.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "relocations": current.relocations,
        "native_operations": operations,
        "arithmetic_oracle": {"rounded": hex(rounded), "extended": hex(extended)},
        "fixtures": rows,
        "negative_controls": negatives,
        "defects": {
            name: {
                "source_sha256": probe.sha((p.config.directory / p.config.source).read_bytes()),
                "body_sha256": probe.sha(p.body.data),
            }
            for name, p in defects.items()
        },
        "metrics": {
            name: {
                "ratio": r.ratio,
                "candidate_instructions": len(r.candidate_lines),
                "target_instructions": len(r.target_lines),
                "references_ok": r.masked_operand_audit.ok_count,
                "reference_problems": r.masked_operand_audit.problem_count,
                "exact": r.exact,
                "body_byte_exact": r.body_byte_exact,
            }
            for name, r in (("current", result), ("previous", previous))
        },
        "boundaries": {
            "grim": "recording thiscall stubs",
            "perk_count_get": "recording zero result; player Sharpshooter counts read from actual memory",
            "math": "machine x87 and native crt_ftol under 0x037f",
            "state": "zero to two players, no active primary or secondary projectiles; fixed camera; no non-stack writes",
            "scope": "caller argument identity for these fixtures, not full renderer or pixel identity",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(f"{len(rows)} laser fixtures agree; {len(negatives)} compiled defect cases rejected; no exact match claimed.")


if __name__ == "__main__":
    main()
