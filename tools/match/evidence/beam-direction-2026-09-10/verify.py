"""Verify native beam direction/anchor at modeled external-call boundaries."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10" / "verify.py"
SPEC = importlib.util.spec_from_file_location("plasma_probe", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match = probe.match
TYPES = (21, 22, 23, 45)
GEOMETRIES = (
    ((111.25, 208.5), (50.125, 91.75)),
    ((-45.5, 12.25), (77.0, 43.5)),
    ((350.0, 0.0), (0.0, 0.0)),
    ((-300.5, 411.25), (50.125, -91.75)),
    ((20.5, -40.25), (20.5, -40.25)),
)
DIRECTION = {
    "projectile->pos_x - projectile->pos.origin_x": "projectile->pos.origin_x - projectile->pos_x",
    "projectile->pos.pos_y - primary->origin_y": "primary->origin_y - projectile->pos.pos_y",
}
ANCHOR = {
    "float base_x = camera_offset_x + projectile->pos.origin_x": "float base_x = camera_offset_x + projectile->pos_x",
    "float base_y = camera_offset_y + primary->origin_y": "float base_y = camera_offset_y + projectile->pos.pos_y",
}


def defect_source(source, changes):
    prefix, beam = source.split("        if (!(type_id == PROJECTILE_TYPE_ION_MINIGUN", 1)
    for old, new in changes.items():
        assert beam.count(old) == 2
        beam = beam.replace(old, new)
    return prefix + "        if (!(type_id == PROJECTILE_TYPE_ION_MINIGUN" + beam


def execute(program, native, type_id, life, alpha, glow, geometry):
    position, origin = geometry
    return probe.run(
        program,
        native,
        type_id,
        life,
        alpha,
        glow,
        position=position,
        origin=origin,
        beam_stubs=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert probe.unicorn.__version__ == "2.1.4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / probe.FUNCTION)
    source = (config.directory / config.source).read_text()
    current = probe.Program(config)
    md = probe.capstone.Cs(probe.capstone.CS_ARCH_X86, probe.capstone.CS_MODE_32)
    instructions = {
        i.address: i
        for i in md.disasm(current.image.function_bytes(current.native_start, current.native_end), current.native_start)
    }
    expected = {
        0x424184: ("mov", f"ebx, {hex(current.address('projectile_pool') + 0x14)}"),
        0x424500: ("fld", "dword ptr [ebx - 0xc]"),
        0x424503: ("fsub", "dword ptr [ebx - 4]"),
        0x424512: ("fld", "dword ptr [ebx - 8]"),
        0x424515: ("fsub", "dword ptr [ebx]"),
        0x424838: ("fld", "dword ptr [ebx - 0xc]"),
        0x42483B: ("fsub", "dword ptr [ebx - 4]"),
        0x42484A: ("fld", "dword ptr [ebx - 8]"),
        0x42484D: ("fsub", "dword ptr [ebx]"),
        0x4245CB: ("fadd", "dword ptr [ebx - 4]"),
        0x4245E2: ("fadd", "dword ptr [ebx]"),
        0x4248F9: ("fadd", "dword ptr [ebx - 4]"),
        0x424910: ("fadd", "dword ptr [ebx]"),
    }
    native_operations = []
    for address, (mnemonic, operands) in expected.items():
        ins = instructions[address]
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands)
        native_operations.append(
            {"address": hex(address), "bytes": bytes(ins.bytes).hex(), "instruction": f"{mnemonic} {operands}"},
        )
    previous_source = defect_source(source, DIRECTION | ANCHOR)
    assert probe.sha(previous_source.encode()) == "52f67505883446b91934c6e9af420ba7626cdc8c75e82a16b6cdfa5c23e21f33"
    defects = {}
    for name, changes in (("direction", DIRECTION), ("anchor", ANCHOR), ("previous", DIRECTION | ANCHOR)):
        directory = out / name
        directory.mkdir(exist_ok=True)
        text = defect_source(source, changes)
        (directory / config.source).write_text(text)
        defects[name] = probe.Program(replace(config, directory=directory))
    rows = []
    examples = {}
    for geometry_index, geometry in enumerate(GEOMETRIES):
        for type_id in TYPES:
            for life in (0.4, 0.2, 1.2, -0.1):
                for alpha in (0.2, 0.7, 1.5):
                    for glow in (0, 1):
                        native = execute(current, True, type_id, life, alpha, glow, geometry)
                        candidate = execute(current, False, type_id, life, alpha, glow, geometry)
                        assert native["calls"] == candidate["calls"], (geometry_index, type_id, life, alpha, glow)
                        assert native["state_sha256"] == candidate["state_sha256"]
                        normalizations = [args for name, args in native["calls"] if name == "D3DXVec2Normalize"]
                        position, origin = geometry
                        # Independent argument oracle: the vector points from origin to head.
                        assert normalizations == [
                            [probe.bits(position[0] - origin[0]), probe.bits(position[1] - origin[1])],
                        ]
                        rows.append(
                            {
                                "geometry": geometry_index,
                                "type_id": type_id,
                                "life": life,
                                "transition_alpha": alpha,
                                "glow": glow,
                                "calls": len(native["calls"]),
                                "call_trace_sha256": probe.sha(json.dumps(native["calls"]).encode()),
                                "projectile_state_sha256": native["state_sha256"],
                                "native_instructions_exercised": native["coverage"],
                                "candidate_instructions_exercised": candidate["coverage"],
                            },
                        )
                        if geometry_index == 0 and type_id == 21 and alpha == 0.7 and glow == 0 and life in (0.4, 0.2):
                            examples[str(life)] = native
    negatives = []
    for name, program in defects.items():
        for type_id in TYPES:
            for life in (0.4, 0.2):
                native = execute(current, True, type_id, life, 0.7, 0, GEOMETRIES[0])
                wrong = execute(program, False, type_id, life, 0.7, 0, GEOMETRIES[0])
                differences = [
                    i for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b
                ]
                assert differences
                i = differences[0]
                assert native["calls"][i][0] == ("grim_draw_quad" if name == "anchor" else "D3DXVec2Normalize")
                negatives.append(
                    {
                        "defect": name,
                        "type_id": type_id,
                        "life": life,
                        "differing_calls": len(differences),
                        "first_difference": i,
                        "native": native["calls"][i],
                        "wrong": wrong["calls"][i],
                        "native_return_site": hex(native["return_sites"][i]),
                    },
                )
    result = current.result
    previous = defects["previous"].result
    assert not result.exact and not result.body_byte_exact
    assert result.ratio == previous.ratio
    assert len(result.candidate_lines) == len(previous.candidate_lines) == 2903
    assert result.masked_operand_audit.ok_count == previous.masked_operand_audit.ok_count == 456
    assert result.masked_operand_audit.problem_count == previous.masked_operand_audit.problem_count == 11
    record = {
        "schema_version": 1,
        "kind": "native-beam-direction-and-anchor",
        "new_source_matches": 0,
        "source_sha256": probe.sha(source.encode()),
        "previous_source_sha256": probe.sha(previous_source.encode()),
        "verifier_sha256": probe.sha(Path(__file__).read_bytes()),
        "engine_sha256": probe.sha(ENGINE.read_bytes()),
        "unicorn_version": probe.unicorn.__version__,
        "image_sha256": probe.sha(match.default_image_path().read_bytes()),
        "native_body_sha256": probe.sha(current.image.function_bytes(current.native_start, current.native_end)),
        "candidate_object_sha256": probe.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": probe.sha(current.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "relocations": current.relocations,
        "defects": {
            name: {
                "source_sha256": probe.sha((p.config.directory / p.config.source).read_bytes()),
                "body_sha256": probe.sha(p.body.data),
            }
            for name, p in defects.items()
        },
        "native_operations": native_operations,
        "geometries": GEOMETRIES,
        "fixtures": rows,
        "negative_controls": negatives,
        "examples": examples,
        "metrics": {
            "ratio": result.ratio,
            "candidate_instructions": 2903,
            "target_instructions": 3021,
            "references_ok": 456,
            "reference_problems": 11,
            "exact": False,
            "body_byte_exact": False,
        },
        "boundaries": {
            "grim": "recording thiscall stubs; initialized config id and value only",
            "D3DXVec2Normalize": "record input vector bits; shared binary64 sqrt/divide with float32 output model; external DLL not executed",
            "creature_find_in_radius": "record input position/radius/start index; always return -1; no chain arcs exercised",
            "effect_select_texture": "recording no-op",
            "perk_count_get": "recording zero result",
            "other_math": "machine x87 instructions and native crt_ftol",
            "x87_control_word": "0x037f",
            "state": "one primary, no players or secondary projectiles, fixed camera/angle/speed; no non-stack writes",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(
        f"{len(rows)} beam fixtures agree; {len(negatives)} compiled direction/anchor defects rejected; no exact match claimed.",
    )


if __name__ == "__main__":
    main()
