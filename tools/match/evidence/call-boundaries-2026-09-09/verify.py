"""Inventory original/candidate call boundaries without claiming dynamic equivalence."""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def call_key(instruction):
    if instruction.masked_references:
        assert len(instruction.masked_references) == 1
        reference = instruction.masked_references[0]
        addresses = [key for key in reference.keys if key.startswith("address:")]
        assert reference.explained and len(addresses) == 1
        return addresses[0]
    # This is only an operand shape, not proof of receiver identity or vtable type.
    assert re.fullmatch(r"call dword \[(eax|ecx|edx|ebp)\+0x[0-9a-f]+\]", instruction.text)
    return re.sub(r"\b(eax|ecx|edx|ebp)\b", "REG", instruction.text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in ("player_update", "projectile_update", "projectile_render"):
        config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / name)
        obj = match.compile_scratch(config)
        result = match.run_match(
            obj_path=obj,
            function=name,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        calls = [
            [instruction for instruction in instructions if instruction.text.startswith("call ")]
            for instructions in (result.target_disassembly, result.candidate_disassembly)
        ]
        keys = [[call_key(instruction) for instruction in instructions] for instructions in calls]
        counts = [Counter(side) for side in keys]
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        row = {
            "function": name,
            "source_sha256": sha((config.directory / config.source).read_bytes()),
            "candidate_body_sha256": sha(body.data),
            "native_calls": len(calls[0]),
            "candidate_calls": len(calls[1]),
            "linear_call_keys_equal": keys[0] == keys[1],
            "native_only_counts": dict(counts[0] - counts[1]),
            "candidate_only_counts": dict(counts[1] - counts[0]),
            "counts": [dict(sorted(count.items())) for count in counts],
        }
        if name == "projectile_render":
            # Three consecutive native calls bracket the recovered color publication.
            native_window = [
                instruction for instruction in result.target_disassembly if 0x424AAE <= instruction.address <= 0x424B11
            ]
            assert [instruction.address for instruction in native_window if instruction.text.startswith("call ")] == [
                0x424AAE,
                0x424AF3,
                0x424B11,
            ]
            assert [call_key(instruction) for instruction in native_window if instruction.text.startswith("call ")] == [
                "call dword [REG+0x114]",
                "call dword [REG+0x11c]",
                "call dword [REG+0x114]",
            ]
            row["native_head_call_window"] = [
                {"address": instruction.address, "text": instruction.text} for instruction in native_window
            ]
            source = (config.directory / config.source).read_text()
            begin = source.index("            float head_alpha = fade * transition_alpha;")
            end = source.index("            if (type_id != PROJECTILE_TYPE_FIRE_BULLETS)", begin)
            window = source[begin:end]
            assert window.count("grim_set_color(") == 2 and window.count("grim_draw_quad(") == 1
            row["candidate_head_color_calls"] = 2
            row["native_head_color_calls"] = 2
        rows.append(row)
    assert rows[0]["candidate_only_counts"] == {"address:0x0041fbb0": 1}
    assert not rows[0]["native_only_counts"]
    assert rows[1]["linear_call_keys_equal"] and rows[1]["native_calls"] == 125
    assert rows[2]["native_only_counts"] == {"call dword [REG+0x114]": 1}
    assert rows[2]["candidate_only_counts"] == {"call dword [REG+0x11c]": 1}
    callees = []
    for name in ("grim_set_color", "grim_draw_quad", "grim_begin_batch", "grim_flush_batch"):
        config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / name)
        result = match.run_match(
            obj_path=match.compile_scratch(config),
            function=name,
            image_path=match.default_image_path(config.image),
            functions_path=match.default_functions_path(config.image),
            metadata_path=match.default_metadata_path(config.image),
            symbol_name=config.symbol,
        )
        assert result.exact and result.body_byte_exact and result.masked_operand_audit.problem_count == 0
        callees.append(
            {
                "function": name,
                "source_sha256": sha((config.directory / config.source).read_bytes()),
                "exact": result.exact,
                "body_byte_exact": result.body_byte_exact,
            },
        )
    payload = {
        "schema": 1,
        "verified": True,
        "caveat": "Static calls in linear instruction order, not dynamic traces. Counts and direct callee identity "
        "do not prove argument, receiver, path, or side-effect equivalence. Indirect keys mask only the register name.",
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "grim_image_sha256": sha(match.default_image_path("grim.dll").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "functions": rows,
        "reviewed_grim_callees": callees,
    }
    (out / "comparison.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(out / "comparison.json")


if __name__ == "__main__":
    main()
