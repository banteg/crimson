"""Reproduce network argument-preparation witnesses and independent VC6 controls."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path

import capstone

from crimson import match, match_micro_oracle
from crimson.match_micro_oracle import evaluate_window

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def window(instructions, start, end):
    rows = instructions[start:end]
    texts = []
    for row in rows:
        text = row.text
        if "ADDR" in text:
            assert len(row.masked_references) == 1
            reference = row.masked_references[0]
            assert reference.explained and "address:0x004d11f4" in reference.keys
            assert text == "mov dword [ADDR], eax"
            text = text.replace("ADDR", "@update_notice_url")
        texts.append(text)
    return {"start_offset": rows[0].offset, "instructions": texts, "effects": asdict(evaluate_window(texts))}


def witness(name, target, candidate):
    effects = [evaluate_window(side["instructions"]) for side in (target, candidate)]
    assert effects[0].call_inputs() == effects[1].call_inputs()
    return {"name": name, "same_projected_call_inputs": True, "native": target, "candidate": candidate}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    witnesses = []
    sources = []
    for name in ("statistics_update_check_worker", "highscore_sync_worker"):
        config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / name)
        obj = match.compile_scratch(config)
        result = match.run_match(
            obj_path=obj, function=name, symbol_name=config.symbol, reference_aliases=config.reference_aliases,
        )
        assert not result.exact and not result.body_byte_exact
        assert result.masked_operand_audit.problem_count == 0
        native, candidate = result.target_disassembly, result.candidate_disassembly
        if name == "statistics_update_check_worker":
            assert result.prefix_instructions == 252
            assert result.target_lines[:252] == result.candidate_lines[:252]
            assert result.target_lines[259:] == result.candidate_lines[259:]
            assert list(result.target_lines[259:262]) == ["push ADDR", "push edi", "call ADDR"]
            # The trailing format/text pushes do not consume EAX, ECX, or EDX.
            assert "address:0x00462ba0" in native[261].masked_references[0].keys
            assert "address:0x00462ba0" in candidate[261].masked_references[0].keys
            witnesses.append(witness("version-output-arguments", window(native, 252, 259), window(candidate, 252, 259)))
        else:
            assert result.prefix_instructions == 340
            assert "address:0x0046f1c0" in native[346].masked_references[0].keys
            assert "address:0x0046f1c0" in candidate[346].masked_references[0].keys
            witnesses.append(witness("response-query-arguments", window(native, 340, 346), window(candidate, 340, 346)))
            assert native[466].text == candidate[466].text == "test eax, eax"
            assert native[467].text.startswith("je ") and candidate[467].text.startswith("je ")
            assert native[469].text == candidate[470].text == "call edi"
            assert native[467].text == f"je L{native[470].offset:x}"
            assert candidate[467].text == f"je L{candidate[471].offset:x}"
            assert native[464].text == candidate[464].text == "mov edi, dword [ADDR]"
            for side in (native, candidate):
                assert "address:0x0046f1cc" in side[464].masked_references[0].keys
            # A separate local witness on the non-null request path; no claim of
            # whole-function path equivalence or equality of incoming states.
            witnesses.append(
                witness("non-null-request-close-argument", window(native, 468, 469), window(candidate, 468, 470)),
            )
        function = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), config.symbol)
        sources.append(
            {
                "function": name,
                "source_sha256": sha((config.directory / config.source).read_bytes()),
                "candidate_body_sha256": sha(function.data),
                "body_byte_exact": result.body_byte_exact,
            },
        )

    # Executable negative control: swapped stack arguments must not pass.
    correct = witnesses[0]["native"]["instructions"]
    wrong = correct[:-2] + [correct[-1], correct[-2]]
    assert evaluate_window(correct).call_inputs() != evaluate_window(wrong).call_inputs()

    shutil.copyfile(HERE / "controls.cpp", out / "controls.cpp")
    environment = dict(os.environ, MSVC_VER=config.compiler)
    environment.pop("CRIMSON_MATCH_INCLUDE_OVERLAY", None)
    subprocess.run(
        [
            str(match.DEFAULT_MATCH_ROOT / "cl.sh"),
            "/c",
            "/O2",
            "/GB",
            "/W3",
            "/GR-",
            "/FAsc",
            "/Facontrols.cod",
            "controls.cpp",
        ],
        cwd=out,
        env=environment,
        capture_output=True,
        check=True,
    )
    obj = match.parse_coff_object((out / "controls.obj").read_bytes())
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    controls = []
    for name in ("array_outputs", "scalar_outputs", "close_local", "query_outputs"):
        body = match.extract_object_function(obj, "_" + name)
        decoded = list(decoder.disasm(body.data, 0))
        assert sum(x.size for x in decoded) == len(body.data)
        if name in ("array_outputs", "scalar_outputs"):
            # Both tiny forms naturally select the native first LEA/register.
            assert decoded[5].mnemonic == "lea" and decoded[5].op_str.startswith("ecx, ")
            assert decoded[6].mnemonic == "mov" and decoded[6].op_str.endswith(", eax")
            assert decoded[7].mnemonic == "lea" and decoded[7].op_str.startswith("edx, ")
        controls.append(
            {
                "function": name,
                "body_sha256": sha(body.data),
                "instructions": [x.mnemonic + " " + x.op_str for x in decoded],
            },
        )
    payload = {
        "schema": 1,
        "verified": True,
        "kind": "bounded-symbolic-call-input-witnesses",
        "limitations": "Straight-line local windows only, with equal incoming symbolic states. Stack-call projection assumes EAX/ECX/EDX are volatile and not inputs. Does not establish full-function equivalence, source provenance, matching exactness, memory safety, or operating-system behavior.",
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "oracle_sha256": sha(Path(match_micro_oracle.__file__).read_bytes()),
        "control_source_sha256": sha((HERE / "controls.cpp").read_bytes()),
        "compiler_sha256": sha(match._compiler_executable_path(config, match.DEFAULT_MATCH_ROOT).read_bytes()),
        "sources": sources,
        "witnesses": witnesses,
        "wrong_argument_order_rejected": True,
        "compiler_controls": controls,
    }
    (out / "comparison.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(out / "comparison.json")


if __name__ == "__main__":
    main()
