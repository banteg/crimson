"""Execute only profile-label argument preparation against a rational oracle."""

import argparse
import json
import struct
from fractions import Fraction
from pathlib import Path

import unicorn
from controls import HERE, build, sha
from unicorn import x86_const as x86

from crimson import match

CODE, STACK, FAKE = 0x1000000, 0x2000000, 0x3000000
NSTART, NEND = 0x44340B, 0x44342D
IMAGE = match.load_image(match.default_image_path())
WINDOWS = {-1: (0xFDD, 0xFF9, 0x20), 0: (0x1033, 0x105D, 0x1C), 3: (0x1033, 0x1055, 0x34)}


def prepare(root, mode):
    if mode == -1:
        cfg, obj, _, _, _ = build("canonical", root / "controls")
    else:
        cfg = match.load_scratch_config(root / "controls/baseline")
        folder = root / "preserving/observed" if mode == 0 else root / f"deny-{mode}"
        obj = folder / "replay.obj"
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    proof = json.loads((root / "results.json").read_text())
    if mode != -1:
        assert sha(body.data) == proof["results"][str(mode)]["body_sha256"]
    r = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    start, end, y = WINDOWS[mode]
    refmap = {}
    for row in r.target_disassembly:
        if NSTART <= row.address < NEND or (mode == -1 and row.address == 0x442A6A):
            for ref in row.masked_references:
                for key in ref.keys:
                    refmap.setdefault(key, set()).add(ref.value)
    patched = bytearray(body.data)
    records = []
    for row in r.candidate_disassembly:
        if not start <= row.offset < end:
            continue
        local = [v for v in body.relocation_references if row.offset <= v.offset < row.offset + row.size]
        assert len(local) == len(row.masked_references)
        for reloc, ref in zip(local, row.masked_references, strict=True):
            values = {int(k[8:], 16) for k in ref.keys if k.startswith("address:")}
            if not values:
                values = set().union(*(refmap.get(k, set()) for k in ref.keys))
            assert len(values) == 1, (row, values)
            addr = values.pop()
            assert reloc.relocation_type == 6
            struct.pack_into("<I", patched, reloc.offset, addr)
            records.append((reloc.offset, addr))
    assert [v[1] for v in records] == (
        [0x48083C, 0x478B70, 0x46F2C4] if mode == -1 else [0x46F6E0, 0x48083C, 0x478B70, 0x46F280]
    )
    assert IMAGE.mapped[0x46F2C4 - IMAGE.image_base : 0x46F2C8 - IMAGE.image_base] == struct.pack("<f", 100.0)
    return bytes(patched), (CODE + start, CODE + end, y), records, sha(body.data)


def audit_window(payload):
    """All 34 bytes must equal native after four relocations and one stack binding."""
    code, (start, end, y), _, _ = payload
    window = bytearray(code[start - CODE : end - CODE])
    assert y == 0x34 and window[:3] == b"\xd9\x44\x24" and window[3] == y
    window[3] = 0x20
    native = IMAGE.mapped[NSTART - IMAGE.image_base : NEND - IMAGE.image_base]
    assert window == native
    return {
        "native_window": [NSTART, NEND],
        "candidate_window": [start - CODE, end - CODE],
        "bytes": len(window),
        "candidate_y_displacement": y,
        "native_y_displacement": 0x20,
        "normalized_window_sha256": sha(window),
    }


class Runner:
    def __init__(self, payload=None):
        self.mu = m = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        m.mem_map(IMAGE.image_base, (len(IMAGE.mapped) + 4095) & ~4095)
        m.mem_write(IMAGE.image_base, IMAGE.mapped)
        m.mem_map(CODE, 0x10000)
        m.mem_map(STACK, 0x10000)
        m.mem_map(FAKE, 0x1000)
        m.mem_write(0x48083C, struct.pack("<I", FAKE))
        m.mem_write(FAKE, struct.pack("<I", FAKE + 0x100))
        self.window = (NSTART, NEND, 0x20)
        if payload:
            m.mem_write(CODE, payload[0])
            self.window = payload[1]

    def run(self, bits, cw):
        m = self.mu
        sp = STACK + 0x8000
        m.mem_write(sp - 0x100, b"\xa5" * 0x300)
        for r in (
            x86.UC_X86_REG_EAX,
            x86.UC_X86_REG_EBX,
            x86.UC_X86_REG_ECX,
            x86.UC_X86_REG_EDX,
            x86.UC_X86_REG_EBP,
            x86.UC_X86_REG_ESI,
            x86.UC_X86_REG_EDI,
        ):
            m.reg_write(r, 0x41A00000)
        m.reg_write(x86.UC_X86_REG_ESP, sp)
        m.reg_write(x86.UC_X86_REG_FPCW, cw)
        m.reg_write(x86.UC_X86_REG_FPSW, 0)
        m.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        m.mem_write(sp + self.window[2], struct.pack("<I", bits))
        m.emu_start(self.window[0], self.window[1], count=100)
        assert m.reg_read(x86.UC_X86_REG_EIP) == self.window[1]
        assert m.reg_read(x86.UC_X86_REG_ESP) == sp - 12
        args = struct.unpack("<3I", m.mem_read(sp - 12, 12))
        assert args[0] == 0x41A00000 and args[2] == 0x478B70
        assert m.reg_read(x86.UC_X86_REG_ECX) == FAKE and m.reg_read(x86.UC_X86_REG_EAX) == FAKE + 0x100
        assert m.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
        return args[1]


def bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def round_binary(value, precision, rounding):
    """Exact finite binary rounding, including directed modes; no host-FPU oracle."""
    if value == 0:
        return value
    sign = -1 if value < 0 else 1
    absolute = abs(value)
    exponent = absolute.numerator.bit_length() - absolute.denominator.bit_length()
    if absolute < Fraction(2) ** exponent:
        exponent -= 1
    step = Fraction(2) ** (exponent - precision + 1)
    if precision == 24:
        step = max(step, Fraction(2) ** -149)
    scaled = absolute / step
    quotient, remainder = divmod(scaled.numerator, scaled.denominator)
    if rounding == 0:
        twice = remainder * 2
        up = twice > scaled.denominator or (twice == scaled.denominator and quotient & 1)
    elif rounding in (1, 2):
        up = remainder != 0 and sign == (-1 if rounding == 1 else 1)
    else:
        assert rounding == 3
        up = False
    return sign * (quotient + bool(up)) * step


def oracle(value, precision, rounding, spill, folded=False):
    y = Fraction.from_float(struct.unpack("<f", struct.pack("<I", value))[0])
    if folded:
        total = round_binary(y + 100, precision, rounding)
    else:
        total = round_binary(y + 114, precision, rounding)
        if spill:
            total = round_binary(total, 24, rounding)
        total = round_binary(total - 14, precision, rounding)
    result = round_binary(total, 24, rounding)
    # Exact cancellation has a negative zero only in round-toward-minus-infinity.
    return 0x80000000 if result == 0 and rounding == 1 else bits(float(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler-proof", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root, out = args.compiler_proof.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    prepared = {i: prepare(root, i) for i in (-1, 0, 3)}
    window = audit_window(prepared[3])
    runners = {"native": Runner(), **{str(i): Runner(v) for i, v in prepared.items()}}
    fixtures = sorted(
        {
            bits(v) + d
            for v in (
                0.0,
                0.5,
                1.0,
                2.0,
                4.0,
                8.0,
                14.0,
                15.0,
                16.0,
                32.0,
                64.0,
                100.0,
                114.0,
                128.0,
                256.0,
                512.0,
                1024.0,
                -1.0,
                -8.0,
                -14.0,
                -15.0,
                -16.0,
                -64.0,
                -100.0,
                -114.0,
                -128.0,
                -256.0,
            )
            for d in range(-4, 5)
            if 0 <= bits(v) + d < 0xFF800000
        },
    )
    results = {}
    for pc, precision in ((0, 24), (2, 53), (3, 64)):
        for rounding in range(4):
            cw = 0x7F | pc << 8 | rounding << 10
            mismatches, canonical_mismatches, outputs = [], [], []
            for f in fixtures:
                actual = {k: v.run(f, cw) for k, v in runners.items()}
                expected = oracle(f, precision, rounding, False)
                assert actual["native"] == actual["3"] == expected, (cw, hex(f), actual, hex(expected))
                assert actual["0"] == oracle(f, precision, rounding, True), (cw, hex(f), actual)
                assert actual["-1"] == oracle(f, precision, rounding, False, folded=True), (cw, hex(f), actual)
                outputs.append(actual)
                if actual["native"] != actual["0"]:
                    mismatches.append({"input": hex(f), **{k: hex(v) for k, v in actual.items()}})
                if actual["native"] != actual["-1"]:
                    canonical_mismatches.append({"input": hex(f), **{k: hex(v) for k, v in actual.items()}})
            results[hex(cw)] = {
                "precision": precision,
                "rounding": rounding,
                "fixtures": len(fixtures),
                "mismatch_count": len(mismatches),
                "examples": mismatches[:4],
                "canonical_mismatch_count": len(canonical_mismatches),
                "canonical_examples": canonical_mismatches[:4],
                "outputs_sha256": sha(json.dumps(outputs).encode()),
            }
    assert [results[hex(cw)]["mismatch_count"] for cw in (0x7F, 0x27F, 0x37F)] == [0, 2, 2]
    assert results["0x7f"]["canonical_mismatch_count"] > 0
    damaged = list(prepared[3])
    code = bytearray(damaged[0])
    code[WINDOWS[3][0] + 1] ^= 1
    damaged[0] = bytes(code)
    try:
        audit_window(damaged)
    except AssertionError:
        pass
    else:
        raise AssertionError("Changed instruction accepted by byte audit")
    wrong_constant = Runner()
    wrong_constant.mu.mem_write(0x46F6E0, struct.pack("<f", 112.0))
    assert wrong_constant.run(0x41800003, 0x27F) != oracle(0x41800003, 53, 0, False)
    wrong_stack = Runner(prepared[3])
    wrong_stack.window = (*wrong_stack.window[:2], 0x20)
    assert wrong_stack.run(0x41800003, 0x27F) != oracle(0x41800003, 53, 0, False)
    result = {
        "schema": 1,
        "scope": "profile-label-arguments-only-stop-before-call",
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "fixtures_sha256": sha(json.dumps(fixtures).encode()),
        "window": window,
        "control_words": results,
        "total_fixtures": len(fixtures) * len(results),
        "corruptions_rejected": ["changed-instruction", "wrong-constant", "wrong-stack-binding"],
        "compiled": {str(k): {"body_sha256": v[3], "relocations": v[2]} for k, v in prepared.items()},
        "compiler_proof_sha256": sha((root / "results.json").read_bytes()),
        "input_hashes": {n: sha((HERE / n).read_bytes()) for n in ("controls.py", "verify_execution.py")},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", result["total_fixtures"], "finite label fixtures against native and rational oracle", flush=True)


if __name__ == "__main__":
    main()
