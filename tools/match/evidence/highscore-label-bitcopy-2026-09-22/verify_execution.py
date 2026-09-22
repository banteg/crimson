"""Execute the stock score row and both label setups against native and oracles."""

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from fractions import Fraction
from pathlib import Path

from controls import HERE, WITNESS, build, sha
from unicorn import x86_const as x86
from verify import IMAGE_SHA, WINDOWS, audit

from crimson import match


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROW = HERE.parent / "highscore-prefix-lifetime-2026-09-22"
FLOAT = HERE.parent / "highscore-float-reuse-2026-09-22"
sys.modules["region"] = load("row_region", ROW / "region.py")
row_model = load("row_execution", ROW / "verify_execution.py")
float_model = load("float_execution", FLOAT / "verify_execution.py")
CODE, STACK = row_model.CODE, row_model.STACK


class LabelRunner(float_model.Runner):
    def __init__(self, code, label):
        ns, ne, cs, ce = WINDOWS[label + "-label"]
        payload = None if code is None else (code, (CODE + cs, CODE + ce, 0x20))
        super().__init__(payload)
        if code is None:
            self.window = (ns, ne, 0x20)
        self.label_address = 0x478B70 if label == "profile" else 0x478B40

    def run(self, bits, cw, xbits):
        m = self.mu
        sp = STACK + 0x8000
        m.mem_write(sp - 0x100, b"\xa5" * 0x300)
        for reg in (
            x86.UC_X86_REG_EAX,
            x86.UC_X86_REG_EBX,
            x86.UC_X86_REG_ECX,
            x86.UC_X86_REG_EDX,
            x86.UC_X86_REG_EBP,
            x86.UC_X86_REG_ESI,
            x86.UC_X86_REG_EDI,
        ):
            m.reg_write(reg, xbits)
        m.reg_write(x86.UC_X86_REG_ESP, sp)
        m.reg_write(x86.UC_X86_REG_FPCW, cw)
        m.reg_write(x86.UC_X86_REG_FPSW, 0)
        m.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        m.mem_write(sp + self.window[2], struct.pack("<I", bits))
        m.emu_start(self.window[0], self.window[1], count=100)
        assert m.reg_read(x86.UC_X86_REG_EIP) == self.window[1]
        assert m.reg_read(x86.UC_X86_REG_ESP) == sp - 12
        args = struct.unpack("<3I", m.mem_read(sp - 12, 12))
        assert args[0] == xbits and args[2] == self.label_address
        assert m.reg_read(x86.UC_X86_REG_ECX) == float_model.FAKE
        assert m.reg_read(x86.UC_X86_REG_EAX) == float_model.FAKE + 0x100
        assert m.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
        return args[1]


def label_oracle(value, precision, rounding, addition):
    y = Fraction.from_float(struct.unpack("<f", struct.pack("<I", value))[0])
    total = float_model.round_binary(y + addition, precision, rounding)
    total = float_model.round_binary(total - 14, precision, rounding)
    total = float_model.round_binary(total, 24, rounding)
    return 0x80000000 if total == 0 and rounding == 1 else float_model.bits(float(total))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    _, _, body, r, measured = build(WITNESS, out / "controls")
    image = match.load_image(match.default_image_path())
    audits = {k: audit(body, r.target_disassembly, r.candidate_disassembly, w, image) for k, w in WINDOWS.items()}
    patched = bytearray(body.data)
    relocations = {}
    for proof in audits.values():
        for ref in proof["relocations"]:
            offset, address, kind = ref["offset"], ref["address"], ref["kind"]
            old = relocations.setdefault(offset, (address, kind))
            assert old == (address, kind)
    for offset, (address, kind) in relocations.items():
        value = address if kind == 6 else (address - (CODE + offset + 4)) & 0xFFFFFFFF
        struct.pack_into("<I", patched, offset, value)
    code = bytes(patched)
    # The exact native row needs neither register renaming nor stack substitutions.
    row_window = (0x77D, 0x8A9, 0x4C, 0x14)
    runners = {"native": row_model.Runner(), "witness": row_model.Runner(code, row_window)}
    cases = [(1, flags, mode, 1001, 0x80000000) for flags in range(256) for mode in (1, 2, 3, 5)]
    for mode in (-1, 0, 1, 2, 3, 4, 5, 6):
        for value in (1, 999, 1000, 1001, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF):
            cases.extend((2, flags, mode, value, value) for flags in range(8))
    cases.extend(
        (n, flags, mode, 0xFFFFFFFF, 0x7FFFFFFE)
        for n in (0, 1, 2, 99, 100)
        for mode in (1, 2, 3, 5)
        for flags in (0, 5)
    )
    row_hashes = {name: hashlib.sha256() for name in runners}
    for i, case in enumerate(cases):
        expected = row_model.oracle(case)
        actual = {name: runner.run(case) for name, runner in runners.items()}
        assert actual["native"] == actual["witness"], case
        for name, value in actual.items():
            assert value[:5] == expected, case
            row_hashes[name].update(repr((value[:3], sha(value[3]), sha(value[4]), value[5])).encode())
        if (i + 1) % 500 == 0:
            print("Verified", i + 1, "row fixtures", flush=True)
    bits = float_model.bits
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
                56.0,
                64.0,
                70.0,
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
                -56.0,
                -64.0,
                -70.0,
                -100.0,
                -114.0,
                -128.0,
                -256.0,
            )
            for d in range(-4, 5)
            if 0 <= bits(v) + d < 0xFF800000
        },
    )
    label_results = {}
    for label, addition in (("profile", 114), ("date", 70)):
        native, candidate = LabelRunner(None, label), LabelRunner(code, label)
        results = {}
        for pc, precision in ((0, 24), (2, 53), (3, 64)):
            for rounding in range(4):
                cw = 0x7F | pc << 8 | rounding << 10
                digest = hashlib.sha256()
                for f in fixtures:
                    expected = label_oracle(f, precision, rounding, addition)
                    for xbits in (0x41A00000, 0x80000000, 0x7FC12345):
                        a, b = native.run(f, cw, xbits), candidate.run(f, cw, xbits)
                        assert a == b == expected, (label, cw, f, a, b, expected)
                        digest.update(struct.pack("<4I", f, xbits, a, b))
                results[hex(cw)] = {
                    "precision": precision,
                    "rounding": rounding,
                    "y_inputs": len(fixtures),
                    "x_inputs": 3,
                    "outputs_sha256": digest.hexdigest(),
                }
        label_results[label] = results
        print("Verified", label, "label for all 12 x87 modes", flush=True)
    rejected = []
    for label, offset, before, after, fixture in (
        ("wrong-prefix-mask", 0x7D7, b"\x05", b"\x01", (1, 4, 1, 1001, 7)),
        ("unsigned-division-shift", 0x80D, b"\xfa", b"\xea", (1, 0, 2, 0x80000000, 7)),
        (
            "ninety-nine-row-limit",
            0x893,
            struct.pack("<I", row_model.BUFFERS + 16400),
            struct.pack("<I", row_model.BUFFERS + 16236),
            (100, 0, 1, 1001, 7),
        ),
    ):
        assert code[offset : offset + len(before)] == before
        bad = bytearray(code)
        bad[offset : offset + len(before)] = after
        assert row_model.Runner(bytes(bad), row_window).run(fixture)[:5] != row_model.oracle(fixture)
        rejected.append(label)
    for label, address, wrong, addition in (("profile", 0x46F6E0, 112.0, 114), ("date", 0x46F4C0, 68.0, 70)):
        runner = LabelRunner(code, label)
        runner.mu.mem_write(address, struct.pack("<f", wrong))
        assert runner.run(0x41800003, 0x27F, 0x41A00000) != label_oracle(0x41800003, 53, 0, addition)
        rejected.append(label + "-wrong-constant")
    dependencies = [ROW / "region.py", ROW / "verify_execution.py", FLOAT / "verify_execution.py"]
    result = {
        "schema": 1,
        "scope": "score-row-and-two-label-argument-windows-only",
        "image_sha256": IMAGE_SHA,
        "compiled": measured,
        "audits": audits,
        "row_fixtures": len(cases),
        "row_fixture_sha256": sha(json.dumps(cases).encode()),
        "row_outputs_sha256": {name: value.hexdigest() for name, value in row_hashes.items()},
        "label_y_fixture_sha256": sha(json.dumps(fixtures).encode()),
        "label_control_words": label_results,
        "label_fixtures": 2 * len(fixtures) * 12 * 3,
        "corruptions_rejected": rejected,
        "input_hashes": {
            n: sha((HERE / n).read_bytes())
            for n in ("controls.py", "controls.json", "verify.py", "verify_execution.py")
        },
        "dependency_hashes": {str(p.relative_to(HERE.parent)): sha(p.read_bytes()) for p in dependencies},
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(
        "Verified", result["row_fixtures"], "row fixtures and", result["label_fixtures"], "label fixtures", flush=True,
    )


if __name__ == "__main__":
    main()
