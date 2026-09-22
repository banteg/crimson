"""Execute saved-state restoration and check ordered writes against an oracle."""

import argparse
import hashlib
import itertools
import json
import struct
from pathlib import Path

from controls import HERE, WITNESS, build, sha, sources
from unicorn import UC_ARCH_X86, UC_HOOK_MEM_WRITE, UC_MODE_32, Uc
from unicorn import x86_const as x86
from verify import IMAGE_SHA, NBASE, audit

from crimson import match

CODE, STACK = 0x10000000, 0x20000000
START, END = 0xD88, 0xDD5
INPUTS = ((0x487250, 4), (0x487254, 4), (0x487258, 4), (0x48725C, 1))
OUTPUTS = ((0x487008, 4), (0x487004, 4), (0x48727C, 1), (0x480360, 4), (0x480790, 1), (0x48724C, 1), (0x487274, 4))
SAVED = (x86.UC_X86_REG_EBX, x86.UC_X86_REG_EBP, x86.UC_X86_REG_ESI, x86.UC_X86_REG_EDI)


class Runner:
    def __init__(self, image, code=None):
        self.mu = m = Uc(UC_ARCH_X86, UC_MODE_32)
        m.mem_map(image.image_base, (len(image.mapped) + 4095) & ~4095)
        m.mem_write(image.image_base, bytes(image.mapped))
        m.mem_map(STACK, 0x10000)
        self.base = NBASE
        if code is not None:
            m.mem_map(CODE, (len(code) + 4095) & ~4095)
            m.mem_write(CODE, code)
            self.base = CODE
        m.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.events = []

    def write(self, _m, _access, address, size, value, _user):
        assert (address, size) in OUTPUTS
        # Unicorn may report the full source register for a byte store. Check
        # the architectural write width and read back every output below.
        self.events.append((address, size, value & ((1 << (8 * size)) - 1)))

    def run(self, case):
        m = self.mu
        for (address, size), value in zip(INPUTS, case, strict=True):
            m.mem_write(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
        for address, size in OUTPUTS:
            m.mem_write(address, b"\xa5" * size)
        sp = STACK + 0x8000
        m.reg_write(x86.UC_X86_REG_ESP, sp)
        for i, reg in enumerate(SAVED):
            m.reg_write(reg, 0xDD000000 + i)
        for reg in (x86.UC_X86_REG_EAX, x86.UC_X86_REG_ECX, x86.UC_X86_REG_EDX):
            m.reg_write(reg, 0xA5A5A5A5)
        m.reg_write(x86.UC_X86_REG_EFLAGS, 0x2)
        self.events = []
        m.emu_start(self.base + START, self.base + END, count=100)
        assert m.reg_read(x86.UC_X86_REG_EIP) == self.base + END
        assert m.reg_read(x86.UC_X86_REG_ESP) == sp
        assert [m.reg_read(r) for r in SAVED] == [0xDD000000 + i for i in range(4)]
        values = [int.from_bytes(m.mem_read(a, s), "little") for a, s in OUTPUTS]
        return self.events.copy(), values


def oracle(case):
    major, minor, mode, hardcore = case
    values = [minor & 0xFFFFFFFF, major & 0xFFFFFFFF, 1, mode & 0xFFFFFFFF, hardcore, 0, 8 if mode == 3 else 7]
    return [(a, s, v) for (a, s), v in zip(OUTPUTS, values, strict=True)], values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    image = match.load_image(match.default_image_path())
    _, _, body, report, measured = build(WITNESS, out / "controls")
    proof = audit(body, report, image, ((START, END),))
    code = bytearray(body.data)
    for ref in proof[0]["relocations"]:
        assert ref["kind"] == 6
        struct.pack_into("<I", code, ref["offset"], ref["address"])
    cases = [
        (major, minor, mode, hardcore)
        for (major, minor), mode, hardcore in itertools.product(
            ((1, 1), (-2147483648, 2147483647), (2147483647, -2147483648), (0x12345678, -1234567)),
            (-2147483648, -1, 0, 1, 2, 3, 4, 5, 2147483647),
            range(256),
        )
    ]
    native, candidate = Runner(image), Runner(image, bytes(code))
    digest = hashlib.sha256()
    for case in cases:
        a, b, expected = native.run(case), candidate.run(case), oracle(case)
        assert a == b == expected, (case, a, b, expected)
        digest.update(json.dumps((case, a), separators=(",", ":")).encode())
    corruptions = []
    fixture = (11, 22, 3, 128)
    for name, offset, replacement in (
        ("wrong-minor-source", 0xD8A, struct.pack("<I", INPUTS[0][0])),
        ("wrong-mode-comparison", 0xDA3, b"\x04"),
        ("wrong-transition-value", 0xDCE, b"\x01"),
        ("mode-before-overlay", 0xDB6, bytes(code[0xDBD:0xDC2] + code[0xDB6:0xDBD])),
    ):
        damaged = bytearray(code)
        damaged[offset : offset + len(replacement)] = replacement
        actual = Runner(image, bytes(damaged)).run(fixture)
        assert actual != oracle(fixture), name
        if name == "mode-before-overlay":
            assert actual[1] == oracle(fixture)[1]  # The write-order check is essential.
        corruptions.append(name)
    result = {
        "schema_version": 1,
        "kind": "highscore-saved-state-execution",
        "image_sha256": IMAGE_SHA,
        "source_sha256": sources()[WITNESS][1]["source_sha256"],
        "metrics": measured,
        "region": proof,
        "fixtures": len(cases),
        "execution_digest": digest.hexdigest(),
        "ordered_writes_equal": True,
        "stack_and_saved_registers_preserved": True,
        "corruptions_rejected": corruptions,
        "full_function_match": False,
        "limitations": "Straight-line restoration only. No callbacks, whole UI execution, or reachability claim for arbitrary input bit patterns.",
        "inputs": {
            p.name: sha(p.read_bytes())
            for p in (HERE / "controls.py", HERE / "controls.json", HERE / "verify.py", Path(__file__))
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", len(cases), "native/stock/oracle cases and four corruptions", flush=True)


if __name__ == "__main__":
    main()
