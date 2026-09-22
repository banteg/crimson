"""Execute the play-game gate, state writes, and modeled sound calls against native."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

from controls import HERE, WITNESS, build, sha
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_MODE_32, Uc
from unicorn import x86_const as x86
from verify import IMAGE_SHA, WINDOWS, audit

from crimson import match

CODE, STACK, SFX = 0x10000000, 0x20000000, 0x43D550
START, END = 0xB8A, 0xC3C
NBASE = 0x4423D0
MODE, HARDCORE, MAJOR, MINOR, NORMAL, FULL = 0x480360, 0x480790, 0x487004, 0x487008, 0x487034, 0x487038
OUTPUTS = ((0x487240, 1), (0x487292, 1), (0x48724C, 1), (0x487274, 4), (0x48702C, 1))
MUSIC = ((0x4C4038, 13579), (0x4C4034, 24680), (0x4C403C, 0xFFFFFFFF))
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
        # Sound effects are external observations here. The stub returns while
        # clobbering all caller-saved integer registers; it models no audio work.
        m.mem_write(SFX, b"\xc3")
        m.hook_add(UC_HOOK_CODE, self.step)
        m.hook_add(UC_HOOK_MEM_WRITE, self.write)
        self.events = []

    def step(self, m, address, _size, _user):
        if address == SFX:
            sp = m.reg_read(x86.UC_X86_REG_ESP)
            self.events.append(("sound", struct.unpack("<I", m.mem_read(sp + 4, 4))[0]))
            for reg, value in (
                (x86.UC_X86_REG_EAX, 0xA123B456),
                (x86.UC_X86_REG_ECX, 0xCAFECAFE),
                (x86.UC_X86_REG_EDX, 0xED00ED00),
            ):
                m.reg_write(reg, value)

    def write(self, _m, _access, address, size, value, _user):
        if STACK <= address < STACK + 0x10000:
            return
        assert (address, size) in OUTPUTS
        self.events.append(("write", address, size, value))

    def run(self, case):
        clicked, mode, hardcore, major, minor, normal, full = case
        m = self.mu
        for address, value in ((MODE, mode), (MAJOR, major), (MINOR, minor), (NORMAL, normal), (FULL, full), *MUSIC):
            m.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))
        m.mem_write(HARDCORE, bytes([hardcore]))
        for address, size in OUTPUTS:
            m.mem_write(address, b"\xa5" * size)
        sp = STACK + 0x8000
        m.mem_write(sp - 0x100, b"\xa5" * 0x200)
        for i, reg in enumerate(SAVED):
            m.reg_write(reg, 0xDD000000 + i)
        m.reg_write(x86.UC_X86_REG_ESP, sp)
        m.reg_write(x86.UC_X86_REG_EAX, 0x12340000 | clicked)
        m.reg_write(x86.UC_X86_REG_ECX, 0x22222222)
        m.reg_write(x86.UC_X86_REG_EDX, 0x33333333)
        m.reg_write(x86.UC_X86_REG_EFLAGS, 0x2)
        self.events = []
        m.emu_start(self.base + START, self.base + END, count=200)
        assert m.reg_read(x86.UC_X86_REG_EIP) == self.base + END
        assert m.reg_read(x86.UC_X86_REG_ESP) == sp
        assert [m.reg_read(reg) for reg in SAVED] == [0xDD000000 + i for i in range(4)]
        outputs = [bytes(m.mem_read(address, size)).hex() for address, size in OUTPUTS]
        return self.events.copy(), outputs


def oracle(case):
    clicked, mode, hardcore, major, minor, normal, full = case
    quest_index = minor + major * 10 - 11
    assert -(2**31) <= quest_index < 2**31
    allowed = bool(clicked) and (mode != 3 or quest_index <= (full if hardcore else normal))
    if not allowed:
        return [], [("a5" * size) for _, size in OUTPUTS]
    pending = 18 if mode == 4 else 9
    events = [("write", address, size, pending if size == 4 else 0) for address, size in OUTPUTS[:4]]
    events += [("sound", value) for _, value in MUSIC]
    events.append(("write", OUTPUTS[4][0], 1, 1))
    return events, ["00", "00", "00", struct.pack("<I", pending).hex(), "01"]


def fixtures():
    cases = []
    for clicked in (0, 1):
        for mode in (-2147483648, -1, 0, 1, 2, 3, 4, 5, 6, 2147483647):
            for hardcore in (0, 1, 128, 255):
                for major, minor in ((1, 1), (5, 10), (0, 0), (-1, 11)):
                    index = minor + major * 10 - 11
                    limits = (-2147483648, index - 1, index, index + 1, 2147483647)
                    cases.extend(
                        (clicked, mode, hardcore, major, minor, normal, full) for normal in limits for full in limits
                    )
    cases.extend(
        (clicked, 3, hardcore, 1, 1, normal, full)
        for clicked in (0, 1)
        for hardcore in range(256)
        for normal, full in ((-1, 0), (0, -1))
    )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    image = match.load_image(match.default_image_path())
    _, _, body, r, measured = build(WITNESS, out / "controls")
    proof = audit(body, r.target_disassembly, r.candidate_disassembly, WINDOWS["row-play-back"], image)
    code = bytearray(body.data)
    for ref in proof["relocations"]:
        offset, address, kind = ref["offset"], ref["address"], ref["kind"]
        value = address if kind == 6 else (address - (CODE + offset + 4)) & 0xFFFFFFFF
        struct.pack_into("<I", code, offset, value)
    native, candidate = Runner(image), Runner(image, bytes(code))
    cases = fixtures()
    digest = hashlib.sha256()
    for i, case in enumerate(cases):
        expected = oracle(case)
        a, b = native.run(case), candidate.run(case)
        assert a == b == expected, (case, a, b, expected)
        digest.update(json.dumps((case, a), separators=(",", ":")).encode())
        if (i + 1) % 3000 == 0:
            print("Verified", i + 1, "gate fixtures", flush=True)
    rejected = []
    for label, offset, replacement, case in (
        ("strict-hardcore-boundary", 0xBBC, b"\x7f", (1, 3, 1, 1, 1, 0, 0)),
        ("wrong-hardcore-limit", 0xBB8, struct.pack("<I", NORMAL), (1, 3, 1, 1, 1, -1, 0)),
        ("missing-fade-write", 0xC3B, b"\x00", (1, 1, 0, 1, 1, 0, 0)),
    ):
        bad = bytearray(code)
        bad[offset : offset + len(replacement)] = replacement
        assert Runner(image, bytes(bad)).run(case) != oracle(case)
        rejected.append(label)
    result = {
        "schema": 1,
        "scope": "play-gate-state-writes-and-modeled-sound-calls-only",
        "image_sha256": IMAGE_SHA,
        "compiled": measured,
        "fixtures": len(cases),
        "fixture_sha256": sha(json.dumps(cases).encode()),
        "outputs_sha256": digest.hexdigest(),
        "native_window": [NBASE + START, NBASE + END],
        "candidate_window": [START, END],
        "ordered_events_equal": True,
        "stack_balanced": True,
        "saved_registers_preserved": True,
        "corruptions_rejected": rejected,
        "input_hashes": {
            n: sha((HERE / n).read_bytes())
            for n in ("controls.py", "controls.json", "verify.py", "verify_execution.py")
        },
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", len(cases), "native/stock/oracle gate fixtures", flush=True)


if __name__ == "__main__":
    main()
