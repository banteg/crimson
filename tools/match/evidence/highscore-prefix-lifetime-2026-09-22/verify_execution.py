"""Execute only the score-row region; model sprintf and verify its caller contract."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import unicorn
from controls import build, sha
from region import STACK_MAPS, audit
from unicorn import x86_const as x86

from crimson import match

ROOT = None
CODE, STACK = 0x1000000, 0x2000000
ITEMS, BUFFERS, TABLE, MODE, SPRINTF = 0x4CC934, 0x4CCD68, 0x482B10, 0x480360, 0x4616E7
NSTART, NEND = 0x442B4D, 0x442C79
IMAGE = match.load_image(match.default_image_path())


def signed(v):
    return v if v < 0x80000000 else v - 0x100000000


def quotient(v):
    return (-1 if v < 0 else 1) * (abs(v) // 1000)


def h(v):
    return hashlib.sha256(v).hexdigest()


def prepare(name):
    cfg = match.load_scratch_config(ROOT / name)
    path = match.compile_scratch(cfg)
    body = match.extract_object_function(match.parse_coff_object(path.read_bytes()), cfg.symbol)
    r = match.run_match(
        obj_path=path, function=cfg.function, symbol_name=cfg.symbol, reference_aliases=cfg.reference_aliases,
    )
    window = {
        "baseline": (0x77D, 0x88D, 0x24, 0x14),
        "prefix-before-clear": (0x77D, 0x8A9, 0x1C, 0x2C),
        "row-plus-widget-labels": (0x77D, 0x8A9, 0x24, 0x14),
    }[name]
    refmap = {}
    for row in r.target_disassembly:
        if NSTART <= row.address < NEND:
            for ref in row.masked_references:
                for key in ref.keys:
                    refmap.setdefault(key, set()).add(ref.value)
    patched = bytearray(body.data)
    records = []
    for row in r.candidate_disassembly:
        if not window[0] <= row.offset < window[1]:
            continue
        local = [ref for ref in body.relocation_references if row.offset <= ref.offset < row.offset + row.size]
        assert len(local) == len(row.masked_references)
        for reloc, ref in zip(local, row.masked_references, strict=True):
            values = {int(k[8:], 16) for k in ref.keys if k.startswith("address:")}
            if not values:
                values = set().union(*(refmap.get(k, set()) for k in ref.keys))
            assert len(values) == 1, (row, values)
            addr = values.pop()
            assert reloc.relocation_type in (6, 20)
            value = addr if reloc.relocation_type == 6 else (addr - (CODE + reloc.offset + 4)) & 0xFFFFFFFF
            struct.pack_into("<I", patched, reloc.offset, value)
            records.append((reloc.offset, addr, reloc.relocation_type))
    return bytes(patched), window, records, h(body.data)


class Runner:
    def __init__(self, code=None, window=None):
        self.mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        m = self.mu
        m.mem_map(IMAGE.image_base, (len(IMAGE.mapped) + 4095) & ~4095)
        m.mem_write(IMAGE.image_base, IMAGE.mapped)
        m.mem_map(CODE, 0x10000)
        m.mem_map(STACK, 0x10000)
        if code:
            m.mem_write(CODE, code)
        self.start, self.end, self.count = (
            (NSTART, NEND, 0x4C) if code is None else (CODE + window[0], CODE + window[1], window[2])
        )
        self.y = 0x14 if code is None else window[3]
        self.calls = []
        self.writes = []
        m.hook_add(unicorn.UC_HOOK_CODE, self.format, begin=SPRINTF, end=SPRINTF)
        m.hook_add(
            unicorn.UC_HOOK_MEM_WRITE, self.write, begin=IMAGE.image_base, end=IMAGE.image_base + len(IMAGE.mapped) - 1,
        )

    def write(self, mu, access, address, size, value, data):
        self.writes.append((address, size, value))

    def format(self, mu, pc, size, data):
        sp = mu.reg_read(x86.UC_X86_REG_ESP)
        ret, dest, fmt, rank, value, name = struct.unpack("<6I", mu.mem_read(sp, 24))
        assert bytes(mu.mem_read(fmt, 9)) == b"%d\t%d\t%s\0"
        text = bytes(mu.mem_read(name, 32)).split(b"\0")[0]
        self.calls.append((dest, fmt, rank, value, name, text.hex()))
        rendered = f"{signed(rank)}\t{signed(value)}\t".encode() + text + b"\0"
        mu.mem_write(dest, rendered)
        mu.reg_write(x86.UC_X86_REG_ESP, sp + 4)
        mu.reg_write(x86.UC_X86_REG_EIP, ret)
        mu.reg_write(x86.UC_X86_REG_EAX, len(rendered) - 1)
        mu.reg_write(x86.UC_X86_REG_ECX, 0xC1C1C1C1)
        mu.reg_write(x86.UC_X86_REG_EDX, 0xD2D2D2D2)

    def run(self, fixture):
        n, flags, mode, elapsed, score = fixture
        m = self.mu
        self.calls = []
        self.writes = []
        records = bytearray(100 * 72)
        for i in range(100):
            name = ("player-" + str(i)).encode()
            records[i * 72 : i * 72 + len(name)] = name
            struct.pack_into("<II", records, i * 72 + 32, elapsed if i < n else 0, (score + i) & 0xFFFFFFFF)
            records[i * 72 + 68] = flags
        m.mem_write(TABLE, bytes(records))
        m.mem_write(BUFFERS, b"\xcc" * (100 * 164))
        m.mem_write(ITEMS, b"\xa7" * 400)
        m.mem_write(MODE, struct.pack("<I", mode & 0xFFFFFFFF))
        m.mem_write(STACK + 0x7000, b"\xa5" * 0x2000)
        sp = STACK + 0x8000
        m.reg_write(x86.UC_X86_REG_ESP, sp)
        for reg in (
            x86.UC_X86_REG_EAX,
            x86.UC_X86_REG_EBX,
            x86.UC_X86_REG_ECX,
            x86.UC_X86_REG_EDX,
            x86.UC_X86_REG_EBP,
            x86.UC_X86_REG_ESI,
            x86.UC_X86_REG_EDI,
        ):
            m.reg_write(reg, 1 if reg in (x86.UC_X86_REG_EBX, x86.UC_X86_REG_ESI) else 0xBAD0BAD0)
        m.reg_write(x86.UC_X86_REG_FPCW, 0x007F)
        m.reg_write(x86.UC_X86_REG_FPSW, 0)
        m.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        m.mem_write(sp + self.y, struct.pack("<f", 3.25))
        m.emu_start(self.start, self.end, count=50000)
        assert m.reg_read(x86.UC_X86_REG_EIP) == self.end
        assert m.reg_read(x86.UC_X86_REG_ESP) == sp
        assert bytes(m.mem_read(TABLE, len(records))) == records
        count = struct.unpack("<I", m.mem_read(sp + self.count, 4))[0]
        y = struct.unpack("<f", m.mem_read(sp + self.y, 4))[0]
        return (count, y, self.calls, bytes(m.mem_read(ITEMS, 400)), bytes(m.mem_read(BUFFERS, 100 * 164)), self.writes)


def oracle(f):
    n, flags, mode, elapsed, score = f
    items = bytearray(b"\xa7" * 400)
    buffers = bytearray(b"\xcc" * (100 * 164))
    calls = []
    prefix = b"\\g" if (flags & 5) != 0 and ((flags & 2) == 0 or (flags & 4) != 0) else b""
    for i in range(min(n + 1, 100)):
        struct.pack_into("<I", items, 4 * i, BUFFERS + 164 * i)
        buffers[164 * i : 164 * (i + 1)] = b"\0" * 164
        if i == n:
            break
        value = quotient(signed(elapsed)) if mode in (2, 3) else signed((score + i) & 0xFFFFFFFF)
        name = ("player-" + str(i)).encode()
        line = prefix + f"{i + 1}\t{value}\t".encode() + name + b"\0"
        buffers[164 * i : 164 * i + len(line)] = line
        calls.append((BUFFERS + 164 * i + len(prefix), 0x478C18, i + 1, value & 0xFFFFFFFF, TABLE + 72 * i, name.hex()))
    return n, 20.25, calls, bytes(items), bytes(buffers)


def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    ROOT = parser.parse_args().out.resolve()
    ROOT.mkdir(parents=True, exist_ok=False)
    assert (
        sha(match.default_image_path().read_bytes()) == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    for name in ("baseline", "prefix-before-clear", "row-plus-widget-labels"):
        build(name, ROOT)
    compiled = {name: prepare(name) for name in ("baseline", "prefix-before-clear", "row-plus-widget-labels")}
    region_audits = {n: audit(n, v[0], v[2]) for n, v in compiled.items() if n != "baseline"}
    code, _, relocations, _ = compiled["prefix-before-clear"]
    corrupted = bytearray(code)
    corrupted[0x7CF] ^= 1  # The empty-record exit's literal branch displacement.
    try:
        audit("prefix-before-clear", corrupted, relocations)
    except AssertionError:
        pass
    else:
        raise AssertionError("literal branch corruption was accepted")
    wrong_map = dict(STACK_MAPS["prefix-before-clear"])
    wrong_map[0x24], wrong_map[0x28] = wrong_map[0x28], wrong_map[0x24]
    try:
        audit("prefix-before-clear", code, relocations, wrong_map)
    except (AssertionError, KeyError):
        pass
    else:
        raise AssertionError("wrong rank stack binding was accepted")
    runners = {"native": Runner(), **{n: Runner(v[0], v[1]) for n, v in compiled.items()}}
    cases = []
    for flags in range(256):
        for mode in (1, 2, 3, 5):
            cases.append((1, flags, mode, 1001, 0x80000000))
    for mode in (-1, 0, 1, 2, 3, 4, 5, 6):
        for value in (1, 999, 1000, 1001, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF):
            for flags in (0, 1, 2, 3, 4, 5, 6, 7):
                cases.append((2, flags, mode, value, value))
    for n in (0, 1, 2, 99, 100):
        for mode in (1, 2, 3, 5):
            for flags in (0, 5):
                cases.append((n, flags, mode, 0xFFFFFFFF, 0x7FFFFFFE))
    digests = {n: hashlib.sha256() for n in runners}
    for i, f in enumerate(cases):
        expected = oracle(f)
        outputs = {n: r.run(f) for n, r in runners.items()}
        for name, value in outputs.items():
            assert value[:5] == expected, (i, f, name, "oracle mismatch")
            assert value == outputs["native"], (i, f, name, "native mismatch")
            digest = repr((value[:3], h(value[3]), h(value[4]), value[5])).encode()
            digests[name].update(digest)
        if (i + 1) % 500 == 0:
            print("Verified", i + 1, flush=True)
    code, window, _, _ = compiled["prefix-before-clear"]
    rejected = []
    corruptions = [
        ("wrong-prefix-mask", 0x7D7, b"\x05", b"\x01", (1, 4, 1, 1001, 7)),
        ("unsigned-division-shift", 0x80D, b"\xfa", b"\xea", (1, 0, 2, 0x80000000, 7)),
        ("ninety-nine-row-limit", 0x893, struct.pack("<I", BUFFERS + 16400),
         struct.pack("<I", BUFFERS + 16236), (100, 0, 1, 1001, 7)),
    ]
    for label, offset, before, after, fixture in corruptions:
        assert code[offset:offset + len(before)] == before
        damaged = bytearray(code)
        damaged[offset:offset + len(before)] = after
        assert Runner(bytes(damaged), window).run(fixture)[:5] != oracle(fixture), label
        rejected.append(label)
    result = {
        "schema": 1,
        "scope": "row-loop-only-sprintf-modeled",
        "region_audits": region_audits,
        "literal_branch_corruption_rejected": True,
        "wrong_stack_binding_rejected": True,
        "fixtures": len(cases),
        "fixtures_sha256": sha(json.dumps(cases).encode()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "input_hashes": {name: sha((Path(__file__).parent / name).read_bytes())
                         for name in ("controls.py", "controls.json", "region.py")},
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "corruption_controls_rejected": rejected,
        "digests": {n: d.hexdigest() for n, d in digests.items()},
        "compiled": {n: {"window": v[1], "relocations": v[2], "body_sha256": v[3]} for n, v in compiled.items()},
    }
    (ROOT / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Verified", len(cases), "native/baseline/two witness row fixtures", flush=True)


if __name__ == "__main__":
    main()
