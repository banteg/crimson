"""Bounded x86 spawn caller execution with real native allocation helpers."""

import importlib.util
import struct

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

ENGINE_PATH = match.DEFAULT_MATCH_ROOT / "evidence/plasma-head-alpha-2026-09-10/verify.py"
s = importlib.util.spec_from_file_location("spawn_execution_engine", ENGINE_PATH)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class Comparison:
    def __init__(self, config):
        self.program = m.Program(config)
        manifest = match.load_function_manifest(scope="all")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.helpers = {}
        for name in ("creature_alloc_slot", "creature_spawn_slot_alloc"):
            _, start, end = match.resolve_function(manifest, name)
            self.helpers[name] = (
                start,
                {i.address for i in md.disasm(self.program.image.function_bytes(start, end), start)},
            )

    def run(self, native, case):
        p = self.program
        helpers = self.helpers
        assert 0 <= case.get("occupied", 0) <= 384
        assert 0 <= case.get("slots_occupied", 0) <= 32
        u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        u.mem_map(p.image.image_base, m.page_size(p.image.size_of_image))
        u.mem_write(p.image.image_base, p.image.mapped)
        u.mem_map(m.CODE, p.code_size)
        for a, b in p.patched_sections.items():
            if b:
                u.mem_write(a, b)
        u.mem_map(m.STACK, 0x10000)
        u.mem_write(m.STACK, bytes([case.get("stack_fill", 0xA5)]) * 0x10000)
        u.mem_map(m.STUB, 0x4000)

        def write(name, value, fmt="i"):
            u.mem_write(p.address(name), struct.pack("<" + fmt, value))

        write("config_hardcore", case.get("hardcore", 0), "B")
        write("demo_mode_active", case.get("demo", 0), "B")
        write("terrain_texture_width", 1024)
        write("terrain_texture_height", 1024)
        write("creature_spawned_count", 101)
        write("quest_fail_retry_count", case.get("retry", 0))
        write("cv_verbose", m.STUB + 0x100, "I")
        u.mem_write(m.STUB + 0x10C, struct.pack("<f", 0))
        pool = p.address("creature_pool")
        slots = p.address("creature_spawn_slot_table")
        initial = bytearray(struct.pack("<f", 0.75) * 38)
        initial[0] = 0
        struct.pack_into("<i", initial, 120, 0)
        for j in range(385):
            initial[0] = int(j < case.get("occupied", 0))
            u.mem_write(pool + j * 152, bytes(initial))
        for j in range(32):
            u.mem_write(
                slots + 24 * j,
                struct.pack("<3i2fi", int(j < case.get("slots_occupied", 0)), 2, 3, 0.5, 0.1, 3),
            )
        pos = m.STUB + 0x180
        u.mem_write(pos, struct.pack("<2f", *case.get("position", (150.25, 350.5))))
        esp = m.STACK + 0xF000
        u.mem_write(esp, struct.pack("<3If", m.STOP, case["template"], pos, case.get("heading", -100)))
        u.reg_write(x86.UC_X86_REG_ESP, esp)
        u.reg_write(x86.UC_X86_REG_FPCW, case.get("fpcw", 0x7F))
        u.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        saved = [
            (x86.UC_X86_REG_EBX, 0x11110000),
            (x86.UC_X86_REG_ESI, 0x22220000),
            (x86.UC_X86_REG_EDI, 0x33330000),
            (x86.UC_X86_REG_EBP, 0x44440000),
        ]
        for r, v in saved:
            u.reg_write(r, v)
        start = p.native_start if native else p.candidate_start
        expected = {
            start + i.offset for i in (p.result.target_disassembly if native else p.result.candidate_disassembly)
        }
        calls = []
        writes = []
        sites = []
        coverage = set()
        random_index = 0
        random_state = case.get("seed", 1) & 0xFFFFFFFF
        callbacks = {p.address(name): name for name in ("crt_rand", "console_printf", "effect_spawn_burst")}

        def hook(uc, a, size, data):
            nonlocal random_index, random_state
            if a in expected:
                coverage.add(a)
                return
            for name, (entry, pcs) in helpers.items():
                if a in pcs:
                    if a == entry:
                        calls.append([name])
                    return
            if a in callbacks:
                name = callbacks[a]
                e = uc.reg_read(x86.UC_X86_REG_ESP)
                ret = struct.unpack("<I", uc.mem_read(e, 4))[0]
                reply = 0
                if name == "crt_rand":
                    if case.get("rng", "lcg") == "lcg":
                        random_state = (random_state * 214013 + 2531011) & 0xFFFFFFFF
                        reply = (random_state >> 16) & 0x7FFF
                    else:
                        reply = ((random_index + case.get("seed", 1)) * 1103515245 + 12345) % 32768
                    random_index += 1
                    calls.append([name, reply])
                elif name == "console_printf":
                    queue, fmt = struct.unpack("<2I", uc.mem_read(e + 4, 8))
                    text = bytes(uc.mem_read(fmt, 100)).split(b"\0")[0].decode("ascii")
                    calls.append([name, queue, text])
                else:
                    ptr, count = struct.unpack("<2I", uc.mem_read(e + 4, 8))
                    calls.append([name, list(struct.unpack("<2I", uc.mem_read(ptr, 8))), count])
                uc.reg_write(x86.UC_X86_REG_EIP, ret)
                uc.reg_write(x86.UC_X86_REG_ESP, e + 4)
                uc.reg_write(x86.UC_X86_REG_EAX, reply)
                uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
                uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)
                uc.reg_write(x86.UC_X86_REG_EFLAGS, 0xAD7)
                return
            raise AssertionError(("unknown", native, hex(a)))

        def onwrite(uc, access, a, size, value, data):
            if m.STACK <= a and a + size <= m.STACK + 0x10000:
                return
            assert any(lo <= a and a + size <= hi for lo, hi in allowed), (hex(a), size)
            writes.append([a, size, value & ((1 << (size * 8)) - 1)])
            sites.append(uc.reg_read(x86.UC_X86_REG_EIP))

        allowed = [(pool, pool + 385 * 152), (slots, slots + 32 * 24)] + [
            (p.address(n), p.address(n) + 4) for n in ("creature_spawned_count", "quest_fail_retry_count")
        ]
        u.hook_add(unicorn.UC_HOOK_CODE, hook)
        u.hook_add(unicorn.UC_HOOK_MEM_WRITE, onwrite)
        u.emu_start(start, m.STOP, count=1000000)
        assert u.reg_read(x86.UC_X86_REG_EIP) == m.STOP
        assert u.reg_read(x86.UC_X86_REG_ESP) == esp + 4
        assert u.reg_read(x86.UC_X86_REG_FPCW) == case.get("fpcw", 0x7F)
        for r, v in saved:
            assert u.reg_read(r) == v
        return {
            "state": bytes(u.mem_read(pool, 385 * 152)),
            "slots": bytes(u.mem_read(slots, 32 * 24)),
            "scalars": [
                bytes(u.mem_read(p.address(n), 4)).hex() for n in ("creature_spawned_count", "quest_fail_retry_count")
            ],
            "result": u.reg_read(x86.UC_X86_REG_EAX),
            "calls": calls,
            "writes": writes,
            "sites": sites,
            "coverage_offsets": sorted(a - start for a in coverage),
            "rng_state": random_state,
            "rng_draws": random_index,
        }
