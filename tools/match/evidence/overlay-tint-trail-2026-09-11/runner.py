"""Bounded player-overlay machine runner with explicit caller-boundary models."""

import importlib.util
import math
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10" / "verify.py"
SPEC = importlib.util.spec_from_file_location("overlay_loader", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match, Program = probe.match, probe.Program
unicorn, capstone, x86 = probe.unicorn, probe.capstone, probe.x86
sha, bits, f32 = probe.sha, probe.bits, probe.f32
CODE, STACK, STUB = probe.CODE, probe.STACK, probe.STUB
STOP, THIS, VTABLE = probe.STOP, probe.THIS, probe.VTABLE


def linked_body(p):
    for address, data in p.patched_sections.items():
        if address <= p.candidate_start < address + len(data):
            offset = p.candidate_start - address
            return data[offset : offset + len(p.body.data)]
    raise AssertionError("candidate body missing from linked sections")


def run(p, native, frame):
    assert p.config.function == "player_render_overlays"
    count, overlay = frame.get("player_count", 1), frame.get("overlay_index", 0)
    assert 0 <= count <= 2 and 0 <= overlay < 2
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    mu.mem_map(p.image.image_base, probe.page_size(p.image.size_of_image))
    mu.mem_write(p.image.image_base, p.image.mapped)
    mu.mem_map(CODE, p.code_size)
    for address, data in p.patched_sections.items():
        if data:
            mu.mem_write(address, data)
    mu.mem_map(STACK, 0x10000)
    mu.mem_write(STACK, b"\xa5" * 0x10000)
    mu.mem_map(STUB, 0x4000)
    slots = {STUB + (slot // 4) * 16: value for slot, value in probe.SLOTS.items()}
    for address, (_, argc) in slots.items():
        mu.mem_write(address, b"\xc2" + struct.pack("<H", 4 * argc))
    mu.mem_write(THIS, struct.pack("<I", VTABLE))
    mu.mem_write(VTABLE, struct.pack("<80I", *(STUB + i * 16 for i in range(80))))

    def write(name, value, fmt="<I"):
        mu.mem_write(p.address(name), struct.pack(fmt, value))

    write("grim_interface_ptr", THIS)
    write("ui_transition_alpha", frame.get("alpha", 0.7), "<f")
    write("player_overlay_suppressed_latch", frame.get("suppressed", 0), "<B")
    write("game_state_id", frame.get("state", 9))
    write("game_state_prev", frame.get("previous_state", 9))
    write("game_time_s", frame.get("time", 0.7), "<f")
    write("config_player_count", count)
    write("render_overlay_player_index", overlay)
    write("perk_id_radioactive", 1)
    write("player_overlay_auto_target_line_perk_id", 2)
    mu.mem_write(p.address("camera_offset"), struct.pack("<2f", *frame.get("camera", (13.125, -21.75))))
    mu.mem_write(p.address("weapon_table") + 0x68, bytes([frame.get("weapon_flags", 0)]))
    players, creatures = p.address("player_state_table"), p.address("creature_pool")
    mu.mem_write(players, bytes(0x360 * 2))
    mu.mem_write(creatures, bytes(0x98 * 384))
    seen = set()
    for row in frame.get("players", ()):
        index = row["index"]
        assert 0 <= index < 2 and index not in seen
        seen.add(index)
        address = players + 0x360 * index
        mu.mem_write(address + 0x14, struct.pack("<2f", *row["position"]))
        for offset, key, default in (
            (0x10, "death_timer", 5.0),
            (0x24, "health", 100.0),
            (0x2C, "heading", 0.5),
            (0x34, "size", 48.0),
            (0x94, "phase", 4.0),
            (0x98, "trail", 1.0),
            (0x2FC, "flash", 0.0),
            (0x300, "aim_heading", 0.3),
            (0x318, "shield", 0.0),
        ):
            mu.mem_write(address + offset, struct.pack("<f", row.get(key, default)))
        target = row.get("target", 0)
        assert 0 <= target < 384
        mu.mem_write(address + 0x320, struct.pack("<i", target))
    seen = set()
    for index, x, y in frame.get("targets", ()):
        assert 0 <= index < 384 and index not in seen
        seen.add(index)
        mu.mem_write(creatures + index * 0x98 + 0x14, struct.pack("<2f", x, y))
    input_players = bytes(mu.mem_read(players, 0x360 * 2))
    input_creatures = bytes(mu.mem_read(creatures, 0x98 * 384))
    esp = STACK + 0xF000
    mu.mem_write(esp, struct.pack("<I", STOP))
    mu.reg_write(x86.UC_X86_REG_ESP, esp)
    mu.reg_write(x86.UC_X86_REG_FPCW, 0x37F)
    mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
    preserved = (
        (x86.UC_X86_REG_EBX, 0x11110000),
        (x86.UC_X86_REG_ESI, 0x22220000),
        (x86.UC_X86_REG_EDI, 0x33330000),
        (x86.UC_X86_REG_EBP, 0x44440000),
    )
    for reg, value in preserved:
        mu.reg_write(reg, value)
    ftol = p.address("crt_ftol")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ftol_pcs = set()
    for ins in md.disasm(p.image.function_bytes(ftol, ftol + 128), ftol):
        ftol_pcs.add(ins.address)
        if ins.mnemonic == "ret":
            break
    assert ins.mnemonic == "ret"
    ftol_bytes = p.image.function_bytes(ftol, ins.address + ins.size)
    start = p.native_start if native else p.candidate_start
    code = p.image.function_bytes(p.native_start, p.native_end) if native else linked_body(p)
    instructions = list(md.disasm(code, start))
    expected = {ins.address for ins in instructions}
    normalize = p.address("D3DXVec2Normalize")
    normalization_calls = [
        i for i, ins in enumerate(instructions) if ins.mnemonic == "call" and ins.op_str == hex(normalize)
    ]
    assert len(normalization_calls) == 1
    preceding = instructions[normalization_calls[0] - 1]
    assert (preceding.mnemonic, preceding.op_str) == ("fstp", "dword ptr [esp + 0x2c]")
    effect, perk = p.address("effect_select_texture"), p.address("perk_count_get")
    calls, sites, writes, distances = [], [], [], []
    coverage = set()

    def clobber(uc, result=0):
        uc.reg_write(x86.UC_X86_REG_EAX, result)
        uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
        uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)

    def hook(uc, address, size, data):
        if address in expected:
            coverage.add(address)
            return
        if address in ftol_pcs:
            return
        stack = uc.reg_read(x86.UC_X86_REG_ESP)
        ret = struct.unpack("<I", uc.mem_read(stack, 4))[0]
        if address in slots:
            name, argc = slots[address]
            assert uc.reg_read(x86.UC_X86_REG_ECX) == THIS
            args = list(struct.unpack("<" + "I" * argc, uc.mem_read(stack + 4, argc * 4))) if argc else []
            if name == "grim_set_config_var":
                args = args[:2]
            calls.append([name, args])
            sites.append(ret)
            clobber(uc)
            return
        if address == normalize:
            dst, src = struct.unpack("<2I", uc.mem_read(stack + 4, 8))
            assert STACK <= dst <= STACK + 0x10000 - 8 and STACK <= src <= STACK + 0x10000 - 8
            raw = bytes(uc.mem_read(src, 8))
            x, y = struct.unpack("<2f", raw)
            calls.append(["D3DXVec2Normalize", list(struct.unpack("<2I", raw))])
            sites.append(ret)
            # The checked FSTP immediately before CALL stores at caller ESP+0x2c.
            distances.append(struct.unpack("<I", uc.mem_read(stack + 0x30, 4))[0])
            length = math.sqrt(x * x + y * y)
            uc.mem_write(dst, struct.pack("<2f", x / length if length else 0.0, y / length if length else 0.0))
            clobber(uc, dst)
            uc.reg_write(x86.UC_X86_REG_ESP, stack + 12)
            uc.reg_write(x86.UC_X86_REG_EIP, ret)
            return
        if address in (effect, perk):
            arg = struct.unpack("<I", uc.mem_read(stack + 4, 4))[0]
            calls.append(["effect_select_texture" if address == effect else "perk_count_get", [arg]])
            sites.append(ret)
            result = (
                int(frame.get("radioactive", False))
                if arg == 1
                else int(frame.get("line_perk", True))
                if arg == 2
                else 0
            )
            clobber(uc, result if address == perk else 0)
            uc.reg_write(x86.UC_X86_REG_ESP, stack + 4)
            uc.reg_write(x86.UC_X86_REG_EIP, ret)
            return
        raise AssertionError(("unhandled instruction", hex(address)))

    allowed_writes = {
        p.address(name) + offset for name in ("render_scratch_f0", "render_scratch_f2") for offset in (0, 4)
    }

    def on_write(uc, access, address, size, value, data):
        if STACK <= address and address + size <= STACK + 0x10000:
            return
        assert size == 4 and address in allowed_writes, (hex(address), size, value)
        writes.append([address, size, value])

    mu.hook_add(unicorn.UC_HOOK_CODE, hook)
    mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
    mu.emu_start(start, STOP, count=500000)
    assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP
    assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4
    for reg, value in preserved:
        assert mu.reg_read(reg) == value
    assert bytes(mu.mem_read(players, len(input_players))) == input_players
    assert bytes(mu.mem_read(creatures, len(input_creatures))) == input_creatures
    return {
        "calls": calls,
        "return_sites": sites,
        "writes": writes,
        "distance_bits": distances,
        "coverage": len(coverage),
        "player_state_sha256": sha(input_players),
        "creature_state_sha256": sha(input_creatures),
        "ftol_sha256": sha(ftol_bytes),
    }
