"""Execute conventional projectile fixtures with recording external-call contracts."""

import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10/verify.py"
SPEC = importlib.util.spec_from_file_location("conventional_program", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match = probe.match
Program = probe.Program
sha, bits, f32 = probe.sha, probe.bits, probe.f32
unicorn, x86 = probe.unicorn, probe.x86
CODE, STACK, STUB = probe.CODE, probe.STACK, probe.STUB
STOP, THIS, VTABLE = probe.STOP, probe.THIS, probe.VTABLE
POOLS = {
    "projectile_pool": 0x40 * 96,
    "secondary_projectile_pool": 0x2C * 64,
    "player_state_table": 0x360 * 2,
    "creature_pool": 0x98 * 384,
}
TYPES = (*range(8), 29)


def run(program, native, case):
    assert case["fpcw"] in (0x007F, 0x037F)
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    mu.mem_map(program.image.image_base, probe.page_size(program.image.size_of_image))
    mu.mem_write(program.image.image_base, program.image.mapped)
    mu.mem_map(CODE, program.code_size)
    for address, data in program.patched_sections.items():
        if data:
            mu.mem_write(address, data)
    mu.mem_map(STACK, 0x10000)
    mu.mem_write(STACK, b"\xa5" * 0x10000)
    mu.mem_map(STUB, 0x4000)
    slots = {STUB + (slot // 4) * 16: contract for slot, contract in probe.SLOTS.items()}
    for address, (_name, count) in slots.items():
        mu.mem_write(address, b"\xc2" + struct.pack("<H", 4 * count))
    mu.mem_write(THIS, struct.pack("<I", VTABLE))
    mu.mem_write(VTABLE, struct.pack("<80I", *(STUB + i * 16 for i in range(80))))
    mu.mem_write(program.address("grim_interface_ptr"), struct.pack("<I", THIS))
    mu.mem_write(program.address("config_blob") + 20, struct.pack("<I", 0))
    mu.mem_write(program.address("config_blob") + 16, bytes([case["glow"]]))
    mu.mem_write(program.address("render_overlay_player_index"), struct.pack("<I", 0))
    mu.mem_write(program.address("quest_spawn_timeline"), struct.pack("<I", 1234))
    mu.mem_write(program.address("camera_offset"), struct.pack("<2f", *case["camera"]))
    for name, size in POOLS.items():
        mu.mem_write(program.address(name), bytes(size))
    expected_pool = bytearray(POOLS["projectile_pool"])
    expected_writes = []
    indices = set()
    for row in case["records"]:
        index = row["index"]
        assert 0 <= index < 96 and index not in indices
        assert row["type_id"] in TYPES and row["active"] in (0, 1, 2)
        indices.add(index)
        record = bytearray(0x40)
        record[0] = row["active"]
        struct.pack_into("<7f", record, 4, row["angle"], *row["position"], *row["origin"], *row["velocity"])
        struct.pack_into("<if", record, 32, row["type_id"], row["life"])
        struct.pack_into("<f", record, 44, 2.0)
        address = program.address("projectile_pool") + index * 0x40
        mu.mem_write(address, bytes(record))
        if row["active"] and row["type_id"] == 0:
            record[0] = 0
            expected_writes.append([address, 1, 0])
        expected_pool[index * 0x40 : (index + 1) * 0x40] = record
    expected_writes.sort()
    initial_pools = {name: bytes(mu.mem_read(program.address(name), size)) for name, size in POOLS.items()}
    esp = STACK + 0xF000
    mu.mem_write(esp, struct.pack("<If", STOP, case["alpha"]))
    caller_guard = bytes(mu.mem_read(esp, 0x100))
    mu.reg_write(x86.UC_X86_REG_ESP, esp)
    mu.reg_write(x86.UC_X86_REG_FPCW, case["fpcw"])
    mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
    saved = (
        (x86.UC_X86_REG_EBX, 0x11110000),
        (x86.UC_X86_REG_ESI, 0x22220000),
        (x86.UC_X86_REG_EDI, 0x33330000),
        (x86.UC_X86_REG_EBP, 0x44440000),
    )
    for register, value in saved:
        mu.reg_write(register, value)
    start = program.native_start if native else program.candidate_start
    disassembly = program.result.target_disassembly if native else program.result.candidate_disassembly
    instructions = {start + ins.offset for ins in disassembly}
    effect, perk = program.address("effect_select_texture"), program.address("perk_count_get")
    ftol_start = program.address("crt_ftol")
    md = probe.capstone.Cs(probe.capstone.CS_ARCH_X86, probe.capstone.CS_MODE_32)
    ftol_pcs = set()
    for ins in md.disasm(program.image.function_bytes(ftol_start, ftol_start + 128), ftol_start):
        ftol_pcs.add(ins.address)
        if ins.mnemonic == "ret":
            break
    assert ins.mnemonic == "ret"
    ftol_bytes = program.image.function_bytes(ftol_start, ins.address + ins.size)
    calls, returns, writes = [], [], []
    coverage = set()

    def clobber(uc):
        uc.reg_write(x86.UC_X86_REG_EAX, 0)
        uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
        uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)

    def instruction_hook(uc, address, _size, _data):
        if address in instructions:
            coverage.add(address - start)
            return
        if address in ftol_pcs:
            return
        stack = uc.reg_read(x86.UC_X86_REG_ESP)
        ret = struct.unpack("<I", uc.mem_read(stack, 4))[0]
        if address in slots:
            name, count = slots[address]
            assert uc.reg_read(x86.UC_X86_REG_ECX) == THIS
            arguments = list(struct.unpack("<" + "I" * count, uc.mem_read(stack + 4, count * 4))) if count else []
            if name == "grim_set_config_var":
                arguments = arguments[:2]
            calls.append([name, arguments])
            returns.append(ret)
            clobber(uc)
            return
        if address in (effect, perk):
            calls.append(
                [
                    "effect_select_texture" if address == effect else "perk_count_get",
                    [struct.unpack("<I", uc.mem_read(stack + 4, 4))[0]],
                ],
            )
            returns.append(ret)
            clobber(uc)
            uc.reg_write(x86.UC_X86_REG_ESP, stack + 4)
            uc.reg_write(x86.UC_X86_REG_EIP, ret)
            return
        raise AssertionError(("unmodeled execution", hex(address), hex(stack)))

    def write_hook(_uc, _access, address, size, value, _data):
        if STACK <= address and address + size <= esp:
            return
        assert [address, size, value] in expected_writes, (hex(address), size, value)
        writes.append([address, size, value])

    mu.hook_add(unicorn.UC_HOOK_CODE, instruction_hook)
    mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write_hook)
    mu.emu_start(start, STOP, count=500000)
    assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP
    assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4
    assert bytes(mu.mem_read(esp, 0x100)) == caller_guard
    assert all(mu.reg_read(register) == value for register, value in saved)
    assert mu.reg_read(x86.UC_X86_REG_FPCW) == case["fpcw"]
    assert mu.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
    assert writes == expected_writes
    pools = {name: bytes(mu.mem_read(program.address(name), size)) for name, size in POOLS.items()}
    assert pools["projectile_pool"] == expected_pool
    for name in POOLS:
        if name != "projectile_pool":
            assert pools[name] == initial_pools[name]
    return {
        "calls": calls,
        "return_sites": returns,
        "coverage_offsets": sorted(coverage),
        "writes": writes,
        "pools": {name: sha(data) for name, data in pools.items()},
        "ftol_sha256": sha(ftol_bytes),
    }
