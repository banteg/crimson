"""Compare bounded plasma draw traces with native code, using recording call stubs.

Requires optional unicorn==2.1.4 and local JIT permission. Does not grant
whole-function exactness or prove rendering equivalence outside these fixtures.
"""

import argparse
import hashlib
import json
import re
import struct
from dataclasses import asdict, replace
from pathlib import Path

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

HERE = Path(__file__).resolve().parent
FUNCTION = "projectile_render"
PAGE = 4096
CODE, STACK, STUB = 0x10000000, 0x20000000, 0x31000000
STOP, THIS = STUB + 0x3000, STUB + 0x1000
VTABLE = THIS + 0x100
SMALL_TYPES = (11, 24, 26)
HEAD_SIZES = {9: 56.0, 11: 16.0, 24: 16.0, 26: 16.0, 28: 84.0}
SLOTS = {
    0x20: ("grim_set_config_var", 5),
    0xC4: ("grim_bind_texture", 2),
    0xE8: ("grim_begin_batch", 0),
    0xF0: ("grim_end_batch", 0),
    0xFC: ("grim_set_rotation", 1),
    0x100: ("grim_set_uv", 4),
    0x104: ("grim_set_atlas_frame", 2),
    0x10C: ("grim_set_uv_point", 3),
    0x114: ("grim_set_color", 4),
    0x118: ("grim_set_color_slot", 5),
    0x11C: ("grim_draw_quad", 4),
    0x138: ("grim_draw_quad_points", 8),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def page_size(size):
    return (max(size, 1) + PAGE - 1) & -PAGE


def bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


class Program:
    def __init__(self, config):
        self.config = config
        self.object_path = match.compile_scratch(config, force=True)
        self.object = match.parse_coff_object(self.object_path.read_bytes())
        self.body = match.extract_object_function(self.object, config.symbol)
        self.result = match.run_match(
            obj_path=self.object_path,
            function=FUNCTION,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        manifest = match.load_function_manifest(scope="all")
        self.catalog = match.load_reference_catalog(manifest).with_object_aliases(config.reference_aliases)
        self.image = match.load_image(match.default_image_path())
        self.native_start, self.native_end = match.resolve_function(manifest, FUNCTION)[1:]
        sections = {}
        cursor = CODE
        for number, section in enumerate(self.object.sections, 1):
            if section.name.startswith(".debug") or section.name == ".drectve":
                continue
            sections[number] = cursor
            cursor += page_size(max(len(section.data), section.logical_size or 0))
        self.code_size = cursor - CODE
        symbols = {symbol.raw_index: symbol for symbol in self.object.symbols}
        self.patched_sections = {}
        self.relocations = []
        for number, section in enumerate(self.object.sections, 1):
            if number not in sections:
                continue
            data = bytearray(section.data)
            for relocation in section.relocations:
                symbol = symbols[relocation.symbol_index]
                if symbol.section_number > 0:
                    destination = sections[symbol.section_number] + symbol.value
                else:
                    assert symbol.section_number == 0
                    destination = self.address(symbol.name)
                offset = relocation.virtual_address
                addend = struct.unpack_from("<I", data, offset)[0]
                assert relocation.relocation_type in (6, 20)
                value = destination + addend
                if relocation.relocation_type == 20:
                    value -= sections[number] + offset + 4
                struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)
                self.relocations.append([number, offset, relocation.relocation_type, symbol.name, destination, addend])
            self.patched_sections[sections[number]] = bytes(data)
        entry = next(symbol for symbol in self.object.symbols if symbol.name == "_projectile_render")
        self.candidate_start = sections[entry.section_number] + entry.value

    def address(self, name):
        addresses = self.catalog._addresses_for_symbol(name)
        assert len(addresses) == 1, (name, addresses)
        return addresses[0]


def run(p, native, type_id, life, alpha, glow):
    slots = {STUB + (slot // 4) * 16: value for slot, value in SLOTS.items()}
    effect = p.address("effect_select_texture")
    perk = p.address("perk_count_get")
    ftol_start = p.address("crt_ftol")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    ftol_pcs = set()
    for ins in md.disasm(
        p.image.mapped[ftol_start - p.image.image_base : ftol_start - p.image.image_base + 128],
        ftol_start,
    ):
        ftol_pcs.add(ins.address)
        if ins.mnemonic == "ret":
            break
    assert ins.mnemonic == "ret"
    ftol_data = p.image.mapped[ftol_start - p.image.image_base : ins.address + ins.size - p.image.image_base]
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    mu.mem_map(p.image.image_base, page_size(p.image.size_of_image))
    mu.mem_write(p.image.image_base, p.image.mapped)
    mu.mem_map(CODE, p.code_size)
    for a, data in p.patched_sections.items():
        if data:
            mu.mem_write(a, data)
    mu.mem_map(STACK, 0x10000)
    mu.mem_write(STACK, b"\xa5" * 0x10000)
    mu.mem_map(STUB, 0x4000)
    for a, (_name, count) in slots.items():
        mu.mem_write(a, b"\xc2" + struct.pack("<H", 4 * count))
    mu.mem_write(THIS, struct.pack("<I", VTABLE))
    mu.mem_write(VTABLE, struct.pack("<" + "I" * 80, *(STUB + i * 16 for i in range(80))))

    def w(name, value, fmt="<I"):
        mu.mem_write(p.address(name), struct.pack(fmt, value))

    w("grim_interface_ptr", THIS)
    mu.mem_write(p.address("config_blob") + 20, struct.pack("<i", 0))
    mu.mem_write(p.address("config_blob") + 16, bytes([glow]))
    w("render_overlay_player_index", 0)
    mu.mem_write(p.address("player_state_table"), bytes(0x360 * 2))
    mu.mem_write(p.address("projectile_pool"), bytes(0x40 * 96))
    mu.mem_write(p.address("secondary_projectile_pool"), bytes(0x2C * 64))
    mu.mem_write(p.address("camera_offset"), struct.pack("<ff", 13.125, -21.75))
    w("quest_spawn_timeline", 1234)
    if type_id is not None:
        b = bytearray(0x40)
        b[0] = 1
        struct.pack_into("<7f", b, 4, 0.3, 111.25, 208.5, 50.125, 91.75, 0.6, -0.8)
        struct.pack_into("<if", b, 32, type_id, life)
        struct.pack_into("<f", b, 44, 2.0)
        mu.mem_write(p.address("projectile_pool"), bytes(b))
    esp = STACK + 0xF000
    mu.mem_write(esp, struct.pack("<If", STOP, alpha))
    mu.reg_write(x86.UC_X86_REG_ESP, esp)
    mu.reg_write(x86.UC_X86_REG_FPCW, 0x37F)
    mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
    for reg, val in [
        (x86.UC_X86_REG_EBX, 0x11110000),
        (x86.UC_X86_REG_ESI, 0x22220000),
        (x86.UC_X86_REG_EDI, 0x33330000),
        (x86.UC_X86_REG_EBP, 0x44440000),
    ]:
        mu.reg_write(reg, val)
    calls = []
    coverage = set()
    call_sites = []
    writes = []
    start = p.native_start if native else p.candidate_start
    expected = {start + i.offset for i in (p.result.target_disassembly if native else p.result.candidate_disassembly)}

    def hook(uc, a, size, data):
        if a in expected:
            coverage.add(a)
            return
        if a in ftol_pcs:
            return
        e = uc.reg_read(x86.UC_X86_REG_ESP)
        if a in slots:
            name, n = slots[a]
            assert uc.reg_read(x86.UC_X86_REG_ECX) == THIS
            values = list(struct.unpack("<" + "I" * n, uc.mem_read(e + 4, n * 4))) if n else []
            if name == "grim_set_config_var":
                values = values[:2]
            calls.append([name, values])
            call_sites.append(struct.unpack("<I", uc.mem_read(e, 4))[0])
            uc.reg_write(x86.UC_X86_REG_EAX, 0)
            uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
            uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)
            return
        if a in (effect, perk):
            calls.append(
                [
                    "effect_select_texture" if a == effect else "perk_count_get",
                    [struct.unpack("<I", uc.mem_read(e + 4, 4))[0]],
                ],
            )
            call_sites.append(struct.unpack("<I", uc.mem_read(e, 4))[0])
            ret = struct.unpack("<I", uc.mem_read(e, 4))[0]
            uc.reg_write(x86.UC_X86_REG_ESP, e + 4)
            uc.reg_write(x86.UC_X86_REG_EIP, ret)
            uc.reg_write(x86.UC_X86_REG_EAX, 0)
            return
        raise AssertionError(("unhandled", hex(a), hex(e)))

    def on_write(uc, access, a, size, value, data):
        if STACK <= a and a + size <= STACK + 0x10000:
            return
        assert a == p.address("projectile_pool") and size == 1 and type_id == 0
        writes.append([a, size, value])

    mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
    mu.hook_add(unicorn.UC_HOOK_CODE, hook)
    mu.emu_start(start, STOP, count=500000)
    assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP
    assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4
    for reg, val in [
        (x86.UC_X86_REG_EBX, 0x11110000),
        (x86.UC_X86_REG_ESI, 0x22220000),
        (x86.UC_X86_REG_EDI, 0x33330000),
        (x86.UC_X86_REG_EBP, 0x44440000),
    ]:
        assert mu.reg_read(reg) == val
    assert not writes
    state = bytes(mu.mem_read(p.address("projectile_pool"), 0x40 * 96))
    return {
        "calls": calls,
        "return_sites": call_sites,
        "state_sha256": sha(state),
        "coverage": len(coverage),
        "ftol_sha256": sha(ftol_data),
    }


def head_color(result, type_id):
    color = None
    found = []
    for name, args in result["calls"]:
        if name == "grim_set_color":
            color = args
        if name == "grim_draw_quad" and args[2:] == [bits(HEAD_SIZES[type_id])] * 2:
            assert color is not None
            found.append(color)
    assert len(found) == 1
    return found[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    header = (match.REPO_ROOT / "tools/match/include/grim2d_cpp.h").read_text()
    methods = re.findall(r"virtual\s+[^;{}]*?\b(grim_\w+)\s*\((.*?)\)", header, re.DOTALL)
    assert all(methods[slot // 4][0] == name for slot, (name, _) in SLOTS.items())
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    current = Program(config)
    source = (config.directory / config.source).read_text()
    assert source.count("transition_alpha * 0.5f") == 4
    # Compile the previous wrong literals as a negative control, leaving the initial half-alpha intact.
    defect_source = source.replace("transition_alpha * 0.5f", "transition_alpha * 0.45f")
    defect_source = defect_source.replace("transition_alpha * 0.45f", "transition_alpha * 0.5f", 1)
    defect_dir = out / "defect"
    defect_dir.mkdir(exist_ok=True)
    (defect_dir / config.source).write_text(defect_source)
    defect = Program(replace(config, directory=defect_dir))
    rows = []
    example = None
    for type_id in HEAD_SIZES:
        for life in (0.4, 0.2, 1.2, -0.1):
            for alpha in (0.0, 0.2, 0.7, 1.0, 1.5):
                for glow in (0, 1):
                    native = run(current, True, type_id, life, alpha, glow)
                    candidate = run(current, False, type_id, life, alpha, glow)
                    assert native["calls"] == candidate["calls"]
                    assert native["state_sha256"] == candidate["state_sha256"]
                    if life == 0.4:
                        head = head_color(native, type_id)
                        assert head[3] == bits(f32(alpha) * (0.5 if type_id in SMALL_TYPES else f32(0.45)))
                    rows.append(
                        {
                            "type_id": type_id,
                            "life": life,
                            "transition_alpha": alpha,
                            "glow": glow,
                            "calls": len(native["calls"]),
                            "call_trace_sha256": sha(json.dumps(native["calls"]).encode()),
                            "native_instructions_exercised": native["coverage"],
                            "candidate_instructions_exercised": candidate["coverage"],
                            "projectile_state_sha256": native["state_sha256"],
                        },
                    )
                    if type_id == 11 and life == 0.4 and alpha == 0.7 and glow == 0:
                        example = native
    negatives = []
    for type_id in SMALL_TYPES:
        native = run(current, True, type_id, 0.4, 0.7, 0)
        wrong = run(defect, False, type_id, 0.4, 0.7, 0)
        differences = [i for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b]
        assert len(differences) == 1
        index = differences[0]
        assert native["calls"][index][0] == wrong["calls"][index][0] == "grim_set_color"
        assert native["calls"][index][1][:3] == wrong["calls"][index][1][:3]
        assert head_color(native, type_id)[3] == bits(f32(0.7) * 0.5)
        assert head_color(wrong, type_id)[3] == bits(f32(0.7) * f32(0.45))
        negatives.append(
            {
                "type_id": type_id,
                "differing_call_index": index,
                "native_call": hex(native["return_sites"][index] - 6),
                "native_alpha_bits": hex(native["calls"][index][1][3]),
                "defect_alpha_bits": hex(wrong["calls"][index][1][3]),
            },
        )
    result = current.result
    assert not result.exact and not result.body_byte_exact
    assert sha(defect_source.encode()) == "6dca4a01d049d243dc72dc1fc15faa7146134e7cb9f36f347cfba4a22af64e84"
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    multiply = next(md.disasm(current.image.function_bytes(0x422C9D, 0x422CA3), 0x422C9D))
    assert multiply.mnemonic == "fmul" and multiply.operands[0].type == capstone.x86.X86_OP_MEM
    constant = multiply.operands[0].mem.disp
    assert current.image.function_bytes(constant, constant + 4) == struct.pack("<f", 0.5)

    record = {
        "schema_version": 1,
        "kind": "native-plasma-head-alpha",
        "unicorn_version": unicorn.__version__,
        "source_sha256": sha(source.encode()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "native_body_sha256": sha(
            current.image.mapped[
                current.native_start - current.image.image_base : current.native_end - current.image.image_base
            ],
        ),
        "native_half_alpha": {
            "multiply": "0x00422c9d",
            "constant_address": hex(constant),
            "constant_bits": "0x3f000000",
            "stored_at": "0x00422cab",
            "stack_offset": "0x20",
            "head_calls": ["0x00423ac8", "0x00423e37", "0x00423fc1"],
        },
        "candidate_object_sha256": sha(current.object_path.read_bytes()),
        "candidate_body_sha256": sha(current.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "relocations": current.relocations,
        "defect_source_sha256": sha(defect_source.encode()),
        "defect_body_sha256": sha(defect.body.data),
        "metrics": {
            "ratio": result.ratio,
            "candidate_instructions": len(result.candidate_lines),
            "target_instructions": len(result.target_lines),
            "references_ok": result.masked_operand_audit.ok_count,
            "reference_problems": result.masked_operand_audit.problem_count,
            "exact": False,
            "body_byte_exact": False,
        },
        "reference_debt": {
            "previous": [asdict(entry) for entry in defect.result.masked_operand_audit.entries if entry.status != "ok"],
            "current": [asdict(entry) for entry in result.masked_operand_audit.entries if entry.status != "ok"],
        },
        "fixtures": rows,
        "negative_controls": negatives,
        "example_native_trace": example,
        "boundaries": {
            "grim": "recording thiscall stubs; only initialized config value word compared",
            "effect_select_texture": "recording no-op stub",
            "perk_count_get": "recording zero-result stub",
            "math": "machine x87 instructions and native crt_ftol",
            "x87_control_word": "0x037f",
        },
        "new_source_matches": 0,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(f"{len(rows)} native/candidate traces agree; three compiled wrong-alpha controls rejected.")


if __name__ == "__main__":
    main()
