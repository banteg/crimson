"""Compare bounded creature-render executions with modeled Grim2D observations.

This is a behavioral audit, not an exact-match or equivalence certificate.
Requires the optional, pinned unicorn==2.1.4 dependency and JIT permission.
"""

import argparse
import hashlib
import itertools
import json
import random
import re
import struct
from dataclasses import replace
from pathlib import Path

import unicorn
from unicorn import x86_const as x86

from crimson import match

PAGE = 4096
CODE = 0x10000000
STACK = 0x20000000
API = 0x30000000
INSTANCE = API + 0x2000
VTABLE = API + 0x3000
STOP = API + 0x4000
FUNCTION = "creature_render_type"
FIELDS = {
    "active": (0, "B"),
    "lifecycle_stage": (16, "f"),
    "pos_x": (20, "f"),
    "pos_y": (24, "f"),
    "max_health": (40, "f"),
    "heading": (44, "f"),
    "size": (52, "f"),
    "hit_flash_timer": (56, "f"),
    "tint_r": (60, "f"),
    "tint_g": (64, "f"),
    "tint_b": (68, "f"),
    "tint_a": (72, "f"),
    "type_id": (108, "i"),
    "link_index": (120, "i"),
    "flags": (140, "i"),
    "anim_phase": (148, "f"),
}
ARGUMENT_WORDS = {
    "grim_set_config_var": 5,
    "grim_bind_texture": 2,
    "grim_set_uv": 4,
    "grim_begin_batch": 0,
    "grim_end_batch": 0,
    "grim_set_rotation": 1,
    "grim_set_atlas_frame": 2,
    "grim_set_color_ptr": 1,
    "grim_draw_quad": 4,
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def word(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


class Comparison:
    def __init__(self, config, object_path):
        self.config = config
        self.manifest = match.load_function_manifest(scope="all")
        self.catalog = match.load_reference_catalog(self.manifest).with_object_aliases(config.reference_aliases)
        self.image = match.load_image(match.default_image_path())
        self.native_start, self.native_end = match.resolve_function(self.manifest, FUNCTION)[1:]
        self.ftol_start, self.ftol_end = match.resolve_function(self.manifest, "crt_ftol")[1:]
        self.object = match.parse_coff_object(object_path.read_bytes())
        self.body = match.extract_object_function(self.object, config.symbol)
        sections = {}
        cursor = CODE
        for number, section in enumerate(self.object.sections, 1):
            # Linker directives and compiler debugging metadata are not executed.
            if section.name.startswith(".debug") or section.name == ".drectve":
                continue
            sections[number] = cursor
            cursor += (max(len(section.data), section.logical_size or 0, 1) + PAGE - 1) & -PAGE
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
                elif symbol.section_number == 0:
                    destination = self.address(symbol.name)
                else:
                    raise AssertionError(f"Unsupported absolute/common symbol: {symbol}")
                offset = relocation.virtual_address
                addend = struct.unpack_from("<I", data, offset)[0]
                assert relocation.relocation_type in (6, 20), relocation
                value = destination + addend
                if relocation.relocation_type == 20:
                    value -= sections[number] + offset + 4
                struct.pack_into("<I", data, offset, value & 0xFFFFFFFF)
                self.relocations.append([number, offset, relocation.relocation_type, symbol.name, destination, addend])
            self.patched_sections[sections[number]] = bytes(data)
        entry = next(symbol for symbol in self.object.symbols if symbol.name == "_creature_render_type")
        self.candidate_start = sections[entry.section_number] + entry.value
        self.candidate_end = self.candidate_start + len(self.body.data)
        header = (match.DEFAULT_MATCH_ROOT / "include/grim2d_cpp.h").read_text()
        names = re.findall(r"virtual\b[^;{]*?\b(grim_\w+)\s*\(", header)
        self.slots = {names.index(name): (name, words) for name, words in ARGUMENT_WORDS.items()}
        self.vtable = b"".join(word(API + index * 16) for index in range(len(names)))

    def address(self, name):
        values = self.catalog._addresses_for_symbol(name)
        assert len(values) == 1, (name, values)
        return values[0]

    def execute(self, side, case):
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        mu.mem_map(self.image.image_base, (self.image.size_of_image + PAGE - 1) & -PAGE)
        mu.mem_write(self.image.image_base, self.image.mapped)
        mu.mem_map(CODE, self.code_size)
        for address, data in self.patched_sections.items():
            if data:
                mu.mem_write(address, data)
        mu.mem_map(STACK, 0x10000)
        mu.mem_write(STACK, b"\xa5" * 0x10000)
        mu.mem_map(API, 0x5000)
        mu.mem_write(API, b"\xcc" * 0x1000)
        mu.mem_write(INSTANCE, word(VTABLE))
        mu.mem_write(VTABLE, self.vtable)
        mu.mem_write(self.address("grim_interface_ptr"), word(INSTANCE))
        fixture = []

        def write(address, fmt, *values):
            data = struct.pack("<" + fmt, *values)
            mu.mem_write(address, data)
            fixture.append((address, data))

        write(self.address("config_shadows_enabled"), "B", case.get("shadows", 1))
        write(self.address("config_violence_disabled"), "B", case.get("flash", 1))
        write(self.address("bonus_energizer_timer"), "f", case.get("energizer", 0.0))
        write(self.address("camera_offset_x"), "ff", 13.25, -18.5)
        pool = self.address("creature_pool")
        mu.mem_write(pool, b"\0" * (384 * 152))
        spawns = self.address("creature_spawn_slot_table")
        mu.mem_write(spawns, b"\x7f" * (24 * 32))
        indices = set()
        for ordinal, record in enumerate(case.get("creatures", [{}])):
            record = dict(record)
            index = record.pop("index", ordinal)
            assert 0 <= index < 384 and index not in indices
            indices.add(index)
            values = {
                "active": 1,
                "lifecycle_stage": 20.0,
                "pos_x": 137.3,
                "pos_y": 241.7,
                "max_health": 100.0,
                "heading": 1.4,
                "size": 32.5,
                "hit_flash_timer": 0.15,
                "tint_r": 0.8,
                "tint_g": 0.7,
                "tint_b": 0.6,
                "tint_a": 0.9,
                "type_id": 0,
                "link_index": index % 32,
                "flags": 0,
                "anim_phase": 4.2,
            }
            values.update(record)
            assert 0 <= values["link_index"] < 32
            for name, value in values.items():
                offset, fmt = FIELDS[name]
                write(pool + index * 152 + offset, fmt, value)
        for index in range(6):
            entry = self.address("creature_type_table") + 68 * index
            write(entry, "I", 100 + index)
            write(entry + 56, "I", 5)
            write(entry + 64, "I", case.get("type_anim_flags", 1))
        # Detect accidental setup overlaps before observing either implementation.
        for address, data in fixture:
            assert bytes(mu.mem_read(address, len(data))) == data, hex(address)
        esp = STACK + 0xF000
        mu.mem_write(esp, word(STOP) + word(case.get("type_id", 0)) + struct.pack("<f", case.get("transition", 0.8)))
        mu.reg_write(x86.UC_X86_REG_ESP, esp)
        mu.reg_write(x86.UC_X86_REG_FPCW, case.get("fpcw", 0x37F))
        mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        preserved = {
            x86.UC_X86_REG_EBP: 0x11110000,
            x86.UC_X86_REG_EBX: 0x22220000,
            x86.UC_X86_REG_ESI: 0x33330000,
            x86.UC_X86_REG_EDI: 0x44440000,
        }
        for register, value in preserved.items():
            mu.reg_write(register, value)
        calls, writes, coverage = [], set(), set()
        begin, end = (
            (self.native_start, self.native_end) if side == "native" else (self.candidate_start, self.candidate_end)
        )
        allowed_writes = {pool + index * 152 for index in range(384)}
        allowed_writes.update(spawns + index * 24 + byte for index in range(32) for byte in range(4))

        def return_from_observer(pop=0, value=0):
            sp = mu.reg_read(x86.UC_X86_REG_ESP)
            pc = struct.unpack("<I", mu.mem_read(sp, 4))[0]
            mu.reg_write(x86.UC_X86_REG_ESP, sp + 4 + pop)
            mu.reg_write(x86.UC_X86_REG_EAX, value)
            mu.reg_write(x86.UC_X86_REG_ECX, 0xC1C1C1C1)
            mu.reg_write(x86.UC_X86_REG_EDX, 0xD2D2D2D2)
            mu.reg_write(x86.UC_X86_REG_EFLAGS, 0x202)
            mu.reg_write(x86.UC_X86_REG_EIP, pc)

        def observe_code(_mu, pc, _size, _data):
            if begin <= pc < end:
                coverage.add(pc - begin)
            elif self.ftol_start <= pc < self.ftol_end:
                pass  # Execute the original 39-byte CRT conversion, including its rounding-mode save/restore.
            elif API <= pc < API + 0x1000:
                assert (pc - API) % 16 == 0
                name, count = self.slots[(pc - API) // 16]
                assert mu.reg_read(x86.UC_X86_REG_ECX) == INSTANCE
                sp = mu.reg_read(x86.UC_X86_REG_ESP)
                words = list(struct.unpack("<" + "I" * count, mu.mem_read(sp + 4, 4 * count))) if count else []
                if name == "grim_set_color_ptr":
                    words = list(struct.unpack("<IIII", mu.mem_read(words[0], 16)))
                elif name == "grim_set_config_var":
                    assert words[0] in (19, 20)
                    # The exact Grim2D consumer reads only words[0] for these two IDs.
                    words = words[:2]
                calls.append([name, words])
                return_from_observer(count * 4)
            elif pc == self.address("perk_count_get"):
                sp = mu.reg_read(x86.UC_X86_REG_ESP)
                calls.append(["perk_count_get", list(struct.unpack("<I", mu.mem_read(sp + 4, 4)))])
                return_from_observer(value=case.get("monster_vision", 0))
            else:
                raise AssertionError(f"Unexpected execution at {pc:#x}")

        def observe_write(_mu, _access, address, size, _value, _data):
            if self.image.image_base <= address < self.image.image_base + self.image.size_of_image:
                touched = set(range(address, address + size))
                assert touched <= allowed_writes, (hex(address), size)
                writes.update(touched)
            else:
                assert STACK <= address and address + size <= STACK + 0x10000, (hex(address), size)

        mu.hook_add(unicorn.UC_HOOK_CODE, observe_code)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, observe_write)
        mu.emu_start(begin, STOP, timeout=5_000_000, count=1_000_000)
        assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP, "Instruction/time limit reached before return"
        assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4, "Unbalanced stack"
        for register, value in preserved.items():
            assert mu.reg_read(register) == value, ("Clobbered preserved register", register)
        assert mu.reg_read(x86.UC_X86_REG_FPCW) == case.get("fpcw", 0x37F)
        return {
            "calls": calls,
            "writes": [[address, mu.mem_read(address, 1)[0]] for address in sorted(writes)],
            "coverage": sorted(coverage),
        }

    def compare(self, case):
        native, candidate = [self.execute(side, case) for side in ("native", "candidate")]
        return {
            "calls_equal": native["calls"] == candidate["calls"],
            "writes_equal": native["writes"] == candidate["writes"],
            "native": native,
            "candidate": candidate,
        }


def check_fixture_layout(config, out):
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    expressions = ["sizeof(creature_t)", "sizeof(creature_spawn_slot_t)", "sizeof(creature_type_t)"]
    expected = [152, 24, 68]
    for name, (offset, _fmt) in FIELDS.items():
        expressions.append(f"offsetof(creature_t, {name})")
        expected.append(offset)
    expressions.extend(["offsetof(creature_type_t, base_frame)", "offsetof(creature_type_t, anim_flags)"])
    expected.extend([56, 64])
    source = '#include "crimsonland_gameplay.h"\n#include <stddef.h>\nextern "C" {\n'
    source += "unsigned int execution_offsets[] = {" + ", ".join(expressions) + "};\n}\n"
    (directory / "scratch.cpp").write_text(source)
    object_path = match.compile_scratch(replace(config, directory=directory))
    obj = match.parse_coff_object(object_path.read_bytes())
    symbol = next(symbol for symbol in obj.symbols if symbol.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + 4 * len(expected)]
    assert list(struct.unpack("<" + "I" * len(expected), raw)) == expected
    return dict(zip(expressions, expected, strict=True))


def scenarios():
    rng = random.Random(20260909)
    flags = [0, 4, 16, 20, 64, 68, 80, 84]
    lives = [-11.0, -10.0, -0.25, 0.0, 0.5, 15.5, 16.0, 20.0]
    phases = [0.0, 7.0, 7.49, 7.5, 8.0, 15.0, 15.5, 16.0, 23.5, 31.0]
    records = []
    for index, (flags_value, lifecycle) in enumerate(itertools.product(flags, lives)):
        records.append(
            {
                "index": 383 if index == 63 else index,
                "flags": flags_value,
                "lifecycle_stage": lifecycle,
                "anim_phase": rng.choice(phases),
                "max_health": rng.choice([0.0, 499.9, 500.0, 700.0]),
                "hit_flash_timer": rng.choice([0.0, 0.01, 0.199, 0.2, 0.21]),
                "tint_a": rng.choice([0.1, 0.4, 0.8, 1.0]),
            },
        )
    records.extend([{"index": 64, "active": 0}, {"index": 65, "type_id": 1}])
    dimensions = itertools.product([0.0, 0.5, 1.0, 2.0], [0, 1], [0, 1], [0, 1], [0, 1], [0x37F, 0x7F])
    for energy, shadows, flash, vision, type_flags, precision in dimensions:
        yield {
            "energizer": energy,
            "shadows": shadows,
            "flash": flash,
            "monster_vision": vision,
            "type_anim_flags": type_flags,
            "fpcw": precision,
            "transition": 0.371,
            "creatures": records,
        }
    for energy in [0.0, 0.5]:
        yield {"energizer": energy, "creatures": [{"flags": 4, "anim_phase": -3.5}]}


def negative_controls():
    draw = "            grim_interface_ptr->grim_draw_quad(\n                draw_pos.x, draw_pos.y, creature->size, creature->size);"
    return [
        ("shadow-alpha", "color.a *= 0.4f;", "color.a *= 0.41f;", {"creatures": [{}]}),
        ("last-slot", "creature_index < 384", "creature_index < 383", {"creatures": [{"index": 383}]}),
        (
            "slot-release",
            "creature_spawn_slot_table[creature->link_index].owner = 0;",
            ";",
            {"creatures": [{"lifecycle_stage": -11.0, "flags": 4}]},
        ),
        ("duplicate-flash-draw", draw + "\n" + draw, draw, {"creatures": [{}]}),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4", unicorn.__version__
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    object_path = match.compile_scratch(config)
    comparison = Comparison(config, object_path)
    layout = check_fixture_layout(config, out)
    result = match.run_match(
        obj_path=object_path,
        function=FUNCTION,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    cases = list(scenarios())
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    rows, coverage = [], [set(), set()]
    for index, case in enumerate(cases):
        execution = comparison.compare(case)
        if not execution["calls_equal"] or not execution["writes_equal"]:
            (out / "failure.json").write_text(json.dumps({"case": case, **execution}, indent=2) + "\n")
            raise AssertionError(f"Execution mismatch in case {index}; see {out / 'failure.json'}")
        rows.append(
            {
                "case": index,
                "calls": len(execution["native"]["calls"]),
                "calls_sha256": sha(json.dumps(execution["native"]["calls"]).encode()),
                "writes_sha256": sha(json.dumps(execution["native"]["writes"]).encode()),
            },
        )
        for side_index, side in enumerate(("native", "candidate")):
            coverage[side_index].update(execution[side]["coverage"])
    instruction_offsets = [
        {i.offset for i in side} for side in (result.target_disassembly, result.candidate_disassembly)
    ]
    assert coverage == instruction_offsets, [
        sorted(expected - actual) for expected, actual in zip(instruction_offsets, coverage, strict=True)
    ]
    controls = []
    source = (config.directory / config.source).read_text()
    for name, old, new, case in negative_controls():
        assert old in source
        directory = out / name
        directory.mkdir(exist_ok=True)
        changed_source = source.replace(old, new)
        (directory / config.source).write_text(changed_source)
        changed_path = match.compile_scratch(replace(config, directory=directory))
        execution = Comparison(config, changed_path).compare(case)
        assert not execution["calls_equal"] or not execution["writes_equal"], f"Control {name} was not detected"
        controls.append(
            {
                "name": name,
                "source_sha256": sha(changed_source.encode()),
                "case": case,
                "calls_equal": execution["calls_equal"],
                "writes_equal": execution["writes_equal"],
            },
        )
    record = {
        "schema_version": 1,
        "function": FUNCTION,
        "unicorn": unicorn.__version__,
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "source_sha256": sha(source.encode()),
        "compiler": config.compiler,
        "cflags": config.cflags,
        "object_sha256": sha(object_path.read_bytes()),
        "compiler_files_sha256": {
            name: sha((match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes())
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")
        },
        "candidate_body_sha256": sha(comparison.body.data),
        "native_body_sha256": sha(
            comparison.image.mapped[
                comparison.native_start - comparison.image.image_base : comparison.native_end
                - comparison.image.image_base
            ],
        ),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "layout": layout,
        "match": {
            "ratio": result.ratio,
            "body_byte_exact": result.body_byte_exact,
            "exact": result.exact,
            "references_ok": result.masked_operand_audit.ok_count,
            "references_problem": result.masked_operand_audit.problem_count,
        },
        "cases_sha256": sha((out / "cases.json").read_bytes()),
        "scenarios": rows,
        "instruction_coverage": {"native": sorted(coverage[0]), "candidate": sorted(coverage[1])},
        "object_relocations": comparison.relocations,
        "negative_controls": controls,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"{len(rows)} scenarios agree; all {len(coverage[0])}/{len(coverage[1])} native/candidate instructions executed; {len(controls)} deliberate defects detected.",
    )


if __name__ == "__main__":
    main()
