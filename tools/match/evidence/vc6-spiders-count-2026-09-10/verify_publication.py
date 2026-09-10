"""Check bounded Spiders output and publication traces against the native body.

Requires optional unicorn==2.1.4 and JIT permission. This is not an exact-match
certificate or a proof over every possible input or alias arrangement.
"""

import argparse
import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path

import unicorn
from unicorn import x86_const as x86

from crimson import match

HERE = Path(__file__).resolve().parent
FUNCTION = "quest_build_spiders_inc"
PAGE = 4096
CODE = 0x10000000
STACK = 0x20000000
ENTRIES = 0x30000000
COUNT = 0x30001000
STOP = 0x30002000
EARLY_SHA = "36596b7961beb2da9bb0cedab291af0e5eb4b56a5c398b46d3d11f38cf658338"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def page_size(size):
    return (max(size, 1) + PAGE - 1) & -PAGE


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
        self.width_address = self.address("terrain_texture_width")
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
        entry = next(symbol for symbol in self.object.symbols if symbol.name == "_quest_build_spiders_inc")
        self.candidate_start = sections[entry.section_number] + entry.value

    def address(self, name):
        addresses = self.catalog._addresses_for_symbol(name)
        assert len(addresses) == 1, (name, addresses)
        return addresses[0]

    def execute(self, native, width):
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        mu.mem_map(self.image.image_base, page_size(self.image.size_of_image))
        mu.mem_write(self.image.image_base, self.image.mapped)
        mu.mem_map(CODE, self.code_size)
        for address, data in self.patched_sections.items():
            if data:
                mu.mem_write(address, data)
        mu.mem_map(STACK, 0x10000)
        mu.mem_write(STACK, b"\xa5" * 0x10000)
        mu.mem_map(ENTRIES, 0x3000)
        mu.mem_write(ENTRIES, b"\xa5" * PAGE)
        mu.mem_write(COUNT, struct.pack("<I", 0xDEADBEEF))
        mu.mem_write(self.width_address, struct.pack("<i", width))
        esp = STACK + 0xF000
        mu.mem_write(esp, struct.pack("<III", STOP, ENTRIES, COUNT))
        mu.reg_write(x86.UC_X86_REG_ESP, esp)
        mu.reg_write(x86.UC_X86_REG_FPCW, 0x37F)
        mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        preserved = {
            x86.UC_X86_REG_EBP: 0x11110000,
            x86.UC_X86_REG_EBX: 0x22220000,
            x86.UC_X86_REG_ESI: 0x33330000,
            x86.UC_X86_REG_EDI: 0x44440000,
        }
        for register, value in preserved.items():
            mu.reg_write(register, value)
        start = self.native_start if native else self.candidate_start
        lines = self.result.target_disassembly if native else self.result.candidate_disassembly
        expected_pcs = {start + line.offset for line in lines}
        writes, coverage = [], set()

        def on_code(_mu, address, _size, _data):
            assert address in expected_pcs, hex(address)
            coverage.add(address)

        def on_write(_mu, _access, address, size, value, _data):
            if STACK <= address < STACK + 0x10000:
                assert address + size <= STACK + 0x10000
                return
            assert size == 4 and (ENTRIES <= address < ENTRIES + 33 * 24 or address == COUNT), hex(address)
            writes.append([address - ENTRIES, size, value & 0xFFFFFFFF])

        mu.hook_add(unicorn.UC_HOOK_CODE, on_code)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
        mu.emu_start(start, STOP, count=100000)
        assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP
        assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4
        assert all(mu.reg_read(register) == value for register, value in preserved.items())
        assert coverage == expected_pcs, "A body instruction was not exercised"
        assert struct.unpack("<I", mu.mem_read(COUNT, 4))[0] == 33
        assert len(writes) == 166
        output = bytes(mu.mem_read(ENTRIES, PAGE))
        assert output == expected_output(width)
        return output, writes, len(coverage)


def expected_output(width):
    half = abs(width) // 2 * (-1 if width < 0 else 1)
    records = [(half, width + 64, 0x38, 500, 1), (half + 64, width + 64, 0x38, 500, 1), (half, -64, 0x40, 500, 4)]
    for step in range(15):
        for y in (width + 64, -64):
            records.append((half, y, 0x38, 17000 + step * 6000, step // 2 + 3))
    data = bytearray(b"\xa5" * PAGE)
    for index, (x, y, template, trigger, amount) in enumerate(records):
        struct.pack_into("<ff", data, index * 24, float(x), float(y))
        struct.pack_into("<iii", data, index * 24 + 12, template, trigger, amount)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / FUNCTION)
    current = Program(config)
    early_source = (HERE / "early-field.cpp").read_bytes()
    assert sha(early_source) == EARLY_SHA
    directory = out / "early-source"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_bytes(early_source)
    early = Program(replace(config, directory=directory))
    result = current.result
    assert len(result.target_lines) == len(result.candidate_lines) == 105
    assert result.masked_operand_audit.ok_count == 8 and result.masked_operand_audit.problem_count == 0
    assert result.exact and result.body_byte_exact
    rows = []
    example = None
    for width in (-3, -2, -1, 0, 1, 2, 3, 511, 512, 1023, 1024, 1025, 2048, 4096, 8192):
        native_output, native_writes, native_coverage = current.execute(True, width)
        candidate_output, candidate_writes, candidate_coverage = current.execute(False, width)
        early_output, early_writes, early_coverage = early.execute(False, width)
        assert native_output == candidate_output == early_output
        assert native_writes == candidate_writes
        assert native_writes != early_writes, "Historical early publication was not rejected"
        first_difference = next(
            index for index, (a, b) in enumerate(zip(native_writes, early_writes, strict=True)) if a != b
        )
        rows.append(
            {
                "width": width,
                "output_sha256": sha(native_output),
                "publication_sha256": sha(json.dumps(native_writes).encode()),
                "publication_writes": len(native_writes),
                "covered_instructions": [native_coverage, candidate_coverage, early_coverage],
                "early_publication_first_difference": first_difference,
            },
        )
        if width == 1024:
            example = {"native_and_candidate": native_writes, "historical_early": early_writes}
    payload = {
        "schema": 1,
        "verified": True,
        "limitations": "15 concrete widths, disjoint output/count/global storage, x87 control word 0x037f. "
        "Checks every executed body instruction, output bytes and non-stack write order. "
        "Not universal semantic equivalence or normalized/encoded-body exactness.",
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "historical_early_source_sha256": EARLY_SHA,
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "native_target": {
            "function": FUNCTION,
            "start": current.native_start,
            "size": current.native_end - current.native_start,
            "body_sha256": sha(current.image.function_bytes(current.native_start, current.native_end)),
        },
        "unicorn_version": unicorn.__version__,
        "candidate_body_sha256": sha(current.body.data),
        "candidate_object_sha256": sha(current.object_path.read_bytes()),
        "relocations": current.relocations,
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "match": {
            "ratio": result.ratio,
            "instructions": [len(result.target_lines), len(result.candidate_lines)],
            "references": [8, 0, 0],
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
        },
        "cases": rows,
        "publication_example_width_1024": example,
    }
    (out / "publication.json").write_text(json.dumps(payload, indent=2) + "\n")
    print("Verified 15 full-body output/publication comparisons; rejected the early-store control in every case")


if __name__ == "__main__":
    main()
