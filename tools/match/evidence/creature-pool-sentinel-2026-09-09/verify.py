"""Derive the creature storage extent from the original constructor's writes."""

import argparse
import hashlib
import json
from pathlib import Path

import capstone

from crimson import match


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = match.load_function_manifest(scope="all")
    catalog = match.load_reference_catalog(manifest)
    (pool,) = catalog._addresses_for_symbol("creature_pool")
    start, end = match.resolve_function(manifest, "creature_pool_global_init")[1:]
    image = match.load_image(match.default_image_path())
    body = image.mapped[start - image.image_base : end - image.image_base]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    instructions = {instruction.address: instruction for instruction in md.disasm(body, start)}
    registers = {}
    writes = {}
    stores = []
    zero = None
    pc = start

    def value(operand):
        if operand.type == capstone.CS_OP_IMM:
            return operand.imm
        assert operand.type == capstone.CS_OP_REG
        name = md.reg_name(operand.reg)
        return registers["ecx"] & 0xFF if name == "cl" else registers[name]

    # Interpret only this small integer constructor. Unsupported instructions,
    # reads, registers, addressing modes, or control transfers fail closed.
    for _executed in range(10000):
        instruction = instructions[pc]
        operands = instruction.operands
        following = pc + instruction.size
        if instruction.mnemonic == "ret":
            break
        if instruction.mnemonic == "mov":
            destination, source = operands
            result = value(source)
            if destination.type == capstone.CS_OP_REG:
                registers[md.reg_name(destination.reg)] = result & 0xFFFFFFFF
            else:
                assert destination.type == capstone.CS_OP_MEM
                memory = destination.mem
                assert memory.index == 0 and memory.segment == 0
                address = registers[md.reg_name(memory.base)] + memory.disp
                raw = (result & ((1 << (destination.size * 8)) - 1)).to_bytes(destination.size, "little")
                stores.append((address, raw))
                for offset, byte in enumerate(raw):
                    assert address + offset not in writes
                    writes[address + offset] = byte
        elif instruction.mnemonic == "xor":
            left, right = operands
            assert left.type == right.type == capstone.CS_OP_REG and left.reg == right.reg
            registers[md.reg_name(left.reg)] = 0
            zero = True
        elif instruction.mnemonic in ("add", "dec"):
            destination = operands[0]
            assert destination.type == capstone.CS_OP_REG
            name = md.reg_name(destination.reg)
            delta = value(operands[1]) if instruction.mnemonic == "add" else -1
            registers[name] = (registers[name] + delta) & 0xFFFFFFFF
            zero = registers[name] == 0
        elif instruction.mnemonic == "jne":
            assert zero is not None
            if not zero:
                following = value(operands[0])
                assert following in instructions
        else:
            raise AssertionError(instruction.mnemonic)
        pc = following
    else:
        raise AssertionError("Constructor did not return within its instruction bound")

    required_size = max(writes) + 1 - pool
    stride = 0x98
    assert min(writes) == pool and required_size % stride == 0
    count = required_size // stride
    assert count == 0x181
    first_record = sorted((address - pool, byte) for address, byte in writes.items() if pool <= address < pool + stride)
    for index in range(count):
        record = sorted(
            (address - pool - index * stride, byte)
            for address, byte in writes.items()
            if pool + index * stride <= address < pool + (index + 1) * stride
        )
        assert record == first_record
    definitions = json.loads(Path("tools/native/data_definitions/crimsonland.exe.json").read_text())
    rows = definitions["entries"]
    definition = next(row for row in rows if row["name"] == "creature_pool")
    assert definition["size"] == required_size
    initial = image.mapped[pool - image.image_base : pool - image.image_base + required_size]
    assert initial == bytes(required_size)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_pool_global_init")
    obj = match.compile_scratch(config)
    result = match.run_match(
        obj_path=obj,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    assert result.exact and result.body_byte_exact and result.masked_operand_audit.problem_count == 0
    record = {
        "schema_version": 1,
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "constructor_address": start,
        "constructor_size": len(body),
        "constructor_sha256": sha(body),
        "instructions_interpreted": _executed + 1,
        "constructor_exact": result.exact,
        "constructor_body_byte_exact": result.body_byte_exact,
        "pool_address": pool,
        "record_stride": stride,
        "constructed_records": count,
        "required_storage_bytes": required_size,
        "writes_per_record": len(stores) // count,
        "written_bytes_per_record": len(first_record),
        "record_byte_writes": first_record,
        "sentinel_start": pool + 384 * stride,
        "storage_end_exclusive": pool + required_size,
        "initial_storage_sha256": sha(initial),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"Original constructor writes {count} records requiring {required_size} bytes; candidate remains exact and body-byte-exact.",
    )


if __name__ == "__main__":
    main()
