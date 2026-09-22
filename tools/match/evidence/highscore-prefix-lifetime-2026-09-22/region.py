"""Strict row byte audit with five explicit stack-home bindings; not exactness credit."""

import struct

import capstone

from crimson import match

NBASE, START, END = 0x4423D0, 0x77D, 0x8A9
STACK_MAPS = {
    'prefix-before-clear': {0x14: 0x2C, 0x24: 0x14, 0x34: 0x20, 0x4C: 0x1C, 0x28: 0x18},
    'row-plus-widget-labels': {0x14: 0x14, 0x24: 0x28, 0x34: 0x2C, 0x4C: 0x24, 0x28: 0x54},
}


def audit(name, code, relocations, stack_map=None):
    image = match.load_image(match.default_image_path())
    native = image.mapped[NBASE + START - image.image_base:NBASE + END - image.image_base]
    patched = bytearray(code)
    for offset, address, kind in relocations:
        # Absolute fields already resolve to the native data; translate only calls.
        if kind == 20:
            struct.pack_into('<I', patched, offset, (address - (NBASE + offset + 4)) & 0xFFFFFFFF)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    target = list(md.disasm(native, NBASE + START))
    candidate = list(md.disasm(patched[START:END], NBASE + START))
    assert len(target) == len(candidate)
    assert sum(n.size for n in target) == END - START
    mapping = STACK_MAPS[name] if stack_map is None else stack_map
    assert len(mapping) == 5 and len(set(mapping.values())) == 5
    inverse = {v: k for k, v in mapping.items()}
    by_address = {n.address: n for n in target}
    depths = {NBASE + START: 0}
    pending = [NBASE + START]
    while pending:
        pc = pending.pop()
        if pc == NBASE + END:
            assert depths[pc] == 0
            continue
        n = by_address[pc]
        new = depths[pc]
        if n.mnemonic == 'push':
            new += 4
        elif n.mnemonic == 'pop':
            new -= 4
        elif n.mnemonic in ('add', 'sub') and n.op_str.startswith('esp, '):
            new += n.operands[1].imm * (-1 if n.mnemonic == 'add' else 1)
        successors = [] if n.mnemonic == 'jmp' else [pc + n.size]
        if n.group(capstone.CS_GRP_JUMP):
            successors.append(n.operands[0].imm)
        for dest in successors:
            assert dest in by_address or dest == NBASE + END
            if dest in depths:
                assert depths[dest] == new
            else:
                depths[dest] = new
                pending.append(dest)
    assert len(depths) == len(target) + 1
    differences = []
    references = 0
    homes = set()
    for t, c in zip(target, candidate, strict=True):
        assert t.address == c.address and t.size == c.size
        depth = depths[t.address]
        nstack = [o for o in t.operands if o.type == capstone.x86.X86_OP_MEM
                  and o.mem.base == capstone.x86.X86_REG_ESP]
        cstack = [o for o in c.operands if o.type == capstone.x86.X86_OP_MEM
                  and o.mem.base == capstone.x86.X86_REG_ESP]
        assert len(nstack) == len(cstack) <= 1
        if nstack:
            ndisp, cdisp = nstack[0].mem.disp, cstack[0].mem.disp
            assert ndisp - depth == inverse[cdisp - depth]
            assert t.disp_size == c.disp_size == 1
            homes.add(ndisp - depth)
            references += 1
            if ndisp != cdisp:
                differences.append({'offset': c.address - NBASE + c.disp_offset,
                                    'native': ndisp, 'candidate': cdisp,
                                    'native_home': ndisp - depth, 'stack_depth': depth})
            patched[c.address - NBASE + c.disp_offset] = ndisp & 0xFF
    assert homes == set(mapping)
    assert patched[START:END] == native
    return {'instructions': len(target), 'bytes': len(native), 'stack_references': references,
            'stack_map': mapping, 'different_stack_displacement_bytes': differences,
            'all_other_bytes_equal_after_audited_relocation': True,
            'literal_branch_bytes_equal': True,
            'exact_match_credit': False}
