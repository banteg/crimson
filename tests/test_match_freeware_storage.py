from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from crimson_re import match as m
from crimson_re import match_freeware_storage as storage


def _object(name, data, *, bss=0, comdat=True):
    sym = m.CoffSymbol(0, name, 0, 1, 0, m.IMAGE_SYM_CLASS_EXTERNAL)
    flags = m.IMAGE_SCN_CNT_UNINITIALIZED_DATA if bss else 0x40
    if comdat:
        flags |= m.IMAGE_SCN_LNK_COMDAT
    section = m.CoffSection(".bss" if bss else ".data", data, flags, (), index=1,
                            logical_size=bss or len(data), comdat_key=name if comdat else None)
    return m.CoffObject((section,), (sym,))


def _image(data):
    return m.LoadedImage(data, 0x401000, len(data))


@pytest.mark.parametrize(("name", "data", "size"), [
    ("??_C@_05example", b"h\0A\0B\0", 6),
    ("??_C@_1BE@example", ("0123456789"[:9] + "\0").encode("utf-16le"), 20),
    ("__real@8@3ffd8000000000000000", struct.pack("<d", .25), 8),
])
def test_compiler_literals_have_exact_local_extents(name, data, size):
    obj = _object(name, data + b"\xaa\xaa")
    image = _image(data + b"\xbb\xbb")
    receipt = storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={}, relocations={})
    assert receipt and receipt["size"] == size
    storage.validate(receipt, image, relocations={})
    assert storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={},
                         relocations={image.image_base - 1: 3}) is None
    with pytest.raises(ValueError, match="initializer differs"):
        storage.validate(receipt, _image(bytes(size)), relocations={})


def test_common_size_and_compiled_scalar_preserve_unmatched_bytes():
    size = 5
    common = m.CoffSymbol(0, "_common", size, 0, 0, m.IMAGE_SYM_CLASS_EXTERNAL)
    obj = m.CoffObject((), (common,))
    image = _image(bytes(size))
    row = storage.prove(obj, common, image.image_base, image, bindings={}, relocations=None)
    assert row and row["storage"] == "coff-common" and row["size"] == size
    assert storage.prove(obj, common, image.image_base, image, bindings={}, relocations=None, declared_size=4) is None
    assert storage.prove(obj, replace(common, value=0), image.image_base, image, bindings={}, relocations=None) is None
    assert storage.prove(obj, common, image.image_base, _image(b"\0\0\0\0!"), bindings={}, relocations=None) is None

    obj = _object("?flag@@3EA", b"", bss=8, comdat=False)
    row = storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={}, relocations={})
    assert row and (row["size"], row["storage"]) == (1, "coff-bss")
    array = _object("?array@@3PAHA", b"\0" * 4)
    assert storage.prove(array, array.symbols[0], image.image_base, image, bindings={}, relocations={}) is None


def test_pointer_initializers_require_symbolic_targets_offsets_and_original_fixups():
    start, target = 0x401000, 0x402010
    obj = _object("_callbacks", struct.pack("<2i", 0, -4))
    section, = obj.sections
    target_symbol = m.CoffSymbol(1, "_other", 0, 0, 0, m.IMAGE_SYM_CLASS_EXTERNAL)
    obj = replace(obj, sections=(replace(section, relocations=(m.CoffRelocation(4, 1, m.IMAGE_REL_I386_DIR32),)),),
                  symbols=(*obj.symbols, target_symbol))
    image = _image(struct.pack("<2I", 0, target - 4))
    sites = {start + 4: 3}
    bindings = {1: target}
    receipt = storage.prove(obj, obj.symbols[0], start, image, declared_size=8, relocations=sites, bindings=bindings)
    assert receipt and receipt["relocations"] == [{"offset": 4, "symbol": "_other", "target": target, "addend": -4}]
    storage.validate(receipt, image, relocations=sites)
    for size, targets, relocs in ((8, {}, sites), (8, {1: target + 1}, sites), (8, bindings, {}),
                                  (8, bindings, {start + 4: 10}), (7, bindings, sites)):
        assert storage.prove(obj, obj.symbols[0], start, image, declared_size=size, relocations=relocs, bindings=targets) is None
    with pytest.raises(ValueError, match="pointer relocation"):
        storage.validate({**receipt, "relocations": [dict(receipt["relocations"][0], target=0)]},
                         image, relocations=sites)
    with pytest.raises(ValueError, match="pointer sites"):
        storage.validate(dict(receipt, relocations=[]), image, relocations=sites)


def test_untyped_definition_requires_extent_and_cannot_overlap_other_symbols():
    obj = _object("_pool", b"ABCD", comdat=False)
    image = _image(b"ABCD")
    assert storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={}, relocations={}) is None
    symbol = replace(obj.symbols[0], raw_index=1, value=2, name="_interior")
    assert storage.prove(replace(obj, symbols=(*obj.symbols, symbol)), obj.symbols[0], image.image_base, image,
                         bindings={}, relocations={}, declared_size=4) is None


def test_saved_literal_evidence_checks_symbol_width_and_terminator_independently_of_byte_hash():
    import hashlib

    obj = _object("__real@8@3ffd8000000000000000", bytes(8))
    image = _image(bytes(8))
    receipt = storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={}, relocations=None)
    assert receipt
    with pytest.raises(ValueError, match="decorated COFF symbol"):
        storage.validate(dict(receipt, size=4, initializer_sha256=hashlib.sha256(bytes(4)).hexdigest()),
                         image, relocations=None)
    with pytest.raises(ValueError, match="decorated COFF symbol"):
        storage.validate(dict(receipt, extent_evidence="vc6-sizeof"), image, relocations=None)

    obj = _object("??_C@_03short", b"abc\0")
    image = _image(b"abc\0")
    receipt = storage.prove(obj, obj.symbols[0], image.image_base, image, bindings={}, relocations=None)
    assert receipt
    with pytest.raises(ValueError, match="initializer differs"):
        storage.validate(dict(receipt, initializer_sha256=hashlib.sha256(b"abcd").hexdigest()),
                         _image(b"abcd"), relocations=None)


def test_primary_vtable_requires_its_own_read_only_comdat_with_a_dir32_at_every_slot():
    obj = _object("??_7ITest@@6B@", bytes(8))
    table, = obj.symbols
    method = m.CoffSymbol(1, "?draw@ITest@@UAEXXZ", 0, 0, 0, m.IMAGE_SYM_CLASS_EXTERNAL)
    relocs = tuple(m.CoffRelocation(offset, 1, m.IMAGE_REL_I386_DIR32) for offset in (0, 4))
    section = replace(obj.sections[0], name=".rdata", relocations=relocs)
    obj = replace(obj, sections=(section,), symbols=(table, method))
    target = 0x401a00
    image = _image(struct.pack("<II", target, target))
    pe = {image.image_base: 3, image.image_base + 4: 3}
    row = storage.prove(obj, table, image.image_base, image, bindings={1: target}, relocations=pe)
    assert row and (row["size"], row["extent_evidence"]) == (8, "vc6-vtable-comdat")
    storage.validate(row, image, relocations=pe)
    for invalid in (replace(section, relocations=relocs[:1]), replace(section, relocations=relocs + relocs[:1]),
                    replace(section, comdat_key=None), replace(section, name=".data"), replace(section, logical_size=7)):
        assert storage.prove(replace(obj, sections=(invalid,)), table, image.image_base, image,
                             bindings={1: target}, relocations=pe) is None
    with pytest.raises(ValueError, match="requires a zero-addend"):
        storage.validate(dict(row, relocations=row["relocations"][:1]), image, relocations=None)
    with pytest.raises(ValueError, match="virtual table extent"):
        storage.validate(dict(row, extent_evidence="vc6-sizeof"), image, relocations=pe)
