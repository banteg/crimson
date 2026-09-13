"""Check the full positional correspondence, recording every permitted residual."""

import importlib.util
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "projectile_frame_depths",
    HERE.parent / "projectile-stack-groups-2026-09-13" / "primary_homes.py",
)
homes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(homes)
STACK = re.compile(r"\[esp(?:\+0x([0-9a-f]+))?\]")


def shape(line):
    return re.sub(r"L[0-9a-f]+", "BRANCH", STACK.sub("[STACK]", line.text))


def inspect(native, candidate, listing, metadata, *, allow_residuals=False):
    nd, cd = homes.frame_depths(native), homes.frame_depths(candidate)
    pairs, residuals = [], []
    i = j = 0
    while i < len(native) and j < len(candidate):
        a, b = native[i], candidate[j]
        if shape(a) == shape(b):
            pairs.append((i, j))
            i += 1
            j += 1
        elif allow_residuals and (i == 0 or i == len(native) - 2):
            assert a.text.startswith(("add esp,", "sub esp,"))
            assert b.text.startswith(a.text.split(",")[0] + ",")
            pairs.append((i, j))
            residuals.append({"kind": "frame", "native": a.text, "candidate": b.text})
            i += 1
            j += 1
        elif allow_residuals and a.address == 0x421AAA:
            assert [n.text for n in native[i : i + 2]] == ["fld dword [esi]", "fmul dword [esi+-0x4]"]
            assert [n.text for n in candidate[j : j + 2]] == ["fld dword [esi+-0x4]", "fmul dword [esi]"]
            pairs.extend(((i, j), (i + 1, j + 1)))
            residuals.append({"kind": "radius-operand-order", "native": a.address, "candidate": b.offset})
            i += 2
            j += 2
        elif allow_residuals and a.address == 0x421CB3:
            assert b.text == native[i + 1].text == "fpatan"
            assert shape(a) == shape(candidate[j + 1])
            pairs.extend(((i, j + 1), (i + 1, j)))
            residuals.append({"kind": "reorder", "native": a.address, "candidate": b.offset})
            i += 2
            j += 2
        elif allow_residuals and a.address == 0x422409:
            assert b.text == "fxch st(0), st(1)"
            assert shape(a) == shape(candidate[j + 1])
            residuals.append({"kind": "extra-fxch", "native": a.address, "candidate": b.offset})
            j += 1
        else:
            raise AssertionError((i, j, a.text, b.text))
    assert i == len(native) and j == len(candidate)
    offsets = {candidate[j].offset: native[i].offset for i, j in pairs}
    branches = references = accesses = 0
    differences, labels = [], {}
    records, offset = {}, None
    for line in listing.splitlines():
        if found := re.match(r"  ([0-9a-f]{5})\s", line):
            offset = int(found[1], 16)
            records[offset] = line
        elif offset is not None and line.startswith("\t"):
            records[offset] += " " + line
    symbols = {
        row["name"]: row["offset"] + metadata["stack_layout"]["prologue_allocation_bytes"] + 16
        for row in metadata["stack_layout"]["symbols"]
    }
    for i, j in pairs:
        a, b = native[i], candidate[j]
        if branch := re.fullmatch(r"j\w+ L([0-9a-f]+)", a.text):
            other = re.fullmatch(r"j\w+ L([0-9a-f]+)", b.text)
            assert other and offsets[int(other[1], 16)] == int(branch[1], 16)
            branches += 1
        assert len(a.masked_references) == len(b.masked_references)
        for left, right in zip(a.masked_references, b.masked_references, strict=True):
            assert left.explained and right.explained and set(left.keys).intersection(right.keys)
            references += 1
        aa, bb = STACK.findall(a.text), STACK.findall(b.text)
        assert len(aa) == len(bb)
        names = [name for name in symbols if re.search(re.escape(name) + r"(?=\b|\+|\[|\s)", records.get(b.offset, ""))]
        assert len(names) <= 1
        for left, right in zip(aa, bb, strict=True):
            na, ca = int(left or "0", 16) + nd[i], int(right or "0", 16) + cd[j]
            accesses += 1
            if na != ca:
                differences.append(
                    {"native": a.address, "candidate": b.offset, "native_home": na, "candidate_home": ca},
                )
            if names:
                name = names[0]
                row = labels.setdefault(name, {"candidate_base": symbols[name], "native_bases": set(), "accesses": 0})
                row["native_bases"].add(na - (ca - symbols[name]))
                row["accesses"] += 1
    for row in labels.values():
        row["native_bases"] = sorted(row["native_bases"])
    if not allow_residuals:
        assert not residuals and not differences
    return {
        "paired_instructions": len(pairs),
        "branches": branches,
        "references": references,
        "stack_accesses": accesses,
        "stack_differences": differences,
        "residuals": residuals,
        "labels": labels,
        "scope": "All mapped instructions, references and branch destinations are checked. Named homes label candidate declarations, not original source names. Only the explicit residual list and stack differences are excluded; encoded identity is checked separately by the native matcher.",
    }
