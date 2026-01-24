from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
C_PATH = ROOT / "analysis/ghidra/raw/crimsonland.exe_decompiled.c"
STRINGS_PATH = ROOT / "analysis/ghidra/raw/crimsonland.exe_strings.txt"
OUT_PATH = ROOT / "src/crimson/weapons.py"
BIN_PATH = ROOT / "game_bins/crimsonland/1.9.93-gog/crimsonland.exe"

BASE_ADDR = 0x4D7A2C
END_ADDR = 0x4D99A0
STRIDE_BYTES = 0x7C

NAME_OFFSET = 0x00
CLIP_SIZE_OFFSET = 0x44
FIRE_RATE_OFFSET = 0x48
RELOAD_TIME_OFFSET = 0x4C
SPREAD_OFFSET = 0x50
FIRE_SOUND_OFFSET = 0x58
RELOAD_SOUND_OFFSET = 0x60
ICON_OFFSET = 0x64
FLAGS_OFFSET = 0x68
PROJECTILE_TYPE_OFFSET = 0x6C
DAMAGE_MULT_OFFSET = 0x70


@dataclass(frozen=True)
class Value:
    raw: str
    number: int | float | None


def load_pe_reader(path: Path) -> Callable[[int], str | None] | None:
    if not path.exists():
        return None
    data = path.read_bytes()
    if len(data) < 0x40:
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    coff = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    num_sections = coff[1]
    opt_size = coff[5]
    opt_offset = pe_offset + 4 + 20
    if opt_offset + opt_size > len(data):
        return None
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]
    elif magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    else:
        return None
    sections = []
    sect_offset = opt_offset + opt_size
    for idx in range(num_sections):
        off = sect_offset + idx * 40
        if off + 40 > len(data):
            break
        virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        span = max(virt_size, raw_size)
        sections.append((virt_addr, span, raw_ptr))

    def va_to_offset(va: int) -> int | None:
        rva = va - image_base
        if rva < 0:
            return None
        for virt_addr, span, raw_ptr in sections:
            if virt_addr <= rva < virt_addr + span:
                return raw_ptr + (rva - virt_addr)
        return None

    def read_c_string(va: int, max_len: int = 256) -> str | None:
        off = va_to_offset(va)
        if off is None:
            return None
        end = data.find(b"\x00", off, off + max_len)
        if end == -1:
            end = off + max_len
        raw = data[off:end]
        if not raw or not any(32 <= b < 127 for b in raw):
            return None
        return raw.decode("ascii", errors="ignore")

    return read_c_string


def parse_strings() -> dict[int, str]:
    addr_to_str: dict[int, str] = {}
    line_re = re.compile(r"^([0-9A-Fa-f]{8}):\s+(.*)$")
    with STRINGS_PATH.open() as fh:
        for line in fh:
            m = line_re.match(line.strip())
            if not m:
                continue
            addr = int(m.group(1), 16)
            addr_to_str[addr] = m.group(2)
    return addr_to_str


def parse_number(expr: str) -> int | float | None:
    expr = expr.strip()
    if re.fullmatch(r"-?0x[0-9A-Fa-f]+", expr):
        return int(expr, 16)
    if re.fullmatch(r"-?\d+", expr):
        return int(expr)
    if re.fullmatch(r"-?\d*\.\d+(?:[eE][+-]?\d+)?", expr):
        return float(expr)
    return None


def float_from_u32(value: int) -> float:
    return struct.unpack("<f", (value & 0xFFFFFFFF).to_bytes(4, "little"))[0]


def value_as_float(value: Value | None) -> float | None:
    if value is None:
        return None
    if isinstance(value.number, float):
        return value.number
    if isinstance(value.number, int):
        return float_from_u32(value.number)
    return None


def value_as_int(value: Value | None) -> int | None:
    if value is None:
        return None
    if isinstance(value.number, int):
        return value.number
    if isinstance(value.number, float):
        return int(value.number)
    return None


def parse_weapon_block(text: str) -> list[str]:
    lines = text.splitlines()
    start = next(
        i
        for i, line in enumerate(lines)
        if line.startswith("/* FUN_004519b0")
        or line.startswith("/* weapon_table_init @ 004519b0")
    )
    end = next(
        i
        for i, line in enumerate(lines[start + 1 :], start + 1)
        if line.startswith("/* FUN_")
    )
    return lines[start:end]


def parse_offset(sign: str | None, value: str | None) -> int:
    if not sign or not value:
        return 0
    amount = int(value)
    return amount if sign == "+" else -amount


def resolve_string(
    addr_to_str: dict[int, str],
    pe_reader: Callable[[int], str | None] | None,
    addr: int,
) -> str | None:
    name = addr_to_str.get(addr)
    if name:
        return name
    if pe_reader:
        return pe_reader(addr)
    return None


def main() -> None:
    addr_to_str = parse_strings()
    block = parse_weapon_block(C_PATH.read_text())
    pe_reader = load_pe_reader(BIN_PATH)

    entries: list[dict[int, Value]] = [dict() for _ in range((END_ADDR - BASE_ADDR) // STRIDE_BYTES)]
    names: dict[int, str] = {}

    current_str_addr: int | None = None
    current_str_offset = 0

    str_src_re = re.compile(
        r"pcVar7\s*=\s*s_[A-Za-z0-9_]+_([0-9A-Fa-f]{8})(?:\s*([+-])\s*(\d+))?"
    )
    str_src_dat_re = re.compile(
        r"pcVar7\s*=\s*&DAT_([0-9A-Fa-f]{8})(?:\s*([+-])\s*(\d+))?"
    )
    str_dst_re = re.compile(r"pcVar8\s*=\s*\(char \*\)&DAT_([0-9A-Fa-f]{8})")
    assign_re = re.compile(r"(?P<dst>_?DAT_[0-9A-Fa-f]{8})\s*=\s*(?P<src>[^;]+);")

    for line in block:
        m = str_src_re.search(line)
        if m:
            current_str_addr = int(m.group(1), 16)
            current_str_offset = parse_offset(m.group(2), m.group(3))

        m = str_src_dat_re.search(line)
        if m:
            current_str_addr = int(m.group(1), 16)
            current_str_offset = parse_offset(m.group(2), m.group(3))

        m = str_dst_re.search(line)
        if m and current_str_addr is not None:
            dst_addr = int(m.group(1), 16)
            if BASE_ADDR <= dst_addr < END_ADDR:
                entry = (dst_addr - BASE_ADDR) // STRIDE_BYTES
                offset = (dst_addr - BASE_ADDR) % STRIDE_BYTES
                if offset == NAME_OFFSET:
                    name = resolve_string(
                        addr_to_str,
                        pe_reader,
                        current_str_addr + current_str_offset,
                    )
                    if name:
                        names[entry] = name
            current_str_addr = None
            current_str_offset = 0

        m = assign_re.search(line)
        if not m:
            continue
        dst_addr = int(m.group("dst").split("_")[-1], 16)
        if not (BASE_ADDR <= dst_addr < END_ADDR):
            continue
        src = m.group("src").strip()
        if "," in src:
            src = src.split(",", 1)[0].strip()
        entry = (dst_addr - BASE_ADDR) // STRIDE_BYTES
        offset = (dst_addr - BASE_ADDR) % STRIDE_BYTES
        entries[entry][offset] = Value(raw=src, number=parse_number(src))

    lines: list[str] = []
    lines.append("from __future__ import annotations\n")
    lines.append("\n")
    lines.append('"""\n')
    lines.append("Weapon table extracted from FUN_004519b0.\n")
    lines.append("\n")
    lines.append("Generated by scripts/extract_weapon_table.py.\n")
    lines.append('"""\n')
    lines.append("\n")
    lines.append("from dataclasses import dataclass\n")
    lines.append("\n")
    lines.append("@dataclass(frozen=True)\n")
    lines.append("class Weapon:\n")
    lines.append("    weapon_id: int\n")
    lines.append("    name: str | None\n")
    lines.append("    clip_size: int | None\n")
    lines.append("    fire_rate: float | None\n")
    lines.append("    reload_time: float | None\n")
    lines.append("    spread: float | None\n")
    lines.append("    fire_sound: str | None\n")
    lines.append("    reload_sound: str | None\n")
    lines.append("    icon_index: int | None\n")
    lines.append("    flags: int | None\n")
    lines.append("    projectile_type: int | None\n")
    lines.append("    damage_mult: float | None\n")
    lines.append("\n")
    lines.append("\n")
    lines.append("WEAPON_TABLE = [\n")
    for idx, fields in enumerate(entries):
        if not fields and idx not in names:
            continue
        name = names.get(idx)
        clip_size = value_as_int(fields.get(CLIP_SIZE_OFFSET))
        fire_rate = value_as_float(fields.get(FIRE_RATE_OFFSET))
        reload_time = value_as_float(fields.get(RELOAD_TIME_OFFSET))
        spread = value_as_float(fields.get(SPREAD_OFFSET))
        fire_sound = fields.get(FIRE_SOUND_OFFSET).raw if fields.get(FIRE_SOUND_OFFSET) else None
        reload_sound = (
            fields.get(RELOAD_SOUND_OFFSET).raw if fields.get(RELOAD_SOUND_OFFSET) else None
        )
        icon_index = value_as_int(fields.get(ICON_OFFSET))
        flags = value_as_int(fields.get(FLAGS_OFFSET))
        projectile_value = value_as_float(fields.get(PROJECTILE_TYPE_OFFSET))
        if projectile_value is None and idx > 0:
            # Most weapons use the default projectile meta (0x6c) of 45.0.
            # Runtime probe (2026-01-18) confirms this for multiple entries.
            projectile_value = 45.0
        projectile_type = None if projectile_value is None else int(round(projectile_value))
        damage_mult = value_as_float(fields.get(DAMAGE_MULT_OFFSET))
        if damage_mult is None and idx > 0:
            # Most weapons use the default damage scale (0x70) of 1.0.
            # Runtime probe (2026-01-18) confirms this for multiple entries.
            damage_mult = 1.0
        lines.append("    Weapon(\n")
        lines.append(f"        weapon_id={idx - 1},\n")
        lines.append(f"        name={name!r},\n")
        lines.append(f"        clip_size={clip_size!r},\n")
        lines.append(f"        fire_rate={fire_rate!r},\n")
        lines.append(f"        reload_time={reload_time!r},\n")
        lines.append(f"        spread={spread!r},\n")
        lines.append(f"        fire_sound={fire_sound!r},\n")
        lines.append(f"        reload_sound={reload_sound!r},\n")
        if icon_index is None and idx - 1 >= -1:
            icon_index = idx - 1
        lines.append(f"        icon_index={icon_index!r},\n")
        lines.append(f"        flags={flags!r},\n")
        lines.append(f"        projectile_type={projectile_type!r},\n")
        lines.append(f"        damage_mult={damage_mult!r},\n")
        lines.append("    ),\n")
    lines.append("]\n")
    lines.append("\n")
    lines.append("WEAPON_BY_ID = {\n")
    lines.append("    entry.weapon_id: entry for entry in WEAPON_TABLE\n")
    lines.append("}\n")
    lines.append("\n")
    lines.append("WEAPON_BY_NAME = {\n")
    lines.append("    entry.name: entry for entry in WEAPON_TABLE if entry.name is not None\n")
    lines.append("}\n")

    OUT_PATH.write_text("".join(lines))


if __name__ == "__main__":
    main()
