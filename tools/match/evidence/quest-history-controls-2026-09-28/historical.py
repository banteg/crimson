"""Extract local historical installers as data and compare the timeline bodies."""

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

import capstone
import pefile

from crimson_re import match

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PACKAGES = (
    (
        "1.9.1", "CrimsonlandSetup-2003.exe",
        "f3f85f1ea647b5173583d49eea80cba28fd449ba84d90736b4e845ff082e6e2b",
        "crimsonland.exe", "4893b64fb1468c08dd2a21e2ab02fd8b3984280e8cde59b4a37921b5f876edc1",
        0x430AA0, 368,
    ),
    (
        "1.9.8", "CrimsonlandSetup-2004.exe",
        "3be3fc79f2d5611c2bb5820035f29b4bced1e6410d0a2af14ddf73ddbdda8a2d",
        "crimsonland.exe", "0a6217c2638886699935213dcf5b75c528347f244f5d845066598d34a7b2052e",
        0x4338C0, 367,
    ),
    (
        "1.9.9", "cland199.zip",
        "deeb915660fdc78df6eeff343aa7a5c894704eac1b04c71a69a44692de401522",
        "crimsonland.RWG", "8f4c81a2e06f8d75867516d77929510da272b98ad35737da6fcd93ad56d1e0cf",
        0x434370, 368,
    ),
)
TRIPLET = bytes.fromhex("8d7e0c897c2410895c2410")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def repair_loader(data):
    """Fix stale absolute loader offsets in a temporary copy, never the package."""
    data = bytearray(data)
    table = data.rfind(b"rDlPtS")
    header = data.rfind(b"Inno Setup Setup Data (")
    assert table >= 0 and header >= 0
    magic = bytes(data[table : table + 12])
    layouts = {
        b"rDlPtS02\x87eVx": (8, 6, (0, 1, 5, 6, 7), None),
        b"rDlPtS07\x87eVx": (7, 4, (0, 1, 4, 5), 36),
        b"rDlPtS\xcd\xe6\xd7{\x0b*": (8, 5, (1, 2, 5, 6), 40),
    }
    count, header_index, offsets, checksum = layouts[magic]
    values = list(struct.unpack_from(f"<{count}I", data, table + 12))
    delta = header - values[header_index]
    for index in offsets:
        values[index] += delta
    struct.pack_into(f"<{count}I", data, table + 12, *values)
    if checksum is not None:
        struct.pack_into("<I", data, table + checksum, zlib.crc32(data[table : table + checksum]))
    struct.pack_into("<4sII", data, 0x30, b"Inno", table, ~table & 0xFFFFFFFF)
    return bytes(data), {"table_offset": table, "header_offset": header, "offset_delta": delta}


def normalized(body, start, image_base, image_end):
    result = []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instructions = list(decoder.disasm(body, start))
    assert sum(item.size for item in instructions) == len(body)
    for item in instructions:
        operand = item.op_str
        if item.mnemonic.startswith("j"):
            operand = hex(int(operand, 16) - start)
        elif item.mnemonic == "call":
            operand = "EXTERNAL_CALL"
        else:
            operand = re.sub(
                r"0x[0-9a-f]+",
                lambda token: "IMAGE" if image_base <= int(token[0], 16) < image_end else token[0],
                operand,
            )
        result.append(item.mnemonic + " " + operand)
    return result


def inspect(path, start, size, out, label):
    data = path.read_bytes()
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    end = base + pe.OPTIONAL_HEADER.SizeOfImage
    body = pe.get_data(start - base, size)
    lines = normalized(body, start, base, end)
    (out / f"{label}.asm").write_text("\n".join(lines) + "\n")
    values = pe.parse_rich_header()["values"]
    rich = [
        {"product": values[i] >> 16, "build": values[i] & 0xFFFF, "count": values[i + 1]}
        for i in range(0, len(values), 2)
    ]
    triplet = body.find(TRIPLET)
    if triplet >= 0:
        wrong = bytearray(body)
        wrong[triplet + 6] = 0x14
        assert TRIPLET not in wrong and normalized(wrong, start, base, end) != lines
    return {
        "image_sha256": sha(data),
        "start": hex(start),
        "size": len(body),
        "body_sha256": sha(body),
        "instruction_count": len(lines),
        "address_masked_instruction_sha256": sha("\n".join(lines).encode()),
        "pointer_triplet_offset": triplet if triplet >= 0 else None,
        "rich_records": rich,
    }, lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages", type=Path, default=ROOT / "game_bins/crimsonland/historical/shareware")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    extractor = shutil.which("innoextract")
    assert extractor is not None, "innoextract is required; no installer is executed"
    args.out.mkdir(parents=True, exist_ok=False)
    records, bodies = {}, {}
    for version, name, package_sha, executable, image_sha, start, size in PACKAGES:
        package = args.packages / name
        assert sha(package.read_bytes()) == package_sha
        if package.suffix == ".zip":
            with zipfile.ZipFile(package) as archive:
                names = [name for name in archive.namelist() if name.lower().endswith(".exe")]
                assert len(names) == 1
                setup = archive.read(names[0])
        else:
            setup = package.read_bytes()
        repaired, loader = repair_loader(setup)
        installer = args.out / f"setup-{version}.exe"
        installer.write_bytes(repaired)
        destination = args.out / version
        proc = subprocess.run(
            [extractor, "-I", f"app/{executable}", "-I", "app/whatsupdated.txt", "-d", str(destination), str(installer)],
            capture_output=True, text=True, check=True,
        )
        (args.out / f"{version}-extract.log").write_text(proc.stdout + proc.stderr)
        image = destination / "app" / executable
        assert sha(image.read_bytes()) == image_sha
        record, body = inspect(image, start, size, args.out, version)
        records[version] = {"package": name, "package_sha256": package_sha, "loader": loader, **record}
        bodies[version] = body
    records["1.9.93"], bodies["1.9.93"] = inspect(
        match.default_image_path(), 0x434250, 368, args.out, "1.9.93",
    )
    assert bodies["1.9.1"] == bodies["1.9.9"] == bodies["1.9.93"]
    assert bodies["1.9.8"] != bodies["1.9.93"]
    assert all(records[name]["pointer_triplet_offset"] == 0xA4 for name in ("1.9.1", "1.9.9", "1.9.93"))
    assert records["1.9.8"]["pointer_triplet_offset"] is None
    receipt = {
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "images": records,
        "matching_address_masked_bodies": ["1.9.1", "1.9.9", "1.9.93"],
        "scope": "Address-masked instruction comparison and literal pointer-store triplet; external reference identities are not audited.",
        "negative_control": "Changing the dead store slot from esp+0x10 to esp+0x14 rejects both comparisons.",
    }
    (args.out / "historical.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("1.9.1, 1.9.9 and 1.9.93 have the same address-masked timeline body and pointer triplet; 1.9.8 differs.")


if __name__ == "__main__":
    main()
