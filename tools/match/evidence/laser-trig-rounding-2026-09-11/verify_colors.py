"""Execute Grim2D's color setters using the laser's recorded native arguments."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


class NativeColors:
    def __init__(self):
        name = "grim.dll"
        self.image = match.load_image(match.default_image_path(name))
        manifest = match.load_function_manifest(
            match.default_functions_path(name),
            metadata_path=match.default_metadata_path(name),
            image_name=name,
            scope="all",
        )
        catalog = match.load_reference_catalog(manifest)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.methods, self.bodies = {}, {}
        self.allowed = set()
        calls = set()
        for name in ("grim_set_color", "grim_set_color_slot"):
            _, start, end = match.resolve_function(manifest, name)
            body = self.image.function_bytes(start, end)
            self.methods[name] = start
            self.bodies[name] = {"start": hex(start), "end": hex(end), "sha256": sha(body)}
            instructions = list(md.disasm(body, start))
            self.allowed.update(i.address for i in instructions)
            calls.update(int(i.op_str, 16) for i in instructions if i.mnemonic == "call")
        assert len(calls) == 1
        _, thunk_start, thunk_end = match.resolve_function(manifest, hex(calls.pop()))
        thunk = self.image.function_bytes(thunk_start, thunk_end)
        assert len(thunk) == 6 and thunk[:2] == b"\xff\x25"
        self.ftol_import = struct.unpack_from("<I", thunk, 2)[0]
        imports = json.loads((match.default_functions_path("grim.dll").parent / "imports.json").read_text())
        assert any(
            row["name"] == "_ftol" and int(row["address"], 16) == self.ftol_import
            for library in imports
            for row in library["entries"]
        )
        self.allowed.add(thunk_start)
        self.game = match.load_image(match.default_image_path())
        _, self.ftol_start, ftol_end = match.resolve_function(match.load_function_manifest(scope="all"), "crt_ftol")
        ftol = self.game.function_bytes(self.ftol_start, ftol_end)
        self.ftol_sha = sha(ftol)
        self.allowed.update(i.address for i in md.disasm(ftol, self.ftol_start))
        addresses = catalog._addresses_for_symbol("grim_color_slot0")
        assert len(addresses) == 1
        self.color = addresses[0]
        self.coverage = set()

    def apply(self, calls, cw):
        assert cw in (0x007F, 0x037F)
        assert [name for name, _ in calls] == ["grim_set_color", "grim_set_color_slot", "grim_set_color_slot"]
        assert calls[1][1][0] == 2 and calls[2][1][0] == 3
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        for image in (self.image, self.game):
            mu.mem_map(image.image_base, (image.size_of_image + 4095) & -4096)
            mu.mem_write(image.image_base, image.mapped)
        mu.mem_write(self.ftol_import, struct.pack("<I", self.ftol_start))
        stack, stop = 0x20000000, 0x30000000
        mu.mem_map(stack, 0x10000)
        mu.mem_write(stack, b"\xa5" * 0x10000)
        mu.mem_map(stop, 4096)
        esp = stack + 0xF000
        mu.reg_write(x86.UC_X86_REG_FPCW, cw)
        mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)

        def code(_uc, pc, _size, _data):
            assert pc in self.allowed, hex(pc)
            self.coverage.add(pc)

        def write(_uc, _access, address, size, _value, _data):
            assert (stack <= address and address + size <= esp) or (
                self.color <= address and address + size <= self.color + 16
            )

        mu.hook_add(unicorn.UC_HOOK_CODE, code)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write)
        saved = (
            (x86.UC_X86_REG_EBX, 0x11110000),
            (x86.UC_X86_REG_ESI, 0x22220000),
            (x86.UC_X86_REG_EDI, 0x33330000),
            (x86.UC_X86_REG_EBP, 0x44440000),
        )
        for name, arguments in calls:
            assert len(arguments) == (4 if name == "grim_set_color" else 5)
            mu.mem_write(esp, struct.pack("<" + "I" * (len(arguments) + 1), stop, *arguments))
            guard = bytes(mu.mem_read(esp, 0x100))
            mu.reg_write(x86.UC_X86_REG_ESP, esp)
            for register, value in saved:
                mu.reg_write(register, value)
            # Both native methods address global color slots and do not dereference this.
            mu.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
            mu.emu_start(self.methods[name], stop, count=1000)
            assert mu.reg_read(x86.UC_X86_REG_EIP) == stop
            assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4 * (1 + len(arguments))
            assert bytes(mu.mem_read(esp, 0x100)) == guard
            assert all(mu.reg_read(register) == value for register, value in saved)
            assert mu.reg_read(x86.UC_X86_REG_FPCW) == cw
            assert mu.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
        return list(struct.unpack("<4I", mu.mem_read(self.color, 16)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    receipt = json.loads((HERE / "results.json").read_text())
    fixture_path = HERE / receipt["fixtures"]["file"]
    assert sha(fixture_path.read_bytes()) == receipt["fixtures"]["sha256"]
    assert receipt["image_sha256"] == sha(match.default_image_path().read_bytes())
    cases = {}
    for line in fixture_path.read_text().splitlines():
        row = json.loads(line)
        key = row["case"]["fpcw"], row["case"]["alpha"]
        assert key not in cases or cases[key] == row["native_colors"]
        cases[key] = row["native_colors"]
    colors = NativeColors()
    rows = []
    for (cw, alpha), calls in cases.items():
        packed = colors.apply(calls, cw)
        assert packed[0] == packed[1] and packed[2] == packed[3]
        assert packed[0] & 0xFFFFFF == 0xFF0000 and packed[2] & 0xFFFFFF == 0
        rows.append({"fpcw": cw, "alpha": alpha, "calls": calls, "packed_argb": packed})
    record = {
        "schema_version": 1,
        "kind": "native-laser-color-setters",
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "native_fixture_sha256": sha(fixture_path.read_bytes()),
        "grim_image_sha256": sha(match.default_image_path("grim.dll").read_bytes()),
        "game_image_sha256": receipt["image_sha256"],
        "native_body_sha256": receipt["native_body_sha256"],
        "methods": colors.bodies,
        "ftol_import": hex(colors.ftol_import),
        "ftol_game_address": hex(colors.ftol_start),
        "ftol_game_sha256": colors.ftol_sha,
        "unicorn_version": unicorn.__version__,
        "coverage": sorted(colors.coverage),
        "cases": rows,
        "scope": "Original Grim setters with recorded laser arguments; the imported MSVCRT _ftol uses the game's converter as an explicit ABI model; CPU packing only",
    }
    (out / "native-colors.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Verified {len(rows)} native laser color palettes through both Grim2D setters.")


if __name__ == "__main__":
    main()
