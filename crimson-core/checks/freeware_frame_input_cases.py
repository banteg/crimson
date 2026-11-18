"""Compare frame input paths with the corresponding original game executables."""

import json
import shlex
import shutil
import struct
import subprocess
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def check_quit_chord(exe, edition, lines):
    # Run from the post-SFX Escape test through the return value, including the FPS footer.
    # 1.0.2 pops two saved registers before setting AL; stop immediately after that write.
    start, stop, grim = {
        "1.0.2": (0x40EC6A, 0x40ED6E, 0x4287EC),
        "1.3.0": (0x4181C6, 0x41838A, 0x447754),
        "1.4.0": (0x41E0E6, 0x41E2CB, 0x452D94),
    }[edition]
    pe = NativeOracle(exe, symbols=SymbolTable({}))
    table = pe.alloc(256)
    pe.write_u32(grim, pe.alloc(4, data=struct.pack("<I", table)))
    held = set()

    def slot(offset, argc, answer, *, fp=False):
        fn = pe.load_code(b"\xc3")
        pe.stub(fn, answer, pop=4 * argc, returns="st0" if fp else "eax")
        pe.write_u32(table + offset, fn)

    early = edition == "1.0.2"
    latest = edition == "1.4.0"
    slot(0x38 if early else 0x40, 1, lambda call: int(call.arg_u32(0) in held))
    slot(0x14 if early else 0x1C, 5 if latest else 7, 0)  # SetConfigVar
    slot(0x8C if early else 0xB8 if latest else 0xA8, 4, 0)  # SetColor
    if not early:
        slot(0x3C, 0, 60, fp=True)
    if latest:
        pe.stub(0x402390, 0)  # Console drawing is outside the exit test.

    def quits(*keys):
        held.clear()
        held.update(keys)
        return (pe.run(start, stop).eax & 0xFF) == 0

    rows = [
        (int(console), int(quit_game))
        for _, console, quit_game in (line.split() for line in lines if line.startswith("quit-chord "))
    ]
    assert [console for console, _ in rows] == [0, 1]
    for console, client_quit in rows:
        if latest:
            pe.write_u8(0x436598, console)
            pe.write_u8(0x43611C, 0)
        assert not quits(0xB8, 0x10), (edition, "right Alt + Q")
        for first, second in [(0x38, 0x10), (0x10, 0x38)]:
            assert not quits(first), (edition, first)
            assert quits(first, second) == client_quit, (edition, console, first, second)
        if latest:
            pe.write_u8(0x43611C, 1)  # quit_requested, set by the game or console.
            assert quits(), (edition, console, "quit_requested")


def check_screenshot_key(install, edition, lines):
    if edition == "1.0.2":
        return

    maps = Path(__file__).resolve().parents[2] / "analysis/decomp" / edition / "grim.dll"
    functions = {row["name"]: int(row["address"], 16) for row in json.loads((maps / "functions.json").read_text())}
    globals_ = {row["name"]: int(row["address"], 16) for row in json.loads((maps / "data.json").read_text())["entries"]}
    samples = [tuple(map(int, line.split()[1:])) for line in lines if line.startswith("f12 ")]
    for console in (0, 1):
        grim = NativeOracle(install / "grim.dll", symbols=SymbolTable({}))
        rows = [row for row in samples if row[0] == console]
        assert [row[1] for row in rows] == list(range(18))
        for _, tick, down, elapsed_ms, requested in rows:
            grim.write_u8(globals_["grim_keyboard_state"] + 0x58, down << 7)
            if edition == "1.4.0":
                # The real Grim run-loop decrements all 256 timers before invoking the game.
                grim.write_f32(globals_["grim_frame_dt"], elapsed_ms * .001)
                grim.run(0x10001F56, 0x10001F7F, regs={"ebx": 0})
            original = grim.call(functions["grim_was_key_pressed"], 0x58).eax & 0xFF
            assert requested == original, (edition, console, tick, requested, original)


def check_screenshot_pixels(compiler_flags, stage):
    """Exercise presentation and BMP readback when the native SDL3 backend is available."""
    pkg_config = shutil.which("pkg-config")
    if not pkg_config or subprocess.run([pkg_config, "--exists", "sdl3"], check=False).returncode:
        print("Skipping freeware screenshot pixels: SDL3 development files unavailable")
        return
    flags = shlex.split(subprocess.check_output([pkg_config, "--cflags", "--libs", "sdl3"], text=True))
    core = Path(__file__).resolve().parents[1]
    binary = stage / "check-screenshots"
    subprocess.run([*compiler_flags, core / "freeware/display.cpp", core / "checks/freeware_screenshots.cpp",
                    *flags, "-o", binary], check=True)
    subprocess.run([binary, stage], check=True)
