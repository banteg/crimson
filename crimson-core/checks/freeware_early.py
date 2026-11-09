"""Compare early weapons, perks, spawns and map collision to each original game, then play through both modes."""

import argparse
import hashlib
import json
import math
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from freeware_acquisition_cases import check_acquisition, prepare_weapon_maps
from freeware_arsenal_cases import (
    check_creature_perks,
    check_flight,
    check_hits,
    check_perks,
    check_player_perks,
    check_weapons,
)
from freeware_creature_motion_cases import check_creature_motion
from freeware_credits_cases import check_credits
from freeware_early_frame_cases import check_early_frames
from freeware_early_hud_cases import check_early_hud, check_early_name, check_name_edit_130
from freeware_frame_input_cases import check_quit_chord, check_screenshot_key, check_screenshot_pixels
from freeware_fx_cases import check_early_fx_writes
from freeware_player_motion_cases import check_player_motion
from freeware_spawn_random_cases import check_random_spawns
from freeware_timing_cases import check_freeware_timing

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crimson-core"))
from freeware.build import game_flags, game_sources

# spawn, pool, elapsed seconds, spawn count, game mode, CRT seed
ADDRESSES = {
    "1.0.2": (0x4067A0, 0x4252D0, 0x428810, 0x428868, 0x41C0A0, 0x41DCC8),
    "1.3.0": (0x40BA70, 0x4374F8, 0x447784, 0x44780C, 0x4374B0, 0x42B634),
}


def check_deaths(exe, edition, lines):
    early = edition == "1.0.2"
    pe = NativeOracle(exe, symbols=SymbolTable({}))
    # Single-player health check through the death-state writes, before the music callbacks.
    start, stop = (0x40DE74, 0x40DEC9) if early else (0x4161F3, 0x41629F)
    state, health, xp, weapon = (
        (0x41C09C, 0x421EAC, 0x421EF8, 0x421F8C) if early else (0x4290D4, 0x42FFB8, 0x430010, 0x4300AC)
    )
    rows = {tuple(map(int, row.split()[1:])) for row in lines if row.startswith("deathcheck ")}
    for mode in (1, 2):
        for score in (6, 66, 666, 6666, 667):
            pe.write_u32(ADDRESSES[edition][4], mode)
            pe.write_u32(state, 3)
            pe.write_f32(health, -1)
            pe.write_u32(xp, score)
            pe.write_u32(weapon, 4 if mode == 1 else 2)
            pe.run(start, stop)
            expected = (mode, score, pe.read_u32(state), pe.read_f32(health), pe.read_u32(weapon))
            assert expected in rows, (edition, expected, rows)
            rows.remove(expected)
    assert not rows
    print(f"{edition}: 10 lethal hits matched original health, weapon and game state")


def run_browser_probe(browser, js):
    # Report from Emscripten's postRun. Chrome's --dump-dom can fail in its teardown even after a successful run.
    page = js.with_suffix(".html")
    page.write_text(
        '<meta charset="utf-8"><script>const lines=[];var Module={arguments:["/"],print:s=>lines.push(s),'
        'postRun:[()=>fetch("/result",{method:"POST",body:lines.join("\\n")})]};</script>'
        f'<script src="{js.name}"></script>',
    )
    output = []

    class Handler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path not in (f"/{page.name}", f"/{js.name}"):
                self.send_error(404)
                return
            super().do_GET()

        def do_POST(self):
            if self.path != "/result" or self.headers.get("Origin") != origin:
                self.send_error(403)
                return
            lines = self.rfile.read(int(self.headers["Content-Length"])).decode().splitlines()
            self.send_response(204)
            self.end_headers()
            output.append(lines)

        def log_message(self, *_):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=js.parent)) as server:
        origin = f"http://127.0.0.1:{server.server_port}"
        server.timeout = 0.25
        with subprocess.Popen(
            [
                browser,
                "--headless",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={js.parent / (js.stem + '-profile')}",
                f"{origin}/{page.name}",
            ],
            stdout=subprocess.DEVNULL,
        ) as process:
            try:
                deadline = time.monotonic() + 120
                while not output:
                    if process.poll() is not None:
                        raise RuntimeError(f"{js.stem}: Chrome exited with {process.returncode} before postRun")
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"{js.stem}: timed out waiting for the WebAssembly probe")
                    server.handle_request()
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
    return output[0]


def check(edition, install, tmp, web, browser):
    exe = install / "crimson.exe"
    registry = json.loads((ROOT / "decomp/builds.json").read_text())
    build = next(b for b in registry["builds"] if b["id"] == edition)
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == next(
        i["sha256"] for i in build["images"] if i["name"] == exe.name
    )

    def tool(name):
        result = shutil.which(name)
        if not result:
            raise SystemExit(f"{name} is required")
        return result

    sources = [
        *game_flags(ROOT, edition),
        *game_sources(ROOT, tmp),
        ROOT / "crimson-core/checks/freeware_early.cpp",
        ROOT / "crimson-core/checks/freeware_arsenal.cpp",
        ROOT / "crimson-core/checks/freeware_perks.cpp",
        ROOT / "crimson-core/checks/freeware_spawn_random.cpp",
        ROOT / "crimson-core/checks/freeware_player_motion.cpp",
        ROOT / "crimson-core/checks/freeware_creature_motion.cpp",
        ROOT / "crimson-core/checks/freeware_credits.cpp",
        ROOT / "crimson-core/checks/freeware_early_frame.cpp",
        ROOT / "crimson-core/checks/freeware_early_hud.cpp",
        ROOT / "crimson-core/checks/freeware_early_menu.cpp",
        ROOT / "crimson-core/checks/freeware_early_fx.cpp",
    ]
    check_screenshot_pixels([tool("clang++"), *game_flags(ROOT, edition)], tmp)
    binary = tmp / edition
    subprocess.run([tool("clang++"), *sources, "-o", binary], check=True)
    if edition == "1.3.0":
        prepare_weapon_maps(install, tmp)
    lines = subprocess.check_output([binary, install], cwd=tmp, text=True).splitlines()

    def compare_combat(output):
        check_quit_chord(exe, edition, output)
        check_screenshot_key(install, edition, output)
        check_freeware_timing(install, edition, output)
        check_deaths(exe, edition, output)
        check_weapons(exe, edition, output)
        check_hits(exe, edition, output)
        check_flight(exe, edition, output)
        check_perks(exe, edition, output)
        check_player_perks(exe, edition, output)
        check_creature_perks(exe, edition, output)
        check_random_spawns(exe, edition, output)
        check_player_motion(exe, edition, output)
        check_creature_motion(exe, edition, output)
        check_credits(exe, edition, output)
        check_early_frames(exe, edition, output)
        if edition == "1.0.2":
            check_early_hud(exe, output)
            check_early_name(exe, output)
        else:
            check_name_edit_130(exe, output)
        check_early_fx_writes(exe, edition, output)
        if edition == "1.3.0":
            check_acquisition(install, tmp, output)

    compare_combat(lines)
    if web or browser:
        js = tmp / f"early-{edition}.js"
        embeds = []
        if edition == "1.3.0":
            embeds = [
                "--embed-file",
                f"{install / 'levels'}@/levels",
                "--embed-file",
                f"{tmp / 'weapon-tests'}@/weapon-tests",
            ]
        subprocess.run(
            [
                tool("em++"),
                *sources,
                *embeds,
                "-sENVIRONMENT=web,node",
                "-sSINGLE_FILE",
                "-sWASM_ASYNC_COMPILATION=0",
                "-o",
                js,
            ],
            check=True,
        )
        if browser:
            wasm = run_browser_probe(browser, js)
        else:
            wasm = subprocess.check_output([tool("node"), js, "/"], text=True).splitlines()
        compare_combat(wasm)
        prefixes = ("spawn ", "wall ")
        assert [s for s in lines if s.startswith(prefixes)] == [s for s in wasm if s.startswith(prefixes)]
    early = edition == "1.0.2"
    spawn, pool, elapsed, counter, mode_addr, seed_addr = ADDRESSES[edition]
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=seed_addr)
    stride = 104 if early else 128
    pos = pe.alloc(8)
    tint = pe.alloc_f32s(0.25, 0.5, 0.75, 1)
    if not early:
        level = pe.alloc(128)
        wall = pe.alloc(48, data=struct.pack("<5f", 106, 90, 0, 10, 20) + bytes(28))
        walls = pe.alloc(4, data=struct.pack("<I", wall))
        pe.write_u32(0x433F10, level)
        pe.write(level + 0x28, struct.pack("<2I", walls, walls + 4))
        pe.write_f32(0x447828, 1 / 60)
        start = pe.alloc_f32s(100, 100)
        records = [line.split() for line in lines if line.startswith("wall ")]
        assert len(records) == 6
        assert any(r[2:4] == ["1", "1"] for r in records), "missing wall ricochet case"
        for _, seed, slot, active, x, y, life, rng in records:
            if slot == "0":
                pe.write(0x4307D0, bytes(64 * 52))
                pe.rand_state = int(seed)
                pe.call(0x4060D0, start, 1.57079637, 1)
                pe.call(0x406260)
            shot = 0x4307D0 + int(slot) * 52
            assert pe.read_u8(shot) == int(active) and pe.rand_state == int(rng), (seed, slot, rng)
            for offset, value in [(8, x), (12, y), (36, life)]:
                assert math.isclose(pe.read_f32(shot + offset), float(value), abs_tol=1e-4), (seed, slot, offset, value)
    previous = None
    cases = 0
    for line in lines:
        if not line.startswith("spawn "):
            continue
        _, mode, seed, x, y, slot, count, rng, *values = line.split()
        if previous != (mode, seed):
            pe.write(pool, bytes((128 if early else 512) * stride))
            pe.write_u32(counter, 0)
            pe.write_f32(elapsed, 12.5)
            pe.write_u32(mode_addr, int(mode))
            pe.rand_state = int(seed)
            previous = mode, seed
        pe.write(pos, struct.pack("<2f", float(x), float(y)))
        ret = pe.call(spawn, pos, tint, 1).eax
        assert pe.rand_state == int(rng) and pe.read_u32(counter) == int(count), line
        if early:
            assert bool(ret & 255) == (int(slot) >= 0), line
        else:
            assert ret == int(slot), line
        if int(slot) >= 0:
            record = pe.read(pool + int(slot) * stride, stride)
            offsets = (12, 16, 28, 32, 72, 36, 80, 68, 40) if early else (24, 28, 40, 44, 88, 52, 96, 84, 56)
            xoff, yoff, hp, heading, speed, size, reward, damage, color = offsets
            fields = [struct.unpack_from("<f", record, offset)[0] for offset in (xoff, yoff, hp, heading, speed, size)]
            fields.append(struct.unpack_from("<i" if early else "<d", record, reward)[0])
            fields.append(struct.unpack_from("<f", record, damage)[0])
            fields.extend(struct.unpack_from("<4f", record, color))
            assert all(math.isclose(a, float(b), rel_tol=1e-7) for a, b in zip(fields, values, strict=True)), (
                line,
                fields,
            )
        cases += 1
    assert cases == (15 if early else 30)
    print(f"{edition}: {cases} original spawn calls matched, including final CRT state")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("installs", type=Path, help="parent directory containing the original release folders")
    parser.add_argument("--web", action="store_true", help="also run the Emscripten game code under Node")
    parser.add_argument("--browser", type=Path, help="run the WebAssembly comparison in this Chromium executable")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        for edition in ADDRESSES:
            check(edition, (args.installs / edition).resolve(), Path(tmp), args.web, args.browser)
