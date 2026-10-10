"""Compare spawn batches to unoptimized recovered bodies and confirm the original late-game loop."""

import argparse
import importlib.util
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
ROOT = CORE.parent
spec = importlib.util.spec_from_file_location("adapter", CORE / "adapter.py")
assert spec and spec.loader
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def batches():
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        optimized = adapter.load_diffs(adapter.DIFFS)
        baseline = adapter.load_diffs(tuple(p for p in adapter.DIFFS if p.name != "optimizations"))
        for path in (ROOT / "tools/match/include").glob("*.h"):
            rel = str(path.relative_to(ROOT))
            text = adapter.apply_diffs(rel, path.read_text(), optimized)
            (out / path.name).write_text(adapter.prototypes(path, text, adapter.PROTOTYPES))
        sources = []
        for rel in (
            "decomp/1.9/crimsonland/crimsonland/creature_alloc_slot.c",
            "decomp/1.9/crimsonland/game/survival_spawn_creature.cpp",
        ):
            path = ROOT / rel
            for label, hunks in (("baseline", baseline), ("optimized", optimized)):
                text = adapter.adapt(path, adapter.apply_diffs(rel, path.read_text(), hunks))
                if label == "baseline":
                    text = 'extern "C" int creature_alloc_slot(void);\n' + text
                    for name in ("creature_alloc_slot", "survival_spawn_creature"):
                        text = text.replace(name, "baseline_" + name)
                source = out / (label + "_" + path.stem + ".cpp")
                source.write_text(text)
                sources.append(str(source))
        subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O2",
                "-fms-extensions",
                "-fno-strict-aliasing",
                "-fwrapv",
                "-ffp-contract=off",
                "-Wno-ignored-attributes",
                "-Wno-write-strings",
                "-include",
                str(CORE / "host/hooks.h"),
                "-I" + str(CORE / "host"),
                "-I" + str(out),
                "-I" + str(ROOT / "third_party/headers"),
                *sources,
                str(CORE / "checks/spawn_batch.cpp"),
                "-o",
                str(out / "check"),
            ],
            check=True,
        )
        subprocess.run([str(out / "check")], check=True)


def original(exe):
    from unicorn import UC_HOOK_CODE

    from crimson_re.dbg.native_oracle import NativeOracle

    oracle = NativeOracle(exe)
    oracle.run_static_initializers()
    oracle.write_u8("demo_mode_active", 0)
    oracle.write_u32("cv_verbose", oracle.alloc(0x20))
    oracle.write_u32("terrain_texture_width", 1024)
    oracle.write_u32("terrain_texture_height", 1024)
    oracle.write_u32("config_player_count", 1)
    # No milestones: this isolates the wave loop, with the actual native spawn and allocator intact.
    oracle.write_u32("survival_spawn_stage", 10)
    base = oracle.resolve("creature_pool")
    for i in range(384):
        oracle.write_u8(base + i * 0x98, 1)
    calls = []
    entry = oracle.resolve("survival_spawn_creature")
    oracle._uc.hook_add(UC_HOOK_CODE, lambda *_: calls.append(None), begin=entry, end=entry)
    for elapsed, dt, expected in (
        (898200, 1, 1),
        (900000, 16, 16),
        (901799, 16, 16),
        (901800, 16, 32),
        (905400, 16, 48),
        (1800000, 16, 4016),
        (2154555, 16, 5584),
    ):
        calls.clear()
        oracle.write_u32("run_elapsed_ms", elapsed)
        oracle.write_u32("frame_dt_ms", dt)
        oracle.write_u32("survival_spawn_cooldown", 0)
        oracle.call("survival_update")
        assert len(calls) == expected, (elapsed, dt, len(calls), expected)
        assert oracle.read_u8(base + 384 * 0x98) == 1
        print(f"original survival_update: elapsed={elapsed} dt={dt} attempts={len(calls)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, help="also exercise the original x86 executable through Unicorn")
    args = parser.parse_args()
    batches()
    if args.exe:
        original(args.exe)
