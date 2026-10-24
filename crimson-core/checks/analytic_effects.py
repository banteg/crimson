"""Exercise production analytic hooks over a recording-only graphics boundary."""
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]


def main():
    compiler = shutil.which("clang++")
    if compiler is None:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory(prefix="crimson-analytic-hooks-") as folder:
        out = Path(folder)
        (out / "grim2d_cpp.h").write_text("""#pragma once
struct grim_config_value_t { unsigned words[4]; };
struct IGrim2D_cpp { void grim_flush_batch(); };
""")
        (out / "crimsonland_gameplay.h").write_text("""#pragma once
struct vec2f_t { float x,y; };
enum { PROJECTILE_TYPE_PLASMA_RIFLE=9, PROJECTILE_TYPE_PLASMA_CANNON=28,
       PROJECTILE_TYPE_SPIDER_PLASMA=26, PROJECTILE_TYPE_SHRINKIFIER=24 };
struct Fields { int type_id; float life_timer,speed_scale,pos_x,pos_y,origin_x,origin_y; };
struct projectile_t { Fields fields; float angle; };
extern projectile_t projectile_pool[96];
struct Config { bool flame_glow_enabled; };
extern Config config_blob;
struct Color { float r,g,b,a; };
struct effect_entry_t { int effect_id; float pos_x,pos_y,half_width,half_height,scale,rotation; Color color; };
""")
        binary = out / "check"
        subprocess.run([
            compiler, "-std=c++17", "-O2", "-Wno-unknown-attributes", "-I" + str(out),
            str(CORE / "checks/analytic_effects.cpp"), "-o", str(binary),
        ], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
