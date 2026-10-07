"""The game module: the verifier selection plus recovered presentation, Grim and a platform layer."""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAME = HERE / "game"


def game_sources(root):
    spec = json.loads((GAME / "sources.json").read_text())
    grim_root = root / "decomp/1.9/grim"
    grim = sorted(
        str(path.relative_to(root))
        for path in grim_root.rglob("*.cpp")
        if ".claude" not in path.parts and path.relative_to(grim_root).as_posix() not in spec["grim_replaced"]
    )
    if missing := [name for name in spec["grim_replaced"] if not (grim_root / name).exists()]:
        raise SystemExit(f"Replaced Grim sources not found: {', '.join(missing)}")
    return spec["exe"] + grim


def object_name(rel):
    # Grim and the executable reuse file names; the path keeps objects apart.
    return re.sub(r"[^A-Za-z0-9_]", "_", str(Path(rel).with_suffix("")).removeprefix("decomp/1.9/"))


def game_headers(headers):
    # Recovered Grim defines every interface method itself.
    path = headers / "grim2d_cpp.h"
    text, count = re.subn(r"\) = 0;", ");", path.read_text())
    if count != 62:
        raise SystemExit(f"Audit the Grim interface before building the game module ({count} pure methods)")
    path.write_text(text)
    # The gameplay header declares sfx_play void; it returns the voice (crimsonland_audio.h).
    path = headers / "crimsonland_gameplay.h"
    path.write_text(
        replace_once(
            path.read_text(),
            "void sfx_play(int sfx_id, float volume);",
            "int sfx_play(int sfx_id, float volume);",
            path,
        ),
    )


def game_platform():
    return sorted(GAME.glob("*.cpp"))


def replace_once(text, old, new, src):
    if text.count(old) != 1:
        raise SystemExit(f"Audit {src.name} before changing this game adapter: {old!r}")
    return text.replace(old, new)


# Recovered functions host/game.inc wraps so that a simulation tick runs them as
# the verifier does; the recovered body keeps a _recovered name.
SEAMS = ("ui_elements_update_and_render",)


def adapt_game(src, txt):
    if src.stem in SEAMS:
        txt, count = re.subn(rf"\b{src.stem}\(", f"{src.stem}_recovered(", txt)
        if not count:
            raise SystemExit(f"Audit {src.name} before changing its seam")
    # Declaration repairs: the recovered translation units disagree about these
    # signatures, which wasm32 calls cannot tolerate. Each matches the callers.
    # Some callers declare sfx_play void; it returns the voice, which they ignore.
    txt = re.sub(r"\bvoid sfx_play\(int sfx_id, float (gain|volume)\);", r"int sfx_play(int sfx_id, float \1);", txt)
    if src.stem == "ui_elements_update_and_render":
        txt = replace_once(
            txt,
            "void config_load_presets(int reset);",
            'extern "C" bool config_load_presets(bool skip_grim_settings);',
            src,
        )
    if src.stem == "jaz_decode":
        # The VC6 declaration spells size_t as a 32-bit unsigned int.
        txt = replace_once(txt, "operator new(unsigned int size)", "operator new(size_t size)", src)
    if src.stem == "noop" and "grim" in src.parts:
        txt = replace_once(txt, 'extern "C" void grim_noop(void)', 'extern "C" void grim_noop(char *, ...)', src)
    return txt


# The COM interfaces the recovered Grim calls; the platform layer overrides the
# methods it supports, and any other call stops the module with its name.
COM_INTERFACES = {
    "d3d8.h": [
        "IDirect3D8",
        "IDirect3DDevice8",
        "IDirect3DSurface8",
        "IDirect3DVertexBuffer8",
        "IDirect3DIndexBuffer8",
        "IDirect3DTexture8",
    ],
    "dinput.h": ["IDirectInput8A", "IDirectInputDevice8A"],
}


def com_defaults(root, headers):
    lines = [
        "#pragma once",
        '#include "grim_d3d8.h"',
        "#include <dinput.h>",
        "[[noreturn]] void platform_unimplemented(const char *method);",
    ]
    for header, interfaces in COM_INTERFACES.items():
        text = (root / "third_party/headers" / header).read_text()
        for interface in interfaces:
            body = re.search(rf"DECLARE_INTERFACE_\({interface},\w+\)\s*\{{(.*?)\n\}};", text, re.DOTALL)
            if not body:
                raise SystemExit(f"COM interface {interface} not found in {header}")
            lines.append(f"struct Unimplemented{interface} : {interface} {{")
            for method in re.findall(r"(STDMETHOD_?\(.*?\)\(.*?\))\s*PURE;", body[1], re.DOTALL):
                name = re.match(r"STDMETHOD_?\((?:[^,()]*,)?\s*(\w+)\s*\)", method)[1]
                lines.append(f'  {" ".join(method.split())} {{ platform_unimplemented("{interface}::{name}"); }}')
            lines.append("};")
    (headers / "com_defaults.h").write_text("\n".join(lines) + "\n")


def engine_globals(root):
    # The console and its registered cvars belong to the engine: registered once,
    # they outlive every run.
    registration = (root / "decomp/1.9/crimsonland/game/register_core_cvars.cpp").read_text()
    cvars = re.findall(r"\b(cv_\w+) =", registration)
    if len(cvars) != 13:
        raise SystemExit("Audit register_core_cvars before changing the engine globals")
    return {"console_log_queue", *cvars}
