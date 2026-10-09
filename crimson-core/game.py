"""The game module: the verifier selection plus recovered presentation, Grim and a platform layer."""

import functools
import json
import re
from pathlib import Path

from adapter import DIFFS, NOT_CPP_LINKAGE, prototypes, sub

HERE = Path(__file__).resolve().parent
GAME = HERE / "game"
# changes/: what the client changes in the recovered game, where its host hooks in and which defaults it picks;
# patches/: the ranked fixes that only change what is drawn (`NN-*.patch` fixes original bug NN), so they leave the
# verifier untouched.
GAME_DIFFS = (*DIFFS, GAME / "changes", GAME / "patches")
# Signatures the recovered files disagree on, as the game module's definitions have them (adapter.PROTOTYPES): some
# callers declare sfx_play void, but it returns the voice, which they ignore.
GAME_PROTOTYPES = {
    "void sfx_play(int sfx_id, float volume);": "int sfx_play(int sfx_id, float volume);",
    "void sfx_play(int sfx_id, float gain);": "int sfx_play(int sfx_id, float gain);",
    "void config_load_presets(int reset);": 'extern "C" bool config_load_presets(bool skip_grim_settings);',
    "void ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);": "bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);",
    "unsigned char game_is_full_version(...);": "unsigned char game_is_full_version(void);",
    "void config_sync_from_grim(void);": "bool config_sync_from_grim(void);",
}


def game_sources(root):
    # Every recovered file outside the verifier's selection, except the Windows
    # surface the platform layer replaces.
    spec = json.loads((GAME / "sources.json").read_text())
    verifier = set(json.loads((HERE / "sources.json").read_text()))
    found = []
    for image, replaced in (("crimsonland", spec["exe_replaced"]), ("grim", spec["grim_replaced"])):
        tree = root / "decomp/1.9" / image
        if missing := [name for name in replaced if not (tree / name).exists()]:
            raise SystemExit(f"Replaced {image} sources not found: {', '.join(missing)}")
        found += sorted(
            str(path.relative_to(root))
            for path in tree.rglob("*")
            if path.suffix in (".c", ".cpp")
            and ".claude" not in path.relative_to(root).parts
            and path.relative_to(tree).as_posix() not in replaced
            and str(path.relative_to(root)) not in verifier
        )
    return found


def game_wrapped(root):
    # The recovered functions the host wraps, by the file that defines each: a
    # simulation tick must run some as the verifier does, a run the client plays
    # drives others, a tick saves nothing, a sound entry the device never created
    # stays silent, a run's wrapped strings live in its arena and a live run names
    # the player's keys.
    spec = json.loads((GAME / "sources.json").read_text())
    wrapped = [f"decomp/1.9/crimsonland/{name}" for name in spec["exe_wrapped"]]
    if missing := [rel for rel in wrapped if not (root / rel).exists()]:
        raise SystemExit(f"Wrapped sources not found: {', '.join(missing)}")
    return set(wrapped)


def object_name(rel):
    # Grim and the executable reuse file names; the path keeps objects apart.
    return re.sub(r"[^A-Za-z0-9_]", "_", str(Path(rel).with_suffix("")).removeprefix("decomp/1.9/"))


def game_header(path, text):
    """The game module's passes over a recovered header."""

    if path.name == "grim2d_cpp.h":
        # Recovered Grim defines every interface method itself.
        text = sub(path, r"\) = 0;", ");", text, 62)
    return prototypes(path, text, GAME_PROTOTYPES)


def game_platform():
    return sorted(GAME.glob("*.cpp"))


# The vendored C the platform layer links (game/leaderboard.cpp): zstd 1.5.7's
# single-file library without its dictionary builder or threads, and Monocypher
# 4.0.2 with its Ed25519.
def game_vendor_c():
    return [GAME / "vendor" / name for name in ("zstd.c", "monocypher.c", "monocypher-ed25519.c")]


def _blank_comments(text):
    # Comments as spaces, so offsets into the code are offsets into the text.
    return re.sub(r"//[^\n]*|/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.DOTALL)


@functools.cache
def _rng_draws(tree):
    # crt_rand and every recovered function that reaches it, by file name.
    bodies = {path.stem: _blank_comments(path.read_text()) for path in tree.rglob("*") if path.suffix in (".c", ".cpp")}
    names = {"crt_rand"}
    while new := {
        stem
        for stem, body in bodies.items()
        if stem not in names and re.search(rf"\b(?:{'|'.join(sorted(names))})\s*\(", body)
    }:
        names |= new
    return re.compile(rf"\b(?:{'|'.join(sorted(names))})\s*\(")


def _arguments(text, open_paren):
    # The (start, end) span of each argument of the call whose "(" is at open_paren.
    spans, depth, start = [], 0, open_paren + 1
    for i in range(open_paren, len(text)):
        if text[i] in "([{":
            depth += 1
        elif text[i] in ")]}":
            depth -= 1
            if not depth:
                return spans + [(start, i)]
        elif text[i] == "," and depth == 1:
            spans.append((start, i))
            start = i + 1
    raise SystemExit("Unbalanced call")


def msvc_argument_order(src, txt):
    # The original's compiler evaluates call arguments right to left; clang goes
    # left to right. Where two arguments of a call draw the RNG, they move into
    # temporaries ahead of the statement in MSVC's order, so each draw lands
    # where the original put it (a terrain stamp's y before its x, a Typ-o name's
    # last part first). The count of draws stays the same.
    draws = _rng_draws(Path(*src.parts[: src.parts.index("1.9") + 1]))
    code = _blank_comments(txt)
    sites = []
    for call in re.finditer(r"\b\w+\s*\(", code):
        spans = _arguments(code, call.end() - 1)
        drawing = [span for span in spans if draws.search(code[slice(*span)])]
        if len(drawing) >= 2:
            sites.append((call.start(), drawing))
    if not sites:
        return txt
    for n, (start, drawing) in enumerate(reversed(sites)):
        statement = max(code.rfind(c, 0, start) for c in ";{}") + 1
        if not re.fullmatch(r"\s*(?:[\w:<>*& ]+\s)?", code[statement:start]):
            raise SystemExit(f"Audit {src.name}: a call that draws in argument order inside an expression")
        line = code.rfind("\n", 0, start) + 1
        indent = re.match(r"[ \t]*", code[line:]).group()
        hoisted = ""
        for i, (a, b) in enumerate(reversed(drawing)):
            name = f"msvc_argument_{n}_{i}"
            argument = txt[a:b].strip()
            hoisted += f"{indent}auto {name} = {' '.join(argument.split())};\n"
            a = txt.index(argument, a)
            txt = txt[:a] + name + txt[a + len(argument) :]
        txt = txt[:line] + hoisted + txt[line:]
    return txt


def adapt_game(src, txt, wrapped=False):
    """The game module's passes, after the verifier's (adapter.adapt)."""

    if src.suffix == ".c":
        # The adapter gives C linkage to the common return types; the rest of a
        # C file's top-level functions need it too.
        txt = sub(
            src,
            rf'(?m)^(?!static |typedef |return |extern "C")(extern )?((?:(?:unsigned|signed|const|struct) )*\w+ ?\**) ?'
            rf"{NOT_CPP_LINKAGE}(\w+)\(",
            r'extern "C" \2 \3(',
            txt,
            None,
        )
    txt = msvc_argument_order(src, txt)
    # Files open through the platform layer, which takes Windows paths.
    txt = sub(src, r"\bfopen\(", "platform_fopen(", txt, None)
    # The static CRT behind the crt_ wrappers has C linkage, whatever a file declares.
    txt = sub(
        src,
        r'(?m)^(?!extern "C")((?:(?:unsigned|const|struct) )*\w+ ?\**) ?(crt_\w+)\(',
        r'extern "C" \1 \2(',
        txt,
        None,
    )
    txt = prototypes(src, txt, GAME_PROTOTYPES)
    if wrapped:
        # The host wraps this function (game/sources.json); the recovered body keeps a _recovered name, in its
        # header's declarations too.
        txt = f"#define {src.stem} {src.stem}_recovered\n" + txt
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
    "dsound.h": ["IDirectSound8", "IDirectSoundBuffer"],
}


def com_defaults(root, headers):
    lines = [
        "#pragma once",
        '#include "grim_d3d8.h"',
        "#include <dinput.h>",
        "#include <dsound.h>",
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


# The libraries Grim links: IJG libjpeg 6a's decompressor and zlib 1.1.3's inflater.
THIRD_PARTY = {
    "ijg-libjpeg-6a": [
        "jcomapi",
        "jdapimin",
        "jdapistd",
        "jdcoefct",
        "jdcolor",
        "jddctmgr",
        "jdhuff",
        "jdinput",
        "jdmainct",
        "jdmarker",
        "jdmaster",
        "jdmerge",
        "jdphuff",
        "jdpostct",
        "jdsample",
        "jerror",
        "jidctflt",
        "jidctfst",
        "jidctint",
        "jidctred",
        "jmemmgr",
        "jmemnobs",
        "jquant1",
        "jquant2",
        "jutils",
    ],
    "zlib-1.1.3": [
        "adler32",
        "crc32",
        "infblock",
        "infcodes",
        "inffast",
        "inflate",
        "inftrees",
        "infutil",
        "uncompr",
        "zutil",
    ],
}


def game_third_party(root):
    return [
        root / "third_party/sources" / library / f"{name}.c" for library, names in THIRD_PARTY.items() for name in names
    ]


def image_entries(root, image):
    d = json.loads((root / f"tools/native/data_definitions/{image}.json").read_text())
    entries = list(d["entries"])
    for group in d["groups"]:
        for member in group["members"]:
            entries.append(
                {
                    "address": member[0],
                    "name": member[1],
                    "size": group["size"],
                    "initializer_hex": member[2] if len(member) > 2 else group.get("initializer_hex", ""),
                },
            )
    return entries


def simulation_names(root):
    # Every identifier the verifier's sources and host name: a superset of the
    # executable's globals a simulation reads or writes.
    sources = json.loads((root / "crimson-core/sources.json").read_text())
    texts = [(root / rel).read_text() for rel in sources]
    texts += [path.read_text() for path in (root / "crimson-core/host").glob("*.*")]
    return {name for text in texts for name in re.findall(r"[A-Za-z_]\w*", text)}


# What a run inside the running original keeps although the simulation names
# it: the texture, sound and music handles the original loaded, the screen's
# transition, which only the UI reads, and the sprite-sheet cells
# effect_uv_tables_init lays out at startup, which effects, bonuses and the player
# draw with and the verifier never fills: effect_spawn copies them only into quads
# no snapshot field holds, the perk prompt's layout, which a tick never
# hit-tests (adapt_game), and the player's time played, which the frame counts
# between ticks and only the menus show. Names inside a kept aggregate stay
# with it.
# Settings and progress reset with the
# rest; the player's own stay outside ticks (host/session.inc).
# Sessions inside the original after it loads its
# assets agree with the verifier on every gate stream (checks/game_check.py --live).
SESSION_KEEPS = re.compile(
    r"_texture$|^terrain_texture_|^sfx_|^music_(track_|entry_table$|playlist$|playlist_entry_count$|ready$|fade_out_flags$)"
    r"|^audio_asset_id_table$"
    r"|^creature_type_table$|^bonus_icon_|^ui_element|^ui_transition_"
    r"|^effect_uv(2|4|8|16|_strip16)$|^perk_prompt_(origin|bounds)_|^time_played_ms$",
)


def game_data(root, out, engine, simulation):
    # wasm32 keeps the original pointer width, so each image's data keeps its
    # original layout: aggregates read through a first symbol, overreads and
    # interior names land on the original bytes. Engine state (Grim's, and the
    # executable's named engine globals) resets once; the rest at every run.
    # A run inside the running original resets only the simulation's globals,
    # so the presentation the original loaded and laid out survives it.
    exe = image_entries(root, "crimsonland.exe")
    names = {e["name"] for e in exe}
    # The compiler emits Grim's interface vtable; its other symbol tables, and the
    # names both images define, belong to the statically linked D3DX.
    grim = [e for e in image_entries(root, "grim.dll") if "initializer_symbols" not in e and e["name"] not in names]
    lines = ["#include <stdint.h>", "#include <string.h>", 'extern "C" {']
    resets = {"run": [], "engine": [], "presentation": []}
    # The spans a run's state lives in, coalesced, for its keyframes (host/keyframes.inc).
    run_spans = []
    for image, entries in (("exe", exe), ("grim", grim)):
        base = min(int(e["address"], 16) for e in entries)
        size = max(int(e["address"], 16) + e["size"] for e in entries) - base
        lines.append(f"alignas(16) unsigned char game_image_{image}[{size}];")
        clears, fills = {kind: [] for kind in resets}, {kind: [] for kind in resets}
        own = {
            e["name"]: "engine"
            if image == "grim" or e["name"] in engine
            else "run"
            if e["name"] in simulation and not SESSION_KEEPS.search(e["name"])
            else "presentation"
            for e in entries
        }
        # A name inside an aggregate the run keeps is kept with it: resetting the
        # name alone would clear that slice of the aggregate.
        kept_spans = [
            (int(e["address"], 16), int(e["address"], 16) + e["size"])
            for e in entries
            if own[e["name"]] != "engine" and SESSION_KEEPS.search(e["name"])
        ]
        for e in sorted(entries, key=lambda e: int(e["address"], 16)):
            offset = int(e["address"], 16) - base
            if re.fullmatch(r"[A-Za-z_]\w*", e["name"]):
                lines.append(f'asm(".globl {e["name"]}\\n.set {e["name"]}, game_image_{image}+{offset}\\n");')
            start, end = int(e["address"], 16), int(e["address"], 16) + e["size"]
            kept = any(s <= start and end <= f and f - s > e["size"] for s, f in kept_spans)
            kind = "presentation" if kept and own[e["name"]] == "run" else own[e["name"]]
            clears[kind].append(f"memset(game_image_{image}+{offset},0,{e['size']});")
            if kind == "run":
                if run_spans and run_spans[-1][0] == image and run_spans[-1][2] >= offset:
                    run_spans[-1][2] = max(run_spans[-1][2], offset + e["size"])
                else:
                    run_spans.append([image, offset, offset + e["size"]])
            if (data := e.get("initializer_hex", "")) and any(bytes.fromhex(data)):
                values = ",".join(map(str, bytes.fromhex(data)))
                fills[kind].append(
                    f"{{const unsigned char b[]={{{values}}}; memcpy(game_image_{image}+{offset},b,sizeof(b));}}",
                )
            if "initializer_target" in e:
                target = e["initializer_target"][1]
                fills[kind].append(
                    f"{{extern unsigned char {target}[]; uint32_t p=(uint32_t)(uintptr_t){target};"
                    f" memcpy(game_image_{image}+{offset},&p,4);}}",
                )
        for kind, parts in resets.items():
            parts.append((clears[kind], fills[kind]))
    # game_frame_update reads the cursor and both aim points as one aggregate.
    lines.append('asm(".globl frame_cursor_state\\n.set frame_cursor_state, ui_mouse_x\\n");')

    def reset(name, *kinds):
        # Every clear before any initializer: interior names overlap aggregates.
        parts = [part for kind in kinds for part in resets[kind]]
        return [
            f"void {name}() {{",
            *(c for clears, _ in parts for c in clears),
            *(f for _, fills in parts for f in fills),
            "}",
        ]

    spans = ",".join(f"{{game_image_{image}+{start},{end - start}}}" for image, start, end in run_spans)
    lines += [
        "struct GameSpan { unsigned char *at; uint32_t size; };",
        f"extern const GameSpan game_run_spans[] = {{{spans}}};",
        f"extern const int game_run_span_count = {len(run_spans)};",
    ]
    lines += reset("portable_reset_data", "run", "presentation")
    lines += reset("portable_reset_simulation_data", "run")
    lines += [*reset("portable_reset_engine_data", "engine"), "}"]
    (out / "data.cpp").write_text("\n".join(lines) + "\n")


# The executable's C++ static initializers, in the order of its .CRT$XCU table
# (VA 0x471004-0x4710dc in the 1.9.93 executable). The first entry, at 0x401000,
# only zeroes two globals that start zeroed and is left out. The *_meta_*
# entries construct tables the platform layer owns (host/game.inc).
STATIC_INITIALIZERS = [
    "console_global_construct_and_register",
    "config_init_defaults_thunk",
    "credits_line_table_global_init_thunk",
    "crimson_crt_empty_initializer_slot_05_thunk",
    "mod_api_init_thunk",
    "crimson_crt_empty_initializer_slot_07_thunk",
    "gameplay_run_state_init_thunk",
    "crimson_crt_empty_initializer_slot_09_thunk",
    "quest_meta_global_construct_and_register",
    "bonus_pool_global_init_thunk",
    "creature_spawn_slot_table_global_init_thunk",
    "game_status_global_init_thunk",
    "highscore_init_sentinels_thunk",
    "bonus_meta_global_construct_and_register",
    "ui_menu_template_pool_init_thunk",
    "ui_element_globals_init_thunk",
    "reserved_color_global_init_thunk",
    "bonus_hud_slot_table_global_init_thunk",
    "unused_fx_queue_random_prefix_color_global_init_thunk",
    "unused_fx_rotated_creature_type_id_prefix_color_global_init_thunk",
    "unused_aim64_prefix_color_global_init_thunk",
    "unused_fx_rotated_scale_prefix_color_global_init_thunk",
    "render_tint_color_global_init_thunk",
    "unused_global_noop_init_thunk",
    "unused_particle_pool_suffix_color_global_init_thunk",
    "unused_effect_uv8_prefix_state_global_init_thunk",
    "unused_effect_uv16_prefix_vec2_global_init_thunk",
    "unused_effect_uv_strip16_prefix_vec2_global_init_thunk",
    "fx_queue_global_init_thunk",
    "crimson_crt_empty_initializer_slot_31_thunk",
    "unused_fx_queue_random_prefix_vec2_global_init_thunk",
    "secondary_projectile_pool_global_init_thunk",
    "sprite_effect_pool_global_init_thunk",
    "particle_pool_global_init_thunk",
    "player_state_table_global_init_thunk",
    "creature_pool_global_init_thunk",
    "crimson_crt_empty_initializer_slot_38_thunk",
    "crimson_crt_empty_initializer_slot_39_thunk",
    "projectile_pool_global_init_thunk",
    "crimson_crt_empty_initializer_slot_41_thunk",
    "crimson_crt_empty_initializer_slot_42_thunk",
    "crimson_crt_empty_initializer_slot_43_thunk",
    "crimson_crt_empty_initializer_slot_44_thunk",
    "crimson_crt_empty_initializer_slot_45_thunk",
    "bonus_pool_sentinel_global_init_thunk",
    "effect_pool_vertices_global_init_thunk",
    "crimson_crt_empty_initializer_slot_48_thunk",
    "crimson_crt_empty_initializer_slot_49_thunk",
    "perk_meta_global_construct_and_register",
    "sfx_entry_table_init_thunk",
    "audio_asset_id_table_init_thunk",
    "music_entry_table_init_thunk",
    "crimson_crt_empty_initializer_slot_54_thunk",
    "weapon_table_defaults_global_init_thunk",
]


def game_initializers(root, out):
    # Each initializer is declared with its recovered return type: a wasm call
    # through the CRT's void(void) type would not match.
    sources = {
        path.stem: path
        for path in (root / "decomp/1.9/crimsonland").rglob("*.c*")
        if ".claude" not in path.relative_to(root).parts
    }
    lines = ['extern "C" {']
    for name in STATIC_INITIALIZERS:
        kind = "void"
        if name in sources:
            definition = re.search(rf"\b(void|int|unsigned char|bool) {name}\(void\)", sources[name].read_text())
            if not definition:
                raise SystemExit(f"Audit the static initializer {name}")
            kind = definition[1]
        lines.append(f"{kind} {name}(void);")
    lines += ["void game_static_init() {", *(f"  {name}();" for name in STATIC_INITIALIZERS), "}", "}"]
    (out / "initializers.cpp").write_text("\n".join(lines) + "\n")
