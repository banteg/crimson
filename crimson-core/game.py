"""The game module: the verifier selection plus recovered presentation, Grim and a platform layer."""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
GAME = HERE / "game"


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
            and ".claude" not in path.parts
            and path.relative_to(tree).as_posix() not in replaced
            and str(path.relative_to(root)) not in verifier
        )
    return found


def object_name(rel):
    # Grim and the executable reuse file names; the path keeps objects apart.
    return re.sub(r"[^A-Za-z0-9_]", "_", str(Path(rel).with_suffix("")).removeprefix("decomp/1.9/"))


def game_headers(headers):
    # Recovered Grim defines every interface method itself.
    path = headers / "grim2d_cpp.h"
    text, count = re.subn(r"\) = 0;", ");", path.read_text())
    if count != 62:
        raise SystemExit(f"Audit the Grim interface before building the game module ({count} pure methods)")
    # VC6 converts a string literal to char *; C++17 would pick the bool overload.
    text = replace_once(
        text,
        "    grim_config_value_t(char *value) {",
        "    grim_config_value_t(const char *value) { words[3] = (unsigned int)(uintptr_t)value; }\n"
        "    grim_config_value_t(char *value) {",
        path,
    )
    path.write_text(text)
    # A fresh configuration is the Python port's (grim/config.py default_crimson_cfg):
    # windowed, since the host owns the window, at 1024x768, the resolution the
    # verifier simulates, so the client's runs replay as they played (host/session.inc).
    path = headers / "crimson_config_defaults_impl.h"
    text = replace_once(
        path.read_text(),
        "CRIMSON_CONFIG_DEFAULTS_BLOB.screen_width = 800;\n    CRIMSON_CONFIG_DEFAULTS_BLOB.screen_height = 600;",
        "CRIMSON_CONFIG_DEFAULTS_BLOB.screen_width = 1024;\n    CRIMSON_CONFIG_DEFAULTS_BLOB.screen_height = 768;",
        path,
    )
    path.write_text(
        replace_once(
            text,
            "CRIMSON_CONFIG_DEFAULTS_BLOB.windowed = 0;",
            "CRIMSON_CONFIG_DEFAULTS_BLOB.windowed = 1;",
            path,
        ),
    )
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


# The vendored C the platform layer links (game/leaderboard.cpp): zstd 1.5.7's
# single-file library without its dictionary builder or threads, and Monocypher
# 4.0.2 with its Ed25519.
def game_vendor_c():
    return [GAME / "vendor" / name for name in ("zstd.c", "monocypher.c", "monocypher-ed25519.c")]


def replace_once(text, old, new, src):
    if text.count(old) != 1:
        raise SystemExit(f"Audit {src.name} before changing this game adapter: {old!r}")
    return text.replace(old, new)


# Recovered functions host/game.inc and host/session.inc wrap: a simulation tick
# must run some as the verifier does, a run the client plays drives others, a
# sound entry the device never created stays silent, and a run's wrapped
# strings live in its arena. The recovered body keeps a _recovered name.
SEAMS = (
    "game_state_set",
    "gameplay_update_and_render",
    "highscore_sync_worker",
    "input_primary_just_pressed",
    "play_time_get",
    "sfx_entry_start_playback",
    "ui_elements_update_and_render",
    "wrap_text_to_width_alloc",
)


def session_seam(session, original, statement=False):
    # The game module takes the recorded input only inside a session (host/game.inc).
    if statement:
        return f"if (game_ticking) {{\n{session}\n}} else {{\n{original}\n}}"
    return f"(game_ticking ? ({session}) : ({original}))"


def adapt_game(src, txt):
    if src.suffix == ".c":
        # The adapter gives C linkage to the common return types; the rest of a
        # C file's top-level functions need it too.
        txt = re.sub(
            r'(?m)^(?!static |typedef |return |extern "C")(extern )?((?:(?:unsigned|signed|const|struct) )*\w+ ?\**) ?(\w+)\(',
            r'extern "C" \2 \3(',
            txt,
        )
    # Files open through the platform layer, which takes Windows paths.
    txt = re.sub(r"\bfopen\(", "platform_fopen(", txt)
    # The static CRT behind the crt_ wrappers has C linkage, whatever a file declares.
    txt = re.sub(
        r'(?m)^(?!extern "C")((?:(?:unsigned|const|struct) )*\w+ ?\**) ?(crt_\w+)\(',
        r'extern "C" \1 \2(',
        txt,
    )
    if "game_ticking" in txt:
        txt = 'extern "C" unsigned char game_ticking;\n' + txt
    if src.stem in SEAMS:
        txt, count = re.subn(rf"\b{src.stem}\(", f"{src.stem}_recovered(", txt)
        if not count:
            raise SystemExit(f"Audit {src.name} before changing its seam")
    if src.parent.name == "texture" and src.stem == "load_file":
        # The distributed crimson.paq stores some images decoded, under the same
        # path with their own extension: Grim loads the stored entry by what it
        # holds (game/repack.cpp).
        txt = replace_once(
            txt,
            "    bool found_in_lookup = false;",
            "    path = grim_lookup_blob_entry(path);\n    bool found_in_lookup = false;",
            src,
        )
        txt = "char *grim_lookup_blob_entry(char *path);\n" + txt
    if src.parent.name == "app" and src.stem == "init_system":
        txt = replace_once(
            txt,
            'grim_lookup_blob_find("load\\\\smallFnt.dat")',
            'grim_lookup_blob_find(grim_lookup_blob_entry((char *)"load\\\\smallFnt.dat"))',
            src,
        )
        txt = "char *grim_lookup_blob_entry(char *path);\n" + txt
    if src.stem == "gameplay_update_and_render":
        # The verifier lays out no perk prompt, so a click in a tick never opens
        # the menu; the run takes a click on it between ticks (host/session.inc).
        txt = replace_once(
            txt,
            "            } else if (relative_mouse.x > perk_prompt_bounds_min_x",
            "            } else if (!game_ticking && relative_mouse.x > perk_prompt_bounds_min_x",
            src,
        )
        if 'extern "C" unsigned char game_ticking;' not in txt:
            txt = 'extern "C" unsigned char game_ticking;\n' + txt
    if src.stem == "config_ensure_file":
        # The original writes a missing crimson.cfg with violence off; a fresh
        # configuration is the Python port's, which keeps it on.
        txt = replace_once(txt, "    config_violence_disabled = 1;\n", "", src)
    if src.stem == "play_game_menu_update":
        # The Ranked row (host/ranked.inc): a ranked attempt lists only the modes
        # that rank, Quests and Survival, and plays one player.
        txt, count = re.subn(
            r"(\n(\s+)ui_button_update\(\(float \*\)&position, \(ui_button_t \*\)&rush_button\);\n"
            r"\s+if \(show_play_counts\) \{\n(?:.*\n)*?\2\}\n\2position\.y \+= (?:32|28)\.0f;\n)",
            lambda m: f"\n{m[2]}if (!ranked_checked) {{{m[1]}{m[2]}}}\n",
            txt,
        )
        if count != 2:
            raise SystemExit(f"Audit {src.name}: Rush rows ({count})")
        txt = replace_once(txt, "        if (game_is_full_version()) {", "        if (!ranked_checked && game_is_full_version()) {", src)
        txt = replace_once(
            txt,
            "            }\n        }\n        position.y += 28.0f;\n\n        if (quest_play_counts[11]",
            "            }\n        }\n        if (!ranked_checked)\n            position.y += 28.0f;\n\n        if (quest_play_counts[11]",
            src,
        )
        txt, count = re.subn(
            r"if \((mode_play_rush \+ quest_play_counts\[11\] \+ mode_play_survival|quest_play_counts\[11\] \+ mode_play_survival \+ mode_play_rush) ([<>]=? 0)\)",
            r"if (!ranked_checked && \1 \2)",
            txt,
        )
        if count != 4:
            raise SystemExit(f"Audit {src.name}: tutorial rows ({count})")
        txt = replace_once(
            txt,
            "    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.81f);\n    int selected = ui_list_widget_update(",
            "    player_count_list.enabled = !ranked_checked;\n"
            "    grim_interface_ptr->grim_set_color(1.0f, 1.0f, 1.0f, 0.81f);\n    int selected = ui_list_widget_update(",
            src,
        )
        txt = replace_once(
            txt,
            "    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);\n\n    if (quests_button.hover_anim > 0) {",
            "    grim_interface_ptr->grim_set_config_var(0x18, 0.5f);\n"
            "    ranked_menu(base_position.v, position.v, player_count_list.open != 0);\n\n"
            "    if (quests_button.hover_anim > 0) {",
            src,
        )
        txt = 'extern "C" bool ranked_checked;\nextern "C" void ranked_menu(float *base, float *tips, bool list_open);\n' + txt
    if src.stem == "ui_menu_layout_init":
        # The Play Game panel grows by the Ranked row (host/ranked.inc).
        txt = replace_once(
            txt,
            "    for (int calc_index = 0; calc_index < 41; calc_index++) {",
            "    ranked_layout();\n    for (int calc_index = 0; calc_index < 41; calc_index++) {",
            src,
        )
        txt = 'extern "C" void ranked_layout(void);\n' + txt
    if src.stem == "mods_any_available":
        # No version runs mods (docs/rewrite/status.md), so the main menu never offers them.
        txt = replace_once(txt, "    int count = 0;", "    return false;\n    int count = 0;", src)
    if src.stem == "input_key_name":
        # Its header defines it; a live run names the player's keys (host/session.inc).
        txt = "#define input_key_name input_key_name_recovered\n" + txt
    if src.stem == "perk_selection_screen_update":
        # In a run the client plays, the choice reaches the run as a command with
        # its next tick (host/session.inc), which applies it as the verifier does.
        pick = """        perk_apply(perk_choice_ids[perk_selection_index]);
        ui_transition_direction = 0;
        game_state_pending = GAME_STATE_GAMEPLAY;
        --perk_pending_count;
        perk_choices_dirty = 1;"""
        txt = replace_once(
            txt,
            pick,
            "        if (game_live_run()) {\n"
            "            game_live_pick(perk_selection_index);\n"
            "            ui_transition_direction = 0;\n"
            "            game_state_pending = GAME_STATE_GAMEPLAY;\n"
            f"        }} else {{\n{pick}\n        }}",
            src,
        )
        txt = 'extern "C" bool game_live_run();\nextern "C" void game_live_pick(int choice);\n' + txt
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
    if src.stem == "game_startup_init_prelude":
        # The SDK header's LARGE_INTEGER lacks the QuadPart view; the counter overwrites it anyway.
        txt = replace_once(
            txt,
            "counter.QuadPart = local_system_time.wMilliseconds;",
            "counter.LowPart = local_system_time.wMilliseconds;\n    counter.HighPart = 0;",
            src,
        )
    if src.stem == "highscore_submit_full_version_guard":
        # A C caller passed an argument the function never takes.
        txt = replace_once(txt, "game_is_full_version(record)", "game_is_full_version()", src)
    if src.stem == "controls_menu_update":
        # This helper flips the list it is given; it is no VC6 temporary.
        txt = replace_once(txt, "const ui_list_widget_t &list)", "ui_list_widget_t &list)", src)
    if src.stem == "vorbis_mem_open":
        # The callbacks spell size_t as the 32-bit unsigned int it was.
        for field in ("read_func", "seek_func", "close_func", "tell_func"):
            txt = re.sub(rf"(callbacks\.{field} = )(\w+);", rf"\1(decltype(callbacks.{field}))\2;", txt)
    if src.stem == "resource_open_read":
        # The resource header gives this reader C++ linkage, as its other callers use.
        txt = replace_once(txt, 'extern "C" unsigned char resource_pack_read_cstring(FILE *fp);\n', "", src)
    if src.stem == "resource_pack_read_cstring":
        txt = replace_once(
            txt,
            'extern "C" unsigned char resource_pack_read_cstring(',
            "unsigned char resource_pack_read_cstring(",
            src,
        )
    if src.stem == "texture_get_or_load_alt":
        # Callers pass only the name, which it uses as the path too.
        txt = replace_once(
            txt,
            "texture_get_or_load_alt(char *name, char *path)",
            "texture_get_or_load_alt(char *name)",
            src,
        )
    if src.stem == "options_menu_update":
        txt = replace_once(
            txt,
            "void ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);",
            "bool ui_checkbox_update(float *xy, ui_checkbox_t *checkbox);",
            src,
        )
    if src.stem == "tutorial_prompt_dialog":
        txt = replace_once(txt, "void console_input_poll(void);", "int console_input_poll(void);", src)
    if src.stem == "game_frame_update":
        txt = replace_once(
            txt,
            "unsigned char game_is_full_version(...);",
            "unsigned char game_is_full_version(void);",
            src,
        )
        # Its loading-screen calls pass a stage the function never reads.
        txt = re.sub(r"game_is_full_version\([123]\);", "game_is_full_version();", txt)
        txt = replace_once(txt, "void config_sync_from_grim(void);", "bool config_sync_from_grim(void);", src)
        # Escape in a run the client plays asks the run for the pause menu: the
        # pending state is simulation state, which only ticks write (host/session.inc).
        txt = replace_once(
            txt,
            "        ui_transition_direction = 0;\n        game_state_pending = GAME_STATE_PAUSE_MENU;",
            "        ui_transition_direction = 0;\n        if (!game_live_pause())\n"
            "            game_state_pending = GAME_STATE_PAUSE_MENU;",
            src,
        )
        # The console's flag pauses parts of a tick: a run keeps it closed.
        txt = replace_once(
            txt,
            "    if (grim_interface_ptr->grim_was_key_pressed(0x29)) {",
            "    if (!game_live_run() && grim_interface_ptr->grim_was_key_pressed(0x29)) {",
            src,
        )
        txt = 'extern "C" bool game_live_pause();\nextern "C" bool game_live_run();\n' + txt
    if src.stem == "crimsonland_main":
        # The host owns the main loop: startup ends where Grim's run loop began,
        # and the code after the loop becomes its own entry point (game/frame.cpp).
        txt = replace_once(
            txt,
            "    grim_interface_ptr->grim_apply_settings();\n",
            '    return 1;\n}\n\nextern "C" int crimsonland_main_exit(void)\n{\n    HKEY status_key;\n',
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
# no snapshot field holds, and the perk prompt's layout, which a tick never
# hit-tests (adapt_game). Names inside a kept aggregate stay with it.
# Settings and progress reset with the
# rest; the player's own stay outside ticks (host/session.inc).
# Sessions inside the original after it loads its
# assets agree with the verifier on every gate stream (checks/game_check.py --live).
SESSION_KEEPS = re.compile(
    r"_texture$|^terrain_texture_|^sfx_|^music_(track_|entry_table$|playlist$|playlist_entry_count$|ready$|fade_out_flags$)"
    r"|^audio_asset_id_table$"
    r"|^creature_type_table$|^bonus_icon_|^ui_element|^ui_transition_"
    r"|^effect_uv(2|4|8|16|_strip16)$|^perk_prompt_(origin|bounds)_",
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
        path.stem: path for path in (root / "decomp/1.9/crimsonland").rglob("*.c*") if ".claude" not in path.parts
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
