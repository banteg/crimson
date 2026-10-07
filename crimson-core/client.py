"""Evidence-only native client adapters; verifier host and sources stay intact."""

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Client seam changed: {old}")
    return text.replace(old, new)


def instrument(src, text):
    # Declarations use (void); instrument calls, retaining recovered source sites.
    original = src.read_text()
    lines = iter(original.count("\n", 0, match.start()) + 1 for match in re.finditer(r"\bcrt_rand\(\)", original))
    text = re.sub(r"\bcrt_rand\(\)", lambda _: f"client_rand(__FILE__, {next(lines)}, __func__)", text)
    if src.stem in {"sfx_play", "sfx_play_panned"}:
        text, count = re.subn(
            r'(extern "C" int sfx_play(?:_panned)?\([^{}]+\)\s*\{)',
            lambda match: match[0] + f'\n    client_sound_trigger("{src.stem}", sfx_id);',
            text,
        )
        if count != 1:
            raise ValueError(f"Client sound entry changed: {src}")
        pan = "0" if src.stem == "sfx_play" else "pan"
        text = replace_once(
            text,
            f"sfx_entry_table[sfx_id].buffers[voice]->SetPan({pan});",
            'client_unsupported("sound-device:SetPan");',
        )
    if src.stem == "ui_element_update":
        text = replace_once(text, "element->on_activate();", 'client_unsupported("ui:element-callback");')
    if src.stem == "ui_menu_layout_init":
        # Restore only its table/default setup stage; the asset/menu layout tail
        # is outside the gameplay slice. Keep the original assignments/defaults.
        text = text[: text.index("    copy_layer(ui_sign_crimson, ui_sign_crimson_template);")] + "}\n"
        text = replace_once(
            text, 'extern "C" void ui_menu_layout_init(void)', 'extern "C" void client_ui_table_defaults_init(void)',
        )
        text += 'extern "C" void ui_menu_layout_init(void) { client_unsupported("ui:menu-layout-assets"); }\n'
        text = replace_once(
            text, "#define CRIMSONLAND_USE_ORIGINAL_UI_OWNER", "// Client globals use native-width storage.",
        )
    return '#include "client.h"\n' + text


def prepare_cvars(root, out):
    # Recover registration unchanged; only generated native storage/layout expands.
    registration = (root / "decomp/1.9/crimsonland/game/register_core_cvars.cpp").read_text()
    cvars = re.findall(r"\b(cv_\w+)\s*=", registration)
    if len(cvars) != 13 or len(set(cvars)) != 13:
        raise ValueError("Audit changed core cvar registration")
    types = (root / "third_party/headers/crimsonland_types.h").read_text()
    types = replace_once(
        types,
        "unsigned char _pad0[0x0c];\n    float value;",
        "unsigned char _pad0[sizeof(void *) * 2 + sizeof(int)];\n    float value;",
    )
    (out / "include/crimsonland_types.h").write_text(types)
    data = (out / "data.cpp").read_text()
    symbols = cvars + ["console_log_queue", "console_command_list_head", "console_log_head"]
    for symbol in symbols:
        data, count = re.subn(r'^asm\("\.globl " P "' + symbol + r"\\n\.set .*?\);\n", "", data, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"Audit changed client cvar data symbol: {symbol}")
    storage = [
        '#include "crimsonland_console.h"',
        "#include <stddef.h>",
        "static_assert(offsetof(cvar_float_t, value) == offsetof(console_cvar_entry_t, value));",
        'extern "C" {',
        "alignas(console_queue_t) unsigned char client_console_queue[sizeof(console_queue_t)];",
        'asm(".globl " P "console_log_queue\\n.set " P "console_log_queue, " P "client_console_queue\\n");',
        *[f"console_cvar_entry_t *{name};" for name in cvars],
        "}",
    ]
    # Console interior aliases are unused here; console activation still aborts.
    resets = "memset(client_console_queue, 0, sizeof(client_console_queue));\n" + "\n".join(
        f"{name} = nullptr;" for name in cvars
    )
    data = replace_once(data, "void portable_reset_data() {", "void portable_reset_data() {\n" + resets)
    (out / "data.cpp").write_text(data.replace('extern "C" {', "\n".join(storage) + '\nextern "C" {', 1))


def prepare_ui_table(root, out):
    owner = (root / "tools/match/include/crimsonland_ui_state_owner.h").read_text()
    elements = re.findall(r"struct ui_element_t (\w+);", owner)
    if len(elements) != 42:
        raise ValueError("Audit changed UI element owner")
    data = (out / "data.cpp").read_text()
    # The original table aliases expose 41 pointers with a 4-byte stride.
    table = re.search(
        r'asm\("\.globl " P "ui_element_table\\n\.set " P "ui_element_table, " P "(portable_data_\d+)\+0\\n"\);', data,
    )
    if not table:
        raise ValueError("Audit changed UI table storage")
    aliases = re.findall(r'asm\("\.globl " P "(\w+)\\n\.set .*?' + table[1] + r'\+(\d+)\\n"\);', data)
    if len(aliases) != 42:
        raise ValueError("Audit changed UI table aliases")
    storage = [
        'extern "C" {',
        *[f"ui_element_t {name};" for name in elements],
        "ui_element_t *ui_element_table[41];",
        "}",
    ]
    for name, offset in aliases:
        if name == "ui_element_table":
            continue
        storage += [
            "#if UINTPTR_MAX > 0xffffffffu",
            f'asm(".globl " P "{name}\\n.set " P "{name}, " P "ui_element_table+{int(offset) * 2}\\n");',
            "#else",
            f'asm(".globl " P "{name}\\n.set " P "{name}, " P "ui_element_table+{offset}\\n");',
            "#endif",
        ]
    for symbol in elements + [name for name, _ in aliases] + ["ui_sign_crimson_update_disabled"]:
        data, count = re.subn(r'^asm\("\.globl " P "' + symbol + r"\\n\.set .*?\);\n", "", data, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"Audit changed UI data symbol: {symbol}")
    storage.append(
        'asm(".globl " P "ui_sign_crimson_update_disabled\\n.set " P "ui_sign_crimson_update_disabled, " P "ui_sign_crimson+2\\n");',
    )
    resets = "\n".join(f"memset(&{name}, 0, sizeof({name}));" for name in elements)
    resets += "\nmemset(ui_element_table, 0, sizeof(ui_element_table));"
    data = replace_once(data, "void portable_reset_data() {", "void portable_reset_data() {\n" + resets)
    (out / "data.cpp").write_text(data.replace('extern "C" {', "\n".join(storage) + '\nextern "C" {', 1))


def prepare(root, out, sources):
    prepare_cvars(root, out)
    prepare_ui_table(root, out)
    header = (root / "tools/match/include/grim2d_cpp.h").read_text()
    methods = re.findall(r"virtual\s+(.+?)\s*(grim_\w+)\(", header)
    methods = [(ret, name) for ret, name in methods if "legacy" not in name]
    reads, callers, sites = set(), [], []
    for rel in sources:
        text = (root / rel).read_text()
        if Path(rel).stem == "ui_menu_layout_init":
            text = text[: text.index("    copy_layer(ui_sign_crimson, ui_sign_crimson_template);")]
        for number, line in enumerate(text.splitlines(), 1):
            if "crt_rand()" in line or re.search(r"\brand\(\)", line):
                callers.append({"source": rel, "line": number, "expression": line.strip()})
        for match in re.finditer(r"grim_interface_ptr->(grim_\w+)\s*\(", text):
            name = match[1]
            # Conservative expression-use flag, not a proof of authoritative influence.
            boundary = max(text.rfind(c, 0, match.start()) for c in ";{}")
            before = text[boundary + 1 : match.start()].strip()
            consumed = bool(before)
            sites.append(
                {
                    "source": rel,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "slot": name,
                    "expression_use": consumed,
                },
            )
            if consumed:
                reads.add(name)
    slots = [
        {
            "index": i,
            "offset": f"0x{i * 4:03x}",
            "name": name,
            "return_type": ret,
            "return_read": ret != "void" and name in reads,
        }
        for i, (ret, name) in enumerate(methods)
    ]
    (out / "inventory.json").write_text(
        json.dumps({"sources": sources, "slots": slots, "grim_sites": sites, "rand_sites": callers}, indent=2) + "\n",
    )
    (out / "include/client.h").write_text(
        '#pragma once\nextern "C" int client_rand(const char *, int, const char *);\n'
        "[[noreturn]] void client_unsupported(const char *);\n"
        "void client_sound_trigger(const char *, int);\n",
    )
    grim = (HERE / "host/grim.inc").read_text()
    grim = grim.replace("HeadlessGrim", "RecordingGrim")
    lookup = {s["name"]: s for s in slots}

    def record_body(match):
        slot = lookup[match[1]]
        body = match[0] + f' client_slot({slot["index"]}, "{slot["name"]}", {str(slot["return_read"]).lower()});'
        if not any(site["slot"] == slot["name"] for site in sites):
            body += f' client_unsupported("grim:{slot["name"]}");'
        return body

    grim, bodies = re.subn(r"\b(grim_\w+)\([^{}]*?\)(?: override)?\s*\{", record_body, grim)
    if len(slots) != 84 or bodies != 108:
        raise ValueError(f"Audit changed Grim layout: {len(slots)} slots, {bodies} bodies")
    (out / "include/client_grim.inc").write_text(grim)
    probe = []
    for name, parameters in re.findall(r"virtual\s+.+?\b(grim_\w+)\(([^)]*)\)", header, re.DOTALL):
        if name not in lookup or not any(site["slot"] == name for site in sites):
            continue
        arguments = []
        for parameter in parameters.split(","):
            if parameter.strip() in {"void", "..."}:
                continue
            arguments.append(
                "nullptr"
                if "*" in parameter
                else "grim_config_value_t(0u)"
                if "grim_config_value_t" in parameter
                else "0",
            )
        probe.append(f"  headless_grim.{name}({', '.join(arguments)});")
    (out / "include/client_probe.inc").write_text("static void client_grim_probe() {\n" + "\n".join(probe) + "\n}\n")
    host = (HERE / "host/host.cpp").read_text()
    host = replace_once(host, '#include "grim.inc"', '#include "client_runtime.inc"\n#include "client_grim.inc"')
    host = replace_once(
        host,
        "int main(int argc, char **argv) {",
        '#include "client_probe.inc"\nint main(int argc, char **argv) {\n'
        "  setvbuf(stdout, nullptr, _IONBF, 0); // Retain complete snapshots if a later tick aborts.\n"
        '  if (argc == 2 && strcmp(argv[1], "--client-grim-probe") == 0) { client_grim_probe(); return 0; }\n'
        '  if (argc == 2 && strcmp(argv[1], "--client-unsupported-probe") == 0) { headless_grim.grim_init_system(); return 0; }\n'
        '  if (argc == 2 && strcmp(argv[1], "--client-rand-probe") == 0) { client_rand("probe", 0, "outside_tick_probe"); return 0; }',
    )
    host = replace_once(
        host,
        'extern "C" int crt_rand() {',
        'extern "C" int crt_rand() {\n  client_check_rand("host/host.cpp", 0, "crt_rand");',
    )
    for stem in [
        "terrain_render",
        "perk_prompt_update_and_render",
        "ui_render_aim_indicators",
        "hud_update_and_render",
        "ui_elements_update_and_render",
        "ui_cursor_render",
    ]:
        host = replace_once(host, f'extern "C" void {stem}() {{}}', "")
    host = replace_once(host, 'extern "C" void sfx_play(int, float) {}', "")
    host = replace_once(host, 'extern "C" int sfx_play_panned(int, const vec2f_t *, float) { return 0; }', "")
    host = replace_once(
        host,
        'extern "C" int sfx_entry_start_playback(music_entry_t *) { return 1; }',
        'extern "C" int sfx_entry_start_playback(music_entry_t *) { client_unsupported("sound-device:playback"); }',
    )
    host = replace_once(
        host,
        'extern "C" void sfx_entry_set_volume(music_entry_t *, float) {}',
        'extern "C" void sfx_entry_set_volume(music_entry_t *, float) { client_unsupported("sound-device:volume"); }',
    )
    host = replace_once(
        host,
        'extern "C" int portable_init(uint32_t seed, int mode, int major, int minor) {',
        'extern "C" int portable_init(uint32_t seed, int mode, int major, int minor) {\n'
        "  ClientTickScope client_init_scope;\n"
        '  if (mode != GAME_MODE_QUEST || major != 1 || minor != 1) client_unsupported("session:only-quest-1.1");',
    )
    first = host.index("  friendly.value = cfg.friendly_fire ? 1 : 0;")
    last = host.index("  config_blob.player_count = 1;", first)
    host = (
        host[:first]
        + "  register_core_cvars();\n  client_record_cvars();\n  cv_friendlyFire->value = cfg.friendly_fire ? 1 : 0;\n"
        + host[last:]
    )
    host = replace_once(
        host, '  trace_init("creature pool");', '  client_ui_table_defaults_init();\n  trace_init("creature pool");',
    )
    host = replace_once(
        host,
        "  // Replay input flags",
        "  ClientTickScope client_tick_scope;\n  // Replay input flags",
    )
    host = replace_once(
        host,
        "  ClientTickScope client_tick_scope;",
        '  if (game_paused_flag) client_unsupported("session:pause");\n'
        '  if (console_open_flag) client_unsupported("console");\n'
        "  ClientTickScope client_tick_scope;",
    )
    host = replace_once(
        host,
        "  if (game_state_pending == GAME_STATE_PERK_SELECTION)\n",
        "  if (game_state_pending == GAME_STATE_PERK_SELECTION) perk_selection_screen_update();\n"
        "  if (game_state_pending == GAME_STATE_PERK_SELECTION)\n",
    )
    for old, new in [
        (
            'extern "C" void demo_mode_start() { abort(); }',
            'extern "C" void demo_mode_start() { client_unsupported("demo-mode"); }',
        ),
        (
            'extern "C" void tutorial_timeline_update() { abort(); }',
            'extern "C" void tutorial_timeline_update() { client_unsupported("tutorial"); }',
        ),
        (
            'extern "C" void demo_trial_overlay_render(float *, float) { abort(); }',
            'extern "C" void demo_trial_overlay_render(float *, float) { client_unsupported("demo-trial"); }',
        ),
        (
            'extern "C" void ui_render_keybind_help(float *, float) {}',
            'extern "C" void ui_render_keybind_help(float *, float) { client_unsupported("pause-keybind-help"); }',
        ),
        (
            'extern "C" void game_save_status() {}',
            'extern "C" void game_save_status() { client_unsupported("persistence:save-status"); }',
        ),
        (
            'extern "C" int play_time_get() { return 0; }',
            'extern "C" int play_time_get() { client_unsupported("persistence:play-time"); }',
        ),
        (
            'extern "C" void game_state_set(game_state_id_t s) { game_state_pending = s; }',
            (
                'extern "C" void game_state_set(game_state_id_t s) {\n'
                "  if (s != GAME_STATE_GAMEPLAY && s != GAME_STATE_PERK_SELECTION && s != GAME_STATE_QUEST_RESULTS && s != GAME_STATE_QUEST_FAILED && s != GAME_STATE_PENDING_IDLE_SENTINEL)\n"
                '    client_unsupported("session:state-outside-quest-slice");\n'
                "  game_state_pending = s;\n}"
            ),
        ),
    ]:
        host = replace_once(host, old, new)
    host = host.replace("  crt_rand();", '  client_rand("host/host.cpp", __LINE__, __func__);')
    (out / "host.cpp").write_text(host)
    (out / "include/client_runtime.inc").write_text((HERE / "client/runtime.inc").read_text())
