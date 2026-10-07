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
    return '#include "client.h"\n' + text


def prepare(root, out, sources):
    header = (root / "tools/match/include/grim2d_cpp.h").read_text()
    methods = re.findall(r"virtual\s+(.+?)\s*(grim_\w+)\(", header)
    methods = [(ret, name) for ret, name in methods if "legacy" not in name]
    reads, callers, sites = set(), [], []
    for rel in sources:
        text = (root / rel).read_text()
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
