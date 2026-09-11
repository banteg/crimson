"""Feed original player-update query witnesses through the actual Frida callbacks."""

import argparse
import importlib.util
import json
import shutil
import struct
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHARED = HERE.parent / "player-aim-direction-2026-09-11"
sys.path.insert(0, str(SHARED))
spec = importlib.util.spec_from_file_location("shortcut", HERE.parent / "player-fire-bullets-shortcut-2026-09-11/verify.py")
shortcut = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shortcut)
v = shortcut.v
BEFORE_HOOKS_SHA = "ba1cf2f034135e8b561dd03fd214d42f679d52439619cae8df9701088271333f"


def scenarios():
    yield from shortcut.scenarios()
    for index in (0, 1):
        for name, overrides in (
            ("auto-no-g", {}),
            ("auto-far", {"creatures": [{"index": 0, "x": 800, "y": 900}]}),
            ("auto-cooldown", {"shot_cooldown": 0.5}),
            ("man-bomb-only", {"aim": 1, "perks": {"man_bomb": 1}, "man_bomb_timer": 5.0}),
            ("hot-tempered-only", {"aim": 1, "perks": {"hot_tempered": 1}, "hot_tempered_timer": 10.0}),
        ):
            yield {"name": f"{name}-p{index}", "frame": {
                "index": index, "movement": 2, "move_speed": 0.0, "shot_cooldown": 0.0,
                "aim": 5, "keys": [], "aim_position": [300, 400],
                "creatures": [{"index": 0, "x": 301, "y": 402}], **overrides,
            }}


def capture_cases(program, cases):
    original_rows = json.loads((HERE.parent / "player-fire-bullets-shortcut-2026-09-11/results.json").read_text())["cases"]
    captures, observations = [], []
    for number, case in enumerate(cases):
        frame = case["frame"]
        native = v.run(program, True, frame)
        candidate = v.run(program, False, frame)
        assert v.observation(native) == v.observation(candidate), case["name"]
        digest = v.sha(v.encoded(v.observation(native)))
        if number < len(original_rows):
            assert case["name"] == original_rows[number]["name"]
            assert digest == original_rows[number]["native_observation_sha256"]
        events = []
        queries = [row for row in native["calls"] if row[0] in ("perk", "key", "keydown")]
        for row, site in zip(queries, native["sites"], strict=True):
            if row[0] == "perk":
                continue
            events.append({
                "name": "grim_is_key_active" if row[0] == "key" else "grim_is_key_down",
                "key": row[1], "caller": int(site, 16), "result": int(row[1] in frame["keys"]),
                "player_index": frame["index"],
            })
        players = bytes.fromhex(native["state"]["players"])
        after_players = [{
            "aim_x": struct.unpack_from("<f", players, index * 864 + 80)[0],
            "aim_y": struct.unpack_from("<f", players, index * 864 + 84)[0],
            "aim_heading": struct.unpack_from("<f", players, index * 864 + 768)[0],
        } for index in (0, 1)]
        captures.append({"name": case["name"], "options": {
            "playerIndex": frame["index"], "aimScheme": frame.get("aim", 1), "players": after_players,
        }, "events": events})
        observations.append({
            **case, "native_observation_sha256": digest, "events": events,
            "native_calls": native["calls"],
            "timer_after": struct.unpack_from("<f", players, frame["index"] * 864 + 796)[0],
            "projectiles": sum(row[0] == "projectile_spawn" for row in native["calls"]),
        })
    return captures, observations


def run_capture(captures, before=False):
    request = {"source": str(ROOT / "scripts/frida/gameplay_diff_capture.js"), "cases": captures}
    if before:
        request["input_hooks"] = str(HERE / "before-input-hooks.js")
    result = subprocess.run(
        [shutil.which("node"), str(HERE / "harness.js")], input=json.dumps(request),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def boolean_return_witnesses(program):
    u, x = v.e.unicorn, v.e.x86
    rows = []
    for name in ("input_primary_just_pressed", "input_any_key_pressed"):
        for upper in (0, 0x100, 0x12340000, 0xFFFFFF00):
            mu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
            mu.mem_map(program.image.image_base, v.e.page_size(program.image.size_of_image))
            mu.mem_write(program.image.image_base, program.image.mapped)
            base = 0x30000000
            mu.mem_map(base, 0x20000)
            stop, stack, this, vtable, stub = base, base + 0x10000, base + 0x100, base + 0x200, base + 0x400
            mu.mem_write(stack, struct.pack("<I", stop))
            mu.mem_write(program.address("console_open_flag"), b"\x01")
            mu.mem_write(program.address("grim_interface_ptr"), struct.pack("<I", this))
            mu.mem_write(this, struct.pack("<I", vtable))
            mu.mem_write(vtable + 0x80, struct.pack("<I", stub))
            mu.reg_write(x.UC_X86_REG_ESP, stack)
            mu.reg_write(x.UC_X86_REG_EAX, upper)
            queried = []

            def input_stub(uc, address, size, data, *, stub=stub, queried=queried, upper=upper):
                if address != stub:
                    return
                sp = uc.reg_read(x.UC_X86_REG_ESP)
                ret, key = struct.unpack("<2I", uc.mem_read(sp, 8))
                queried.append(key)
                # The external key method returns false in AL; its upper EAX
                # bytes are outside the unsigned-char return contract.
                uc.reg_write(x.UC_X86_REG_EAX, upper)
                uc.reg_write(x.UC_X86_REG_ESP, sp + 8)
                uc.reg_write(x.UC_X86_REG_EIP, ret)

            mu.hook_add(u.UC_HOOK_CODE, input_stub)
            mu.emu_start(program.address(name), stop, count=100000)
            assert mu.reg_read(x.UC_X86_REG_EIP) == stop
            assert mu.reg_read(x.UC_X86_REG_ESP) == stack + 4
            eax = mu.reg_read(x.UC_X86_REG_EAX)
            assert eax == upper and eax & 0xFF == 0
            assert queried == (list(range(2, 0x17F)) if name == "input_any_key_pressed" else [])
            rows.append({"name": f"{name}-{upper:08x}", "function": name,
                         "upper_eax": upper, "returned_eax": eax, "modeled_key_queries": len(queried),
                         "events": [{"name": name, "key": 0, "caller": 0x00440000, "result": eax}]})
    captures = [{"name": row["name"], "events": row["events"]} for row in rows]
    for row, current, previous in zip(rows, run_capture(captures), run_capture(captures, before=True), strict=True):
        assert len(current["queries"]) == len(previous["queries"]) == 1
        row["captured_pressed"] = current["queries"][0][1]
        row["before_pressed"] = previous["queries"][0][1]
        assert not row["captured_pressed"] and row["before_pressed"] == bool(row["upper_eax"])
    return rows


def check_port(observed, capture):
    from crimson.gameplay import player_update
    from crimson.perks import PerkId
    from crimson.replay.input_codec import unpack_player_input
    from crimson.sim.gameplay_state import GameplayState
    from crimson.sim.state_types import PlayerState, WeaponSlot
    from crimson.weapons import WeaponId
    from grim.geom import Vec2

    frame = observed["frame"]
    if frame.get("console") or observed["name"].startswith(("man-bomb-only", "hot-tempered-only")):
        return None
    state = GameplayState(preserve_bugs=True)
    players = [PlayerState(index=i, pos=Vec2(100.0, 100.0)) for i in (0, 1)]
    player = players[frame["index"]]
    player.health = frame.get("health", 100.0)
    player.experience = frame.get("experience", 0)
    player.fire_bullets_timer = frame.get("fire_bullets_timer", 0.0)
    player.weapon = WeaponSlot(
        weapon_id=WeaponId.PISTOL, clip_size=10, ammo=frame.get("ammo", 7.0),
        shot_cooldown=frame.get("shot_cooldown", 0.0), reload_timer=frame.get("reload_timer", 0.0),
        reload_active=bool(frame.get("reload_active", 0)),
    )
    for name, perk in (("regression_bullets", PerkId.REGRESSION_BULLETS), ("ammunition_within", PerkId.AMMUNITION_WITHIN)):
        if frame.get("perks", {}).get(name):
            for entry in players:
                entry.perk_counts[int(perk)] = 1
    decoded = unpack_player_input(capture["inputs"][frame["index"]])
    player_update(player, decoded, 0.016, state, players=players)
    active = [entry for entry in state.projectiles.entries if entry.active]
    return {
        "fired": bool(active), "timer_after": player.fire_bullets_timer,
        "expected_fired": bool(observed["projectiles"]), "expected_timer": observed["timer_after"],
        "equal": bool(active) == bool(observed["projectiles"]) and player.fire_bullets_timer == observed["timer_after"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert v.e.unicorn.__version__ == "2.1.4"
    assert v.sha(v.ENGINE.read_bytes()) == v.ENGINE_SHA
    assert v.sha(v.e.match.default_image_path().read_bytes()) == v.IMAGE_SHA
    assert v.sha((HERE / "before-input-hooks.js").read_bytes()) == BEFORE_HOOKS_SHA
    config = v.e.match.load_scratch_config(v.e.match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    private = args.out / "candidate"
    private.mkdir(exist_ok=True)
    (private / config.source).write_bytes((config.directory / config.source).read_bytes())
    config = replace(config, directory=private)
    layout = v.check_layout(config, args.out)
    program = v.e.Program(config)
    assert program.address("render_overlay_player_index") == 0x004AAF0C
    boolean_returns = boolean_return_witnesses(program)
    cases = list(scenarios())
    captures, observations = capture_cases(program, cases)
    (args.out / "capture-cases.json").write_bytes(v.encoded(captures))
    current = run_capture(captures)
    previous = run_capture(captures, before=True)
    results = []
    for native, captured, old in zip(observations, current, previous, strict=True):
        assert native["name"] == captured["name"] == old["name"]
        assert not captured["errors"] and not captured["contexts"]
        index = native["frame"]["index"]
        if native["name"].startswith(("man-bomb-only", "hot-tempered-only")):
            assert native["projectiles"] == 8 and not captured["keys"][index]["fire_down"]
        port = check_port(native, captured)
        old_port = check_port(native, old)
        assert port is None or port["equal"], (native["name"], port)
        results.append({**native, "current": captured, "before": old, "port": port, "before_port": old_port})
    negatives = [row["name"] for row in results if row["before_port"] and not row["before_port"]["equal"]]
    assert negatives == ["computer-auto-p0", "computer-auto-p1", "auto-no-g-p0", "auto-no-g-p1"], negatives
    output = {
        "image_sha256": v.IMAGE_SHA, "engine_sha256": v.ENGINE_SHA,
        "runner_sha256": v.sha((SHARED / "runner.py").read_bytes()),
        "agent_sha256": v.sha((ROOT / "scripts/frida/gameplay_diff_capture.js").read_bytes()),
        "verifier_sha256": v.sha(Path(__file__).read_bytes()),
        "harness_sha256": v.sha((HERE / "harness.js").read_bytes()), "before_hooks_sha256": BEFORE_HOOKS_SHA,
        "cases_sha256": v.sha(v.encoded(captures)), "layout": layout, "candidate": v.metrics(program),
        "before_port_mismatches": negatives, "boolean_returns": boolean_returns, "results": results,
    }
    (args.out / "results.json").write_bytes(v.encoded(output))
    print(json.dumps({"native_cases": len(results), "current_port_mismatches": 0, "before_port_mismatches": negatives}))


if __name__ == "__main__":
    main()
