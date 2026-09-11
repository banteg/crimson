"""Execute the original G-key firing shortcut and compare the current C++ body."""

import argparse
import importlib.util
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "player-aim-direction-2026-09-11"
sys.path.insert(0, str(SHARED))
spec = importlib.util.spec_from_file_location("aim_verify", SHARED / "verify.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def scenarios():
    controls = [
        ("shot", {}),
        ("no-g", {"keys": [104]}),
        ("g-only", {"keys": [0x22]}),
        ("no-keys", {"keys": []}),
        ("cooldown", {"shot_cooldown": 0.5}),
        ("reload", {"reload_timer": 1.0, "reload_active": 1}),
        ("dead", {"health": 0.0}),
        ("console", {"console": 1}),
        ("empty-ammo", {"ammo": 0.0}),
        ("refresh", {"fire_bullets_timer": 2.0}),
        ("overwrite-longer", {"fire_bullets_timer": 20.0}),
        ("no-g-existing", {"keys": [104], "fire_bullets_timer": 2.0}),
        ("g-only-existing", {"keys": [0x22], "fire_bullets_timer": 2.0}),
        ("cooldown-existing", {"shot_cooldown": 0.5, "fire_bullets_timer": 2.0}),
        ("regression-reload", {"reload_timer": 1.0, "reload_active": 1, "experience": 1000,
                               "perks": {"regression_bullets": 1}}),
        ("regression-no-xp", {"reload_timer": 1.0, "reload_active": 1,
                              "perks": {"regression_bullets": 1}}),
        ("ammunition-reload", {"reload_timer": 1.0, "reload_active": 1, "experience": 1,
                               "perks": {"ammunition_within": 1}}),
        ("ammunition-no-xp", {"reload_timer": 1.0, "reload_active": 1,
                              "perks": {"ammunition_within": 1}}),
        ("computer-auto", {"aim": 5, "keys": [0x22], "aim_position": [300, 400],
                           "creatures": [{"index": 0, "x": 301, "y": 402}]}),
    ]
    for index in (0, 1):
        for name, control in controls:
            yield {"name": f"{name}-p{index}", "frame": {
                "index": index, "movement": 2, "move_speed": 0.0,
                "shot_cooldown": 0.0, "keys": [104, 0x22], **control,
            }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert v.e.unicorn.__version__ == "2.1.4"
    assert v.sha(v.ENGINE.read_bytes()) == v.ENGINE_SHA
    assert v.sha(v.e.match.default_image_path().read_bytes()) == v.IMAGE_SHA
    config = v.e.match.load_scratch_config(v.e.match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    layout = v.check_layout(config, args.out)
    program = v.e.Program(config)
    rows, witnesses = [], []
    for case in scenarios():
        native = v.run(program, True, case["frame"])
        candidate = v.run(program, False, case["frame"])
        assert v.observation(native) == v.observation(candidate), case["name"]
        frame = case["frame"]
        players = bytes.fromhex(native["state"]["players"])
        index = frame["index"]
        timer = struct.unpack_from("<f", players, index * 864 + 796)[0]
        other_timer = struct.unpack_from("<f", players, (1 - index) * 864 + 796)[0]
        assert other_timer == 0.0
        queried = ["key", 0x22] in native["calls"]
        assert timer == (10.0 if queried and 0x22 in frame["keys"] else frame.get("fire_bullets_timer", 0.0))
        fired = any(call[0] == "projectile_spawn" for call in native["calls"])
        witnesses.append({"name": case["name"], "index": index,
            "fire_down": 104 in frame["keys"] or case["name"].startswith("computer-auto"),
            "fire_bullets_key_down": 0x22 in frame["keys"],
            "health": frame.get("health", 100.0), "console": bool(frame.get("console", 0)),
            "shot_cooldown": frame.get("shot_cooldown", 0.0),
            "reload_timer": frame.get("reload_timer", 0.0), "reload_active": bool(frame.get("reload_active", 0)),
            "ammo": frame.get("ammo", 7.0), "experience": frame.get("experience", 0),
            "regression_bullets": bool(frame.get("perks", {}).get("regression_bullets", 0)),
            "ammunition_within": bool(frame.get("perks", {}).get("ammunition_within", 0)),
            "timer_before": frame.get("fire_bullets_timer", 0.0), "timer_after": timer,
            "queried": queried, "fired": fired})
        rows.append({**case, "native_observation_sha256": v.sha(v.encoded(v.observation(native))),
                     "candidate_observation_sha256": v.sha(v.encoded(v.observation(candidate))),
                     "native_calls": native["calls"]})
    result = {"image_sha256": v.IMAGE_SHA, "engine_sha256": v.ENGINE_SHA,
              "runner_sha256": v.sha((SHARED / "runner.py").read_bytes()),
              "layout": layout, "candidate": v.metrics(program), "cases": rows}
    (args.out / "results.json").write_bytes(v.encoded(result))
    (args.out / "player-fire-bullets-shortcut.json").write_bytes(v.encoded({"witnesses": witnesses}))
    print(json.dumps({"cases": len(rows), "mismatches": 0, "witnesses": len(witnesses)}))


if __name__ == "__main__":
    main()
