from __future__ import annotations

from crimson.gameplay import PlayerInput
from crimson.replay.crdemo import ActionType, Demo, DemoAction, DemoFrame, DemoHeader, PlayerInit, build_header_flags, dumps, loads


def test_crdemo_roundtrip_bytes() -> None:
    header = DemoHeader(
        flags=build_header_flags(
            demo_mode_active=False,
            hardcore=False,
            preserve_bugs=False,
            perk_progression_enabled=True,
            auto_pick_perks=False,
        ),
        game_mode=1,
        player_count=1,
        difficulty_level=0,
        world_size=1024.0,
        rng_state=0xBEEF,
        detail_preset=5,
        fx_toggle=0,
        status_blob=b"",
        player_inits=(PlayerInit(pos_x=512.0, pos_y=512.0, weapon_id=1),),
    )
    frames = (
        DemoFrame(
            dt=1.0 / 60.0,
            inputs=(
                PlayerInput(
                    move_x=0.0,
                    move_y=0.0,
                    aim_x=100.0,
                    aim_y=200.0,
                    fire_down=True,
                    fire_pressed=True,
                    reload_pressed=False,
                ),
            ),
        ),
    )
    actions = (
        DemoAction(
            tick=0,
            action_type=int(ActionType.PERK_PICK),
            player_index=0,
            payload_u16=1,
            payload_f32=1.0 / 60.0,
        ),
    )
    demo = Demo(header=header, frames=frames, actions=actions)
    raw = dumps(demo)
    parsed = loads(raw)
    rebuilt = dumps(parsed)
    assert rebuilt == raw

