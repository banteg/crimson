from pathlib import Path

import msgspec
import pytest

from crimson import local_input
from crimson.gameplay import player_update
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.replay.input_codec import pack_player_input, unpack_player_input
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.config import default_crimson_cfg
from grim.geom import Vec2


class _Witness(msgspec.Struct, frozen=True):
    name: str
    index: int
    fire_down: bool
    fire_bullets_key_down: bool
    health: float
    console: bool
    shot_cooldown: float
    reload_timer: float
    reload_active: bool
    ammo: float
    experience: int
    regression_bullets: bool
    ammunition_within: bool
    timer_before: float
    timer_after: float
    queried: bool
    fired: bool


class _Witnesses(msgspec.Struct, frozen=True):
    witnesses: list[_Witness]


def _witnesses() -> list[_Witness]:
    path = Path(__file__).parents[2] / "crimson-zig/src/runtime/testdata/player-fire-bullets-shortcut.json"
    return msgspec.json.decode(path.read_bytes(), type=_Witnesses).witnesses


@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_fire_bullets_shortcut_native_witnesses_through_replay(preserve_bugs: bool) -> None:
    rows = _witnesses()
    assert len(rows) == 38
    for row in rows:
        # Native console return is a whole-frame pause in the port, outside player_update.
        if row.console:
            continue
        state = GameplayState(preserve_bugs=preserve_bugs)
        players = [PlayerState(index=i, pos=Vec2(100.0, 100.0)) for i in range(2)]
        player = players[row.index]
        player.health = row.health
        player.experience = row.experience
        player.fire_bullets_timer = row.timer_before
        player.weapon = WeaponSlot(
            weapon_id=WeaponId.PISTOL,
            clip_size=10,
            ammo=row.ammo,
            shot_cooldown=row.shot_cooldown,
            reload_timer=row.reload_timer,
            reload_active=row.reload_active,
        )
        if row.regression_bullets:
            for entry in players:
                entry.perk_counts[int(PerkId.REGRESSION_BULLETS)] = 1
        if row.ammunition_within:
            for entry in players:
                entry.perk_counts[int(PerkId.AMMUNITION_WITHIN)] = 1
        live = PlayerInput(
            aim=Vec2(200.0, 100.0),
            move_mode=MovementControlType.STATIC,
            fire_down=row.fire_down,
            fire_bullets_key_down=row.fire_bullets_key_down,
        )
        decoded = unpack_player_input(pack_player_input(live))
        assert decoded == live
        player_update(player, decoded, 0.016, state, players=players)
        expected_timer = row.timer_after if preserve_bugs else row.timer_before
        assert player.fire_bullets_timer == expected_timer, row.name
        assert players[1 - row.index].fire_bullets_timer == 0.0, row.name
        active = [p for p in state.projectiles.entries if p.active]
        assert bool(active) == row.fired, row.name
        if active:
            expected_type = ProjectileTemplateId.FIRE_BULLETS if expected_timer > 0.0 else ProjectileTemplateId.PISTOL
            assert all(p.type_id == expected_type for p in active), row.name
            if expected_timer > 0.0:
                assert player.weapon.ammo == row.ammo, row.name


def test_live_input_records_fixed_g_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_input, "input_code_is_down", lambda code, **_kw: code == 0x22)
    monkeypatch.setattr(local_input, "input_code_is_pressed", lambda *_a, **_kw: False)
    config = default_crimson_cfg(Path("<memory>"))
    config.controls.player(0).movement = MovementControlType.STATIC
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    interpreter = local_input.LocalInputInterpreter()
    interpreter.reset(players=[player])
    result = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(200.0, 100.0),
        screen_center=Vec2(),
        dt=0.016,
        creatures=[],
    )
    assert result.fire_bullets_key_down
    assert not result.fire_down
