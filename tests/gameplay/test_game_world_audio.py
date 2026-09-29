from __future__ import annotations

from pathlib import Path

import crimson.world.audio_bridge as audio_bridge_module
from crimson.bonuses import BonusId
from crimson.perks import PerkId
from crimson.sim.batch_apply import apply_presentation_plans
from crimson.sim.input import PlayerInput
from crimson.sim.presentation_step import DeterministicPresentationPlan, plan_player_audio_sfx
from crimson.weapons import WeaponId
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest
from tests.support.builders.tick_payload import make_tick_payload
from tests.support.factories import step_player
from tests.support.helpers import assert_float_close
from tests.support.world_runtime import WorldRuntimeHost


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0, rng=Crand(0x1234)),
    )


def test_reload_finish_and_immediate_shot_plays_fire_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)
    runtime.sync_audio_bridge_state()

    player = runtime.world.players[0]

    # Setup: reload is about to finish and the player is holding fire.
    player.weapon.weapon_id = WeaponId.PISTOL
    player.weapon.clip_size = 12
    player.weapon.ammo = 0
    player.weapon.reload_active = True
    player.weapon.reload_timer = 0.01
    player.weapon.reload_timer_max = 1.0
    player.weapon.shot_cooldown = 0.0

    prev_shot_seq = int(player.shot_seq)
    prev_reload_active = bool(player.weapon.reload_active)
    prev_reload_timer = float(player.weapon.reload_timer)

    input_state = PlayerInput(
        fire_down=True,
        aim=Vec2(player.pos.x + 10.0, player.pos.y),
    )
    step_player(runtime.world, player, input_state, 0.05)

    sounds = plan_player_audio_sfx(
        player,
        prev_shot_seq=prev_shot_seq,
        prev_reload_active=prev_reload_active,
        prev_reload_timer=prev_reload_timer,
    )
    apply_presentation_plans(plans=[DeterministicPresentationPlan(sfx=tuple(sounds))], runtime=runtime)

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.PISTOL_FIRE


def test_fire_bullets_suppresses_weapon_fire_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)
    runtime.sync_audio_bridge_state()

    player = runtime.world.players[0]

    player.weapon.weapon_id = WeaponId.SHOTGUN  # Shotgun
    player.weapon.clip_size = 12
    player.weapon.ammo = 12
    player.weapon.reload_active = False
    player.weapon.reload_timer = 0.0
    player.weapon.reload_timer_max = 1.0
    player.weapon.shot_cooldown = 0.0
    player.fire_bullets_timer = 1.0

    prev_shot_seq = int(player.shot_seq)
    prev_reload_active = bool(player.weapon.reload_active)
    prev_reload_timer = float(player.weapon.reload_timer)

    input_state = PlayerInput(
        fire_down=True,
        aim=Vec2(player.pos.x + 10.0, player.pos.y),
    )
    step_player(runtime.world, player, input_state, 0.05)

    sounds = plan_player_audio_sfx(
        player,
        prev_shot_seq=prev_shot_seq,
        prev_reload_active=prev_reload_active,
        prev_reload_timer=prev_reload_timer,
    )
    apply_presentation_plans(plans=[DeterministicPresentationPlan(sfx=tuple(sounds))], runtime=runtime)

    assert play_sfx.call_count == 2
    assert {call.args[1] for call in play_sfx.call_args_list} == {SfxId.AUTORIFLE_FIRE, SfxId.PLASMAMINIGUN_FIRE}


def test_pending_perk_increase_plays_levelup_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)

    player = runtime.world.players[0]
    player.experience = 10_000

    runtime.step_survival_frame(
        0.05,
        inputs=[PlayerInput()],
        perk_progression_enabled=True,
    )

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_LEVELUP


def test_bonus_pickup_plays_bonus_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)

    player = runtime.world.players[0]
    entry = runtime.world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.POINTS,
        state=runtime.world.state,
    )
    assert entry is not None

    runtime.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_BONUS


def test_fireblast_pickup_plays_explosion_medium_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)

    player = runtime.world.players[0]
    entry = runtime.world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.FIREBLAST,
        state=runtime.world.state,
    )
    assert entry is not None

    runtime.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert play_sfx.call_count == 2
    assert {call.args[1] for call in play_sfx.call_args_list} == {SfxId.UI_BONUS, SfxId.EXPLOSION_MEDIUM}


def test_presentation_apply_plays_post_apply_bonus_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)
    step = make_tick_payload(post_apply_sfx=(SfxRequest(SfxId.UI_BONUS),))

    apply_presentation_plans(plans=[step.presentation], runtime=runtime)

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_BONUS


def test_perk_bursts_play_explosion_small_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)

    player = runtime.world.players[0]
    perks = runtime.world.state.perks
    aim = PlayerInput(aim=Vec2(player.pos.x + 1.0, player.pos.y))

    play_sfx.reset_mock()
    perks[int(PerkId.MAN_BOMB)] = 1
    player.man_bomb_timer = 3.9
    runtime.step_survival_frame(0.2, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL

    play_sfx.reset_mock()
    perks[int(PerkId.MAN_BOMB)] = 0
    player.man_bomb_timer = 0.0
    perks[int(PerkId.HOT_TEMPERED)] = 1
    player.hot_tempered_timer = 1.95
    runtime.step_survival_frame(0.1, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL

    play_sfx.reset_mock()
    perks[int(PerkId.HOT_TEMPERED)] = 0
    player.hot_tempered_timer = 0.0
    perks[int(PerkId.ANGRY_RELOADER)] = 1
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.1
    player.weapon.reload_timer_max = 2.0
    player.weapon.clip_size = 10
    player.weapon.ammo = 0
    runtime.step_survival_frame(0.2, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL


def test_audio_bridge_forwards_live_reflex_timer(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    runtime = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    runtime.audio = _audio_state_stub()
    runtime.audio_rng = Crand(0)
    runtime.sync_audio_bridge_state()

    runtime.world.state.bonuses.reflex_boost = 0.75
    runtime.audio_bridge.play_sfx(SfxId.PISTOL_FIRE)

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.PISTOL_FIRE
    assert_float_close(float(play_sfx.call_args.kwargs["reflex_boost_timer"]), 0.75)
