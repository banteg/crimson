from __future__ import annotations

from pathlib import Path

import crimson.world.audio_bridge as audio_bridge_module
from crimson.bonuses import BonusId
from crimson.game_modes import GameMode
from crimson.gameplay import player_update
from crimson.perks import PerkId
from crimson.sim.hooks import TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import InputStatus, ResolvedTick
from crimson.sim.presentation_step import DeterministicPresentationPlan, plan_player_audio_sfx
from crimson.sim.tick_runner import TickBatchResult
from crimson.weapons import WeaponId
from crimson.world.standalone_tick_harness import StandaloneTickHarness
from grim.audio import AudioState
from grim.geom import Vec2
from grim.music import init_music_state
from grim.rand import Crand
from grim.sfx import init_sfx_state
from grim.sfx_map import SfxId
from tests.support.builders.input_providers import StaticLocalInputRuntime
from tests.support.builders.session import make_session
from tests.support.builders.tick_payload import make_tick_payload
from tests.support.helpers import assert_float_close
from tests.support.world_runtime import WorldRuntimeHost


def _audio_state_stub() -> AudioState:
    return AudioState(
        ready=False,
        music=init_music_state(ready=False, enabled=True, volume=1.0),
        sfx=init_sfx_state(ready=False, enabled=True, volume=1.0),
    )


def test_reload_finish_and_immediate_shot_plays_fire_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)
    world.sync_audio_bridge_state()

    player = world.sim_world.players[0]

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
    player_update(player, input_state, 0.05, world.sim_world.state, world_size=float(world.world_size))

    sounds = plan_player_audio_sfx(
        player,
        prev_shot_seq=prev_shot_seq,
        prev_reload_active=prev_reload_active,
        prev_reload_timer=prev_reload_timer,
    )
    world.audio_bridge.apply_plan(plan=DeterministicPresentationPlan(sfx=tuple(sounds)))

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.PISTOL_FIRE


def test_fire_bullets_suppresses_weapon_fire_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)
    world.sync_audio_bridge_state()

    player = world.sim_world.players[0]

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
    player_update(player, input_state, 0.05, world.sim_world.state, world_size=float(world.world_size))

    sounds = plan_player_audio_sfx(
        player,
        prev_shot_seq=prev_shot_seq,
        prev_reload_active=prev_reload_active,
        prev_reload_timer=prev_reload_timer,
    )
    world.audio_bridge.apply_plan(plan=DeterministicPresentationPlan(sfx=tuple(sounds)))

    assert play_sfx.call_count == 2
    assert {call.args[1] for call in play_sfx.call_args_list} == {SfxId.AUTORIFLE_FIRE, SfxId.PLASMAMINIGUN_FIRE}


def test_pending_perk_increase_plays_levelup_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)

    player = world.sim_world.players[0]
    player.experience = 10_000

    world.step_survival_frame(
        0.05,
        inputs=[PlayerInput()],
        perk_progression_enabled=True,
    )

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_LEVELUP


def test_bonus_pickup_plays_bonus_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.POINTS,
        state=world.sim_world.state,
    )
    assert entry is not None

    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_BONUS


def test_fireblast_pickup_plays_explosion_medium_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)

    player = world.sim_world.players[0]
    entry = world.sim_world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=BonusId.FIREBLAST,
        state=world.sim_world.state,
    )
    assert entry is not None

    world.step_survival_frame(0.016, perk_progression_enabled=False)

    assert entry.picked
    assert play_sfx.call_count == 2
    assert {call.args[1] for call in play_sfx.call_args_list} == {SfxId.UI_BONUS, SfxId.EXPLOSION_MEDIUM}


def test_world_runtime_apply_tick_batch_applies_post_apply_bonus_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)

    batch = TickBatchResult(
        ticks_completed=1,
        batch_status=InputStatus.READY,
        next_tick_index=1,
        completed_results=[
            TickResult(
                source_tick=ResolvedTick(
                    tick_index=0,
                    dt_seconds=1.0 / 60.0,
                    inputs=(),
                    commands=(),
                ),
                payload=make_tick_payload(post_apply_sfx=(SfxId.UI_BONUS,)),
            ),
        ],
    )

    StandaloneTickHarness(
        game_mode=GameMode.SURVIVAL,
        input_runtime=StaticLocalInputRuntime(),
    )._apply_tick_batch(
        world,
        batch=batch,
        session=make_session()[0],
    )

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.UI_BONUS


def test_perk_bursts_play_explosion_small_sfx(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)

    player = world.sim_world.players[0]
    aim = PlayerInput(aim=Vec2(player.pos.x + 1.0, player.pos.y))

    play_sfx.reset_mock()
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1
    player.man_bomb_timer = 3.9
    world.step_survival_frame(0.2, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL

    play_sfx.reset_mock()
    player.perk_counts[int(PerkId.MAN_BOMB)] = 0
    player.man_bomb_timer = 0.0
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1
    player.hot_tempered_timer = 1.95
    world.step_survival_frame(0.1, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL

    play_sfx.reset_mock()
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 0
    player.hot_tempered_timer = 0.0
    player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1
    player.weapon.reload_active = True
    player.weapon.reload_timer = 1.1
    player.weapon.reload_timer_max = 2.0
    player.weapon.clip_size = 10
    player.weapon.ammo = 0
    world.step_survival_frame(0.2, inputs=[aim], perk_progression_enabled=False)
    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.EXPLOSION_SMALL


def test_audio_bridge_forwards_live_reflex_timer(mocker) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = WorldRuntimeHost(assets_dir=repo_root / "artifacts" / "assets")
    play_sfx = mocker.patch.object(audio_bridge_module, "play_sfx")
    world.audio = _audio_state_stub()
    world.audio_rng = Crand(0)
    world.sync_audio_bridge_state()

    world.sim_world.state.bonuses.reflex_boost = 0.75
    world.audio_bridge.play_sfx(SfxId.PISTOL_FIRE)

    play_sfx.assert_called_once()
    assert play_sfx.call_args.args[1] == SfxId.PISTOL_FIRE
    assert_float_close(float(play_sfx.call_args.kwargs["reflex_boost_timer"]), 0.75)
