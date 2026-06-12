from __future__ import annotations

from typing import TYPE_CHECKING

import msgspec

from grim.audio import AudioState, play_sfx, trigger_game_tune
from grim.rand import Crand, CrandLike
from grim.sfx_map import SfxId

from .game_modes import GameMode
from .projectiles.types import ProjectileHit, ProjectileTemplateId
from .rng_caller_static import RngCallerStatic
from .weapons import WEAPON_BY_ID, WeaponId, weapon_entry_for_projectile_type_id

if TYPE_CHECKING:
    from .sim.state_types import PlayerState


_BULLET_HIT_SFX = (
    SfxId.BULLET_HIT_01,
    SfxId.BULLET_HIT_02,
    SfxId.BULLET_HIT_03,
    SfxId.BULLET_HIT_04,
    SfxId.BULLET_HIT_05,
    SfxId.BULLET_HIT_06,
)


class AudioRouterRuntime(msgspec.Struct):
    def reflex_boost_timer(self) -> float:
        return 0.0


class AudioRouter(msgspec.Struct):
    audio_rng: Crand
    audio: AudioState | None = None
    demo_mode_active: bool = False
    sfx_enabled: bool = True
    runtime: AudioRouterRuntime = msgspec.field(default_factory=AudioRouterRuntime)

    def _reflex_boost_timer(self) -> float:
        return float(self.runtime.reflex_boost_timer())

    def play_sfx(self, sfx: SfxId) -> None:
        if self.audio is None or (not self.sfx_enabled):
            return
        play_sfx(
            self.audio,
            sfx,
            reflex_boost_timer=self._reflex_boost_timer(),
        )

    def trigger_game_tune(self) -> str | None:
        if self.audio is None:
            return None
        return trigger_game_tune(self.audio, rng=self.audio_rng)

    def handle_player_audio(
        self,
        player: PlayerState,
        *,
        prev_shot_seq: int,
        prev_reload_active: bool,
        prev_reload_timer: float,
    ) -> None:
        if self.audio is None:
            return
        weapon = WEAPON_BY_ID[player.weapon.weapon_id]

        if int(player.shot_seq) > int(prev_shot_seq):
            if float(player.fire_bullets_timer) > 0.0:
                # player_update (crimsonland.exe): when Fire Bullets is active, the regular per-weapon
                # shot sfx is suppressed and replaced by Fire Bullets + Plasma Minigun fire sfx.
                fire_bullets = WEAPON_BY_ID[WeaponId.FIRE_BULLETS]
                plasma_minigun = WEAPON_BY_ID[WeaponId.PLASMA_MINIGUN]
                self.play_sfx(fire_bullets.fire_sound)
                self.play_sfx(plasma_minigun.fire_sound)
            else:
                self.play_sfx(weapon.fire_sound)

        reload_active = player.weapon.reload_active
        reload_timer = float(player.weapon.reload_timer)
        reload_started = (not prev_reload_active and reload_active) or (reload_timer > prev_reload_timer + 1e-6)
        if reload_started:
            self.play_sfx(weapon.reload_sound)

    def _hit_sfx_for_type(
        self,
        type_id: int,
        *,
        beam_types: frozenset[int],
        rng: CrandLike,
    ) -> SfxId:
        ammo_class = weapon_entry_for_projectile_type_id(ProjectileTemplateId(type_id)).ammo_class
        if ammo_class == 4:
            return SfxId.SHOCK_HIT_01
        return _BULLET_HIT_SFX[rng.rand_tagged(RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX) % len(_BULLET_HIT_SFX)]

    def play_hit_sfx(
        self,
        hits: list[ProjectileHit],
        *,
        game_mode: GameMode,
        rng: CrandLike,
        beam_types: frozenset[int],
    ) -> None:
        if self.audio is None or not hits:
            return

        # Native plays the panned hit sample for every hit, uncapped.
        game_tune_started = bool(self.audio.music.game_tune_started)
        for idx in range(len(hits)):
            if (not self.demo_mode_active) and game_mode != GameMode.RUSH and (not game_tune_started):
                trigger_game_tune(self.audio, rng=rng)
                game_tune_started = True
                continue
            type_id = int(hits[idx].type_id)
            self.play_sfx(self._hit_sfx_for_type(type_id, beam_types=beam_types, rng=rng))
