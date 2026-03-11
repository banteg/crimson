from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING

import msgspec

from grim.audio import AudioState, play_sfx, play_sfx_resolved, trigger_game_tune
from grim.rand import Crand, CrandLike

from .creatures.spawn import CreatureTypeId
from .game_modes import GameMode
from .projectiles.types import ProjectileHit, ProjectileTemplateId
from .weapons import WEAPON_BY_ID, WeaponId, weapon_entry_for_projectile_type_id

if TYPE_CHECKING:
    from .creatures.runtime import CreatureDeath
    from .sim.state_types import PlayerState

_MAX_HIT_SFX_PER_FRAME = 4
_MAX_DEATH_SFX_PER_FRAME = 3

_BULLET_HIT_SFX = (
    "sfx_bullet_hit_01",
    "sfx_bullet_hit_02",
    "sfx_bullet_hit_03",
    "sfx_bullet_hit_04",
    "sfx_bullet_hit_05",
    "sfx_bullet_hit_06",
)

_CREATURE_DEATH_SFX: dict[CreatureTypeId, tuple[str, ...]] = {
    CreatureTypeId.ZOMBIE: (
        "sfx_zombie_die_01",
        "sfx_zombie_die_02",
        "sfx_zombie_die_03",
        "sfx_zombie_die_04",
    ),
    CreatureTypeId.LIZARD: (
        "sfx_lizard_die_01",
        "sfx_lizard_die_02",
        "sfx_lizard_die_03",
        "sfx_lizard_die_04",
    ),
    CreatureTypeId.ALIEN: (
        "sfx_alien_die_01",
        "sfx_alien_die_02",
        "sfx_alien_die_03",
        "sfx_alien_die_04",
    ),
    CreatureTypeId.SPIDER_SP1: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.SPIDER_SP2: (
        "sfx_spider_die_01",
        "sfx_spider_die_02",
        "sfx_spider_die_03",
        "sfx_spider_die_04",
    ),
    CreatureTypeId.TROOPER: (
        "sfx_trooper_die_01",
        "sfx_trooper_die_02",
        "sfx_trooper_die_03",
        "sfx_trooper_die_04",
    ),
}


class AudioRouter(msgspec.Struct):
    audio_rng: Crand
    audio: AudioState | None = None
    demo_mode_active: bool = False
    sfx_enabled: bool = True
    reflex_boost_timer_source: Callable[[], float] | None = None

    @staticmethod
    def _rand_choice(rng: CrandLike, options: tuple[str, ...]) -> str | None:
        if not options:
            return None
        idx = int(rng.rand()) % len(options)
        return options[idx]

    def _reflex_boost_timer(self) -> float:
        source = self.reflex_boost_timer_source
        if source is None:
            return 0.0
        return float(source())

    def play_sfx(self, key: str | None) -> None:
        if self.audio is None or (not self.sfx_enabled):
            return
        play_sfx(
            self.audio,
            key,
            rng=self.audio_rng,
            reflex_boost_timer=self._reflex_boost_timer(),
        )

    def play_sfx_resolved(self, key: str | None) -> None:
        if self.audio is None or (not self.sfx_enabled):
            return
        play_sfx_resolved(
            self.audio,
            key,
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
    ) -> str | None:
        ammo_class = weapon_entry_for_projectile_type_id(ProjectileTemplateId(type_id)).ammo_class
        if ammo_class == 4:
            return "sfx_shock_hit_01"
        return self._rand_choice(rng, _BULLET_HIT_SFX)

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

        end = min(len(hits), _MAX_HIT_SFX_PER_FRAME)
        game_tune_started = bool(self.audio.music.game_tune_started)
        for idx in range(0, end):
            if (not self.demo_mode_active) and game_mode != GameMode.RUSH and (not game_tune_started):
                trigger_game_tune(self.audio, rng=rng)
                game_tune_started = True
                continue
            type_id = int(hits[idx].type_id)
            self.play_sfx(self._hit_sfx_for_type(type_id, beam_types=beam_types, rng=rng))

    def play_death_sfx(self, deaths: Sequence[CreatureDeath], *, rng: CrandLike) -> None:
        if self.audio is None or not deaths:
            return
        for idx in range(min(len(deaths), _MAX_DEATH_SFX_PER_FRAME)):
            death = deaths[idx]
            self.play_sfx(self._rand_choice(rng, _CREATURE_DEATH_SFX[death.type_id]))
