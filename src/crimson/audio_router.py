from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Callable

from grim.audio import AudioState, play_sfx, trigger_game_tune

from .creatures.spawn import CreatureTypeId
from .game_modes import GameMode
from .projectiles import ProjectileHit
from .weapon_sfx import resolve_weapon_sfx_ref
from .weapons import WEAPON_BY_ID, WeaponId

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


@dataclass(slots=True)
class AudioRouter:
    audio: AudioState | None = None
    audio_rng: random.Random | None = None
    demo_mode_active: bool = False

    @staticmethod
    def _rand_choice(rand: Callable[[], int], options: tuple[str, ...]) -> str | None:
        if not options:
            return None
        idx = int(rand()) % len(options)
        return options[idx]

    def play_sfx(self, key: str | None) -> None:
        if self.audio is None:
            return
        play_sfx(self.audio, key, rng=self.audio_rng)

    def play_sfx_resolved(self, key: str | None) -> None:
        if self.audio is None:
            return
        play_sfx(self.audio, key, rng=self.audio_rng, allow_variants=False)

    def trigger_game_tune(self) -> str | None:
        if self.audio is None:
            return None

        audio_rng = self.audio_rng
        if audio_rng is None:
            return trigger_game_tune(self.audio)

        def _rand() -> int:
            # Keep music randomization deterministic when a session RNG is bound.
            return int(audio_rng.randrange(0, 0x8000))

        return trigger_game_tune(self.audio, rand=_rand)

    def handle_player_audio(
        self,
        player: object,
        *,
        prev_shot_seq: int,
        prev_reload_active: bool,
        prev_reload_timer: float,
    ) -> None:
        if self.audio is None:
            return
        weapon = WEAPON_BY_ID.get(int(getattr(player, "weapon_id", 0)))
        if weapon is None:
            return

        if int(getattr(player, "shot_seq", 0)) > int(prev_shot_seq):
            if float(getattr(player, "fire_bullets_timer", 0.0)) > 0.0:
                # player_update (crimsonland.exe): when Fire Bullets is active, the regular per-weapon
                # shot sfx is suppressed and replaced by Fire Bullets + Plasma Minigun fire sfx.
                fire_bullets = WEAPON_BY_ID.get(int(WeaponId.FIRE_BULLETS))
                plasma_minigun = WEAPON_BY_ID.get(int(WeaponId.PLASMA_MINIGUN))
                if fire_bullets is not None:
                    self.play_sfx(resolve_weapon_sfx_ref(fire_bullets.fire_sound))
                if plasma_minigun is not None:
                    self.play_sfx(resolve_weapon_sfx_ref(plasma_minigun.fire_sound))
            else:
                self.play_sfx(resolve_weapon_sfx_ref(weapon.fire_sound))

        reload_active = bool(getattr(player, "reload_active", False))
        reload_timer = float(getattr(player, "reload_timer", 0.0))
        reload_started = (not prev_reload_active and reload_active) or (reload_timer > prev_reload_timer + 1e-6)
        if reload_started:
            self.play_sfx(resolve_weapon_sfx_ref(weapon.reload_sound))

    def _hit_sfx_for_type(
        self,
        type_id: int,
        *,
        beam_types: frozenset[int],
        rand: Callable[[], int],
    ) -> str | None:
        weapon = WEAPON_BY_ID.get(int(type_id))
        ammo_class = weapon.ammo_class if weapon is not None else None
        if ammo_class == 4:
            return "sfx_shock_hit_01"
        return self._rand_choice(rand, _BULLET_HIT_SFX)

    def play_hit_sfx(
        self,
        hits: list[ProjectileHit],
        *,
        game_mode: int,
        rand: Callable[[], int],
        beam_types: frozenset[int],
    ) -> None:
        if self.audio is None or not hits:
            return

        if (not self.demo_mode_active) and int(game_mode) != int(GameMode.RUSH):
            trigger_game_tune(self.audio, rand=rand)

        end = min(len(hits), _MAX_HIT_SFX_PER_FRAME)
        for idx in range(0, end):
            type_id = int(hits[idx].type_id)
            self.play_sfx(self._hit_sfx_for_type(type_id, beam_types=beam_types, rand=rand))

    def play_death_sfx(self, deaths: tuple[object, ...], *, rand: Callable[[], int]) -> None:
        if self.audio is None or not deaths:
            return
        for idx in range(min(len(deaths), _MAX_DEATH_SFX_PER_FRAME)):
            death = deaths[idx]
            type_id = getattr(death, "type_id", None)
            if type_id is None:
                continue
            try:
                creature_type = CreatureTypeId(int(type_id))
            except ValueError:
                continue
            options = _CREATURE_DEATH_SFX.get(creature_type)
            if options:
                self.play_sfx(self._rand_choice(rand, options))
