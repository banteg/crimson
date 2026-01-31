from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Callable

from grim.audio import AudioState, play_sfx, trigger_game_tune

from .creatures.spawn import CreatureTypeId
from .game_modes import GameMode
from .weapon_sfx import resolve_weapon_sfx_ref
from .weapons import WEAPON_BY_ID

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
        if type_id in beam_types:
            return "sfx_shock_hit_01"
        return self._rand_choice(rand, _BULLET_HIT_SFX)

    def play_hit_sfx(
        self,
        hits: list[tuple[int, float, float, float, float, float, float]],
        *,
        game_mode: int,
        rand: Callable[[], int],
        beam_types: frozenset[int],
    ) -> None:
        if self.audio is None or not hits:
            return

        start_idx = 0
        if (not self.demo_mode_active) and int(game_mode) != int(GameMode.RUSH):
            if trigger_game_tune(self.audio, rand=rand) is not None:
                start_idx = 1

        end = min(len(hits), start_idx + _MAX_HIT_SFX_PER_FRAME)
        for idx in range(start_idx, end):
            type_id = int(hits[idx][0])
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
