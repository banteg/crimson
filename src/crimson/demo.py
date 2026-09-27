from __future__ import annotations

import math

from grim.audio import update_audio
from grim.geom import Vec2
from grim.raylib_api import rl

from .creatures.spawn import RANDOM_HEADING_SENTINEL, SpawnId
from .game.types import GameState
from .game_modes import GameMode
from .math_parity import f32
from .quests import quest_by_level
from .quests.level import QuestLevel
from .rng_caller_static import RngCallerStatic
from .screens.actions import Route
from .sim.bootstrap import advance_explicit_terrain
from .sim.input import PlayerInput
from .sim.state_types import TERRAIN_SIZE, PlayerState
from .terrain_slots import Q2_TERRAIN_SLOTS, TerrainSlotTriplet
from .weapon_runtime import weapon_assign_player
from .weapons import WeaponId, weapon_display_name
from .world import WorldRuntime
from .world.standalone_tick_harness import StandaloneTickHarness

# Native `demo_mode_start` cycles modulo 6; slot 5 is the shareware purchase
# interstitial (`demo_purchase_interstitial_begin`), which the port omits.
DEMO_VARIANT_COUNT = 5


class DemoView:
    """Attract-mode demo scaffold.

    Modeled after the classic demo helpers in crimsonland.exe:
      - demo_setup_variant_0 @ 0x00402ED0
      - demo_setup_variant_1 @ 0x004030F0
      - demo_setup_variant_2 @ 0x00402FE0
      - demo_setup_variant_3 @ 0x00403250
      - demo_mode_start       @ 0x00403390
    """

    def __init__(self, state: GameState) -> None:
        self.state = state
        self._runtime = WorldRuntime(
            assets_dir=state.assets_dir,
            demo_mode_active=True,
            hardcore=state.config.gameplay.hardcore,
            preserve_bugs=bool(state.preserve_bugs),
            config=state.config,
            audio=state.audio,
            audio_rng=state.rng,
        )
        self._runtime.reset()

        self._demo_targets: list[int | None] = []
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._finished = False
        self._tick_harness = StandaloneTickHarness(
            game_mode=GameMode.DEMO,
            frame_inputs=self._build_demo_inputs,
        )
        self._seed_from_app_state = True

    def _open_world_runtime(self) -> None:
        self._runtime.open_runtime()

    def _close_world_runtime(self) -> None:
        self._runtime.close_runtime()

    def _apply_terrain_setup(
        self,
        *,
        terrain_slots: TerrainSlotTriplet,
    ) -> None:
        terrain = advance_explicit_terrain(
            self._runtime.world.state.rng,
            terrain_slots=terrain_slots,
        )
        self._runtime.terrain_runtime.apply_terrain_setup(
            terrain_slots=terrain.terrain_slots,
            seed=terrain.terrain_seed,
        )
        self._sync_audio_rng_from_runtime()

    def _sync_audio_rng_from_runtime(self) -> None:
        live_rng = self._runtime.world.state.rng
        self._runtime.audio_rng = live_rng
        self._runtime.sync_audio_bridge_state()

    def _commit_live_rng_state_to_app(self) -> None:
        self.state.rng.srand(int(self._runtime.world.state.rng.state))

    def _next_demo_reset_seed(self) -> int:
        if self._seed_from_app_state:
            self._seed_from_app_state = False
            return int(self.state.rng.state)
        return int(self._runtime.world.state.rng.state)

    def _draw_world(self, *, draw_aim_indicators: bool = True, entity_alpha: float = 1.0) -> None:
        self._runtime.draw(draw_aim_indicators=draw_aim_indicators, entity_alpha=entity_alpha)

    def open(self) -> None:
        self._finished = False
        self._variant_index = 0
        self._demo_variant_index = 0
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        self._open_world_runtime()
        self._demo_mode_start()

    def close(self) -> None:
        self._finished = True
        if not self._seed_from_app_state:
            self._commit_live_rng_state_to_app()
        self._tick_harness.reset()
        self._close_world_runtime()
        self._seed_from_app_state = True

    def is_finished(self) -> bool:
        return self._finished

    def take_action(self) -> Route | None:
        if not self._finished:
            return None
        return Route.MENU

    def update(self, dt: float) -> None:
        if self.state.audio is not None:
            update_audio(self.state.audio, dt, advance_sfx=self._finished)
        if self._finished:
            return
        frame_dt = min(dt, 0.1)
        frame_dt_ms = int(frame_dt * 1000.0)
        if frame_dt_ms <= 0:
            return

        if self._skip_triggered():
            self._finished = True
            return

        self._quest_spawn_timeline_ms += frame_dt_ms
        self._update_world(frame_dt)
        self._sync_audio_rng_from_runtime()
        if self._quest_spawn_timeline_ms > self._demo_time_limit_ms:
            self._demo_mode_start()

    def draw(self) -> None:
        if self._finished:
            return
        self._draw_world()
        self._draw_overlay()

    def _skip_triggered(self) -> bool:
        if rl.get_key_pressed() != 0:
            return True
        if rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_LEFT):
            return True
        return bool(rl.is_mouse_button_pressed(rl.MouseButton.MOUSE_BUTTON_RIGHT))

    def _demo_mode_start(self) -> None:
        index = self._demo_variant_index
        self._demo_variant_index = (index + 1) % DEMO_VARIANT_COUNT
        self._variant_index = index
        self._quest_spawn_timeline_ms = 0
        self._demo_time_limit_ms = 0
        player_count = 2 if index in (0, 1, 4) else 1
        self._runtime.reset(seed=self._next_demo_reset_seed(), player_count=player_count)
        self._tick_harness.reset()
        self._sync_audio_rng_from_runtime()
        self._runtime.world.state.bonuses.weapon_power_up = 0.0
        if index == 1:
            self._setup_variant_1()
        elif index == 2:
            self._setup_variant_2()
        elif index == 3:
            self._setup_variant_3()
        else:
            # Slots 0 and 4 both run demo_setup_variant_0.
            self._setup_variant_0()
        self._sync_audio_rng_from_runtime()

    def _setup_world_players(self, specs: list[tuple[Vec2, int]]) -> None:
        for idx, (pos, weapon_id) in enumerate(specs):
            if idx >= len(self._runtime.world.players):
                continue
            player = self._runtime.world.players[idx]
            player.pos = pos
            # Keep aim anchored to the spawn position so demo aim starts stable.
            player.aim = pos
            weapon_assign_player(player, WeaponId(weapon_id), state=self._runtime.world.state)
        self._demo_targets = [None] * len(self._runtime.world.players)

    def _spawn(self, spawn_id: SpawnId, pos: Vec2, *, heading: float = 0.0) -> None:
        self._runtime.world.creatures.spawn_template(
            spawn_id,
            pos,
            float(heading),
            state=self._runtime.world.state,
            detail_preset=self._runtime.detail_preset,
        )

    def _setup_variant_0(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_0 uses weapon_id=0x0B.
        weapon_id = 11
        self._setup_world_players(
            [
                (Vec2(448.0, 384.0), weapon_id),
                (Vec2(546.0, 654.0), weapon_id),
            ],
        )
        y = 256
        i = 0
        while y < 1696:
            col = i % 2
            self._spawn(
                SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(float((col + 2) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL,
            )
            self._spawn(
                SpawnId.SPIDER_SP1_AI7_TIMER_38, Vec2(float(col * 64 + 798), float(y)), heading=RANDOM_HEADING_SENTINEL,
            )
            y += 80
            i += 1

    def _setup_variant_1(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_1 uses weapon_id=0x05.
        weapon_id = 5
        rng = self._runtime.world.state.rng
        self._setup_world_players(
            [
                (Vec2(490.0, 448.0), weapon_id),
                (Vec2(480.0, 576.0), weapon_id),
            ],
        )
        # Native variant 1 calls terrain_generate(&quest_meta_terrain_desc_unlock_gt_0x13).
        self._apply_terrain_setup(terrain_slots=Q2_TERRAIN_SLOTS)
        self._runtime.world.state.bonuses.weapon_power_up = 15.0
        for idx in range(20):
            x = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_X) % 200,
                )
                + 32,
            )
            y = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP1_Y) % 899,
                )
                + 64,
            )
            self._spawn(SpawnId.SPIDER_SP1_RANDOM_GREEN_34, Vec2(x, y), heading=RANDOM_HEADING_SENTINEL)
            if idx % 3 != 0:
                spawn_pos = Vec2(
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_X) % 30,
                        )
                        + 32,
                    ),
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_1_SPIDER_SP2_Y) % 899,
                        )
                        + 64,
                    ),
                )
                self._spawn(SpawnId.SPIDER_SP2_RANDOM_35, spawn_pos, heading=RANDOM_HEADING_SENTINEL)

    def _setup_variant_2(self) -> None:
        self._demo_time_limit_ms = 5000
        # demo_setup_variant_2 uses weapon_id=0x15.
        weapon_id = 21
        self._setup_world_players([(Vec2(512.0, 512.0), weapon_id)])
        y = 128
        i = 0
        while y < 848:
            col = i % 2
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float(col * 64 + 32), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(
                SpawnId.ZOMBIE_RANDOM_41, Vec2(float((col + 2) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL,
            )
            self._spawn(SpawnId.ZOMBIE_RANDOM_41, Vec2(float(col * 64 - 64), float(y)), heading=RANDOM_HEADING_SENTINEL)
            self._spawn(
                SpawnId.ZOMBIE_RANDOM_41, Vec2(float((col + 12) * 64), float(y)), heading=RANDOM_HEADING_SENTINEL,
            )
            y += 60
            i += 1

    def _setup_variant_3(self) -> None:
        self._demo_time_limit_ms = 4000
        # demo_setup_variant_3 uses weapon_id=0x12.
        weapon_id = 18
        rng = self._runtime.world.state.rng
        self._setup_world_players([(Vec2(512.0, 512.0), weapon_id)])
        quest = quest_by_level(QuestLevel(1, 1))
        assert quest is not None
        # Native variant 3 calls terrain_generate(&quest_selected_meta), which is the
        # base of the quest metadata array in this build, so it resolves to quest 1.1.
        self._apply_terrain_setup(terrain_slots=quest.terrain_slots)
        for idx in range(20):
            x = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_X) % 200,
                )
                + 32,
            )
            y = float(
                int(
                    rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_BIG_Y) % 899,
                )
                + 64,
            )
            self._spawn(SpawnId.ALIEN_CONST_GREEN_24, Vec2(x, y), heading=0.0)
            if idx % 3 != 0:
                spawn_pos = Vec2(
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_X) % 30,
                        )
                        + 32,
                    ),
                    float(
                        int(
                            rng.rand_tagged(RngCallerStatic.DEMO_SETUP_VARIANT_3_ALIEN_SMALL_Y) % 899,
                        )
                        + 64,
                    ),
                )
                self._spawn(SpawnId.ALIEN_SMALL_GREEN_MAN_25, spawn_pos, heading=0.0)

    def _draw_overlay(self) -> None:
        title = f"DEMO MODE  ({self._variant_index + 1}/{DEMO_VARIANT_COUNT})"
        hint = "Press any key / click to skip"
        remaining = max(0.0, float(self._demo_time_limit_ms - self._quest_spawn_timeline_ms) / 1000.0)
        weapons = ", ".join(
            f"P{p.index + 1}:{weapon_display_name(p.weapon.weapon_id)}"
            for p in self._runtime.world.players
        )
        detail = f"{weapons}  —  next in {remaining:0.1f}s"
        rl.draw_text(title, 16, 12, 20, rl.Color(240, 240, 240, 255))
        rl.draw_text(detail, 16, 36, 16, rl.Color(180, 180, 190, 255))
        rl.draw_text(hint, 16, 56, 16, rl.Color(140, 140, 150, 255))

    def _update_world(self, dt: float) -> None:
        if not self._runtime.world.players:
            return
        self._tick_harness.advance_frame(self._runtime, float(dt))

    def _build_demo_inputs(self, dt: float) -> list[PlayerInput]:
        players = self._runtime.world.players
        creatures = self._runtime.world.creatures.entries
        if len(self._demo_targets) != len(players):
            self._demo_targets = [None] * len(players)
        center = Vec2(TERRAIN_SIZE * 0.5, TERRAIN_SIZE * 0.5)

        dt = float(dt)

        inputs: list[PlayerInput] = []
        for idx, player in enumerate(players):
            target_idx = self._select_demo_target(idx, player, creatures)
            target = None
            if target_idx is not None and 0 <= target_idx < len(creatures):
                candidate = creatures[target_idx]
                if candidate.active and candidate.hp > 0.0:
                    target = candidate

            # Aim: ease the aim point toward the target.
            aim = player.aim
            auto_fire = False
            if target is not None:
                target_pos = target.pos
                aim_dir, aim_dist = (target_pos - aim).normalized_with_length()
                if aim_dist >= 4.0:
                    step = aim_dist * 6.0 * dt
                    aim += aim_dir * step
                else:
                    aim = target_pos
                auto_fire = aim_dist < 128.0
            else:
                away_from_center, amag = (player.pos - center).normalized_with_length()
                if amag <= 1e-6:
                    away_from_center = Vec2(0.0, -1.0)
                aim = player.pos + away_from_center * 60.0

            # Movement:
            # - orbit center if no target
            # - chase target when near center
            # - return to center when too far
            if target is None:
                move_delta = (player.pos - center).rotated(math.pi / 2.0)
            else:
                center_dist = (player.pos - center).length()
                if center_dist <= 300.0:
                    move_delta = target.pos - player.pos
                else:
                    move_delta = center - player.pos

            # player_update eases the heading toward this vector and scales the
            # speed by the remaining turn, as native computer movement does.
            move = Vec2(f32(move_delta.x), f32(move_delta.y))

            inputs.append(
                PlayerInput(
                    move=move,
                    aim=aim,
                    fire_down=auto_fire,
                    fire_pressed=auto_fire,
                    reload_pressed=False,
                ),
            )

        return inputs

    def _nearest_world_creature_index(self, pos: Vec2) -> int | None:
        best_idx = None
        best_dist = 0.0
        for idx, creature in enumerate(self._runtime.world.creatures.entries):
            if not (creature.active and creature.hp > 0.0):
                continue
            d = Vec2.distance_sq(pos, creature.pos)
            if best_idx is None or d < best_dist:
                best_idx = idx
                best_dist = d
        return best_idx

    def _select_demo_target(self, player_index: int, player: PlayerState, creatures: list) -> int | None:
        candidate = self._nearest_world_creature_index(player.pos)
        current = self._demo_targets[player_index] if player_index < len(self._demo_targets) else None
        if current is None:
            self._demo_targets[player_index] = candidate
            return candidate
        if not (0 <= current < len(creatures)):
            self._demo_targets[player_index] = candidate
            return candidate
        current_creature = creatures[current]
        if current_creature.hp <= 0.0 or not current_creature.active:
            self._demo_targets[player_index] = candidate
            return candidate
        if candidate is None or candidate == current:
            return current
        cand_creature = creatures[candidate]
        if not cand_creature.active or cand_creature.hp <= 0.0:
            return current
        cur_d = (current_creature.pos - player.pos).length()
        cand_d = (cand_creature.pos - player.pos).length()
        if cand_d + 64.0 < cur_d:
            self._demo_targets[player_index] = candidate
            return candidate
        return current
