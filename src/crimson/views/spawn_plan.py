from __future__ import annotations

from dataclasses import dataclass
import math

import pyray as rl

from grim.geom import Vec2
from grim.rand import Crand
from ..creatures.spawn import (
    CreatureTypeId,
    SPAWN_TEMPLATES,
    SpawnEnv,
    SpawnSlotInit,
    build_spawn_plan,
    spawn_id_label,
    tick_spawn_slot,
)
from ._ui_helpers import draw_ui_text, ui_line_height
from .registry import register_view
from grim.fonts.small import SmallFontData, load_small_font, measure_small_text_width
from grim.view import View, ViewContext


BASE_POS = Vec2(512.0, 512.0)

UI_TEXT_SCALE = 1
UI_TEXT_COLOR = rl.Color(220, 220, 220, 255)
UI_HINT_COLOR = rl.Color(140, 140, 140, 255)
UI_ERROR_COLOR = rl.Color(240, 80, 80, 255)

BG_COLOR = rl.Color(12, 12, 14, 255)
GRID_COLOR = rl.Color(40, 40, 48, 255)
LINK_COLOR = rl.Color(80, 160, 255, 120)
OFFSET_COLOR = rl.Color(255, 200, 80, 140)


def _type_color(type_id: CreatureTypeId | None) -> rl.Color:
    if type_id == CreatureTypeId.ZOMBIE:
        return rl.Color(120, 220, 120, 255)
    if type_id == CreatureTypeId.LIZARD:
        return rl.Color(120, 160, 255, 255)
    if type_id == CreatureTypeId.ALIEN:
        return rl.Color(200, 140, 255, 255)
    if type_id == CreatureTypeId.SPIDER_SP1:
        return rl.Color(255, 120, 120, 255)
    if type_id == CreatureTypeId.SPIDER_SP2:
        return rl.Color(255, 160, 120, 255)
    return rl.Color(200, 200, 200, 255)


@dataclass(frozen=True, slots=True)
class _PlanSummary:
    creature_count: int
    spawn_slot_count: int
    effect_count: int
    primary_idx: int


class SpawnPlanView:
    def __init__(self, ctx: ViewContext) -> None:
        self._assets_root = ctx.assets_dir
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._template_ids = [t.spawn_id for t in sorted(SPAWN_TEMPLATES, key=lambda t: t.spawn_id)]
        self._index = 0

        self._seed = 0xBEEF
        self._world_scale = 1.0
        self._hardcore = False
        self._difficulty = 0
        self._demo_mode_active = True

        self._plan = None
        self._plan_summary = None
        self._error = None

        self._sim_running = False
        self._sim_time = 0.0
        self._sim_slots: list[SpawnSlotInit] = []
        self._sim_events: list[str] = []

        self._rebuild_plan()

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except FileNotFoundError:
            self._small = None

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _draw_ui_label(self, label: str, value: str, pos: Vec2) -> None:
        label_text = f"{label}: "
        draw_ui_text(self._small, label_text, pos.x, pos.y, scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)
        label_w = measure_small_text_width(self._small, label_text, UI_TEXT_SCALE) if self._small else 0.0
        draw_ui_text(self._small, value, pos.x + label_w, pos.y, scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)

    def _rebuild_plan(self) -> None:
        spawn_id = self._template_ids[self._index]
        rng = Crand(self._seed)
        env = SpawnEnv(
            terrain_width=1024.0,
            terrain_height=1024.0,
            demo_mode_active=self._demo_mode_active,
            hardcore=self._hardcore,
            difficulty_level=self._difficulty,
        )
        try:
            self._plan = build_spawn_plan(spawn_id, BASE_POS, 0.0, rng, env)
            self._plan_summary = _PlanSummary(
                creature_count=len(self._plan.creatures),
                spawn_slot_count=len(self._plan.spawn_slots),
                effect_count=len(self._plan.effects),
                primary_idx=self._plan.primary,
            )
            self._reset_sim()
            self._error = None
        except Exception as exc:
            self._plan = None
            self._plan_summary = None
            self._error = str(exc)
            self._reset_sim()

    def _reset_sim(self) -> None:
        self._sim_running = False
        self._sim_time = 0.0
        self._sim_events.clear()
        self._sim_slots = []
        if self._plan is None:
            return
        for slot in self._plan.spawn_slots:
            self._sim_slots.append(
                SpawnSlotInit(
                    owner_creature=slot.owner_creature,
                    timer=slot.timer,
                    count=slot.count,
                    limit=slot.limit,
                    interval=slot.interval,
                    child_template_id=slot.child_template_id,
                )
            )

    def _advance_template(self, delta: int) -> None:
        if not self._template_ids:
            return
        self._index = (self._index + delta) % len(self._template_ids)
        self._rebuild_plan()

    def _adjust_seed(self, delta: int) -> None:
        self._seed = (self._seed + delta) & 0xFFFFFFFF
        self._rebuild_plan()

    def _adjust_scale(self, delta: float) -> None:
        self._world_scale = max(0.1, min(4.0, self._world_scale + delta))

    def _toggle_hardcore(self) -> None:
        self._hardcore = not self._hardcore
        self._rebuild_plan()

    def _toggle_demo_mode(self) -> None:
        self._demo_mode_active = not self._demo_mode_active
        self._rebuild_plan()

    def _adjust_difficulty(self, delta: int) -> None:
        self._difficulty = max(0, min(5, self._difficulty + delta))
        self._rebuild_plan()

    def update(self, dt: float) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT):
            self._advance_template(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT):
            self._advance_template(-1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_UP):
            self._adjust_seed(1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_DOWN):
            self._adjust_seed(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._seed = rl.get_random_value(0, 0x7FFFFFFF)
            self._rebuild_plan()

        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._adjust_scale(-0.1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._adjust_scale(0.1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._toggle_hardcore()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_D):
            self._toggle_demo_mode()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_COMMA):
            self._adjust_difficulty(-1)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_PERIOD):
            self._adjust_difficulty(1)

        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._sim_running = not self._sim_running
        if rl.is_key_pressed(rl.KeyboardKey.KEY_BACKSPACE):
            self._reset_sim()

        if self._sim_running and self._sim_slots:
            sim_dt = min(max(0.0, float(dt)), 0.1)
            self._sim_time += sim_dt
            for idx, slot in enumerate(self._sim_slots):
                child_template_id = tick_spawn_slot(slot, sim_dt)
                if child_template_id is None:
                    continue
                self._sim_events.append(
                    f"t={self._sim_time:6.2f}  slot={idx:02d}  spawn=0x{child_template_id:02x} ({spawn_id_label(child_template_id)})"
                )
            if len(self._sim_events) > 12:
                self._sim_events = self._sim_events[-12:]

    def _world_to_screen(self, pos: Vec2) -> Vec2:
        screen_w = float(rl.get_screen_width())
        screen_h = float(rl.get_screen_height())
        return Vec2(
            screen_w * 0.5 + (pos.x - BASE_POS.x) * self._world_scale,
            screen_h * 0.5 + (pos.y - BASE_POS.y) * self._world_scale,
        )

    def _draw_grid(self) -> None:
        screen_w = rl.get_screen_width()
        screen_h = rl.get_screen_height()
        step = int(64 * self._world_scale)
        if step < 24:
            return
        x = 0
        while x < screen_w:
            rl.draw_line(x, 0, x, screen_h, GRID_COLOR)
            x += step
        y = 0
        while y < screen_h:
            rl.draw_line(0, y, screen_w, y, GRID_COLOR)
            y += step

    def draw(self) -> None:
        rl.clear_background(BG_COLOR)
        self._draw_grid()

        margin = 16.0
        line_h = float(ui_line_height(self._small, scale=UI_TEXT_SCALE))

        spawn_id = self._template_ids[self._index] if self._template_ids else 0
        draw_ui_text(
            self._small,
            f"spawn-plan view  (template 0x{spawn_id:02x})",
            margin,
            margin,
            scale=0.8,
            color=UI_TEXT_COLOR,
        )
        hints = "Left/Right: id  Up/Down: seed  R: random seed  [,]: scale  H: hardcore  D: demo-mode  ,/.: difficulty  Space: sim  Backspace: reset"
        draw_ui_text(self._small, hints, margin, margin + line_h, scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)

        y = margin + line_h * 2.0 + 4.0
        self._draw_ui_label("seed", f"0x{self._seed:08x}", Vec2(margin, y))
        y += line_h
        self._draw_ui_label("world_scale", f"{self._world_scale:.2f}", Vec2(margin, y))
        y += line_h
        self._draw_ui_label("hardcore", str(self._hardcore), Vec2(margin, y))
        y += line_h
        self._draw_ui_label("difficulty", str(self._difficulty), Vec2(margin, y))
        y += line_h
        self._draw_ui_label("demo_mode_active", str(self._demo_mode_active), Vec2(margin, y))
        y += line_h

        if self._error is not None:
            draw_ui_text(self._small, self._error, margin, y + 6.0, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return
        if self._plan is None or self._plan_summary is None:
            draw_ui_text(self._small, "No plan.", margin, y + 6.0, scale=UI_TEXT_SCALE, color=UI_ERROR_COLOR)
            return

        summary = self._plan_summary
        self._draw_ui_label(
            "plan",
            f"creatures={summary.creature_count}  slots={summary.spawn_slot_count}  effects={summary.effect_count}  primary={summary.primary_idx}",
            Vec2(margin, y),
        )
        y += line_h
        sim_state = "running" if self._sim_running else "paused"
        self._draw_ui_label("sim", f"{sim_state}  t={self._sim_time:.2f}s", Vec2(margin, y))
        y += line_h
        for idx, slot in enumerate(self._sim_slots[:3]):
            self._draw_ui_label(
                f"slot{idx:02d}",
                f"timer={slot.timer:5.2f} count={slot.count:3d}/{slot.limit:<3d} interval={slot.interval:5.2f} child=0x{slot.child_template_id:02x}",
                Vec2(margin, y),
            )
            y += line_h
        if self._sim_events:
            draw_ui_text(self._small, "events:", margin, y + 2.0, scale=UI_TEXT_SCALE, color=UI_HINT_COLOR)
            y += line_h
            for ev in self._sim_events[-5:]:
                draw_ui_text(self._small, ev, margin, y, scale=UI_TEXT_SCALE, color=UI_TEXT_COLOR)
                y += line_h

        # Link lines.
        for idx, c in enumerate(self._plan.creatures):
            if c.ai_link_parent is None:
                continue
            if not (0 <= c.ai_link_parent < len(self._plan.creatures)):
                continue
            p = self._plan.creatures[c.ai_link_parent]
            child_screen = self._world_to_screen(c.pos)
            parent_screen = self._world_to_screen(p.pos)
            rl.draw_line_ex(
                child_screen.to_vector2(rl.Vector2),
                parent_screen.to_vector2(rl.Vector2),
                2.0,
                LINK_COLOR,
            )

        # Offset hints.
        for c in self._plan.creatures:
            if c.target_offset is None:
                continue
            origin_screen = self._world_to_screen(c.pos)
            target_screen = self._world_to_screen(c.pos + c.target_offset)
            rl.draw_line_ex(
                origin_screen.to_vector2(rl.Vector2),
                target_screen.to_vector2(rl.Vector2),
                2.0,
                OFFSET_COLOR,
            )
            rl.draw_circle_lines(int(target_screen.x), int(target_screen.y), max(2.0, 4.0 * self._world_scale), OFFSET_COLOR)

        # Creature dots.
        for idx, c in enumerate(self._plan.creatures):
            screen_pos = self._world_to_screen(c.pos)
            radius = max(3.0, 6.0 * math.sqrt(max(1.0, (c.size or 50.0) / 50.0)))
            radius = min(radius, 24.0)
            color = _type_color(c.type_id)
            rl.draw_circle(int(screen_pos.x), int(screen_pos.y), radius, color)
            if idx == summary.primary_idx:
                rl.draw_circle_lines(int(screen_pos.x), int(screen_pos.y), radius + 2.0, rl.Color(255, 255, 255, 200))

        # Spawn-slot owners.
        for slot in self._plan.spawn_slots:
            if not (0 <= slot.owner_creature < len(self._plan.creatures)):
                continue
            owner = self._plan.creatures[slot.owner_creature]
            owner_screen = self._world_to_screen(owner.pos)
            rl.draw_circle_lines(
                int(owner_screen.x),
                int(owner_screen.y),
                max(8.0, 12.0 * self._world_scale),
                rl.Color(120, 255, 180, 200),
            )


@register_view("spawn-plan", "Spawn plan")
def view_spawn_plan(*, ctx: ViewContext) -> View:
    return SpawnPlanView(ctx)
