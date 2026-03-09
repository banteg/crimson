from __future__ import annotations

from collections.abc import Callable
from typing import Never, TypeAlias

import msgspec

from grim.assets import RuntimeResources, TextureId
from grim.audio import play_music, play_sfx, stop_music, update_audio
from grim.geom import Vec2
from grim.raylib_api import rl
from grim.terrain_render import GroundRenderer

from ...game.types import GameState
from ...sim.bootstrap import run_unlock_terrain_prelude, terrain_stamping_draws
from ...terrain_slots import terrain_slots_to_texture_ids
from ...ui.cursor import draw_menu_cursor
from ...ui.shadow import draw_ui_quad_shadow as _draw_ui_quad_shadow
from ..assets import require_runtime_resources
from ..transitions import _draw_screen_fade
from .geometry import SignFrame, menu_widescreen_y_shift, sign_frame


def menu_ground_camera(state: GameState) -> Vec2:
    camera = state.menu_ground_camera
    if isinstance(camera, Vec2):
        return camera
    return Vec2()


def ensure_menu_ground(state: GameState, *, regenerate: bool = False) -> GroundRenderer:
    resources = require_runtime_resources(state)
    ground = state.menu_ground
    screen_width = float(state.config.screen_width)
    screen_height = float(state.config.screen_height)
    texture_scale = state.config.texture_scale
    explicit_regenerate = bool(regenerate)
    generated_new_terrain = ground is None or explicit_regenerate
    scale_changed = False
    if ground is not None:
        scale_changed = abs(float(ground.texture_scale) - texture_scale) > 1e-6

    if generated_new_terrain:
        terrain = run_unlock_terrain_prelude(
            state.rng,
            unlock_index=int(state.status.quest_unlock_index),
            width=1024,
            height=1024,
        )
        base_id, overlay_id, detail_id = terrain_slots_to_texture_ids(terrain.terrain_slots)
        base = resources.texture(base_id)
        overlay = resources.texture(overlay_id)
        detail = resources.texture(detail_id)
    else:
        assert ground is not None
        base = ground.texture
        overlay = ground.overlay
        detail = ground.overlay_detail

    if ground is None:
        ground = GroundRenderer(
            texture=base,
            overlay=overlay,
            overlay_detail=detail,
            width=1024,
            height=1024,
            texture_scale=texture_scale,
            screen_width=screen_width,
            screen_height=screen_height,
        )
        state.menu_ground = ground
        regenerate = True
    else:
        ground.texture = base
        ground.overlay = overlay
        ground.overlay_detail = detail
        ground.texture_scale = texture_scale
        ground.screen_width = screen_width
        ground.screen_height = screen_height
        if scale_changed:
            regenerate = True
    if regenerate:
        assert ground is not None
        if generated_new_terrain:
            ground.schedule_generate(seed=int(terrain.terrain_seed))
        else:
            ground.schedule_generate(seed=int(state.rng.state))
            for _ in range(terrain_stamping_draws(width=int(ground.width), height=int(ground.height))):
                state.rng.rand()
        state.menu_ground_camera = None
    return ground


def draw_menu_cursor_frame(state: GameState, *, resources: RuntimeResources, pulse_time: float) -> None:
    particles = resources.texture(TextureId.PARTICLES)
    cursor_tex = resources.texture(TextureId.UI_CURSOR)
    mouse = rl.get_mouse_position()
    draw_menu_cursor(particles, cursor_tex, pos=Vec2.from_xy(mouse), pulse_time=float(pulse_time))


def draw_ui_quad(
    *,
    texture: rl.Texture,
    src: rl.Rectangle,
    dst: rl.Rectangle,
    origin: rl.Vector2,
    rotation_deg: float,
    tint: rl.Color,
) -> None:
    rl.draw_texture_pro(texture, src, dst, origin, rotation_deg, tint)


def draw_ui_quad_shadow(
    *,
    texture: rl.Texture,
    src: rl.Rectangle,
    dst: rl.Rectangle,
    origin: rl.Vector2,
    rotation_deg: float,
) -> None:
    _draw_ui_quad_shadow(texture=texture, src=src, dst=dst, origin=origin, rotation_deg=rotation_deg)


def _unexpected_policy(value: object, *, name: str) -> Never:
    raise AssertionError(f"Unsupported {name}: {value!r}")


def _require_bool(value: object, *, name: str) -> None:
    if type(value) is not bool:
        raise TypeError(f"{name} must be a bool")


def _require_optional_str(value: object, *, name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{name} must be a str | None")


def _require_str_tuple(value: object, *, name: str) -> None:
    if type(value) is not tuple or any(not isinstance(item, str) for item in value):
        raise TypeError(f"{name} must be a tuple[str, ...]")


class OpaqueEntityAlpha(msgspec.Struct, frozen=True, tag="opaque"):
    pass


class CloseTimelineEntityAlpha(msgspec.Struct, frozen=True, tag="close_timeline_fraction"):
    duration_ms: int = 300
    action: str | None = None

    def __post_init__(self) -> None:
        if type(self.duration_ms) is not int:
            raise TypeError("CloseTimelineEntityAlpha.duration_ms must be an int")
        if self.duration_ms <= 0:
            raise ValueError("CloseTimelineEntityAlpha.duration_ms must be positive")
        if self.action is not None and not isinstance(self.action, str):
            raise TypeError("CloseTimelineEntityAlpha.action must be a str | None")


EntityAlphaPolicy: TypeAlias = OpaqueEntityAlpha | CloseTimelineEntityAlpha


class BackdropPolicy(msgspec.Struct, frozen=True):
    allow_pause_background: bool = True
    use_menu_ground: bool = True
    entity_alpha: EntityAlphaPolicy = OpaqueEntityAlpha()

    def __post_init__(self) -> None:
        _require_bool(self.allow_pause_background, name="BackdropPolicy.allow_pause_background")
        _require_bool(self.use_menu_ground, name="BackdropPolicy.use_menu_ground")
        if not isinstance(self.entity_alpha, (OpaqueEntityAlpha, CloseTimelineEntityAlpha)):
            raise TypeError("BackdropPolicy.entity_alpha must be an EntityAlphaPolicy")


class MusicPolicy(msgspec.Struct, frozen=True):
    primary_track: str | None = None
    demo_track: str | None = None
    refresh_while_open: bool = False
    stop_if_track_mismatch: bool = False

    def __post_init__(self) -> None:
        _require_optional_str(self.primary_track, name="MusicPolicy.primary_track")
        _require_optional_str(self.demo_track, name="MusicPolicy.demo_track")
        _require_bool(self.refresh_while_open, name="MusicPolicy.refresh_while_open")
        _require_bool(self.stop_if_track_mismatch, name="MusicPolicy.stop_if_track_mismatch")


class SignPolicy(msgspec.Struct, frozen=True):
    animated: bool = False
    lock_on_fully_open: bool = False
    unlock_on_actions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_bool(self.animated, name="SignPolicy.animated")
        _require_bool(self.lock_on_fully_open, name="SignPolicy.lock_on_fully_open")
        _require_str_tuple(self.unlock_on_actions, name="SignPolicy.unlock_on_actions")


class PendingOnceDispatch(msgspec.Struct, frozen=True, tag="pending_once"):
    pass


class DirectActionDispatch(msgspec.Struct, frozen=True, tag="direct_action"):
    pass


DispatchPolicy: TypeAlias = PendingOnceDispatch | DirectActionDispatch


class NoOpenSfx(msgspec.Struct, frozen=True, tag="none"):
    pass


class PlayOpenSfxOnOpen(msgspec.Struct, frozen=True, tag="on_open"):
    sfx_id: str = "sfx_ui_panelclick"

    def __post_init__(self) -> None:
        if not isinstance(self.sfx_id, str):
            raise TypeError("PlayOpenSfxOnOpen.sfx_id must be a str")


class PlayOpenSfxOnFullyOpen(msgspec.Struct, frozen=True, tag="on_fully_open"):
    sfx_id: str = "sfx_ui_panelclick"

    def __post_init__(self) -> None:
        if not isinstance(self.sfx_id, str):
            raise TypeError("PlayOpenSfxOnFullyOpen.sfx_id must be a str")


OpenSfxPolicy: TypeAlias = NoOpenSfx | PlayOpenSfxOnOpen | PlayOpenSfxOnFullyOpen


class ChromeSpec(msgspec.Struct, frozen=True):
    backdrop: BackdropPolicy = BackdropPolicy()
    music: MusicPolicy = MusicPolicy()
    sign: SignPolicy = SignPolicy()
    dispatch: DispatchPolicy = PendingOnceDispatch()
    timeline_max_ms: int = 300
    open_sfx: OpenSfxPolicy = PlayOpenSfxOnFullyOpen()
    close_sfx: str | None = "sfx_ui_buttonclick"
    fade_to_game_actions: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.backdrop, BackdropPolicy):
            raise TypeError("ChromeSpec.backdrop must be a BackdropPolicy")
        if not isinstance(self.music, MusicPolicy):
            raise TypeError("ChromeSpec.music must be a MusicPolicy")
        if not isinstance(self.sign, SignPolicy):
            raise TypeError("ChromeSpec.sign must be a SignPolicy")
        if not isinstance(self.dispatch, (PendingOnceDispatch, DirectActionDispatch)):
            raise TypeError("ChromeSpec.dispatch must be a DispatchPolicy")
        if type(self.timeline_max_ms) is not int:
            raise TypeError("ChromeSpec.timeline_max_ms must be an int")
        if self.timeline_max_ms < 0:
            raise ValueError("ChromeSpec.timeline_max_ms must be non-negative")
        if not isinstance(self.open_sfx, (NoOpenSfx, PlayOpenSfxOnOpen, PlayOpenSfxOnFullyOpen)):
            raise TypeError("ChromeSpec.open_sfx must be an OpenSfxPolicy")
        _require_optional_str(self.close_sfx, name="ChromeSpec.close_sfx")
        if type(self.fade_to_game_actions) is not frozenset or any(
            not isinstance(action, str) for action in self.fade_to_game_actions
        ):
            raise TypeError("ChromeSpec.fade_to_game_actions must be a frozenset[str]")


class ChromeState(msgspec.Struct):
    screen_width: int = 0
    widescreen_y_shift: float = 0.0
    timeline_ms: int = 0
    timeline_max_ms: int = 0
    cursor_pulse_time: float = 0.0
    closing: bool = False
    close_action: str | None = None
    pending_action: str | None = None
    action: str | None = None
    panel_open_sfx_played: bool = False


class ChromeTick(msgspec.Struct, frozen=True):
    dt_ms: int
    interactive: bool


class ChromeRuntime:
    def __init__(self, state: GameState, *, spec: ChromeSpec) -> None:
        self.state = state
        self.spec = spec
        self.chrome = ChromeState()
        self.ground: GroundRenderer | None = None
        self.is_open = False

    def open(self) -> None:
        screen_width = float(self.state.config.screen_width)
        self.chrome.screen_width = int(screen_width)
        self.chrome.widescreen_y_shift = menu_widescreen_y_shift(screen_width)
        self.chrome.timeline_ms = 0
        self.chrome.timeline_max_ms = int(self.spec.timeline_max_ms)
        self.chrome.cursor_pulse_time = 0.0
        self.chrome.closing = False
        self.chrome.close_action = None
        self.chrome.pending_action = None
        self.chrome.action = None
        self.chrome.panel_open_sfx_played = False
        self.ground = self._init_ground()
        self._play_open_music()
        self._play_open_sfx_on_open()
        self.is_open = True

    def close(self) -> None:
        self.is_open = False
        self.ground = None

    def restart_open_timeline(self, *, play_open_sfx: bool = False) -> None:
        self._assert_open()
        self.chrome.timeline_ms = 0
        self.chrome.closing = False
        self.chrome.close_action = None
        self.chrome.pending_action = None
        self.chrome.action = None
        self.chrome.panel_open_sfx_played = False
        if play_open_sfx:
            self._play_open_sfx_on_open()

    def update(self, dt: float) -> ChromeTick:
        self._assert_open()
        dt_clamped = min(float(dt), 0.1)
        if self.state.audio is not None:
            self._refresh_music()
            update_audio(self.state.audio, dt_clamped)
        if self.ground is not None:
            self.ground.process_pending()
        self.chrome.cursor_pulse_time += dt_clamped * 1.1
        dt_ms = int(dt_clamped * 1000.0)

        if self.chrome.closing:
            if dt_ms > 0 and self.chrome.pending_action is None and self.chrome.action is None:
                self.chrome.timeline_ms -= dt_ms
                if self.chrome.timeline_ms < 0 and self.chrome.close_action is not None:
                    self._dispatch_close_action(self.chrome.close_action)
                    self.chrome.close_action = None
            return ChromeTick(dt_ms=dt_ms, interactive=False)

        if dt_ms > 0:
            self.chrome.timeline_ms = min(int(self.chrome.timeline_max_ms), int(self.chrome.timeline_ms) + dt_ms)
            if self.chrome.timeline_ms >= self.chrome.timeline_max_ms:
                if self.spec.sign.lock_on_fully_open:
                    self.state.menu_sign_locked = True
                self._play_open_sfx_on_fully_open()

        interactive = self.chrome.timeline_ms >= self.chrome.timeline_max_ms
        return ChromeTick(dt_ms=dt_ms, interactive=interactive)

    def take_action(self) -> str | None:
        self._assert_open()
        dispatch = self.spec.dispatch
        match dispatch:
            case DirectActionDispatch():
                action = self.chrome.action
                self.chrome.action = None
                return action
            case PendingOnceDispatch():
                action = self.chrome.pending_action
                self.chrome.pending_action = None
                return action
            case _:
                _unexpected_policy(dispatch, name="dispatch policy")

    def begin_close_transition(
        self,
        action: str,
        *,
        before_close: Callable[[str], None] | None = None,
    ) -> None:
        if self.chrome.closing:
            return
        if not isinstance(action, str):
            raise TypeError("ChromeRuntime.begin_close_transition action must be a str")
        close_action = action
        self.chrome.closing = True
        self.chrome.close_action = close_action
        if before_close is not None:
            before_close(close_action)
        if close_action in self.spec.sign.unlock_on_actions:
            self.state.menu_sign_locked = False
        if close_action in self.spec.fade_to_game_actions:
            self.state.screen_fade_alpha = 0.0
            self.state.screen_fade_ramp = True
        if self.state.audio is not None and self.spec.close_sfx is not None:
            play_sfx(self.state.audio, self.spec.close_sfx, rng=self.state.rng)

    def draw_background(self, *, entity_alpha: float | None = None) -> None:
        self._assert_open()
        rl.clear_background(rl.BLACK)
        pause_background = self.state.pause_background if self.spec.backdrop.allow_pause_background else None
        if pause_background is not None:
            kwargs: dict[str, float] = {}
            resolved_entity_alpha = entity_alpha
            if resolved_entity_alpha is None:
                resolved_entity_alpha = self._pause_background_entity_alpha()
            if resolved_entity_alpha is not None:
                kwargs["entity_alpha"] = resolved_entity_alpha
            pause_background.draw_pause_background(**kwargs)
            return
        if self.ground is not None:
            self.ground.draw(menu_ground_camera(self.state))

    def draw_fade(self) -> None:
        _draw_screen_fade(self.state)

    def draw_sign(self, *, resources: RuntimeResources | None = None, animated: bool | None = None) -> None:
        self._assert_open()
        resources = require_runtime_resources(self.state) if resources is None else resources
        frame = sign_frame(
            int(self.chrome.timeline_ms),
            screen_width=float(self.state.config.screen_width),
            sign_locked=bool(self.state.menu_sign_locked),
            animated=self.spec.sign.animated if animated is None else bool(animated),
        )
        self._draw_sign_frame(resources=resources, frame=frame)

    def draw_cursor(self, *, resources: RuntimeResources | None = None) -> None:
        self._assert_open()
        resources = require_runtime_resources(self.state) if resources is None else resources
        draw_menu_cursor_frame(self.state, resources=resources, pulse_time=float(self.chrome.cursor_pulse_time))

    def _draw_sign_frame(self, *, resources: RuntimeResources, frame: SignFrame) -> None:
        sign = resources.texture(TextureId.UI_SIGN_CRIMSON)
        fx_detail = self.state.config.fx_detail(level=0, default=False)
        if fx_detail:
            draw_ui_quad_shadow(
                texture=sign,
                src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
                dst=rl.Rectangle(frame.pos.x + 7.0, frame.pos.y + 7.0, frame.width, frame.height),
                origin=frame.origin,
                rotation_deg=frame.rotation_deg,
            )
        draw_ui_quad(
            texture=sign,
            src=rl.Rectangle(0.0, 0.0, float(sign.width), float(sign.height)),
            dst=rl.Rectangle(frame.pos.x, frame.pos.y, frame.width, frame.height),
            origin=frame.origin,
            rotation_deg=frame.rotation_deg,
            tint=rl.WHITE,
        )

    def _pause_background_entity_alpha(self) -> float | None:
        if self.state.pause_background is None:
            return None
        policy = self.spec.backdrop.entity_alpha
        match policy:
            case OpaqueEntityAlpha():
                return 1.0
            case CloseTimelineEntityAlpha(duration_ms=duration_ms, action=action):
                if not self.chrome.closing:
                    return 1.0
                if action is not None and self.chrome.close_action != action:
                    return 1.0
                alpha = float(self.chrome.timeline_ms) / float(duration_ms)
                if alpha < 0.0:
                    return 0.0
                if alpha > 1.0:
                    return 1.0
                return alpha
            case _:
                _unexpected_policy(policy, name="entity alpha policy")

    def _init_ground(self) -> GroundRenderer | None:
        if self.state.pause_background is not None and self.spec.backdrop.allow_pause_background:
            return None
        if not self.spec.backdrop.use_menu_ground:
            return None
        return ensure_menu_ground(self.state)

    def _dispatch_close_action(self, action: str) -> None:
        if not isinstance(action, str):
            raise TypeError("ChromeRuntime close action must be a str")
        dispatch = self.spec.dispatch
        match dispatch:
            case DirectActionDispatch():
                self.chrome.action = action
            case PendingOnceDispatch():
                self.chrome.pending_action = action
            case _:
                _unexpected_policy(dispatch, name="dispatch policy")

    def _selected_track(self) -> str | None:
        if self.spec.music.demo_track is not None:
            return self.spec.music.demo_track if self.state.demo_enabled else self.spec.music.primary_track
        return self.spec.music.primary_track

    def _play_open_music(self) -> None:
        if self.state.audio is None:
            return
        track = self._selected_track()
        if track is None:
            return
        if self.spec.music.stop_if_track_mismatch and self.state.audio.music.active_track != track:
            stop_music(self.state.audio)
        play_music(self.state.audio, track)

    def _refresh_music(self) -> None:
        if self.state.audio is None or self.chrome.closing or not self.spec.music.refresh_while_open:
            return
        track = self._selected_track()
        if track is not None:
            play_music(self.state.audio, track)

    def _play_open_sfx(self, sfx_id: str) -> None:
        if self.chrome.panel_open_sfx_played:
            return
        if self.state.audio is None:
            return
        play_sfx(self.state.audio, sfx_id, rng=self.state.rng)
        self.chrome.panel_open_sfx_played = True

    def _play_open_sfx_on_open(self) -> None:
        policy = self.spec.open_sfx
        match policy:
            case NoOpenSfx():
                return
            case PlayOpenSfxOnOpen(sfx_id=sfx_id):
                self._play_open_sfx(sfx_id)
            case PlayOpenSfxOnFullyOpen():
                return
            case _:
                _unexpected_policy(policy, name="open sfx policy")

    def _play_open_sfx_on_fully_open(self) -> None:
        policy = self.spec.open_sfx
        match policy:
            case NoOpenSfx() | PlayOpenSfxOnOpen():
                return
            case PlayOpenSfxOnFullyOpen(sfx_id=sfx_id):
                self._play_open_sfx(sfx_id)
            case _:
                _unexpected_policy(policy, name="open sfx policy")

    def _assert_open(self) -> None:
        assert self.is_open, "ChromeRuntime must be opened before use"
