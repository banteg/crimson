from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

from crimson.render.world import WorldRenderer
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2

if TYPE_CHECKING:
    from crimson.game_world import GameWorld
    from crimson.render.world.draw import _WorldDrawContext


class _AimWorldLike(Protocol):
    players: list[PlayerState]
    aim_texture: object
    lan_player_rings_enabled: bool
    lan_local_aim_indicators_only: bool
    lan_local_player_slot_index: int


@dataclass(slots=True)
class _AimWorldStub(_AimWorldLike):
    players: list[PlayerState]
    aim_texture: object = field(default_factory=object)
    lan_player_rings_enabled: bool = False
    lan_local_aim_indicators_only: bool = False
    lan_local_player_slot_index: int = 0


@dataclass(slots=True)
class _DrawCtxStub:
    camera: Vec2 = field(default_factory=Vec2)
    view_scale: Vec2 = field(default_factory=lambda: Vec2(1.0, 1.0))
    scale: float = 1.0
    entity_alpha: float = 1.0
    particles_texture: object | None = None


def _as_world(world: _AimWorldLike) -> GameWorld:
    return cast("GameWorld", world)


def _make_players() -> list[PlayerState]:
    return [
        PlayerState(index=0, pos=Vec2(0.0, 0.0), aim=Vec2(10.0, 0.0), spread_heat=0.25),
        PlayerState(index=1, pos=Vec2(0.0, 0.0), aim=Vec2(20.0, 0.0), spread_heat=0.25),
        PlayerState(index=2, pos=Vec2(0.0, 0.0), aim=Vec2(30.0, 0.0), spread_heat=0.25),
    ]


def _make_renderer(*, players: list[PlayerState], local_only: bool, local_slot: int) -> WorldRenderer:
    world = _AimWorldStub(
        players=players,
        lan_player_rings_enabled=False,
        lan_local_aim_indicators_only=bool(local_only),
        lan_local_player_slot_index=int(local_slot),
    )
    return WorldRenderer(_world=_as_world(world))


def _draw_ctx() -> _WorldDrawContext:
    return cast("_WorldDrawContext", _DrawCtxStub())


def test_lan_aim_indicators_draw_local_player_only(monkeypatch) -> None:
    renderer = _make_renderer(players=_make_players(), local_only=True, local_slot=1)
    circles: list[float] = []
    cursors: list[float] = []
    ctx = _draw_ctx()

    monkeypatch.setattr(renderer, "_world_to_screen_with", lambda pos, **_kwargs: pos)
    monkeypatch.setattr(
        renderer,
        "_draw_aim_circle",
        lambda *, center, radius, alpha=1.0: circles.append(float(center.x)),
    )
    monkeypatch.setattr(renderer, "_draw_clock_gauge", lambda **_kwargs: None)
    monkeypatch.setattr(
        "crimson.render.world.draw.draw_aim_cursor",
        lambda _particles, _aim, pos: cursors.append(float(pos.x)),
    )

    renderer._draw_aim_indicators(ctx=ctx)
    renderer._draw_aim_enhancements(ctx=ctx)

    assert circles == [20.0]
    assert cursors == [20.0]


def test_non_lan_aim_indicators_draw_all_players(monkeypatch) -> None:
    renderer = _make_renderer(players=_make_players(), local_only=False, local_slot=1)
    circles: list[float] = []
    cursors: list[float] = []
    ctx = _draw_ctx()

    monkeypatch.setattr(renderer, "_world_to_screen_with", lambda pos, **_kwargs: pos)
    monkeypatch.setattr(
        renderer,
        "_draw_aim_circle",
        lambda *, center, radius, alpha=1.0: circles.append(float(center.x)),
    )
    monkeypatch.setattr(renderer, "_draw_clock_gauge", lambda **_kwargs: None)
    monkeypatch.setattr(
        "crimson.render.world.draw.draw_aim_cursor",
        lambda _particles, _aim, pos: cursors.append(float(pos.x)),
    )

    renderer._draw_aim_indicators(ctx=ctx)
    renderer._draw_aim_enhancements(ctx=ctx)

    assert circles == [10.0, 20.0, 30.0]
    assert cursors == [10.0, 20.0, 30.0]
