from __future__ import annotations

from typing import cast

import pyray as rl

from crimson.sim.state_types import PlayerState
from crimson.ui.hud import HudAssets, HudState, draw_hud_overlay
from grim.geom import Vec2


class _TextureStub:
    def __init__(self, width: int, height: int) -> None:
        self.width = int(width)
        self.height = int(height)


def _texture(width: int, height: int) -> rl.Texture:
    return cast("rl.Texture", _TextureStub(width, height))


def test_draw_hud_overlay_stacks_player_bars_for_multiplayer(monkeypatch, mocker) -> None:
    # Force HUD scale = 1.0 for easy coordinate assertions.
    mocker.patch("crimson.ui.hud.rl.get_screen_width", side_effect=lambda: 1024)
    mocker.patch("crimson.ui.hud.rl.get_screen_height", side_effect=lambda: 768)

    textures: dict[str, rl.Texture] = {
        "game_top": _texture(512, 64),
        "life_heart": _texture(32, 32),
        "ind_life": _texture(120, 9),
        "wicons": _texture(256, 128),
        "ind_bullet": _texture(6, 16),
    }
    assets = HudAssets(
        game_top=textures["game_top"],
        life_heart=textures["life_heart"],
        ind_life=textures["ind_life"],
        ind_panel=None,
        ind_bullet=textures["ind_bullet"],
        ind_fire=None,
        ind_rocket=None,
        ind_electric=None,
        wicons=textures["wicons"],
        clock_table=None,
        clock_pointer=None,
        bonuses=None,
    )

    player0 = PlayerState(index=0, pos=Vec2(), health=80.0)
    player0.weapon_id = 1
    player0.clip_size = 1
    player0.ammo = 1

    player1 = PlayerState(index=1, pos=Vec2(), health=50.0)
    player1.weapon_id = 1
    player1.clip_size = 1
    player1.ammo = 1

    draws: list[tuple[object, float, float, float, float]] = []

    def _draw_texture_pro(texture, _src, dst, _origin, _rotation, _tint) -> None:
        draws.append((texture, float(dst.x), float(dst.y), float(dst.width), float(dst.height)))

    mocker.patch("crimson.ui.hud.rl.draw_texture_pro", side_effect=_draw_texture_pro)
    mocker.patch("crimson.ui.hud.rl.draw_text", side_effect=lambda *args, **kwargs: None)

    draw_hud_overlay(
        assets,
        state=HudState(),
        player=player0,
        players=[player0, player1],
        bonus_hud=None,
        elapsed_ms=0.0,
        score=0,
        font=None,
        alpha=1.0,
        show_weapon=True,
        show_xp=False,
        show_time=False,
    )

    weapon_icons = [tuple(dst) for tex, *dst in draws if tex is textures["wicons"]]
    assert weapon_icons == [
        (220.0, 4.0, 32.0, 16.0),
        (220.0, 20.0, 32.0, 16.0),
    ]

    ammo_bars = [tuple(dst) for tex, *dst in draws if tex is textures["ind_bullet"]]
    assert ammo_bars == [
        (290.0, 4.0, 6.0, 16.0),
        (290.0, 18.0, 6.0, 16.0),
    ]

    health_bars = [tuple(dst) for tex, *dst in draws if tex is textures["ind_life"]]
    assert (64.0, 6.0, 120.0, 9.0) in health_bars
    assert (64.0, 22.0, 120.0, 9.0) in health_bars
    assert (64.0, 6.0, 96.0, 9.0) in health_bars
    assert (64.0, 22.0, 60.0, 9.0) in health_bars


def test_draw_hud_overlay_preserve_bugs_shares_player1_heart_pulse_speed(monkeypatch, mocker) -> None:
    mocker.patch("crimson.ui.hud.rl.get_screen_width", side_effect=lambda: 1024)
    mocker.patch("crimson.ui.hud.rl.get_screen_height", side_effect=lambda: 768)
    mocker.patch("crimson.ui.hud.rl.draw_text", side_effect=lambda *args, **kwargs: None)

    life_heart = _texture(32, 32)
    assets = HudAssets(
        game_top=None,
        life_heart=life_heart,
        ind_life=None,
        ind_panel=None,
        ind_bullet=None,
        ind_fire=None,
        ind_rocket=None,
        ind_electric=None,
        wicons=None,
        clock_table=None,
        clock_pointer=None,
        bonuses=None,
    )

    player0 = PlayerState(index=0, pos=Vec2(), health=20.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)

    draws: list[tuple[object, float, float, float, float]] = []

    def _draw_texture_pro(texture, _src, dst, _origin, _rotation, _tint) -> None:
        draws.append((texture, float(dst.x), float(dst.y), float(dst.width), float(dst.height)))

    mocker.patch("crimson.ui.hud.rl.draw_texture_pro", side_effect=_draw_texture_pro)

    draws.clear()
    draw_hud_overlay(
        assets,
        state=HudState(preserve_bugs=False),
        player=player0,
        players=[player0, player1],
        bonus_hud=None,
        elapsed_ms=300.0,
        score=0,
        font=None,
        alpha=1.0,
        show_weapon=False,
        show_xp=False,
        show_time=False,
    )
    default_hearts = [tuple(dst) for tex, *dst in draws if tex is life_heart]

    draws.clear()
    draw_hud_overlay(
        assets,
        state=HudState(preserve_bugs=True),
        player=player0,
        players=[player0, player1],
        bonus_hud=None,
        elapsed_ms=300.0,
        score=0,
        font=None,
        alpha=1.0,
        show_weapon=False,
        show_xp=False,
        show_time=False,
    )
    preserve_hearts = [tuple(dst) for tex, *dst in draws if tex is life_heart]

    assert len(default_hearts) == 2
    assert len(preserve_hearts) == 2
    assert preserve_hearts[1][2] < default_hearts[1][2] - 1.0
