from __future__ import annotations

from crimson.gameplay import PlayerState
from crimson.ui.hud import HudAssets, HudState, draw_hud_overlay


class _TextureStub:
    def __init__(self, width: int, height: int) -> None:
        self.width = int(width)
        self.height = int(height)


def test_draw_hud_overlay_stacks_player_bars_for_multiplayer(monkeypatch) -> None:
    # Force HUD scale = 1.0 for easy coordinate assertions.
    monkeypatch.setattr("crimson.ui.hud.rl.get_screen_width", lambda: 1024)
    monkeypatch.setattr("crimson.ui.hud.rl.get_screen_height", lambda: 768)

    textures: dict[str, _TextureStub] = {
        "game_top": _TextureStub(512, 64),
        "life_heart": _TextureStub(32, 32),
        "ind_life": _TextureStub(120, 9),
        "wicons": _TextureStub(256, 128),
        "ind_bullet": _TextureStub(6, 16),
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
        missing=[],
    )

    player0 = PlayerState(index=0, pos_x=0.0, pos_y=0.0, health=80.0)
    player0.weapon_id = 1
    player0.clip_size = 1
    player0.ammo = 1

    player1 = PlayerState(index=1, pos_x=0.0, pos_y=0.0, health=50.0)
    player1.weapon_id = 1
    player1.clip_size = 1
    player1.ammo = 1

    draws: list[tuple[object, float, float, float, float]] = []

    def _draw_texture_pro(texture, _src, dst, _origin, _rotation, _tint) -> None:  # noqa: ANN001,ARG001
        draws.append((texture, float(dst.x), float(dst.y), float(dst.width), float(dst.height)))

    monkeypatch.setattr("crimson.ui.hud.rl.draw_texture_pro", _draw_texture_pro)
    monkeypatch.setattr("crimson.ui.hud.rl.draw_text", lambda *args, **kwargs: None)  # noqa: ARG005

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
