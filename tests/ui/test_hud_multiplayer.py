from __future__ import annotations

import crimson.ui.hud as hud_module
from crimson.bonuses.hud import BonusHudState
from crimson.game_modes import GameMode
from crimson.sim.state_types import PlayerState
from crimson.ui.hud import HudRenderContext, HudState, draw_hud_overlay
from crimson.weapons import WeaponId
from grim.assets import RuntimeResources, TextureId
from grim.geom import Vec2


def test_draw_hud_overlay_stacks_player_bars_for_multiplayer(mocker, headless_resources: RuntimeResources) -> None:
    resources = headless_resources
    # Force HUD scale = 1.0 for easy coordinate assertions.
    mocker.patch.object(hud_module.rl, "get_screen_width", side_effect=lambda: 1024)
    mocker.patch.object(hud_module.rl, "get_screen_height", side_effect=lambda: 768)


    player0 = PlayerState(index=0, pos=Vec2(), health=80.0)
    player0.weapon.weapon_id = WeaponId.PISTOL
    player0.weapon.clip_size = 1
    player0.weapon.ammo = 1

    player1 = PlayerState(index=1, pos=Vec2(), health=50.0)
    player1.weapon.weapon_id = WeaponId.PISTOL
    player1.weapon.clip_size = 1
    player1.weapon.ammo = 1

    draw_texture_pro = mocker.patch.object(hud_module.rl, "draw_texture_pro")
    mocker.patch.object(hud_module, "_draw_progress_bar")
    mocker.patch.object(hud_module.rl, "draw_text", side_effect=lambda *args, **kwargs: None)

    draw_hud_overlay(
        HudRenderContext(
            resources=resources,
            state=HudState(),
            alpha=1.0,
            game_mode=GameMode.SURVIVAL,
        ),
        players=[player0, player1],
        bonus_hud=BonusHudState(),
        elapsed_ms=0.0,
        frame_dt_ms=0.0,
    )

    draws = [
        (
            call.args[0],
            float(call.args[2].x),
            float(call.args[2].y),
            float(call.args[2].width),
            float(call.args[2].height),
        )
        for call in draw_texture_pro.call_args_list
    ]
    weapon_icons = [tuple(dst) for tex, *dst in draws if tex is resources.texture(TextureId.UI_WICONS)]
    assert weapon_icons == [
        (220.0, 4.0, 32.0, 16.0),
        (220.0, 20.0, 32.0, 16.0),
    ]

    ammo_bars = [tuple(dst) for tex, *dst in draws if tex is resources.texture(TextureId.UI_IND_BULLET)]
    assert ammo_bars == [
        (290.0, 4.0, 6.0, 16.0),
        (290.0, 18.0, 6.0, 16.0),
    ]

    health_bars = [tuple(dst) for tex, *dst in draws if tex is resources.texture(TextureId.UI_IND_LIFE)]
    assert (64.0, 6.0, 120.0, 9.0) in health_bars
    assert (64.0, 22.0, 120.0, 9.0) in health_bars
    assert (64.0, 6.0, 96.0, 9.0) in health_bars
    assert (64.0, 22.0, 60.0, 9.0) in health_bars


def test_draw_hud_overlay_preserve_bugs_shares_player1_heart_pulse_speed(mocker, headless_resources: RuntimeResources) -> None:
    resources = headless_resources
    mocker.patch.object(hud_module.rl, "get_screen_width", side_effect=lambda: 1024)
    mocker.patch.object(hud_module.rl, "get_screen_height", side_effect=lambda: 768)
    mocker.patch.object(hud_module.rl, "draw_text", side_effect=lambda *args, **kwargs: None)

    life_heart = resources.texture(TextureId.UI_LIFE_HEART)

    player0 = PlayerState(index=0, pos=Vec2(), health=20.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0)

    draw_texture_pro = mocker.patch.object(hud_module.rl, "draw_texture_pro")
    mocker.patch.object(hud_module, "_draw_progress_bar")

    draw_texture_pro.reset_mock()
    draw_hud_overlay(
        HudRenderContext(
            resources=resources,
            state=HudState(preserve_bugs=False),
            alpha=1.0,
            game_mode=GameMode.RUSH,
        ),
        players=[player0, player1],
        bonus_hud=BonusHudState(),
        elapsed_ms=300.0,
        frame_dt_ms=0.0,
    )
    draws = [
        (
            call.args[0],
            float(call.args[2].x),
            float(call.args[2].y),
            float(call.args[2].width),
            float(call.args[2].height),
        )
        for call in draw_texture_pro.call_args_list
    ]
    default_hearts = [tuple(dst) for tex, *dst in draws if tex is life_heart]

    draw_texture_pro.reset_mock()
    draw_hud_overlay(
        HudRenderContext(
            resources=resources,
            state=HudState(preserve_bugs=True),
            alpha=1.0,
            game_mode=GameMode.RUSH,
        ),
        players=[player0, player1],
        bonus_hud=BonusHudState(),
        elapsed_ms=300.0,
        frame_dt_ms=0.0,
    )
    draws = [
        (
            call.args[0],
            float(call.args[2].x),
            float(call.args[2].y),
            float(call.args[2].width),
            float(call.args[2].height),
        )
        for call in draw_texture_pro.call_args_list
    ]
    preserve_hearts = [tuple(dst) for tex, *dst in draws if tex is life_heart]

    assert len(default_hearts) == 2
    assert len(preserve_hearts) == 2
    assert preserve_hearts[1][2] < default_hearts[1][2] - 1.0


def test_draw_hud_overlay_uses_native_aux_origin_without_xp(mocker, headless_resources: RuntimeResources) -> None:
    resources = headless_resources
    mocker.patch.object(hud_module.rl, "get_screen_width", side_effect=lambda: 1024)
    mocker.patch.object(hud_module.rl, "get_screen_height", side_effect=lambda: 768)
    mocker.patch.object(hud_module.rl, "draw_text", side_effect=lambda *args, **kwargs: None)

    panel = resources.texture(TextureId.UI_IND_PANEL)
    player = PlayerState(index=0, pos=Vec2(), health=100.0, aux_timer=0.5)
    player.weapon.weapon_id = WeaponId.PISTOL
    draw_texture_pro = mocker.patch.object(hud_module.rl, "draw_texture_pro")
    mocker.patch.object(hud_module, "_draw_progress_bar")

    draw_hud_overlay(
        HudRenderContext(
            resources=resources,
            state=HudState(),
            alpha=1.0,
            game_mode=GameMode.DEMO,
        ),
        players=[player],
        bonus_hud=BonusHudState(),
        elapsed_ms=0.0,
        frame_dt_ms=0.0,
    )

    panel_draws = [
        (float(call.args[2].x), float(call.args[2].y))
        for call in draw_texture_pro.call_args_list
        if call.args[0] is panel
    ]
    assert panel_draws == [(-12.0, 61.0)]


def test_draw_hud_overlay_compacts_active_aux_rows(mocker, headless_resources: RuntimeResources) -> None:
    resources = headless_resources
    mocker.patch.object(hud_module.rl, "get_screen_width", side_effect=lambda: 1024)
    mocker.patch.object(hud_module.rl, "get_screen_height", side_effect=lambda: 768)
    mocker.patch.object(hud_module.rl, "draw_text", side_effect=lambda *args, **kwargs: None)
    mocker.patch.object(hud_module.rl, "draw_rectangle", side_effect=lambda *args, **kwargs: None)

    panel = resources.texture(TextureId.UI_IND_PANEL)
    player0 = PlayerState(index=0, pos=Vec2(), health=100.0, aux_timer=0.0)
    player1 = PlayerState(index=1, pos=Vec2(), health=100.0, aux_timer=0.5)
    player0.weapon.weapon_id = WeaponId.PISTOL
    player1.weapon.weapon_id = WeaponId.PISTOL
    draw_texture_pro = mocker.patch.object(hud_module.rl, "draw_texture_pro")
    mocker.patch.object(hud_module, "_draw_progress_bar")

    draw_hud_overlay(
        HudRenderContext(
            resources=resources,
            state=HudState(),
            alpha=1.0,
            game_mode=GameMode.TYPO,
        ),
        players=[player0, player1],
        bonus_hud=BonusHudState(),
        elapsed_ms=0.0,
        frame_dt_ms=0.0,
    )

    popup_panels = [
        (float(call.args[2].x), float(call.args[2].y))
        for call in draw_texture_pro.call_args_list
        if call.args[0] is panel and float(call.args[2].x) == -12.0
    ]
    assert popup_panels == [(-12.0, 104.0)]


def test_bonus_hud_draws_four_timer_bars(mocker, headless_resources: RuntimeResources) -> None:
    resources = headless_resources
    from crimson.bonuses.ids import BonusId

    mocker.patch.object(hud_module.rl, "get_screen_width", return_value=1024)
    mocker.patch.object(hud_module.rl, "get_screen_height", return_value=768)
    mocker.patch.object(hud_module.rl, "draw_texture_pro")
    mocker.patch.object(hud_module.rl, "draw_rectangle")
    mocker.patch.object(hud_module.rl, "draw_text")
    bars = mocker.patch.object(hud_module, "_draw_progress_bar")
    players = [PlayerState(index=index, pos=Vec2()) for index in range(4)]
    hud = BonusHudState()
    hud.register(BonusId.SHIELD, label="Shield", icon_id=6)
    hud.slots[0].slide_x = -2.0
    hud.slots[0].timer_values = (0.0, 0.0, 5.0, 10.0)
    draw_hud_overlay(
        HudRenderContext(resources=resources, state=HudState(), game_mode=GameMode.DEMO),
        players=players, bonus_hud=hud, elapsed_ms=0.0, frame_dt_ms=0.0,
    )
    assert [call.args[2] for call in bars.call_args_list] == [0.0, 0.0, 0.25, 0.5]
    ys = [call.args[0].y for call in bars.call_args_list]
    assert ys == [ys[0] + index * 6 for index in range(4)]
