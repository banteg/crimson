from grim.geom import Vec2

from crimson.frontend.panels.hit_test import mouse_inside_rect_with_padding


def test_mouse_inside_rect_with_padding_matches_native_edges() -> None:
    pos = Vec2(100.0, 200.0)

    assert mouse_inside_rect_with_padding(Vec2(90.0, 198.0), pos=pos, width=80.0, height=14.0)
    assert mouse_inside_rect_with_padding(Vec2(180.0, 214.0), pos=pos, width=80.0, height=14.0)

    assert not mouse_inside_rect_with_padding(Vec2(89.99, 198.0), pos=pos, width=80.0, height=14.0)
    assert not mouse_inside_rect_with_padding(Vec2(90.0, 197.99), pos=pos, width=80.0, height=14.0)
    assert not mouse_inside_rect_with_padding(Vec2(180.01, 214.0), pos=pos, width=80.0, height=14.0)
    assert not mouse_inside_rect_with_padding(Vec2(180.0, 214.01), pos=pos, width=80.0, height=14.0)


def test_mouse_inside_rect_with_custom_padding_for_slider_hover() -> None:
    pos = Vec2(200.0, 300.0)

    assert mouse_inside_rect_with_padding(
        Vec2(197.0, 299.0),
        pos=pos,
        width=80.0,
        height=18.0,
        left_pad=3.0,
        top_pad=1.0,
    )
    assert not mouse_inside_rect_with_padding(
        Vec2(196.99, 299.0),
        pos=pos,
        width=80.0,
        height=18.0,
        left_pad=3.0,
        top_pad=1.0,
    )
    assert not mouse_inside_rect_with_padding(
        Vec2(197.0, 298.99),
        pos=pos,
        width=80.0,
        height=18.0,
        left_pad=3.0,
        top_pad=1.0,
    )
