from __future__ import annotations

import pytest

from crimson.ui.menu_layout import back_button_scale, main_menu_item_scale, pause_menu_item_scale

# Expected values transcribe the width branches of `ui_menu_layout_init`.


@pytest.mark.parametrize(
    ("width", "expected"),
    [(640, (0.9, 22.0)), (641, (1.0, 0.0))],
)
def test_main_menu_items_only_shrink_at_640(width: int, expected: tuple[float, float]) -> None:
    assert main_menu_item_scale(width, 2) == expected


@pytest.mark.parametrize(
    ("width", "expected"),
    [(640, (0.8, 22.0)), (641, (0.9, 10.0)), (800, (0.9, 10.0)), (801, (1.0, 0.0))],
)
def test_pause_menu_items_shrink_to_0_8_at_640_and_0_9_at_800(width: int, expected: tuple[float, float]) -> None:
    assert pause_menu_item_scale(width, 2) == expected


@pytest.mark.parametrize(
    ("width", "expected"),
    [(640, (0.8, 11.0)), (641, (0.9, 3.0)), (800, (0.9, 3.0)), (801, (1.0, 0.0))],
)
def test_back_buttons_shrink_to_0_8_at_640_and_0_9_at_800(width: int, expected: tuple[float, float]) -> None:
    assert back_button_scale(width) == expected
