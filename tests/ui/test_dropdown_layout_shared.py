from __future__ import annotations

import msgspec

from crimson.screens.chrome.widgets import autosize_dropdown_layout, dropdown_layout
from crimson.ui.layout import DropdownLayoutBase
from grim.geom import Vec2


def _field_names(struct_type: type[msgspec.Struct]) -> list[str]:
    return [field.name for field in msgspec.structs.fields(struct_type)]


def _font_stub():
    return type("_FontStub", (), {"cell_size": 8, "widths": [8] * 256})()


def test_dropdown_helpers_return_common_base_layout() -> None:
    assert _field_names(DropdownLayoutBase) == [
        "pos",
        "width",
        "header_h",
        "row_h",
        "rows_y0",
        "full_h",
    ]
    fixed_layout = dropdown_layout(pos=Vec2(10.0, 20.0), width=120.0, item_count=4, scale=1.0)
    auto_layout = autosize_dropdown_layout(
        pos=Vec2(10.0, 20.0),
        items=("One", "Three"),
        font=_font_stub(),
        scale=1.0,
    )
    assert type(fixed_layout) is DropdownLayoutBase
    assert type(auto_layout) is DropdownLayoutBase
    assert auto_layout.rows_y0 == fixed_layout.rows_y0
    assert auto_layout.header_h == fixed_layout.header_h
