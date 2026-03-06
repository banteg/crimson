from __future__ import annotations

import msgspec

from crimson.frontend.high_scores_view.view import _ScoresDropdownLayout as HighScoresDropdownLayout
from crimson.frontend.panels.controls import _ControlsDropdownLayout as ControlsDropdownLayout
from crimson.ui.layout import DropdownLayoutBase


def _field_names(struct_type: type[msgspec.Struct]) -> list[str]:
    return [field.name for field in msgspec.structs.fields(struct_type)]


def test_dropdown_layouts_share_common_base_fields() -> None:
    assert issubclass(ControlsDropdownLayout, DropdownLayoutBase)
    assert issubclass(HighScoresDropdownLayout, DropdownLayoutBase)

    assert _field_names(DropdownLayoutBase) == [
        "pos",
        "width",
        "header_h",
        "row_h",
        "rows_y0",
        "full_h",
    ]
    assert _field_names(HighScoresDropdownLayout) == _field_names(DropdownLayoutBase)
    assert _field_names(ControlsDropdownLayout)[: len(_field_names(DropdownLayoutBase))] == _field_names(
        DropdownLayoutBase,
    )
