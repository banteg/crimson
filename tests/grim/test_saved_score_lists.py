from __future__ import annotations

from grim.config import default_crimson_cfg


def test_adding_lists_selects_them_and_a_full_set_overwrites_slot_one() -> None:
    profile = default_crimson_cfg().profile

    profile.add_saved_name("alpha")
    assert (profile.saved_name_count, profile.selected_saved_name_slot, profile.named_score_list) == (2, 1, "alpha")

    for name in ("b", "c", "d", "e", "f"):
        profile.add_saved_name(name)
    assert profile.saved_name_count == 7
    # The eighth list would fill every slot: native overwrites slot 1 and keeps seven.
    profile.add_saved_name("g/h")
    assert profile.saved_name_count == 7
    assert (profile.selected_saved_name_slot, profile.named_score_list) == (1, "gh")


def test_deleting_moves_the_last_list_into_the_slot_and_selects_the_default() -> None:
    profile = default_crimson_cfg().profile
    for name in ("alpha", "beta", "gamma"):
        profile.add_saved_name(name)
    profile.selected_saved_name_slot = 1

    profile.delete_selected_saved_name()

    assert profile.saved_name_labels() == ("default", "gamma", "beta")
    assert (profile.selected_saved_name_slot, profile.named_score_list) == (0, "")
