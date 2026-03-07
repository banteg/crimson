from __future__ import annotations

from crimson.demo import DemoView
from crimson.quests import quest_by_stage
from crimson.terrain_slots import Q2_TERRAIN_SLOTS


def test_demo_variant_1_uses_q2_descriptor_slots(make_game_state, mocker) -> None:
    state = make_game_state()
    view = DemoView(state)
    mocker.patch.object(view, "_setup_world_players")
    mocker.patch.object(view, "_spawn")
    apply_terrain_setup = mocker.patch.object(view, "_apply_terrain_setup")

    view._setup_variant_1()

    apply_terrain_setup.assert_called_once_with(terrain_slots=Q2_TERRAIN_SLOTS)


def test_demo_variant_3_uses_first_quest_descriptor_slots(make_game_state, mocker) -> None:
    state = make_game_state()
    view = DemoView(state)
    mocker.patch.object(view, "_setup_world_players")
    mocker.patch.object(view, "_spawn")
    apply_terrain_setup = mocker.patch.object(view, "_apply_terrain_setup")

    view._setup_variant_3()

    quest = quest_by_stage(1, 1)
    assert quest is not None
    apply_terrain_setup.assert_called_once_with(terrain_slots=quest.terrain_slots)


def test_demo_variants_without_descriptor_keep_existing_terrain(make_game_state, mocker) -> None:
    state = make_game_state()
    view = DemoView(state)
    apply_terrain_setup = mocker.patch.object(view, "_apply_terrain_setup")
    mocker.patch.object(view, "_setup_variant_0")
    mocker.patch.object(view, "_setup_variant_2")

    for variant_index in (0, 2, 4):
        view._demo_variant_index = variant_index
        view._demo_mode_start()

    apply_terrain_setup.assert_not_called()
