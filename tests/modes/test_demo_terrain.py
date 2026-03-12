from __future__ import annotations

from types import SimpleNamespace

import crimson.world.render_resources as render_resources_module
from crimson.demo import DemoView
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.sim.bootstrap import advance_explicit_terrain
from crimson.terrain_slots import Q2_TERRAIN_SLOTS
from grim.rand import Crand


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

    quest = quest_by_level(QuestLevel(1, 1))
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


def test_demo_apply_terrain_setup_uses_runtime_rng_and_explicit_terrain_seed(make_game_state, mocker) -> None:
    state = make_game_state()
    view = DemoView(state)
    runtime_rng = Crand(0x1234)
    view._runtime.sim_world.state.rng = runtime_rng
    mocker.patch.object(
        render_resources_module,
        "runtime_resources_for",
        return_value=SimpleNamespace(texture=lambda _texture_id: object()),
    )
    sync_audio_rng = mocker.patch.object(view, "_sync_audio_rng_from_runtime")
    expected_rng = Crand(0x1234)
    expected_terrain = advance_explicit_terrain(
        expected_rng,
        terrain_slots=Q2_TERRAIN_SLOTS,
        width=1024,
        height=1024,
    )

    view._apply_terrain_setup(terrain_slots=Q2_TERRAIN_SLOTS)

    sync_audio_rng.assert_called_once_with()
    ground = view._runtime.render_resources.ground
    assert ground is not None
    assert int(ground._scheduled_seed or -1) == int(expected_terrain.terrain_seed)
    assert int(view._runtime.sim_world.state.rng.state) == int(expected_rng.state)
