from __future__ import annotations

import math

import msgspec
import pytest

from crimson.render.rtx.contact_glow import GLOW_PEAK, glow_color
from crimson.render.rtx.material_lights import (
    MAX_ILLUMINATION_SOURCES,
    MAX_MATERIAL_LIGHTS,
    SLEW_TICKS,
    VOLLEY_UNITS,
    LightSelection,
    MaterialLight,
    merge_volleys,
    select_material_lights,
)
from grim.geom import Vec2

TICK_MS = 1000. / 60.


def shot(x: float, y: float = 0., *, ident: int, rgb=(.2, .4, 1.), angle: float = 0.) -> MaterialLight:
    return MaterialLight(Vec2(x, y), 100., rgb, direction=Vec2.from_angle(angle), length=40., source_width=4.,
                         ident=ident)


def test_volley_merges_as_one_source_with_its_summed_light_and_one_shots_width() -> None:
    pellets = [shot(0, -6, ident=7), shot(4, 0, ident=3, rgb=(.1, .2, .5)), shot(0, 6, ident=5)]
    merged, = merge_volleys(pellets)
    assert merged.rgb == pytest.approx((.5, 1., 2.5))
    assert merged.ident == 3
    assert merged.source_width == 4. and merged.length == pytest.approx(40.)
    # Heads and tails average by brightness.
    assert merged.pos.x == pytest.approx(.8) and merged.pos.y == pytest.approx(0.)


def test_volley_splits_as_it_fans_out_without_changing_its_total_light() -> None:
    def total(lights):
        return tuple(sum(light.rgb[c] for light in lights) for c in range(3))

    for spread in (0., VOLLEY_UNITS * .9, VOLLEY_UNITS * 1.1, VOLLEY_UNITS * 4):
        pellets = [shot(0, spread * k, ident=k) for k in range(-2, 3)]
        merged = merge_volleys(pellets)
        assert total(merged) == pytest.approx(total(pellets))
        assert all(light.source_width == 4. for light in merged)
    assert len(merge_volleys([shot(0, VOLLEY_UNITS * 4 * k, ident=k) for k in range(5)])) == 5
    # A shot flying the other way, or of another kind, keeps its own light.
    crossing = shot(0, ident=2, angle=math.pi)
    rocket = msgspec.structs.replace(shot(0, ident=3), radius=110.)
    assert len(merge_volleys([shot(0, ident=1), crossing, rocket])) == 3


def lamps(count: int, *, near: int) -> list[MaterialLight]:
    """Point lights 40 apart along x with ident = index; the one at index `near` sits on the view center."""
    return [MaterialLight(Vec2(0. if i == near else 40. * (i + 1), 0.), 100., (1., 1., 1.), reflection_gain=0.,
                          ident=i) for i in range(count)]


def lit(lights: list[MaterialLight]) -> dict[int, float]:
    return {light.ident: light.illumination_gain for light in lights}


def test_selection_fades_sources_across_the_budget_edge_and_new_ones_start_lit() -> None:
    selection = LightSelection()
    count = MAX_ILLUMINATION_SOURCES + 1
    selection.advance(0.)
    first = lit(select_material_lights(lamps(count, near=0), view_center=Vec2(), selection=selection))
    assert first == dict.fromkeys(range(MAX_ILLUMINATION_SOURCES), 1.)
    # The farthest lamp moves onto the view: it fades in as the farthest selected one fades out.
    for tick in range(1, SLEW_TICKS + 1):
        selection.advance(tick * TICK_MS)
        now = lit(select_material_lights(lamps(count, near=count - 1), view_center=Vec2(), selection=selection))
        assert now.get(count - 1) == pytest.approx(tick / SLEW_TICKS)
        assert now.get(count - 2, 0.) == pytest.approx(1. - tick / SLEW_TICKS)
    assert count - 2 not in now
    # A source never seen before lights at once.
    selection.advance((SLEW_TICKS + 1) * TICK_MS)
    newcomer = msgspec.structs.replace(lamps(1, near=0)[0], ident=99)
    assert lit(select_material_lights([newcomer], view_center=Vec2(), selection=selection)) == {99: 1.}


@pytest.mark.parametrize('elapsed_ms', [0., 1200. + TICK_MS])
def test_selection_starts_over_after_a_rewind_or_a_long_gap(elapsed_ms) -> None:
    count = MAX_ILLUMINATION_SOURCES + 1
    selection = LightSelection()
    selection.advance(200.)
    select_material_lights(lamps(count, near=0), view_center=Vec2(), selection=selection)
    selection.advance(elapsed_ms)
    after = lit(select_material_lights(lamps(count, near=count - 1), view_center=Vec2(), selection=selection))
    assert after == lit(select_material_lights(lamps(count, near=count - 1), view_center=Vec2()))


def test_fading_union_keeps_what_delivers_most_within_the_shader_budget() -> None:
    def group(x: float, *, reflection: bool) -> list[MaterialLight]:
        return [MaterialLight(Vec2(x + i, 0.), 100., (1., 1., 1.), illumination_gain=0. if reflection else 1.,
                              reflection_gain=1. if reflection else 0., ident=int(x) + i + 100 * reflection)
                for i in range(MAX_ILLUMINATION_SOURCES)]

    lights = [light for x in (0., 1000.) for reflection in (False, True) for light in group(x, reflection=reflection)]
    selection = LightSelection()
    selection.advance(0.)
    select_material_lights(lights, view_center=Vec2(), selection=selection)
    # Both budgets move to the far groups in one tick, so four groups are fading at once.
    selection.advance(TICK_MS)
    chosen = select_material_lights(lights, view_center=Vec2(1000., 0.), selection=selection)
    assert len(chosen) == MAX_MATERIAL_LIGHTS
    # The near groups fading out deliver less than the groups fading in under the view.
    assert all(light.pos.x >= 1000. for light in chosen)
    assert all(max(light.illumination_gain, light.reflection_gain) == pytest.approx(1. / SLEW_TICKS) for light in chosen)


def test_glow_color_carries_hue_at_full_value_and_peak_in_alpha() -> None:
    assert glow_color((.5, 1., 2.), 1.) == (64, 128, 255, 128)
    assert glow_color((.5, 1., 2.), .5) == (64, 128, 255, 64)
    assert glow_color((GLOW_PEAK * 2, 0., 0.), 1.) == (255, 0, 0, 255)
