from __future__ import annotations

import ctypes
import shutil
import subprocess
from contextlib import contextmanager
from itertools import groupby
from pathlib import Path
from typing import Any, cast

import msgspec
import numpy as np
import pytest

from crimson.effects import EffectPool
from crimson.effects_atlas import EFFECT_ID_ATLAS_TABLE_BY_ID, EffectId
from crimson.render.rtx.debris import (
    FADE_SECONDS,
    ICE_EFFECTS,
    MAXIMUM,
    TARGET,
    Candidate,
    DebrisBudget,
    _key,
    candidates,
    scaled_alpha,
)
from crimson.render.rtx.mode import RtxRenderMode
from crimson.render.world import effects
from crimson.render.world.context import WorldRenderCtx
from crimson.sim.sessions import DeterministicSession
from grim.color import RGBA
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from grim.math import f32
from grim.rand import Crand
from tests.support.creature_draw_capture import render_ctx_for_creatures
from tests.support.world_runtime import WorldRuntimeHost

SCREEN = Vec2(1024, 768)


def grid(count: int, area: float = 100.) -> list[Candidate]:
    """Pieces spread over the 8x6 tiles, in slot order."""
    return [Candidate(slot, 1, (slot % 8) * 128 + 64., (slot % 6) * 128 + 64., area) for slot in range(count)]


def drawn(budget: DebrisBudget) -> set[int]:
    return {slot for slot, piece in budget.pieces.items() if piece.alpha > 0.}


def test_a_dense_burst_draws_the_target_from_every_tile_whatever_the_pool_order() -> None:
    shown = grid(1400)
    budget = DebrisBudget()
    budget.select(shown, screen=SCREEN, elapsed_ms=0.)
    chosen = drawn(budget)
    assert len(chosen) == TARGET
    again = DebrisBudget()
    again.select(shown[::-1], screen=SCREEN, elapsed_ms=0.)
    assert drawn(again) == chosen
    tiles = {(c.x // 128, c.y // 128) for c in shown}
    assert {(c.x // 128, c.y // 128) for c in shown if c.slot in chosen} == tiles


def test_a_piece_leaving_fades_out_as_its_replacement_fades_in_on_the_runs_clock() -> None:
    shown = grid(1400)
    budget = DebrisBudget()
    budget.select(shown, screen=SCREEN, elapsed_ms=0.)
    before = drawn(budget)
    leaving = min(before)
    # Too large for the selection's half of the screen.
    shown = [msgspec.structs.replace(c, area=400000.) if c.slot == leaving else c for c in shown]
    budget.select(shown, screen=SCREEN, elapsed_ms=20.)
    (joining,) = drawn(budget) - before
    assert (budget.alpha(leaving), budget.alpha(joining)) == pytest.approx((.75, .25))
    # A paused redraw moves neither.
    budget.select(shown, screen=SCREEN, elapsed_ms=20.)
    assert (budget.alpha(leaving), budget.alpha(joining)) == pytest.approx((.75, .25))
    for step in (2, 3, 4):
        budget.select(shown, screen=SCREEN, elapsed_ms=20. * step)
        assert (budget.alpha(leaving), budget.alpha(joining)) == pytest.approx((1 - step * .25, step * .25))
    assert len(drawn(budget)) == TARGET


def test_large_chunks_run_out_of_screen_before_count_and_churn_never_passes_the_cap() -> None:
    budget = DebrisBudget()
    budget.select(grid(1400, SCREEN.x * SCREEN.y / 16), screen=SCREEN, elapsed_ms=0.)
    assert len(drawn(budget)) == 8
    budget.reset()
    for frame in range(120):
        shown = [Candidate(slot, 1, (slot + frame) % 8 * 128 + 64., (slot + frame // 2) % 6 * 128 + 64.,
                           100. if (slot + frame) % 3 else 1e9) for slot in range(1400)]
        budget.select(shown, screen=SCREEN, elapsed_ms=frame * 4.)
        assert len(drawn(budget)) <= MAXIMUM


def test_a_respawned_slot_keeps_no_fade_and_a_rewind_starts_over() -> None:
    shown = grid(12)
    budget = DebrisBudget()
    budget.select(shown, screen=SCREEN, elapsed_ms=1000.)
    budget.pieces[0].alpha = .5
    budget.select(shown, screen=SCREEN, elapsed_ms=1000.)
    assert budget.alpha(0) == .5
    shown[0] = msgspec.structs.replace(shown[0], generation=2)
    budget.select(shown, screen=SCREEN, elapsed_ms=1000.)
    assert budget.alpha(0) == 1.
    budget.pieces[1].alpha = .5
    budget.select(shown, screen=SCREEN, elapsed_ms=990.)
    assert budget.alpha(1) == 1.
    # A piece leaving the screen forgets its place.
    budget.select(shown[2:], screen=SCREEN, elapsed_ms=1000.)
    assert set(budget.pieces) == {c.slot for c in shown[2:]}


class Lighting:
    """The creature lighting's scopes, as draw_effect_pool opens them."""

    def __init__(self) -> None:
        self.scopes: list[int] = []

    @contextmanager
    def scope(self, *, texture, restore_shader, ice=0, frozen=False):
        self.scopes.append(ice)
        yield


def rtx_effects(resources) -> tuple[WorldRenderCtx, Lighting, DebrisBudget]:
    lighting, budget = Lighting(), DebrisBudget()
    ctx = render_ctx_for_creatures(resources, [])
    ctx = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(
        ctx.frame, rtx_mode=RtxRenderMode.RTX, creature_lighting=cast(Any, lighting), debris=budget, run_elapsed_ms=0.,
    ))
    return ctx, lighting, budget


def test_the_effect_pool_draws_only_the_selection_without_splitting_ice_runs(
    headless_window, headless_resources, mocker,
) -> None:
    ctx, lighting, budget = rtx_effects(headless_resources)
    pool = ctx.frame.state.effects
    rng = Crand(7)
    for corpse in range(80):
        pool.spawn_freeze_shatter(pos=Vec2(40 + corpse % 20 * 48, 100 + corpse // 20 * 150), angle=.3, rng=rng,
                                  detail_preset=5, preserve_bugs=False)
    ice = [entry for entry in (*pool.entries, *pool.overflow_entries) if entry.flags and entry.effect_id in ICE_EFFECTS]
    assert len(ice) == 80 * 8
    state = msgspec.to_builtins([(e.effect_id, e.pos, e.color, e.age) for e in ice])
    quad = mocker.spy(effects, "draw_centered_quad")
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    shown = [entry for slot, entry in enumerate((*pool.entries, *pool.overflow_entries))
             if entry.flags and entry.effect_id in ICE_EFFECTS and budget.alpha(slot) > 0.]
    assert len(shown) == len(quad.call_args_list) == TARGET
    # New pieces draw at their own opacity, packed as the clients pack it; the pool is untouched.
    assert [call.args[6].a for call in quad.call_args_list] == [scaled_alpha(entry.color.a, 1.) for entry in shown]
    assert msgspec.to_builtins([(e.effect_id, e.pos, e.color, e.age) for e in ice]) == state
    runs = [grid for grid, _ in groupby(EFFECT_ID_ATLAS_TABLE_BY_ID[int(e.effect_id)].grid for e in shown)]
    assert lighting.scopes == runs


def test_a_piece_faded_to_no_alpha_neither_draws_nor_splits_its_neighbours_scope(
    headless_window, headless_resources, mocker,
) -> None:
    ctx, lighting, budget = rtx_effects(headless_resources)
    # Two cubes with a faint shard between them, in the pool's draw order.
    for slot, effect_id, alpha in ((0, EffectId.FREEZE_SHATTER, .7), (1, EffectId.FREEZE_SHARD_0, .02),
                                   (2, EffectId.FREEZE_SHATTER, .7)):
        entry = ctx.frame.state.effects.entries[slot]
        entry.effect_id, entry.flags, entry.age, entry.scale = effect_id, 0x5D, 0., 1.
        entry.pos, entry.half_width, entry.half_height = Vec2(100 + slot * 100, 100), 16., 16.
        entry.color = RGBA(1., 1., 1., alpha)
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    # The shard fading out: its alpha byte, 5, at a share of 0.05 rounds to nothing, as the clients round it.
    budget.pieces[1].alpha = .05
    lighting.scopes.clear()
    quad = mocker.spy(effects, "draw_centered_quad")
    effects.draw_effect_pool(ctx, camera=Vec2(), view_scale=Vec2(1, 1))
    assert len(quad.call_args_list) == 2
    assert lighting.scopes == [EFFECT_ID_ATLAS_TABLE_BY_ID[int(EffectId.FREEZE_SHATTER)].grid]


def test_the_selection_keeps_the_run_s_clock_and_holds_it_outside_a_run(headless_window, headless_resources) -> None:
    ctx, _, budget = rtx_effects(headless_resources)
    ctx.frame.state.effects.spawn_freeze_shatter(pos=Vec2(300, 300), angle=.3, rng=Crand(7), detail_preset=5,
                                                  preserve_bugs=False)
    for ms in (1000., 1016., None):
        frame = msgspec.structs.replace(ctx.frame, run_elapsed_ms=ms)
        effects.draw_effect_pool(msgspec.structs.replace(ctx, frame=frame), camera=Vec2(), view_scale=Vec2(1, 1))
        assert budget.elapsed_ms == (1016. if ms is None else ms)
    # A budget started over outside a run holds a clock from zero, so a redraw keeps what the last one chose.
    budget.reset()
    outside = msgspec.structs.replace(ctx, frame=msgspec.structs.replace(ctx.frame, run_elapsed_ms=None))
    effects.draw_effect_pool(outside, camera=Vec2(), view_scale=Vec2(1, 1))
    slot = next(iter(budget.pieces))
    budget.pieces[slot].alpha = .5
    effects.draw_effect_pool(outside, camera=Vec2(), view_scale=Vec2(1, 1))
    assert (budget.elapsed_ms, budget.alpha(slot)) == (0., .5)


def test_the_selection_starts_over_where_the_clients_start_theirs(tmp_path, headless_resources) -> None:
    runtime = WorldRuntimeHost(assets_dir=tmp_path, config=default_crimson_cfg(), rtx_mode=RtxRenderMode.RTX)
    runtime.render_resources.resources = headless_resources
    debris = runtime.render_resources.debris
    assert runtime.build_render_frame().debris is debris
    assert runtime.build_render_frame().run_elapsed_ms is None

    def chosen() -> bool:
        debris.select(grid(12), screen=SCREEN, elapsed_ms=100.)
        return bool(debris.pieces)

    # A change of render mode, a run (or a replay's keyframe) starting, and a reset world.
    assert chosen()
    runtime.rtx_mode = RtxRenderMode.CLASSIC
    assert not debris.pieces and debris.elapsed_ms < 0.
    runtime.rtx_mode = RtxRenderMode.RTX
    assert chosen()
    runtime.start_session(DeterministicSession.start(runtime.world, perk_progression_enabled=False))
    assert not debris.pieces
    assert chosen()
    runtime.reset()
    assert not debris.pieces


@pytest.fixture(scope="module")
def native_budget(tmp_path_factory: pytest.TempPathFactory):
    compiler = shutil.which("clang++") or shutil.which("c++")
    if compiler is None:
        pytest.skip("A C++ compiler is required for the clients' budget")
    root = Path(__file__).resolve().parents[2]
    work = tmp_path_factory.mktemp("debris-budget")
    source = work / "budget.cpp"
    source.write_text(
        '#include "rtx_debris.h"\nstatic RtxDebrisBudget budget;\n'
        'extern "C" void forget(int slot) { budget.forget(slot); }\n'
        'extern "C" void reset() { budget.reset(); }\n'
        'extern "C" void choose(const int *slots, const float *xs, const float *ys, const float *areas, int n, float width,\n'
        '                       float height, float dt, float *alpha) {\n'
        '  std::vector<RtxDebrisBudget::Candidate> shown;\n'
        '  for (int i = 0; i < n; ++i) shown.push_back({slots[i], xs[i], ys[i], areas[i]});\n'
        '  budget.select(shown, width, height, dt);\n'
        '  for (int i = 0; i < RtxDebrisBudget::capacity; ++i) alpha[i] = budget.alpha(i);\n}\n'
        # effect_pack_color's alpha byte at rtx_debris_color's share, and rtx_debris_prepare's projection, as written
        # there.
        'extern "C" unsigned scale(float a, float alpha) {\n'
        '  unsigned char byte = (unsigned char)(a * 255.0f);\n'
        '  return (unsigned)(byte * alpha + .5f);\n}\n'
        'extern "C" void project(float px, float py, float rotation, float hx, float hy, float scale, float cx,\n'
        '                        float cy, float width, float height, float *out) {\n'
        '  float x = px + cx, y = py + cy;\n'
        '  float co = fabsf(cosf(rotation)), si = fabsf(sinf(rotation));\n'
        '  float w = (co * hx + si * hy) * fabsf(scale);\n'
        '  float h = (si * hx + co * hy) * fabsf(scale);\n'
        '  out[0] = x, out[1] = y;\n'
        '  out[2] = std::max(0.f, std::min(width, x + w) - std::max(0.f, x - w)) *\n'
        '           std::max(0.f, std::min(height, y + h) - std::max(0.f, y - h));\n}\n',
    )
    library = work / "budget.so"
    # The clients' builds keep each float operation's own rounding (crimson-core/build.py).
    subprocess.run([compiler, "-std=c++17", "-shared", "-fPIC", "-O2", "-ffp-contract=off",
                    f"-I{root / 'crimson-core/game/include'}", str(source), "-o", str(library)], check=True)
    native = ctypes.CDLL(str(library))
    native.choose.argtypes = [ctypes.c_void_p] * 4 + [ctypes.c_int] + [ctypes.c_float] * 3 + [ctypes.c_void_p]
    native.scale.argtypes = [ctypes.c_float, ctypes.c_float]
    native.scale.restype = ctypes.c_uint
    native.project.argtypes = [ctypes.c_float] * 10 + [ctypes.c_void_p]
    return native


def same_choice(native, budget: DebrisBudget, shown: list[Candidate], *, screen: Vec2, elapsed_ms: float,
                dt: float) -> bool:
    """One frame's selection by the clients' budget (`dt` from their frame clock) and by `budget`, compared."""
    slots = np.array([c.slot for c in shown], dtype=np.int32)
    xs, ys, areas = (np.array([getattr(c, name) for c in shown], dtype=np.float32) for name in ("x", "y", "area"))
    alpha = np.zeros(2560, dtype=np.float32)
    native.choose(slots.ctypes.data, xs.ctypes.data, ys.ctypes.data, areas.ctypes.data, len(shown), screen.x, screen.y,
                  dt, alpha.ctypes.data)
    budget.select(shown, screen=screen, elapsed_ms=elapsed_ms)
    return {slot: budget.alpha(slot) for slot in budget.pieces if budget.alpha(slot) > 0.} == \
        {int(slot): float(alpha[slot]) for slot in np.flatnonzero(alpha)}


def test_the_selection_is_the_clients_frame_for_frame(native_budget) -> None:
    # Churning debris: slots respawn, pieces come and go, and the run's clock rewinds once.
    rng = np.random.default_rng(5)
    generations = np.ones(2560, dtype=np.int64)
    live = rng.choice(2560, 1200, replace=False)
    budget = DebrisBudget()
    native_budget.reset()
    last = -1
    for frame in range(240):
        if frame % 7 == 0:
            for slot in rng.choice(live, 60):
                generations[slot] += 1
                native_budget.forget(int(slot))
        if frame % 11 == 0:
            live = np.unique(np.concatenate([live[rng.random(len(live)) > .05], rng.choice(2560, 40)]))
        xs = rng.uniform(-20, 1044, len(live)).astype(np.float32)
        ys = rng.uniform(-20, 788, len(live)).astype(np.float32)
        areas = rng.uniform(40, 9000, len(live)).astype(np.float32)
        elapsed = frame * 16 if frame < 200 else (frame - 60) * 16
        # The clients' frame clock (rtx_debris_prepare).
        if last < 0 or elapsed < last or elapsed - last > 250:
            native_budget.reset()
            dt = 0.
        else:
            dt = f32((elapsed - last) * f32(.001))
        last = elapsed
        shown = [Candidate(int(s), int(generations[s]), float(x), float(y), float(a))
                 for s, x, y, a in zip(live, xs, ys, areas, strict=True)]
        assert same_choice(native_budget, budget, shown, screen=SCREEN, elapsed_ms=elapsed, dt=dt), frame


# A window of another shape leaves the logical screen a fraction of a pixel off whole (1027x768: 765.7565...).
@pytest.mark.parametrize("screen", [Vec2(1024, 768), Vec2(1024, 800), Vec2(1366, 768), Vec2(1280, 720),
                                    Vec2(1024, 768 * 1024 / 1027)])
def test_pieces_on_tile_edges_and_at_the_area_limit_choose_as_the_clients_do(native_budget, screen: Vec2) -> None:
    # Pieces a float apart either side of every tile edge, crowding one tile's neighbours...
    edges = [np.float32(k * screen.x / 8) for k in range(1, 8)], [np.float32(k * screen.y / 6) for k in range(1, 6)]
    near = [[float(np.nextafter(e, d, dtype=np.float32)) for e in axis for d in (-np.inf, np.inf)] + [float(e) for e in axis]
            for axis in edges]
    shown = [Candidate(slot, 1, x, y, 64.) for slot, (x, y) in enumerate((x, y) for x in near[0] for y in near[1])]
    native_budget.reset()
    assert same_choice(native_budget, DebrisBudget(), shown, screen=screen, elapsed_ms=0., dt=0.)
    # ... and the target's worth of pieces just filling half the screen, the first a float over its share.
    share = np.float32(screen.x * screen.y / 2 / TARGET)
    shown = [Candidate(slot, 1, 64. + slot % 8 * screen.x / 8, 64. + slot % 6 * screen.y / 6,
                       float(np.nextafter(share, np.inf, dtype=np.float32)) if slot == 0 else float(share))
             for slot in range(TARGET)]
    native_budget.reset()
    assert same_choice(native_budget, DebrisBudget(), shown, screen=screen, elapsed_ms=0., dt=0.)


def test_a_piece_s_alpha_at_its_share_is_the_clients(native_budget) -> None:
    # Alphas across the range, a faint shatter's among them, at the shares fades of 16, 17 and 33 ms steps pass through.
    alphas = {f32(a) for a in np.linspace(0., 1., 2049)} | {f32(.0154545903)}
    shares = {0., 1., f32(.14999987185)}
    for ms in (16., 17., 33.):
        step = min(f32(f32(ms * f32(.001)) / f32(FADE_SECONDS)), 1.)
        alpha = 1.
        while alpha > 0.:
            shares.add(alpha)
            alpha = max(0., f32(alpha - step))
    assert all(scaled_alpha(a, share) == native_budget.scale(a, share) for a in alphas for share in shares)


# A wide window's logical screen and camera, and a tall one's, each a fraction of a pixel off whole.
@pytest.mark.parametrize(("camera", "screen"), [(Vec2(-311.14285714285717, -240.33333333333334), Vec2(1024, 575.7188872620791)),
                                                (Vec2(-129.1210300292969, -88.77777777777777), Vec2(765.7565725413826, 1024))])
def test_a_piece_s_place_on_screen_is_the_clients(native_budget, camera: Vec2, screen: Vec2) -> None:
    # Shatter pieces in a pool, under a camera and screen a fraction of a pixel off whole, as a wide window leaves them.
    # Their rotations stay within a turn or so: past that the clients' cosf (musl's, in the game module) and the host's
    # here may each differ from a correctly rounded cosine by an ulp, which flips a piece whose visible part is a
    # sliver at the screen's edge.
    pool = EffectPool()
    rng = np.random.default_rng(3)
    for entry in pool.entries[:400]:
        entry.effect_id, entry.flags, entry.age = int(EffectId.FREEZE_SHARD_1), 0x5D, 0.
        entry.pos = Vec2(*(f32(v) for v in rng.uniform(250, 1400, 2)))
        entry.rotation, entry.scale = f32(rng.uniform(-7, 7)), f32(rng.uniform(.3, 2.5))
        entry.half_width, entry.half_height = f32(rng.uniform(2, 40)), f32(rng.uniform(2, 40))
        entry.color = RGBA(1., 1., 1., .5)
    shown = {c.slot: c for c in candidates(pool, camera=camera, screen=screen)}
    out = np.zeros(3, dtype=np.float32)
    for slot, entry in enumerate(pool.entries[:400]):
        native_budget.project(entry.pos.x, entry.pos.y, entry.rotation, entry.half_width, entry.half_height,
                              entry.scale, camera.x, camera.y, screen.x, screen.y, out.ctypes.data)
        assert (slot in shown) == (out[2] > 0)
        if slot in shown:
            assert (shown[slot].x, shown[slot].y, shown[slot].area) == tuple(float(v) for v in out), slot


def test_pieces_joining_retiring_ones_fill_the_reserve_as_the_clients_do(native_budget) -> None:
    # The slots the selection takes first, all in one tile: the first frame draws the next 256 at half the screen,
    # and the next wants the first 32 instead, which join while the retiring 256 still hold their half, until the
    # three quarters are full, the last a float over its share.
    slots = sorted(range(2560), key=_key)
    share = np.float32(SCREEN.x * SCREEN.y / 64)
    retiring = [Candidate(slot, 1, 64., 64., float(SCREEN.x * SCREEN.y / 2 / TARGET)) for slot in slots[32:32 + TARGET]]
    joining = [Candidate(slot, 1, 64., 64., float(np.nextafter(share, np.inf, dtype=np.float32)) if i == 15
                         else float(share)) for i, slot in enumerate(slots[:32])]
    budget = DebrisBudget()
    native_budget.reset()
    assert same_choice(native_budget, budget, retiring, screen=SCREEN, elapsed_ms=0., dt=0.)
    assert same_choice(native_budget, budget, joining + retiring, screen=SCREEN, elapsed_ms=20.,
                       dt=f32(20 * f32(.001)))
    assert 0 < sum(budget.alpha(c.slot) > 0. for c in joining) < 32
