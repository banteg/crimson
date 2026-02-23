from __future__ import annotations

from pathlib import Path

from crimson.projectiles import ProjectileTypeId
from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan, iter_beam_sample_offsets
from crimson.views.beam_debug import (
    BeamCountInput,
    BeamDebugView,
    BeamFrameStats,
    BeamRenderMode,
    BeamScenarioPreset,
    BeamShaderGemini2Params,
    _fit_shader_profile_to_reference,
    _profile_match_metrics,
    _shader_profile_value,
    beam_scenario_config,
    cycle_beam_render_mode,
    estimate_beam_frame_counts,
)
from grim.view import ViewContext


def test_cycle_beam_render_mode_order_is_stable() -> None:
    mode = BeamRenderMode.BASELINE_SPRITE
    mode = cycle_beam_render_mode(mode)
    assert mode == BeamRenderMode.SHADER_GEMINI_2
    mode = cycle_beam_render_mode(mode)
    assert mode == BeamRenderMode.BASELINE_SPRITE


def test_beam_scenario_presets_match_spec() -> None:
    plasma = beam_scenario_config(BeamScenarioPreset.PLASMA_LIKE)
    assert plasma.projectile_count == 14
    assert plasma.base_distance_units == 220.0
    assert plasma.distance_jitter_units == 80.0
    assert plasma.cap_enabled is True
    assert plasma.use_fire_profile is True
    assert plasma.force_life_high is True

    crowd = beam_scenario_config(BeamScenarioPreset.CROWD_STRESS)
    assert crowd.projectile_count == 64
    assert crowd.base_distance_units == 220.0
    assert crowd.distance_jitter_units == 80.0
    assert crowd.cap_enabled is True

    long_uncapped = beam_scenario_config(BeamScenarioPreset.LONG_UNCAPPED)
    assert long_uncapped.projectile_count == 32
    assert long_uncapped.base_distance_units == 900.0
    assert long_uncapped.distance_jitter_units == 250.0
    assert long_uncapped.cap_enabled is False


def test_reset_experiment_stats_clears_accumulators_only() -> None:
    view = BeamDebugView(ViewContext(assets_dir=Path("artifacts") / "assets"))
    view.apply_scenario_preset(BeamScenarioPreset.CROWD_STRESS)
    view.cycle_render_mode()

    mode_before = view.render_mode
    preset_before = view.scenario_preset

    stats = BeamFrameStats(
        beam_draw_calls_total=10,
        beam_draw_calls_body=8,
        beam_draw_calls_head=1,
        beam_draw_calls_overlay=1,
        beam_draw_ms=1.0,
        frame_ms=2.0,
    )
    view._rolling_stats(BeamRenderMode.SHADER_GEMINI_2, BeamScenarioPreset.CROWD_STRESS).add(stats)
    assert view._rolling_by_mode_preset

    view.reset_experiment_stats()

    assert not view._rolling_by_mode_preset
    assert view.render_mode == mode_before
    assert view.scenario_preset == preset_before


def test_baseline_call_accounting_matches_segment_head_overlay_counts() -> None:
    plan = build_beam_sample_plan(dist=220.0, step=2.48, max_span=256.0)
    assert plan is not None

    item = BeamCountInput(plan=plan, life=0.4, screen_length_px=220.0)
    counts = estimate_beam_frame_counts([item], mode=BeamRenderMode.BASELINE_SPRITE, is_fire=True)

    expected_visible = 0
    for offset in iter_beam_sample_offsets(plan):
        t = (float(offset) - float(plan.start)) / float(plan.span)
        if t > 1e-3:
            expected_visible += 1

    assert counts.body_calls == expected_visible
    assert counts.head_calls == 1
    assert counts.overlay_calls == 1
    assert counts.total_calls == expected_visible + 2


def test_shader_gemini_2_mode_body_call_accounting_is_bounded() -> None:
    plan = build_beam_sample_plan(dist=1024.0, step=2.48, max_span=256.0)
    assert plan is not None

    item = BeamCountInput(plan=plan, life=0.4, screen_length_px=520.0)
    baseline = estimate_beam_frame_counts([item], mode=BeamRenderMode.BASELINE_SPRITE, is_fire=True)
    shader_gemini_2 = estimate_beam_frame_counts([item], mode=BeamRenderMode.SHADER_GEMINI_2, is_fire=True)
    assert shader_gemini_2.body_calls <= baseline.body_calls
    assert shader_gemini_2.body_calls <= 2


def test_estimate_counts_handles_degenerate_inputs() -> None:
    inputs = [
        BeamCountInput(plan=None, life=0.4, screen_length_px=100.0),
        BeamCountInput(plan=build_beam_sample_plan(dist=220.0, step=2.48, max_span=256.0), life=0.0, screen_length_px=100.0),
    ]
    counts = estimate_beam_frame_counts(inputs, mode=BeamRenderMode.BASELINE_SPRITE, is_fire=True)
    assert counts.total_calls == 0


def test_life_below_threshold_keeps_head_and_disables_overlay_across_modes() -> None:
    plan = build_beam_sample_plan(dist=240.0, step=2.48, max_span=256.0)
    assert plan is not None
    item = BeamCountInput(plan=plan, life=0.2, screen_length_px=260.0)

    for mode in (
        BeamRenderMode.BASELINE_SPRITE,
        BeamRenderMode.SHADER_GEMINI_2,
    ):
        counts = estimate_beam_frame_counts([item], mode=mode, is_fire=True)
        assert counts.head_calls == 1
        assert counts.overlay_calls == 0


def test_disable_head_rendering_removes_head_and_overlay_calls() -> None:
    plan = build_beam_sample_plan(dist=220.0, step=2.48, max_span=256.0)
    assert plan is not None
    item = BeamCountInput(plan=plan, life=0.4, screen_length_px=220.0)

    for mode in (
        BeamRenderMode.BASELINE_SPRITE,
        BeamRenderMode.SHADER_GEMINI_2,
    ):
        counts = estimate_beam_frame_counts(
            [item],
            mode=mode,
            is_fire=True,
            draw_heads_enabled=False,
        )
        assert counts.head_calls == 0
        assert counts.overlay_calls == 0


def test_shader_mode_uses_no_texture_overlay_calls() -> None:
    plan = build_beam_sample_plan(dist=220.0, step=2.48, max_span=256.0)
    assert plan is not None
    item = BeamCountInput(plan=plan, life=0.4, screen_length_px=220.0)

    counts = estimate_beam_frame_counts(
        [item],
        mode=BeamRenderMode.SHADER_GEMINI_2,
        is_fire=True,
    )
    assert counts.body_calls == 1
    assert counts.head_calls == 1
    assert counts.overlay_calls == 0


def test_benchmark_mode_cycles_and_completes() -> None:
    view = BeamDebugView(ViewContext(assets_dir=Path("artifacts") / "assets"))
    view._side_by_side_enabled = True
    view._bench_frames_per_mode = 2
    view.start_benchmark()
    assert view._bench_active is True
    assert view._side_by_side_enabled is False
    assert view.render_mode == BeamRenderMode.BASELINE_SPRITE
    assert view._bench_total_frames == 4

    view._advance_benchmark_after_frame()
    assert view.render_mode == BeamRenderMode.BASELINE_SPRITE

    view._advance_benchmark_after_frame()
    assert view.render_mode == BeamRenderMode.SHADER_GEMINI_2

    view._advance_benchmark_after_frame()
    view._advance_benchmark_after_frame()
    assert view._bench_active is False
    assert view._bench_completed is True
    assert view.render_mode == BeamRenderMode.BASELINE_SPRITE


def test_batch_probe_defaults_and_flush_label_formatting() -> None:
    view = BeamDebugView(ViewContext(assets_dir=Path("artifacts") / "assets"))
    assert view._batch_probe_quads == 4096
    assert view._batch_probe_auto is False
    assert view._batch_probe_run_once is False
    assert view._format_flush_quad(None) == "none"
    assert view._format_flush_quad(128) == "128"


def test_beam_distance_uses_fixed_life_window_and_projectile_speed() -> None:
    view = BeamDebugView(ViewContext(assets_dir=Path("artifacts") / "assets"))
    view._phase = 0.0
    view._distance_jitter_units = 0.0
    view._base_distance_units = 220.0

    view._use_fire_profile = True
    view._sync_effect_scale()
    fire_speed = view._projectile_speed_units_per_second_for_type(int(ProjectileTypeId.FIRE_BULLETS))
    fire_dist_low_life = view._beam_dist_units(0)

    view._use_fire_profile = False
    view._sync_effect_scale()
    ion_speed = view._projectile_speed_units_per_second_for_type(int(ProjectileTypeId.ION_RIFLE))
    ion_dist_low_life = view._beam_dist_units(0)

    assert fire_speed == 1200.0
    assert ion_speed == 300.0
    assert abs(float(fire_dist_low_life) - 480.0) <= 1e-6
    assert abs(float(ion_dist_low_life) - 120.0) <= 1e-6
    assert float(fire_dist_low_life) > float(ion_dist_low_life)


def test_shader_profile_value_is_monotonic_outward() -> None:
    params = BeamShaderGemini2Params(approx_a=1.06, approx_b=-4.8, approx_c=0.01, intensity_gain=2.5)
    values = [_shader_profile_value(float(i) / 96.0, params) for i in range(97)]
    assert values[0] > values[-1]
    for prev, curr in zip(values, values[1:], strict=False):
        assert float(curr) <= float(prev) + 1e-8


def test_shader_profile_autofit_reduces_reference_error() -> None:
    distances = tuple(float(i) / 95.0 for i in range(96))
    target = BeamShaderGemini2Params(approx_a=1.5, approx_b=-6.0, approx_c=0.05, intensity_gain=2.5)
    reference = tuple(_shader_profile_value(d, target) for d in distances)
    base = BeamShaderGemini2Params()

    baseline_metrics = _profile_match_metrics(
        reference_distances=distances,
        reference_profile=reference,
        params=base,
    )
    fitted, fitted_metrics = _fit_shader_profile_to_reference(
        reference_distances=distances,
        reference_profile=reference,
        base_params=base,
    )

    assert fitted_metrics.score <= baseline_metrics.score
    assert abs(float(fitted.approx_a) - float(target.approx_a)) <= 0.15
    assert abs(float(fitted.approx_b) - float(target.approx_b)) <= 0.5
