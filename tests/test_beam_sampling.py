from __future__ import annotations

import pytest

from crimson.render.projectile_draw.beam_sampling import build_beam_sample_plan, iter_beam_sample_offsets


def test_build_beam_sample_plan_rejects_degenerate_inputs() -> None:
    assert build_beam_sample_plan(dist=0.0, step=1.0) is None
    assert build_beam_sample_plan(dist=100.0, step=0.0) is None


def test_build_beam_sample_plan_without_cap_uses_full_range() -> None:
    plan = build_beam_sample_plan(dist=10.0, step=2.0, max_span=256.0)
    assert plan is not None
    assert plan.start == pytest.approx(0.0)
    assert plan.stop == pytest.approx(10.0)
    assert plan.span == pytest.approx(10.0)
    assert plan.step == pytest.approx(2.0)
    assert plan.count == 5
    assert list(iter_beam_sample_offsets(plan)) == pytest.approx([0.0, 2.0, 4.0, 6.0, 8.0])


def test_build_beam_sample_plan_with_cap_uses_tail_window() -> None:
    plan = build_beam_sample_plan(dist=1024.0, step=2.48, max_span=256.0)
    assert plan is not None
    assert plan.start == pytest.approx(768.0)
    assert plan.stop == pytest.approx(1024.0)
    assert plan.span == pytest.approx(256.0)
    assert plan.step == pytest.approx(2.48)

    offsets = list(iter_beam_sample_offsets(plan))
    assert len(offsets) == plan.count
    assert offsets[0] == pytest.approx(768.0)
    assert offsets[-1] < 1024.0
    assert offsets[-1] + 2.48 >= 1024.0
