from __future__ import annotations

import numpy as np
import pytest

from crimson.render.rtx.gpu_smoke import GpuSmokeSimulation
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.render.test_smoke_simulation import emission


def pixels(sim: GpuSmokeSimulation):
    image = rl.load_image_from_texture(sim.texture)
    try:
        n = sim.resolution
        # Read IEEE half directly: raylib's image conversion does not preserve
        # NaN/Inf correctly, which would conceal a numerical failure here.
        return np.frombuffer(rl.ffi.buffer(image.data,n*n*8),dtype=np.float16).reshape(n,n,4)[::-1].astype(np.float32)
    finally:
        rl.unload_image(image)


def test_gpu_events_do_not_allocate_or_advance_gl_until_prepared():
    sim = GpuSmokeSimulation()
    sim.consume((emission(), emission(delay_seconds=.5)), 1/60)
    assert not sim.targets and sim.shader is None
    assert len(sim.pending) == 1 and len(sim.batches) == 1
    assert sim.executed_steps == 0
    sim.reset()
    assert not sim.pending and not sim.batches and not sim.fields
    with pytest.raises(ValueError):
        sim.consume((), float("nan"))


def test_native_gpu_smoke_transport_pause_and_reset(raylib_context):
    sim = GpuSmokeSimulation(resolution=128)
    try:
        sim.consume((emission(pos=Vec2(400,300),vel=Vec2(100,0),scale=50),),0.)
        sim.prepare()
        initial = pixels(sim)
        assert initial[:,:,0].max() > .1
        iy, ix = np.unravel_index(initial[:,:,0].argmax(), initial[:,:,0].shape)
        assert 50 < ix < 60 and 38 < iy < 48
        sim.prepare()
        np.testing.assert_array_equal(pixels(sim),initial)
        for _ in range(12):
            sim.consume((),1/60)
        sim.prepare()
        moved=pixels(sim)
        assert np.isfinite(moved).all() and np.max(np.abs(moved-initial)) > .01
        assert sim.executed_steps == 12
        sim.reset()
        sim.consume((emission(pos=Vec2(800,800)),),0.)
        sim.prepare()
        assert pixels(sim)[iy,ix,0] == 0.
    finally:
        sim.close()


def test_native_gpu_tick_grouping_is_invariant(raylib_context):
    a,b=GpuSmokeSimulation(resolution=64),GpuSmokeSimulation(resolution=64)
    try:
        for tick in range(8):
            batch=(emission(pos=Vec2(400+tick*3,300),vel=Vec2(20,4)),)
            a.consume(batch,1/60)
            a.prepare()
            b.consume(batch,1/60)
        b.prepare()
        np.testing.assert_array_equal(pixels(a),pixels(b))
    finally:
        a.close()
        b.close()


def test_native_gpu_pressure_reduces_divergence(raylib_context):
    sim=GpuSmokeSimulation(resolution=128)
    try:
        sim.consume((emission(pos=Vec2(500,500),scale=100,vel=Vec2(120,40)),),0.)
        sim.prepare()
        before=pixels(sim)
        sim._pass(2,sim.current,1)
        p=3
        for _ in range(12):
            nxt=7-p
            sim._pass(nxt,p,2,2)
            p=nxt
        # Zero dt isolates pressureprojection from thermal expansion.
        assert sim.shader is not None
        sim._set(sim.shader,sim.locations,"u_dt",(0.,))
        sim._pass(1-sim.current,sim.current,3,p)
        sim.current=1-sim.current
        after=pixels(sim)
        def divergence(q):
            return q[1:,1:,2]-q[1:,:-1,2]+q[1:,1:,3]-q[:-1,1:,3]
        assert np.linalg.norm(divergence(after)) < np.linalg.norm(divergence(before))*.85
    finally:
        sim.close()


def test_native_gpu_new_deposit_does_not_resurrect_fading_smoke(raylib_context):
    sim=GpuSmokeSimulation(resolution=64)
    try:
        sim.consume((emission(pos=Vec2(300,300),scale=100,vel=Vec2()),),0.)
        sim.prepare()
        sim.consume((),9.)
        sim.prepare()
        before=pixels(sim)
        assert sim.fields[0].fade == .5
        sim.consume((emission(pos=Vec2(900,900),scale=20),),0.)
        sim.prepare()
        after=pixels(sim)
        np.testing.assert_allclose(after[:32,:32,:2],before[:32,:32,:2]*.5,atol=.0001)
        assert sim.fields[0].fade == 1.
    finally:
        sim.close()


def test_native_gpu_rectangular_world_and_expansion_only_source(raylib_context):
    sim=GpuSmokeSimulation(resolution=96)
    try:
        sim.prepare(world_size=Vec2(1024,512))
        assert sim.targets and sim.executed_steps == 0 and not sim.fields
        sim.consume((emission(pos=Vec2(300,100),scale=0,expansion=180,vel=Vec2()),),0.)
        sim.prepare(world_size=Vec2(1024,512))
        first=pixels(sim)
        iy,ix=np.unravel_index(first[:,:,0].argmax(),first[:,:,0].shape)
        assert 29 <= ix <= 34 and 26 <= iy <= 30
        assert first[:,:,0].max() > .01
        for _ in range(10):
            sim.consume((),1/60)
        sim.prepare(world_size=Vec2(1024,512))
        assert np.isfinite(pixels(sim)).all()
    finally:
        sim.close()
