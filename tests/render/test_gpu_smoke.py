from __future__ import annotations

import numpy as np
import pytest

from crimson.render.rtx.gpu_smoke import MAX_BODY_IMPULSES_PER_TICK, MAX_IMPULSES_PER_TICK, GpuSmokeSimulation
from crimson.sim.smoke_events import AtmosphereImpulse
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


def test_body_wakes_keep_their_own_budget_beside_shots():
    sim = GpuSmokeSimulation()
    wake = AtmosphereImpulse(Vec2(), Vec2(10, 0), 5., 3.)
    impulses = tuple(wake for _ in range(100)) + tuple(
        AtmosphereImpulse(Vec2(), Vec2(1, 0), 17.5, float(i), kind="body") for i in range(100))
    sim.consume((emission(),), 1/60, impulses=impulses)
    kept = sim.batches[0][3]
    assert [i.kind for i in kept] == ["wake"] * MAX_IMPULSES_PER_TICK + ["body"] * MAX_BODY_IMPULSES_PER_TICK
    # The strongest bodies are kept.
    assert min(i.strength for i in kept if i.kind == "body") == 100 - MAX_BODY_IMPULSES_PER_TICK


def test_body_drag_carries_air_toward_the_body_but_never_past_it(raylib_context):
    sim = GpuSmokeSimulation(resolution=128)
    try:
        sim.consume((emission(pos=Vec2(300, 300), vel=Vec2()),), 0.)
        sim.prepare()
        # A body standing in one place but moving at 90 units a second.
        body = AtmosphereImpulse(Vec2(500, 500), Vec2(501.5, 500), 17.5, 90., kind="body")
        speeds = []
        for _ in range(240):
            sim._drag([body])
            speeds.append(np.hypot(*pixels(sim)[:, :, 2:].transpose(2, 0, 1)).max())
        assert speeds[0] > 5 and speeds == sorted(speeds)
        assert 85 < speeds[-1] <= 90 * 1.01
        # Tick after tick through the solver, the flow it turns into around the body stays bounded.
        sim.reset()
        sim.consume((emission(pos=Vec2(300, 300), vel=Vec2()),), 0.)
        for _ in range(300):
            sim.consume((), 1/60, impulses=(body,))
        sim.prepare()
        assert np.hypot(*pixels(sim)[:, :, 2:].transpose(2, 0, 1)).max() <= 90 * 1.5
    finally:
        sim.close()


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
    from crimson.sim.smoke_events import AtmosphereImpulse
    a,b=GpuSmokeSimulation(resolution=64),GpuSmokeSimulation(resolution=64)
    try:
        for tick in range(8):
            batch=(emission(pos=Vec2(400+tick*3,300),vel=Vec2(20,4)),)
            impulses = (AtmosphereImpulse(Vec2(400,300),Vec2(430,300),20,80,curl=12,
                                          kind="blast" if tick == 0 else "wake"),)
            a.consume(batch,1/60,impulses=impulses)
            a.prepare()
            b.consume(batch,1/60,impulses=impulses)
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


def test_airflow_is_bounded_prioritized_and_never_creates_smoke():
    from crimson.render.rtx.gpu_smoke import MAX_IMPULSES_PER_TICK
    from crimson.sim.smoke_events import AtmosphereImpulse
    sim=GpuSmokeSimulation()
    wake=AtmosphereImpulse(Vec2(200,200),Vec2(220,200),8,10)
    blast=AtmosphereImpulse(Vec2(500,500),Vec2(500,500),40,200,kind="blast")
    muzzle=AtmosphereImpulse(Vec2(200,200),Vec2(240,200),10,50,kind="muzzle")
    sim.consume((),1/60,impulses=(wake,))
    assert not sim.fields and not sim.batches
    sim.consume((emission(),),0.)
    sim.consume((),1/60,impulses=(*((wake,)*200),muzzle,blast))
    impulses=sim.batches[-1][3]
    assert len(impulses)==MAX_IMPULSES_PER_TICK
    assert impulses[:2]==(blast,muzzle)
    sim.reset()
    assert not sim.waiting_impulses and not sim.blasts and not sim.batches


def test_native_velocity_only_wake_moves_existing_smoke_without_deposit(raylib_context):
    from crimson.sim.smoke_events import AtmosphereImpulse
    sim=GpuSmokeSimulation(resolution=128)
    try:
        sim.consume((emission(pos=Vec2(300,300),scale=80,vel=Vec2()),),0.)
        sim.prepare()
        before=pixels(sim)
        # Isolate the splat: it must write only velocity, even in clear air.
        impulse=AtmosphereImpulse(Vec2(600,500),Vec2(720,500),16,80,curl=20)
        sim._inject_impulses(((impulse,0.,1.),))
        after=pixels(sim)
        np.testing.assert_array_equal(before[:,:,:2],after[:,:,:2])
        assert np.linalg.norm(after[:,:,2:]-before[:,:,2:])>10.
        near=AtmosphereImpulse(Vec2(260,300),Vec2(340,300),24,100,curl=30,kind="muzzle")
        sim.consume((),1/60,impulses=(near,))
        for _ in range(20):
            sim.consume((),1/60)
        sim.prepare()
        moved=pixels(sim)
        assert np.isfinite(moved).all()
        _,xx=np.indices(moved[:,:,0].shape)
        before_x=(xx*before[:,:,0]).sum()/before[:,:,0].sum()
        after_x=(xx*moved[:,:,0]).sum()/moved[:,:,0].sum()
        assert after_x>before_x+.25
    finally:
        sim.close()


def test_native_blast_front_delivers_outward_motion_after_projection(raylib_context):
    from crimson.sim.smoke_events import AtmosphereImpulse
    control,blast=GpuSmokeSimulation(resolution=128),GpuSmokeSimulation(resolution=128)
    try:
        event=emission(pos=Vec2(500,500),scale=180,vel=Vec2())
        impulse=AtmosphereImpulse(Vec2(500,500),Vec2(500,500),40,240,kind="blast",duration=.4,expansion_speed=180)
        for sim in (control,blast):
            sim.consume((event,),0.)
            sim.prepare()
        for tick in range(12):
            control.consume((),1/60)
            blast.consume((),1/60,impulses=(impulse,) if tick==0 else ())
        control.prepare()
        blast.prepare()
        a,b=pixels(control),pixels(blast)
        yy,xx=np.indices(a[:,:,0].shape)
        dx,dy=(xx+.5)*10-628,(yy+.5)*10-628
        r=np.sqrt(dx*dx+dy*dy)
        shell=(r>35)&(r<85)
        radial=((b[:,:,2]-a[:,:,2])*dx+(b[:,:,3]-a[:,:,3])*dy)/np.maximum(r,1.)
        assert radial[shell].mean()>3.
        assert np.isfinite(b).all()
        assert blast.blasts and blast.blasts[0][1]>.19
        blast.consume((),.3)
        blast.prepare()
        assert not blast.blasts
    finally:
        control.close()
        blast.close()


def test_native_muzzle_density_follows_firing_direction(raylib_context):
    x,y=GpuSmokeSimulation(resolution=128),GpuSmokeSimulation(resolution=128)
    try:
        for sim,direction in ((x,Vec2(1,0)),(y,Vec2(0,1))):
            sim.consume((emission(pos=Vec2(500,500),scale=80,vel=Vec2(),
                                  profile="muzzle",flow_dir=direction),),0.)
            sim.prepare()
        def variances(sim):
            density=pixels(sim)[:,:,0]
            yy,xx=np.indices(density.shape)
            mass=density.sum()
            mx,my=(xx*density).sum()/mass,(yy*density).sum()/mass
            return (((xx-mx)**2*density).sum()/mass,((yy-my)**2*density).sum()/mass)
        xx,xy=variances(x)
        yx,yy=variances(y)
        assert xx>xy*3 and yy>yx*3
        np.testing.assert_allclose((xx,xy),(yy,yx),rtol=.02)
    finally:
        x.close()
        y.close()


def test_native_small_muzzle_puff_is_resolved_on_production_grid(raylib_context):
    sim=GpuSmokeSimulation()
    try:
        sim.consume((emission(pos=Vec2(500,500),scale=1,vel=Vec2(),
                              profile="muzzle",flow_dir=Vec2(1,0)),),0.)
        sim.prepare()
        density=pixels(sim)[:,:,0]
        mask=density>density.max()*.1
        yy,xx=np.nonzero(mask)
        # Both axes must cover several cells rather than a sub-cell slug.
        assert xx.max()-xx.min()+1>=6
        assert yy.max()-yy.min()+1>=4
        assert np.isfinite(density).all()
    finally:
        sim.close()


def test_native_expanding_blast_dilutes_smoke_instead_of_creating_mass(raylib_context):
    from crimson.sim.smoke_events import AtmosphereImpulse
    control,blast=GpuSmokeSimulation(resolution=128),GpuSmokeSimulation(resolution=128)
    try:
        cloud=emission(pos=Vec2(500,500),scale=180,vel=Vec2())
        impulse=AtmosphereImpulse(Vec2(500,500),Vec2(500,500),28,220,
                                  kind="blast",duration=.55,expansion_speed=300)
        for sim in (control,blast):
            sim.consume((cloud,),0.)
            sim.prepare()
        for tick in range(300):
            control.consume((),1/60)
            blast.consume((),1/60,impulses=(impulse,) if tick==0 else ())
        control.prepare()
        blast.prepare()
        a,b=pixels(control),pixels(blast)
        assert np.isfinite(b).all()
        # Approximate dilution, not a claim of exactly conservative advection.
        assert b[:,:,0].sum()<a[:,:,0].sum()*1.30
        assert np.linalg.norm(b[:,:,0]-a[:,:,0])>.1
    finally:
        control.close()
        blast.close()



def test_native_production_grid_blast_keeps_integrated_column_mass_bounded(raylib_context):
    import math

    from crimson.sim.smoke_events import AtmosphereImpulse, SmokeEmission
    from grim.color import RGBA
    control,blast=GpuSmokeSimulation(),GpuSmokeSimulation()
    try:
        cloud=tuple(SmokeEmission(slot=i,generation=1,
                    pos=Vec2(495+36*math.cos(i*2.4),440+i*16),vel=Vec2(),scale=34,
                    color=RGBA(1,1,1,.4),rotation=i*.4,retention_seconds=10) for i in range(10))
        impulse=AtmosphereImpulse(Vec2(420,512),Vec2(420,512),28,220,
                                  kind="blast",duration=.55,expansion_speed=300)
        for sim in (control,blast):
            sim.consume(cloud,0.)
            sim.prepare()
        for tick in range(300):
            control.consume((),1/60)
            blast.consume((),1/60,impulses=(impulse,) if tick==60 else ())
        control.prepare()
        blast.prepare()
        a,b=pixels(control),pixels(blast)
        assert np.isfinite(b).all() and b[:,:,:2].min()>=0
        np.testing.assert_allclose(b[:,:,:2].sum(axis=(0,1)),a[:,:,:2].sum(axis=(0,1)),rtol=.04)
        assert np.linalg.norm(b[:,:,0]-a[:,:,0])>1
    finally:
        control.close()
        blast.close()


def test_native_scalar_outflow_limiter_handles_more_than_one_cell_per_step(raylib_context):
    from crimson.sim.smoke_events import AtmosphereImpulse
    sim=GpuSmokeSimulation()
    try:
        sim.consume((emission(pos=Vec2(500,500),scale=80,vel=Vec2()),),0.)
        sim.prepare()
        sim._inject_impulses(((AtmosphereImpulse(Vec2(300,500),Vec2(700,500),
                               80,800,curl=400,kind="wake"),0.,1.),))
        before=pixels(sim)
        assert np.abs(before[:,:,2:]).max()/60>4
        assert sim.shader is not None
        sim._set(sim.shader,sim.locations,"u_decay",(0.,))
        sim._pass(1-sim.current,sim.current,4)
        sim.current=1-sim.current
        after=pixels(sim)
        assert np.isfinite(after).all() and after[:,:,:2].min()>=0
        expected=before[:,:,:2].sum(axis=(0,1))*np.exp(-np.array([0.,.70])/60)
        np.testing.assert_allclose(after[:,:,:2].sum(axis=(0,1)),expected,rtol=.003)
    finally:
        sim.close()
