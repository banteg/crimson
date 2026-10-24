#version 330
// Presentation-only airflow: muzzle jets, projectile wakes and blast fronts (render/rtx/gpu_smoke.py).
uniform vec2 u_resolution;
uniform vec2 u_world_size;
uniform vec4 u_segment;
uniform vec4 u_impulse; // radius, total velocity impulse, curl, kind
uniform vec4 u_phase; // age, delivery fraction, expansion speed, duration
out vec4 finalColor;
void main() {
    vec2 uv=vec2(gl_FragCoord.x/u_resolution.x,1.0-gl_FragCoord.y/u_resolution.y);
    vec2 world=uv*u_world_size;
    vec2 delta=u_segment.zw-u_segment.xy;
    float span=length(delta);
    vec2 axis=span>.001 ? delta/span : vec2(1,0);
    vec2 side=vec2(-axis.y,axis.x);
    float radius=max(u_impulse.x,4.0);
    vec2 flow=vec2(0);
    if(u_impulse.w>1.5) { // blast: deliver an expanding pressure front after projection
        vec2 d=world-u_segment.xy;
        float distance=length(d);
        float front=radius+max(0.0,u_phase.x)*u_phase.z;
        float width=max(6.0,radius*.35+u_phase.x*u_phase.z*.08);
        float shell=exp(-.5*pow((distance-front)/width,2.0));
        flow=d/max(distance,1.0)*shell*u_impulse.y*u_phase.y;
    } else {
        float along=clamp(dot(world-u_segment.xy,axis),0.0,span);
        vec2 near=u_segment.xy+axis*along;
        vec2 offset=world-near;
        float falloff=exp(-dot(offset,offset)/(2.0*radius*radius));
        float taper=u_impulse.w<.5 ? mix(1.0,.35,along/max(span,1.0)) : 1.0;
        flow=axis*u_impulse.y*falloff*taper;
        // A counter-rotating vortex pair entrains surrounding air. These curls
        // survive incompressible projection, unlike a purely divergent puff.
        vec2 center=mix(u_segment.xy,u_segment.zw,.65);
        for(int i=0;i<2;i++) {
            float sign=i==0 ? -1.0 : 1.0;
            vec2 q=world-center-side*(sign*radius*.9);
            float g=exp(-dot(q,q)/(2.0*radius*radius*2.25));
            flow+=sign*vec2(-q.y,q.x)/radius*g*u_impulse.z;
        }
    }
    finalColor=vec4(0,0,clamp(flow,vec2(-800),vec2(800)));
}
