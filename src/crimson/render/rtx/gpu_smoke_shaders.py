"""GL 3.3 fragment passes for a shared world-space smoke field."""
GPU_SMOKE_FRAGMENT = """#version 330
uniform sampler2D texture0;
uniform sampler2D u_aux;
uniform vec2 u_resolution;
uniform vec2 u_world_size;
uniform int u_mode;
uniform float u_dt;
uniform float u_decay;
uniform float u_fade;
out vec4 finalColor;
vec2 uv;
vec2 cell;
vec4 sampleState(vec2 p) {
    if (any(lessThan(p,vec2(0))) || any(greaterThan(p,vec2(1)))) return vec4(0);
    return texture(texture0,vec2(p.x,1.0-p.y));
}
float pressure(vec2 p) {
    if (any(lessThan(p,vec2(0))) || any(greaterThan(p,vec2(1)))) return 0.0;
    return texture(u_aux,vec2(p.x,1.0-p.y)).r;
}
float curlAt(vec2 p) {
    return (sampleState(p+vec2(cell.x,0)).a-sampleState(p-vec2(cell.x,0)).a)/(2.0*u_world_size.x*cell.x)
         - (sampleState(p+vec2(0,cell.y)).b-sampleState(p-vec2(0,cell.y)).b)/(2.0*u_world_size.y*cell.y);
}
// Shared-face donor fluxes conserve column mass. Each donor scales all its
// outflows equally so even a high-speed impulse cannot remove more than it owns.
vec2 limitedDensity(vec2 p, vec4 q, vec2 spacing) {
    float right=.5*(q.b+sampleState(p+vec2(cell.x,0)).b);
    float left=.5*(q.b+sampleState(p-vec2(cell.x,0)).b);
    float down=.5*(q.a+sampleState(p+vec2(0,cell.y)).a);
    float up=.5*(q.a+sampleState(p-vec2(0,cell.y)).a);
    float outflow=(max(right,0.0)+max(-left,0.0))/spacing.x
                 +(max(down,0.0)+max(-up,0.0))/spacing.y;
    return q.rg/min(max(u_dt*outflow,1.0),1e10);
}
vec2 faceFlux(vec2 p, vec2 axis, vec2 spacing) {
    vec4 a=sampleState(p);
    vec4 b=sampleState(p+axis*cell);
    float velocity=.5*dot(a.ba+b.ba,axis);
    return velocity*(velocity>=0.0 ? limitedDensity(p,a,spacing)
                                   : limitedDensity(p+axis*cell,b,spacing));
}
void main() {
    uv=vec2(gl_FragCoord.x/u_resolution.x,1.0-gl_FragCoord.y/u_resolution.y);
    cell=1.0/u_resolution;
    vec2 spacing=u_world_size/u_resolution;
    vec4 q=sampleState(uv);
    if(u_mode==0) {
        vec2 v=sampleState(uv-u_dt*q.ba/u_world_size).ba;
        float curl=curlAt(uv);
        vec2 g=vec2(abs(curlAt(uv+vec2(cell.x,0)))-abs(curlAt(uv-vec2(cell.x,0))),
                    abs(curlAt(uv+vec2(0,cell.y)))-abs(curlAt(uv-vec2(0,cell.y))));
        g/=max(length(g),.0001);
        v+=u_dt*3.0*spacing.x*vec2(g.y,-g.x)*curl;
        v+=u_dt*.025*(vec2(2.0,-.6)-v);
        finalColor=vec4(q.rg,clamp(v,vec2(-350),vec2(350)));
    } else if(u_mode==1) {
        vec2 v=q.ba/spacing;
        float d=v.x-sampleState(uv-vec2(cell.x,0)).b/spacing.x+v.y-sampleState(uv-vec2(0,cell.y)).a/spacing.y;
        finalColor=vec4(d,0,0,0);
    } else if(u_mode==2) {
        float p=(sampleState(uv+vec2(cell.x,0)).r+sampleState(uv-vec2(cell.x,0)).r
                +sampleState(uv+vec2(0,cell.y)).r+sampleState(uv-vec2(0,cell.y)).r-pressure(uv))*.25;
        finalColor=vec4(p,0,0,0);
    } else if(u_mode==3) {
        vec2 grad=vec2(pressure(uv+vec2(cell.x,0))-pressure(uv),pressure(uv+vec2(0,cell.y))-pressure(uv));
        vec2 t=vec2(tanh(sampleState(uv+vec2(cell.x,0)).g*.25)-tanh(sampleState(uv-vec2(cell.x,0)).g*.25),
                    tanh(sampleState(uv+vec2(0,cell.y)).g*.25)-tanh(sampleState(uv-vec2(0,cell.y)).g*.25));
        finalColor=vec4(q.rg,(q.ba-grad*spacing-u_dt*72.0*t)*exp(-u_dt*.12));

    } else if(u_mode==5) {
        finalColor=vec4(q.rg*u_fade,q.ba);
    } else {
        vec2 rg=q.rg-u_dt*(
            (faceFlux(uv,vec2(1,0),spacing)-faceFlux(uv-vec2(cell.x,0),vec2(1,0),spacing))/spacing.x
           +(faceFlux(uv,vec2(0,1),spacing)-faceFlux(uv-vec2(0,cell.y),vec2(0,1),spacing))/spacing.y);
        float edge=min(min(uv.x,uv.y),min(1.0-uv.x,1.0-uv.y));
        float sponge=exp(-u_dt*3.0*pow(clamp(1.0-edge/.045,0.0,1.0),2.0));
        finalColor=vec4(max(vec2(0),rg)*exp(-u_dt*vec2(u_decay,.70))*sponge,q.ba);
    }
}
"""
GPU_SMOKE_SPLAT_FRAGMENT = """#version 330
uniform vec2 u_resolution;
uniform vec2 u_world_size;
uniform vec4 u_source;
uniform vec4 u_motion;
uniform float u_rotation;
uniform vec4 u_flow;
out vec4 finalColor;
void main() {
    vec2 uv=vec2(gl_FragCoord.x/u_resolution.x,1.0-gl_FragCoord.y/u_resolution.y);
    vec2 d=(uv-u_source.xy)*u_world_size;
    float sigma=max(4.0,u_source.z*.5);
    vec2 shape=d;
    if(u_flow.z>.5) {
        vec2 direction=u_flow.xy;
        shape=vec2(dot(d,direction)/1.2,dot(d,vec2(-direction.y,direction.x))/.50);
    }
    float mass=exp(-dot(shape,shape)/(2.0*sigma*sigma));
    vec2 swirl=vec2(0);
    if(u_motion.w>.5) {
        mass*=.3;
        for(int i=0;i<7;i++) {
            float f=float(i);
            float angle=u_rotation+f*6.2831853/7.0+.18*sin(f*2.4);
            float radius=u_source.z*(.42+.10*sin(f*1.7+u_rotation));
            vec2 local=d-vec2(cos(angle),sin(angle))*radius;
            float lobe=exp(-dot(local,local)/(2.0*pow(sigma*.85,2.0)));
            mass+=lobe*.25;
            swirl+=lobe*vec2(-local.y,local.x)/sigma*10.0*sin(f*2.1+u_rotation);
        }
        vec2 w=uv*u_world_size;
        mass*=.75+.125*(sin(w.x*.135+w.y*.07)+sin(w.x*.055-w.y*.115));
    }
    vec2 flow=mass*(u_motion.xy*.44+d*(2.0*u_motion.z/max(u_source.z,.001)*.44))+swirl;
    finalColor=vec4(mass*u_source.w*vec2(1.7,2.0),flow);
}
"""

GPU_ATMOSPHERE_IMPULSE_FRAGMENT = """#version 330
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
"""
