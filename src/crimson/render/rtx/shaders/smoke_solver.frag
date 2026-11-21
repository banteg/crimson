#version 330
// The fluid smoke solver's passes over a shared world-space field (render/rtx/gpu_smoke.py), by u_mode.
uniform sampler2D texture0;
uniform sampler2D u_aux;
uniform vec2 u_resolution;
uniform vec2 u_world_size;
uniform int u_mode;
uniform float u_dt;
uniform float u_decay;
uniform float u_fade;
// Moving bodies (mode 6): each one's path this tick in the field's world units, then its radius and velocity.
uniform int u_body_count;
uniform vec4 u_body_path[64];
uniform vec4 u_body_motion[64];
// How fast the air under a body takes on its velocity, per second.
const float BODY_DRAG = 12.0;
out vec4 finalColor;
vec2 uv;
vec2 cell;
vec4 sampleState(vec2 p) {
    if (any(lessThan(p,vec2(0))) || any(greaterThan(p,vec2(1)))) return vec4(0);
    return textureLod(texture0,vec2(p.x,1.0-p.y),0.0);
}
float pressure(vec2 p) {
    if (any(lessThan(p,vec2(0))) || any(greaterThan(p,vec2(1)))) return 0.0;
    return textureLod(u_aux,vec2(p.x,1.0-p.y),0.0).r;
}
// Shared-face donor fluxes conserve column mass. Each donor scales all its
// outflows equally so even a high-speed impulse cannot remove more than it owns.
vec2 limitedDensityFromFaces(vec2 rg, float right, float left, float down, float up, vec2 spacing) {
    float outflow=(max(right,0.0)+max(-left,0.0))/spacing.x
                 +(max(down,0.0)+max(-up,0.0))/spacing.y;
    return rg/min(max(u_dt*outflow,1.0),1e10);
}
void main() {
    uv=vec2(gl_FragCoord.x/u_resolution.x,1.0-gl_FragCoord.y/u_resolution.y);
    cell=1.0/u_resolution;
    vec2 dx=vec2(cell.x,0.0), dy=vec2(0.0,cell.y);
    vec2 spacing=u_world_size/u_resolution;
    vec4 q=sampleState(uv);
    if(u_mode==0) {
        vec2 v=sampleState(uv-u_dt*q.ba/u_world_size).ba;
        // Pre-fetch the 12 unique velocity neighbors shared by the five curl taps (was 20 fetches).
        vec2 vR=sampleState(uv+dx).ba, vL=sampleState(uv-dx).ba;
        vec2 vD=sampleState(uv+dy).ba, vU=sampleState(uv-dy).ba;
        vec2 vRD=sampleState(uv+dx+dy).ba, vRU=sampleState(uv+dx-dy).ba;
        vec2 vLD=sampleState(uv-dx+dy).ba, vLU=sampleState(uv-dx-dy).ba;
        float vRR_y=sampleState(uv+dx*2.0).a, vLL_y=sampleState(uv-dx*2.0).a;
        float vDD_x=sampleState(uv+dy*2.0).b, vUU_x=sampleState(uv-dy*2.0).b;
        float inv2x=1.0/(2.0*u_world_size.x*cell.x);
        float inv2y=1.0/(2.0*u_world_size.y*cell.y);
        float curl=(vR.y-vL.y)*inv2x-(vD.x-vU.x)*inv2y;
        float curlR=(vRR_y-q.a)*inv2x-(vRD.x-vRU.x)*inv2y;
        float curlL=(q.a-vLL_y)*inv2x-(vLD.x-vLU.x)*inv2y;
        float curlD=(vRD.y-vLD.y)*inv2x-(vDD_x-q.b)*inv2y;
        float curlU=(vRU.y-vLU.y)*inv2x-(q.b-vUU_x)*inv2y;
        vec2 g=vec2(abs(curlR)-abs(curlL), abs(curlD)-abs(curlU));
        g/=max(length(g),.0001);
        v+=u_dt*3.0*spacing.x*vec2(g.y,-g.x)*curl;
        v+=u_dt*.025*(vec2(2.0,-.6)-v);
        finalColor=vec4(q.rg,clamp(v,vec2(-350),vec2(350)));
    } else if(u_mode==1) {
        vec2 v=q.ba/spacing;
        float d=v.x-sampleState(uv-dx).b/spacing.x+v.y-sampleState(uv-dy).a/spacing.y;
        finalColor=vec4(d,0,0,0);
    } else if(u_mode==2) {
        float p=(sampleState(uv+dx).r+sampleState(uv-dx).r
                +sampleState(uv+dy).r+sampleState(uv-dy).r-pressure(uv))*.25;
        finalColor=vec4(p,0,0,0);
    } else if(u_mode==3) {
        vec2 grad=vec2(pressure(uv+dx)-pressure(uv),pressure(uv+dy)-pressure(uv));
        vec2 t=vec2(tanh(sampleState(uv+dx).g*.25)-tanh(sampleState(uv-dx).g*.25),
                    tanh(sampleState(uv+dy).g*.25)-tanh(sampleState(uv-dy).g*.25));
        finalColor=vec4(q.rg,(q.ba-grad*spacing-u_dt*72.0*t)*exp(-u_dt*.12));

    } else if(u_mode==5) {
        finalColor=vec4(q.rg*u_fade,q.ba);
    } else if(u_mode==6) {
        // Bodies drag the air under them toward their own velocity: toward the weighted mean of the bodies near it, so
        // the drag never pushes it faster than they move, however long a crowd walks through it.
        vec2 world=uv*u_world_size;
        float weight=0.0;
        vec2 target=vec2(0);
        for(int i=0;i<64;i++) {
            if(i>=u_body_count) break;
            vec4 path=u_body_path[i], motion=u_body_motion[i];
            vec2 span=path.zw-path.xy;
            vec2 offset=world-path.xy-span*clamp(dot(world-path.xy,span)/max(dot(span,span),.0001),0.0,1.0);
            float w=exp(-dot(offset,offset)/(2.0*motion.x*motion.x));
            weight+=w;
            target+=w*motion.yz;
        }
        float k=weight>.0001 ? (1.0-exp(-u_dt*BODY_DRAG))*min(weight,1.0) : 0.0;
        finalColor=vec4(q.rg,mix(q.ba,target/max(weight,.0001),k));
    } else {
        // Reuse the 4 axial neighbors and the center cell's limiter across all four faces, fetching a neighbor's
        // three outer faces only when it is the upwind donor (cuts 24 fetches/cell down to ~10).
        vec4 qR=sampleState(uv+dx), qL=sampleState(uv-dx);
        vec4 qD=sampleState(uv+dy), qU=sampleState(uv-dy);
        float vR=.5*(q.b+qR.b), vL=.5*(qL.b+q.b);
        float vD=.5*(q.a+qD.a), vU=.5*(qU.a+q.a);
        vec2 center_lim=limitedDensityFromFaces(q.rg,vR,vL,vD,vU,spacing);
        vec2 fR=vR*(vR>=0.0 ? center_lim : limitedDensityFromFaces(
            qR.rg, .5*(qR.b+sampleState(uv+dx*2.0).b), vR,
            .5*(qR.a+sampleState(uv+dx+dy).a), .5*(qR.a+sampleState(uv+dx-dy).a), spacing));
        vec2 fL=vL*(vL<0.0 ? center_lim : limitedDensityFromFaces(
            qL.rg, vL, .5*(qL.b+sampleState(uv-dx*2.0).b),
            .5*(qL.a+sampleState(uv-dx+dy).a), .5*(qL.a+sampleState(uv-dx-dy).a), spacing));
        vec2 fD=vD*(vD>=0.0 ? center_lim : limitedDensityFromFaces(
            qD.rg, .5*(qD.b+sampleState(uv+dx+dy).b), .5*(qD.b+sampleState(uv-dx+dy).b),
            .5*(qD.a+sampleState(uv+dy*2.0).a), vD, spacing));
        vec2 fU=vU*(vU<0.0 ? center_lim : limitedDensityFromFaces(
            qU.rg, .5*(qU.b+sampleState(uv+dx-dy).b), .5*(qU.b+sampleState(uv-dx-dy).b),
            vU, .5*(qU.a+sampleState(uv-dy*2.0).a), spacing));
        vec2 rg=q.rg-u_dt*((fR-fL)/spacing.x+(fD-fU)/spacing.y);
        float edge=min(min(uv.x,uv.y),min(1.0-uv.x,1.0-uv.y));
        float sponge=exp(-u_dt*3.0*pow(clamp(1.0-edge/.045,0.0,1.0),2.0));
        finalColor=vec4(max(vec2(0),rg)*exp(-u_dt*vec2(u_decay,.70))*sponge,q.ba);
    }
}
