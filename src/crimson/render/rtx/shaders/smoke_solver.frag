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
