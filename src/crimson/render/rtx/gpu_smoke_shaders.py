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
        vec2 p=uv-u_dt*q.ba/u_world_size;
        vec2 rg=sampleState(p).rg;
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
out vec4 finalColor;
void main() {
    vec2 uv=vec2(gl_FragCoord.x/u_resolution.x,1.0-gl_FragCoord.y/u_resolution.y);
    vec2 d=(uv-u_source.xy)*u_world_size;
    float sigma=max(4.0,u_source.z*.5);
    float mass=exp(-dot(d,d)/(2.0*sigma*sigma));
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
