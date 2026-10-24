#version 330
// A smoke emission's density, heat and motion deposited into the field (render/rtx/gpu_smoke.py).
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
