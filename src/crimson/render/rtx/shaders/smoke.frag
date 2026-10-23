#version 330
// Single-scattering display of the simulated planar density and temperature field (render/rtx/smoke.py).
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;
uniform sampler2D texture0;
uniform int u_state_flip;
uniform vec2 u_origin;
uniform vec2 u_size;
uniform float u_opacity;
uniform int u_light_count;
uniform vec4 u_light_pos[16];
uniform vec4 u_light_rgb[16];
uniform vec4 u_light_shape[16];
uniform int u_sight_count;
uniform vec4 u_sights[4];
uniform int u_debug; // RtxDebugView: smoke maps draw opaque over the cleared map background

// Density (edge-faded), temperature and planar world velocity; zero outside the field.
vec4 state_at(vec2 xy) {
    vec2 uv=(xy-u_origin)/u_size;
    if(any(lessThan(uv,vec2(0)))||any(greaterThan(uv,vec2(1)))) return vec4(0);
    // CPU uploads are top-first; framebuffer textures are bottom-first.
    vec2 sample_uv=vec2(uv.x,u_state_flip!=0 ? 1.-uv.y : uv.y);
    vec4 state=textureLod(texture0,sample_uv,0.);
    vec2 edge=smoothstep(vec2(0),vec2(12),uv*u_size)*(1.-smoothstep(u_size-12.,u_size,uv*u_size));
    return vec4(state.x*edge.x*edge.y,state.yzw);
}
// A planar texel describes an entire vertical Gaussian column. Cache columns
// before integrating height; their texture lookup and edge fade do not depend on z.
vec3 column(vec2 xy) {
    vec4 state=state_at(xy);
    return vec3(state.x,16.+min(state.y,2.)*8.,11.+min(state.y,2.)*3.);
}
vec3 debug_radiance(vec3 value) {
    vec3 positive=max(value,vec3(0));
    return pow(positive/(vec3(1)+positive),vec3(1./2.2));
}
vec3 heat(float temperature) {
    float t=clamp(temperature/2.,0.,1.)*3.;
    return clamp(vec3(t,t-1.,t-2.),0.,1.);
}
vec3 flow(vec2 velocity) {
    float hue=atan(velocity.y,velocity.x)/6.2831853+.5;
    vec3 rgb=clamp(abs(mod(hue*6.+vec3(0,4,2),6.)-3.)-1.,0.,1.);
    return rgb*(1.-exp(-length(velocity)/60.));
}
float vertical(vec3 col,float z) {
    return col.x*exp(-.5*pow((z-col.y)/col.z,2.))*smoothstep(0.,6.,z)*(1.-smoothstep(52.,72.,z));
}
float density(vec3 p) { return vertical(column(p.xy),p.z); }
vec3 sight_scattering(vec2 xy,vec4 sight) {
    vec2 a=sight.xy, b=sight.zw, ab=b-a;
    float along=dot(xy-a,ab)/max(dot(ab,ab),.001);
    if(along<0. || along>1.) return vec3(0);
    vec2 q=a+ab*along;
    float radius=length(xy-q);
    float core=exp(-radius*radius/(2.*1.7*1.7));
    float halo=exp(-radius*radius/(2.*4.2*4.2))*.14;
    if(core+halo<.0001) return vec3(0);
    float optical_depth=0.;
    for(int j=0;j<6;j++) optical_depth+=density(vec3(mix(a,q,(float(j)+.5)/6.),28.));
    float transmission=exp(-optical_depth*length(q-a)/6.*.012);
    return vec3(1.,.018,.008)*(core+halo)*transmission*18.*(1.-.65*along);
}

void main() {
    vec2 xy=u_origin+fragTexCoord*u_size;
    vec4 state=state_at(xy);
    // Raw fields cover the whole domain: air moves and stays warm where smoke has thinned out.
    if(u_debug==16) { finalColor=vec4(heat(state.y),1.); return; }
    if(u_debug==17) { finalColor=vec4(flow(state.zw),1.); return; }
    vec3 local=column(xy);
    if(local.x<=.00001) { finalColor=u_debug!=0 ? vec4(0,0,0,1) : vec4(0); return; }
    vec3 sky1=column(xy-vec2(12,9)),sky2=column(xy-vec2(24,18));
    vec3 sights=vec3(0);
    for(int j=0;j<4;j++) { if(j>=u_sight_count) break; sights+=sight_scattering(xy,u_sights[j]); }
    // Extinction depends only on smoke, not on the light. Integrate it once,
    // then sum each light against those same front-to-back weights.
    float weights[14];
    float transmission=1.;
    vec3 scattered=vec3(0);
    for(int i=0;i<14;i++) {
        float z=70.-float(i)*5.;
        float opacity=1.-exp(-vertical(local,z)*.024*5.);
        weights[i]=0.;
        if(opacity<=.00001) continue;
        weights[i]=transmission*opacity;
        float sky_depth=vertical(sky1,z+16.)+vertical(sky2,z+32.);
        vec3 color=u_debug==18 ? vec3(0) : vec3(.29,.32,.35)+vec3(.22,.23,.24)*exp(-sky_depth*.55);
        color+=sights*exp(-pow((z-28.)/5.,2.));
        scattered+=weights[i]*color;
        transmission*=1.-opacity;
    }
    for(int light=0;light<16;light++) {
        if(light>=u_light_count) break;
        vec4 source=u_light_pos[light],shape=u_light_shape[light],radiance=u_light_rgb[light];
        vec2 nearest=source.xy+shape.xy*clamp(dot(xy-source.xy,shape.xy),-shape.z,shape.z);
        if(shape.w>0.) {
            vec2 radial=xy-source.xy;
            nearest=source.xy+radial/max(length(radial),.0001)*shape.w;
        }
        vec2 lateral=nearest-xy;
        float dist2=dot(lateral,lateral);
        if(dist2>=source.w*source.w) continue;
        // The six shadow rays share their XY samples at every viewing height.
        // Keep full height-dependent attenuation, phase and optical depth.
        vec3 columns[6];
        for(int j=0;j<6;j++) columns[j]=column(xy+lateral*((float(j)+.5)/6.));
        for(int i=0;i<14;i++) {
            if(weights[i]<=0.) continue;
            float z=70.-float(i)*5.;
            float dz=source.z-z;
            float distance=sqrt(dist2+dz*dz);
            float attenuation=pow(max(0.,1.-distance/max(source.w,.001)),2.);
            if(attenuation<=0.) continue;
            float optical_depth=0.;
            for(int j=0;j<6;j++) optical_depth+=vertical(columns[j],z+dz*((float(j)+.5)/6.));
            float shadow=exp(-optical_depth*distance/6.*.020);
            float phase=.7-.35*dz/max(distance,.001);
            scattered+=weights[i]*radiance.rgb*attenuation*shadow*phase*radiance.w;
        }
    }
    float opacity=1.-transmission;
    // Maps show what the composite adds: premultiplied radiance and coverage at the field's fade.
    if(u_debug==15) { finalColor=vec4(vec3(opacity*u_opacity),1.); return; }
    if(u_debug==18) { finalColor=vec4(debug_radiance(scattered*u_opacity),1.); return; }
    finalColor=vec4(scattered/max(opacity,.0001),opacity*u_opacity);
}
