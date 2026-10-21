"""Single-scattering display of a simulated planar density/temperature field."""

from .hdr import _HDR_TONEMAP_VS_330

SMOKE_VERTEX = _HDR_TONEMAP_VS_330
SMOKE_FRAGMENT = """#version 330
in vec2 fragTexCoord;
in vec4 fragColor;
out vec4 finalColor;
uniform sampler2D texture0;
uniform vec2 u_origin;
uniform float u_opacity;
uniform int u_light_count;
uniform vec4 u_light_pos[16];
uniform vec4 u_light_rgb[16];
uniform vec4 u_light_shape[16];
uniform int u_sight_count;
uniform vec4 u_sights[4];

float density(vec3 p) {
    vec2 uv = (p.xy-u_origin)/288.;
    if (any(lessThan(uv,vec2(0))) || any(greaterThan(uv,vec2(1)))) return 0.;
    vec2 state = texture(texture0,uv).rg;
    float center = 16.+min(state.y,2.)*8.;
    float thickness = 11.+min(state.y,2.)*3.;
    vec2 edge = smoothstep(vec2(0),vec2(.06),uv)*(1.-smoothstep(vec2(.94),vec2(1),uv));
    return state.x*edge.x*edge.y*exp(-.5*pow((p.z-center)/thickness,2.))
        *smoothstep(0.,6.,p.z)*(1.-smoothstep(52.,72.,p.z));
}

vec3 light_scattering(vec3 p,int index) {
    vec4 source=u_light_pos[index], shape=u_light_shape[index], radiance=u_light_rgb[index];
    vec2 nearest=source.xy+shape.xy*clamp(dot(p.xy-source.xy,shape.xy),-shape.z,shape.z);
    if (shape.w>0.) {
        vec2 radial=p.xy-source.xy;
        nearest=source.xy+radial/max(length(radial),.0001)*shape.w;
    }
    vec3 delta=vec3(nearest,source.z)-p;
    float distance=length(delta);
    float attenuation=pow(max(0.,1.-distance/max(source.w,.001)),2.);
    if (attenuation<=0.) return vec3(0);
    float optical_depth=0.;
    for(int j=0;j<6;j++) optical_depth+=density(p+delta*((float(j)+.5)/6.));
    float phase=.7+.35*delta.z/max(distance,.001);
    return radiance.rgb*attenuation*exp(-optical_depth*distance/6.*.020)*phase*radiance.w;
}

vec3 sight_scattering(vec3 p,vec4 sight) {
    vec2 a=sight.xy, b=sight.zw, ab=b-a;
    float along=dot(p.xy-a,ab)/max(dot(ab,ab),.001);
    if(along<0. || along>1.) return vec3(0);
    vec2 q=a+ab*along;
    float radius=length(p.xy-q);
    float core=exp(-radius*radius/(2.*1.7*1.7));
    float halo=exp(-radius*radius/(2.*4.2*4.2))*.14;
    if(core+halo<.0001) return vec3(0);
    float height=exp(-pow((p.z-28.)/5.,2.));
    float optical_depth=0.;
    for(int j=0;j<6;j++) optical_depth+=density(vec3(mix(a,q,(float(j)+.5)/6.),28.));
    float transmission=exp(-optical_depth*length(q-a)/6.*.012);
    return vec3(1.,.018,.008)*(core+halo)*height*transmission*18.*(1.-.65*along);
}

void main() {
    vec2 xy=u_origin+fragTexCoord*288.;
    float transmission=1.;
    vec3 scattered=vec3(0);
    for(int i=0;i<14;i++) {
        vec3 p=vec3(xy,70.-float(i)*5.);
        float opacity=1.-exp(-density(p)*.024*5.);
        if(opacity<=.00001) continue;
        vec3 color=vec3(.48,.50,.52);
        for(int j=0;j<16;j++) {
            if(j>=u_light_count) break;
            color+=light_scattering(p,j);
        }
        for(int j=0;j<4;j++) {
            if(j>=u_sight_count) break;
            color+=sight_scattering(p,u_sights[j]);
        }
        scattered+=transmission*opacity*color;
        transmission*=1.-opacity;
    }
    float opacity=1.-transmission;
    finalColor=vec4(scattered/max(opacity,.0001),opacity*u_opacity);
}
"""
