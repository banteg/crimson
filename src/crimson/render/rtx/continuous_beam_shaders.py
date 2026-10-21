"""Analytic longitudinal visibility for the opt-in narrow-core emitter."""

CONTINUOUS_BEAM_GLSL = r"""
uniform int u_beam_enabled;
uniform vec2 u_beam_tuning; // Ion direct gain, bounded local ambient dip
uniform sampler2D u_beam_candidates;
uniform sampler2D u_moments;
uniform vec2 u_beam_grid; // tile columns, rows (128 world units per tile)
uniform vec4 u_beam_info[MAX_SPEC_LIGHTS]; // longitudinal padding, span, Ion, enabled
int beam_index;
vec2 beam_start, beam_axis;
vec4 u_emitter;
vec4 beamData(int address) {
    int width=textureSize(u_beam_candidates,0).x;
    return texelFetch(u_beam_candidates,ivec2(address%width,address/width),0);
}
vec3 tri0,tri1,tri2;
vec2 tri_lo,tri_hi;
vec3 edgePlane(vec2 a,vec2 b,float sign_area) {
    vec2 e=b-a;vec2 n=sign_area*vec2(-e.y,e.x)/max(length(e),1e-10);
    return vec3(n,-dot(n,a));
}
void setTriangle(vec2 receiver,vec2 start,vec2 end) {
    vec2 a=start-receiver,b=end-receiver;
    tri_lo=min(receiver,min(start,end));tri_hi=max(receiver,max(start,end));
    float p=a.x*b.y,q=a.y*b.x;
    if(abs(p-q)<=8e-7*(abs(p)+abs(q))){tri0=vec3(0.);tri1=vec3(0.);tri2=vec3(0.);return;}
    float sign_area=p-q>=0.?1.:-1.;
    tri0=edgePlane(receiver,start,sign_area);tri1=edgePlane(start,end,sign_area);tri2=edgePlane(end,receiver,sign_area);
    tri_lo=min(receiver,min(start,end));tri_hi=max(receiver,max(start,end));
}
vec2 sortedPair(vec2 x) { return vec2(min(x.x,x.y),max(x.x,x.y)); }
vec2 quadraticRoots(float A,float B,float C) {
    float scale=max(max(abs(A),abs(B)),abs(C));
    if(scale<1e-20)return vec2(1.);
    A/=scale; B/=scale; C/=scale;
    if(abs(A)<1e-7)return abs(B)>1e-7 ? vec2(clamp(-C/B,0.,1.),1.) : vec2(1.);
    float D=B*B-4.*A*C;
    if(D<0.)return vec2(1.);
    float q=-.5*(B+(B>=0.?1.:-1.)*sqrt(D));
    if(abs(q)<1e-12)return vec2(clamp(-B/(2.*A),0.,1.));
    return clamp(vec2(q/A,C/q),0.,1.);
}
bool blockedAt(vec3 q,vec3 a,vec3 b,float s) {
    vec3 v=a+s*b;
    float t=clamp(-dot(q,v)/max(dot(v,v),1e-20),0.,1.);
    vec3 p=q+t*v;return dot(p,p)<=1.;
}
void extendInterval(float lo,float hi,vec3 q,vec3 a,vec3 b,inout vec2 interval) {
    if(hi>lo && blockedAt(q,a,b,.5*(lo+hi)))interval=vec2(min(interval.x,lo),max(interval.y,hi));
}
vec2 bodyInterval(int body,vec3 receiver,vec3 start,vec3 axis) {
    vec4 center=beamData(body);
    vec4 shape=beamData(body+1);
    float bound=max(1./shape.x,1./shape.y)+.001;
    if(any(lessThan(center.xy,tri_lo-vec2(bound)))||any(greaterThan(center.xy,tri_hi+vec2(bound))))return vec2(1.,0.);
    vec3 planar=vec3(center.xy,1.);
    if(min(dot(tri0,planar),min(dot(tri1,planar),dot(tri2,planar))) < -bound)return vec2(1.,0.);
    vec2 rotation=beamData(body+2).xy;
    mat2 local=mat2(rotation.x,-rotation.y,rotation.y,rotation.x);
    vec3 q=receiver-center.xyz,a=start-receiver,b=axis;
    q.xy=local*q.xy;a.xy=local*a.xy;b.xy=local*b.xy;
    q*=shape.xyz;a*=shape.xyz;b*=shape.xyz;
    if(dot(q,q)<=1.)return vec2(0.,1.);
    float forwardA=dot(q,a),forwardB=dot(q,b);
    vec2 domain=vec2(0.,1.);
    if(forwardB>0.)domain.y=clamp(-forwardA/forwardB,0.,1.);
    else if(forwardB<0.)domain.x=clamp(-forwardA/forwardB,0.,1.);
    else if(forwardA>=0.)return vec2(1.,0.);
    if(domain.y<=domain.x)return vec2(1.,0.);
    vec3 qa=cross(q,a),qb=cross(q,b),endpoint=q+a;
    vec4 cuts=vec4(
      quadraticRoots(dot(b,b)-dot(qb,qb),2.*(dot(a,b)-dot(qa,qb)),dot(a,a)-dot(qa,qa)),
      quadraticRoots(dot(b,b),2.*dot(endpoint,b),dot(endpoint,endpoint)-1.));
    cuts=clamp(cuts,domain.x,domain.y);
    // Sorting network: no dynamically indexed temporary root array.
    cuts.xy=sortedPair(cuts.xy);cuts.zw=sortedPair(cuts.zw);
    cuts.xz=sortedPair(cuts.xz);cuts.yw=sortedPair(cuts.yw);cuts.yz=sortedPair(cuts.yz);
    vec2 result=vec2(1.,0.);
    extendInterval(domain.x,cuts.x,q,a,b,result);
    extendInterval(cuts.x,cuts.y,q,a,b,result);
    extendInterval(cuts.y,cuts.z,q,a,b,result);
    extendInterval(cuts.z,cuts.w,q,a,b,result);
    extendInterval(cuts.w,domain.y,q,a,b,result);
    return result;
}
vec3 momentAt(int row,int cell,float t) {
    float x=clamp(t,0.,1.)*32.;int j=min(int(floor(x)),31);float f=x-float(j);
    return mix(texelFetch(u_moments,ivec2(cell*33+j,beam_index),0).rgb,texelFetch(u_moments,ivec2(cell*33+j+1,beam_index),0).rgb,f);
}
vec3 sourceKernel(vec2 source,vec2 world,vec3 N_sub,vec3 absorption,vec3 wetted,vec3 blood,vec3 albedo,float ice,vec4 sp_pos,vec4 sp_col,vec4 response,float broad) {
    source=beam_start+beam_axis*(source.x-u_emitter.x);vec2 to_l=source-world;float d=length(to_l),rad=max(1.,sp_pos.z);
    if(d>=rad)return vec3(0.);
    float atten=pow(max(0.,1.-d/rad),2.);
    vec3 L=normalize(vec3(to_l,max(.001,sp_pos.w)));
    float ndl=max(dot(N_sub,L),0.);
    vec3 transmittance=exp(-absorption*(.90+.35/clamp(L.z,.22,1.)));
    vec3 direct_albedo=mix(wetted*transmittance+blood,albedo,ice);
    float relief=broad>.5?clamp((ndl+.10)/(L.z+.10),.35,2.5):clamp((ndl+.18)/(L.z+.18),.64,1.55);
    float angular=broad>.5?.22+.78*ndl:.22*ndl;
    return direct_albedo*sp_col.rgb*(response.x*atten*angular*relief);
}
vec3 integrateVisible(vec2 gap,int row,float y,vec2 world,vec3 N_sub,vec3 absorption,vec3 wetted,vec3 blood,vec3 albedo,float ice,vec4 sp_pos,vec4 sp_col,vec4 response,float broad) {
    vec3 result=vec3(0.);float count=8.;
    int first=max(0,int(floor(gap.x*count))),last=min(7,int(ceil(gap.y*count))-1);
    for(int cell=first;cell<=last;cell++) {
        float lo=max(gap.x*count-float(cell),0.),hi=min(gap.y*count-float(cell),1.);
        if(hi<=lo)continue;
        vec3 m=momentAt(row,cell,hi)-momentAt(row,cell,lo);
        if(m.x<=1e-10)continue;
        float mu=clamp(m.y/m.x,lo,hi),variance=max(0.,m.z/m.x-mu*mu);
        variance=min(variance,max(0.,(mu-lo)*(hi-mu)));
        float left=min(sqrt(variance),mu-lo),right=min(sqrt(variance),hi-mu);
        if(left>1e-6&&right>1e-6){if(left<right)right=variance/left;else left=variance/right;}
        float sum=left+right;
        if(sum<1e-6){left=0.;right=0.;sum=1.;}
        float wl=right/sum,wr=left/sum;
        if(wl+wr<.5){wl=1.;wr=0.;}
        float x0=u_emitter.x+(float(cell)+clamp(mu-left,lo,hi))*u_emitter.z/count;
        float x1=u_emitter.x+(float(cell)+clamp(mu+right,lo,hi))*u_emitter.z/count;
        result+=m.x*(wl*sourceKernel(vec2(x0,y),world,N_sub,absorption,wetted,blood,albedo,ice,sp_pos,sp_col,response,broad)+wr*sourceKernel(vec2(x1,y),world,N_sub,absorption,wetted,blood,albedo,ice,sp_pos,sp_col,response,broad));
    }
    return result;
}

// At most 64 local intervals use scratch storage. Overflow takes the
// exact streaming sweep over ALL candidates; it is slower, never truncated.
vec3 continuousLight(int index, vec4 direction, vec2 world,vec3 N_sub,vec3 absorption,vec3 wetted,vec3 blood,vec3 albedo,float ice,vec4 sp_pos,vec4 sp_col,vec4 response,float broad, out vec3 unshadowed) {
    beam_index=index;
    beam_axis=length(direction.xy)>.0001?normalize(direction.xy):vec2(1.,0.);
    vec4 info=u_beam_info[index];
    beam_start=sp_pos.xy-beam_axis*(direction.w*.5+info.x);
    u_emitter=vec4(beam_start,info.y,sp_pos.w);
    response.x*=info.z>.5?u_beam_tuning.x:1.;
    unshadowed=integrateVisible(vec2(0.,1.),0,0.,world,N_sub,absorption,wetted,blood,albedo,ice,sp_pos,sp_col,response,broad);
    if(u_dynamic_shadows==0)return unshadowed;
    ivec2 tile=clamp(ivec2(floor(world/128.)),ivec2(0),ivec2(u_beam_grid)-1);
    vec4 header=beamData(index*int(u_beam_grid.x*u_beam_grid.y)+tile.y*int(u_beam_grid.x)+tile.x);
    int count=int(header.y);
    if(count==0)return unshadowed;
    vec3 receiver=vec3(world,0.),start=vec3(beam_start,sp_pos.w),axis=vec3(beam_axis*info.y,0.);
    setTriangle(world,beam_start,beam_start+beam_axis*info.y);
    vec3 intervals[64];
    int n=0;
    bool overflow=false;
    for(int j=0;j<count;j++) {
        int address=int(beamData(int(header.x)+j).x);
        vec2 interval=bodyInterval(address,receiver,start,axis);
        if(interval.x>=interval.y)continue;
        if(n==64){overflow=true;break;}
        intervals[n++]=vec3(interval,clamp(beamData(address+2).z,0.,1.));
    }
    if(n==0&&!overflow)return unshadowed;
    float cursor=0.;
    vec3 result=vec3(0.);
    // Each pass consumes the next distinct endpoint. Overlapping ellipsoids
    // use maximum active opacity, so two lobes do not double-darken a corpse.
    int limit=overflow?2*count+1:2*n+1;
    for(int pass=0;pass<limit && cursor<1.;pass++) {
        float next=1.,opacity=0.;
        int scan=overflow?count:n;
        for(int j=0;j<scan;j++) {
            vec3 interval;
            if(overflow) {
                int address=int(beamData(int(header.x)+j).x);
                interval=vec3(bodyInterval(address,receiver,start,axis),clamp(beamData(address+2).z,0.,1.));
            } else interval=intervals[j];
            if(interval.x>=interval.y || interval.y<=cursor)continue;
            if(interval.x>cursor)next=min(next,interval.x);
            else {opacity=max(opacity,interval.z);next=min(next,interval.y);}
        }
        if(next<=cursor)break;
        if(opacity<1.)result+=(1.-opacity)*integrateVisible(vec2(cursor,next),0,0.,world,N_sub,absorption,wetted,blood,albedo,ice,sp_pos,sp_col,response,broad);
        cursor=next;
    }
    return result;
}
"""
