// Production effect hooks over a recording-only Grim/host boundary.
#include "../game/rtx_effects.cpp"
#include <cassert>
#include <cstring>
#include <cstdio>

projectile_t projectile_pool[96];
Config config_blob{true};
extern "C" {
vec2f_t camera_offset{};
int particles_texture=7, grim_bound_texture_handle=7;
grim_config_value_t grim_config_values[128]{};
unsigned long grim_color_slot0[4]={0xffffffff,0xffffffff,0xffffffff,0xffffffff};
float grim_uv_u0[8]={.75f,0,1,0,1,.25f,.75f,.25f};
float grim_rotation_radians;
unsigned char portable_preserve_bugs;
}
bool enabled=true, outputs=true, disabled=false;
int calls=0, flushes=0;
float captured[16];
extern "C" bool rtx_drawing() { return enabled && outputs && !disabled; }
void IGrim2D_cpp::grim_flush_batch() { ++flushes; }
IGrim2D_cpp grim;
IGrim2D_cpp *grim_interface_ptr=&grim;
extern "C" void host_effect(const float *corners,int,const float *,unsigned) {
  ++calls;
  memcpy(captured,corners,sizeof captured);
}

int main() {
  projectile_pool[0].fields.type_id=PROJECTILE_TYPE_PLASMA_CANNON;
  projectile_pool[0].fields.life_timer=.4f;
  projectile_pool[0].fields.speed_scale=1;
  projectile_pool[0].fields.pos_x=200;
  rtx_effects_active=1;
  for(int mode=0;mode<4;++mode) {
    enabled=mode!=0; outputs=mode!=1; disabled=mode==2; rtx_effects_active=mode!=3;
    calls=flushes=0;
    rtx_plasma(0,.7f);
    rtx_ion_arc(10,10,50,20,2,.7f);
    assert(calls==0 && flushes==0);
  }
  enabled=outputs=true;disabled=false;rtx_effects_active=1;
  rtx_plasma(0,.7f);rtx_ion_arc(10,10,50,20,2,.7f);
  assert(calls==2);
  const float points[8]={-12,7, 23,-15, 45,20, 10,42};
  // Normal-alpha warm glows keep the original texture coverage.
  grim_config_values[0x12].words[0]=1;
  grim_config_values[0x13].words[0]=5;
  grim_config_values[0x14].words[0]=6;
  assert(!rtx_effect_quad(points));
  effect_entry_t entry{};entry.effect_id=13;entry.scale=1;entry.half_width=20;entry.half_height=40;
  entry.color={1,1,1,1};
  assert(!rtx_effect_entry(&entry));
  grim_config_values[0x14].words[0]=2;
  assert(rtx_effect_quad(points));
  for(int i=0;i<4;++i) {
    assert(captured[i*4]==points[i*2]);
    assert(captured[i*4+1]==points[i*2+1]);
  }
  puts("analytic hooks: output suppression, alpha blending and original quad geometry passed");
}
