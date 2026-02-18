/* WORK COPY: effect_spawn_splitter_hit_burst */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* effect_spawn_splitter_hit_burst @ 0042f3f0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns a radial burst of effect id 0 particles around the hit point; used by splitter gun impacts
    */

void * __cdecl effect_spawn_splitter_hit_burst(float *pos,float radius,int count)

{
  float fVar1;
  uint rng_value;
  int radius_rand;
  void *effect_ptr;
  float10 fVar5;
  float10 fVar6;
  longlong radius_i64;
  float spawn_x;
  float spawn_y;
  undefined4 local_8;
  undefined4 local_4;
  
  spawn_x = 1.0;
  spawn_y = 0.9;
  local_8 = 0x3dcccccd;
  local_4 = 0x3f800000;
  _effect_template_color_r = 0x3f800000;
  effect_ptr = (void *)0x3f800000;
  _effect_template_flags = 0x19;
  _effect_template_color_g = 0x3f666666;
  _effect_template_color_b = 0x3dcccccd;
  _effect_template_color_a = 0x3f800000;
  _effect_template_half_width = 0x40800000;
  _effect_template_half_height = 0x40800000;
  _effect_template_rotation = 0;
  effect_template_vel_x = 0;
  effect_template_vel_y = 0;
  _effect_template_scale_step = 0x425c0000;
  if (0 < count) {
    radius_i64 = __ftol();
    do {
      rng_value = crt_rand();
      fVar1 = (float)(rng_value & 0x1ff) * 0.001953125 * 6.2831855;
      radius_rand = crt_rand();
      fVar5 = (float10)(radius_rand % (int)radius_i64);
      fVar6 = (float10)fcos((float10)fVar1);
      spawn_x = (float)(fVar6 * fVar5 + (float10)*pos);
      fVar6 = (float10)fsin((float10)fVar1);
      spawn_y = (float)(fVar6 * fVar5 + (float10)pos[1]);
      rng_value = crt_rand();
      _effect_template_age = (float)(int)-(rng_value & 0xff) * 0.0012;
      _effect_template_lifetime = 0.1 - _effect_template_age;
      effect_ptr = effect_spawn(0,&spawn_x);
      count = count + -1;
    } while (count != 0);
  }
  return effect_ptr;
}



/*
