/* WORK COPY: effect_spawn_shrinkifier_hit */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* effect_spawn_shrinkifier_hit @ 0042f080 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns shrinkifier impact effects: one core pulse (effect id 1) plus detail-scaled debris (effect
   id 0) */

void * __cdecl effect_spawn_shrinkifier_hit(float *pos)

{
  uint rng_value;
  int scale_rand;
  void *effect_ptr;
  int spark_count;
  
  _effect_template_color_r = 0x3e99999a;
  _effect_template_flags = 0x19;
  _effect_template_color_g = 0x3f19999a;
  _effect_template_color_b = 0x3f666666;
  _effect_template_color_a = 0x3f800000;
  _effect_template_age = 0;
  _effect_template_lifetime = 0x3e99999a;
  _effect_template_half_width = 0x42100000;
  _effect_template_half_height = 0x42100000;
  _effect_template_rotation = 0.0;
  effect_template_vel_x = 0.0;
  effect_template_vel_y = 0.0;
  _effect_template_scale_step = -4.0;
  effect_spawn(1,pos);
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_r = 0x3ecccccd;
  _effect_template_flags = 0x1d;
  _effect_template_color_g = 0x3f000000;
  _effect_template_color_a = 0x3f000000;
  _effect_template_age = 0;
  _effect_template_lifetime = 0x3e99999a;
  _effect_template_half_width = 0x42000000;
  _effect_template_half_height = 0x42000000;
  spark_count = 4;
  effect_ptr = _config_detail_preset;
  if ((int)_config_detail_preset < 3) {
    spark_count = 2;
  }
  for (; spark_count != 0; spark_count = spark_count + -1) {
    rng_value = crt_rand();
    _effect_template_rotation = (float)(rng_value & 0x7f) * 0.049087387;
    rng_value = crt_rand();
    effect_template_vel_x = (float)(int)((rng_value & 0x7f) - 0x40) * 1.4;
    rng_value = crt_rand();
    effect_template_vel_y = (float)(int)((rng_value & 0x7f) - 0x40) * 1.4;
    scale_rand = crt_rand();
    _effect_template_scale_step = (float)(scale_rand % 100) * 0.01 + 0.1;
    effect_ptr = effect_spawn(0,pos);
  }
  return effect_ptr;
}



/*
