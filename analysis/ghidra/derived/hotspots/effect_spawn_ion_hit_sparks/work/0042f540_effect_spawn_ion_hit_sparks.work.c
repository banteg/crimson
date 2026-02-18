/* WORK COPY: effect_spawn_ion_hit_sparks */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* effect_spawn_ion_hit_sparks @ 0042f540 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns detail-scaled ion impact sparks (effect id 0) around the hit position */

void * effect_spawn_ion_hit_sparks(float *pos, float scale)

{
  float spark_scale;
  void *effect_ptr;
  uint rng_value;
  int scale_rand;
  void *sparks_left;
  longlong spark_count_i64;
  
  spark_scale = scale * 0.8;
  _effect_template_color_r = 0x3ecccccd;
  _effect_template_lifetime = spark_scale * 0.7;
  _effect_template_color_a = 0x3f000000;
  _effect_template_flags = 0x1d;
  _effect_template_color_g = 0x3f000000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_age = 0;
  if (1.1 < _effect_template_lifetime) {
    _effect_template_lifetime = 1.1;
  }
  _effect_template_half_width = spark_scale * 32.0;
  _effect_template_half_height = _effect_template_half_width;
  spark_count_i64 = __ftol();
  effect_ptr = (void *)spark_count_i64;
  if (_config_detail_preset < 3) {
    effect_ptr = (void *)((int)effect_ptr / 2);
  }
  sparks_left = effect_ptr;
  if (0 < (int)effect_ptr) {
    do {
      rng_value = crt_rand();
      _effect_template_rotation = (float)(rng_value & 0x7f) * 0.049087387;
      rng_value = crt_rand();
      effect_template_vel_x = (float)(int)((rng_value & 0x7f) - 0x40) * spark_scale * 1.4;
      rng_value = crt_rand();
      effect_template_vel_y = (float)(int)((rng_value & 0x7f) - 0x40) * spark_scale * 1.4;
      scale_rand = crt_rand();
      _effect_template_scale_step = ((float)(scale_rand % 100) * 0.01 + 0.1) * spark_scale;
      effect_ptr = effect_spawn(0,pos);
      sparks_left = (void *)((int)sparks_left + -1);
    } while (sparks_left != (void *)0x0);
  }
  return effect_ptr;
}



/*
