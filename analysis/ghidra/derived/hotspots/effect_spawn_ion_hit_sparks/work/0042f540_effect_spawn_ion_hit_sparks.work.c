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
  void *last_effect_ptr;
  uint rng_value;
  int scale_rand;
  int detail_preset;
  int spark_count;
  longlong spark_count_i64;
  
  /* Shared ion spark template setup scaled by incoming hit strength. */
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
  spark_count = (int)spark_count_i64;
  detail_preset = (int)_config_detail_preset;
  last_effect_ptr = (void *)(long)spark_count;
  if (detail_preset < 3) {
    spark_count = spark_count / 2;
    last_effect_ptr = (void *)(long)spark_count;
  }
  /* Detail-scaled randomized spark emission loop. */
  if (0 < spark_count) {
    do {
      rng_value = crt_rand();
      _effect_template_rotation = (float)(rng_value & 0x7f) * 0.049087387;
      rng_value = crt_rand();
      effect_template_vel_x = (float)(int)((rng_value & 0x7f) - 0x40) * spark_scale * 1.4;
      rng_value = crt_rand();
      effect_template_vel_y = (float)(int)((rng_value & 0x7f) - 0x40) * spark_scale * 1.4;
      scale_rand = crt_rand();
      _effect_template_scale_step = ((float)(scale_rand % 100) * 0.01 + 0.1) * spark_scale;
      last_effect_ptr = effect_spawn(0,pos);
      spark_count = spark_count + -1;
    } while (spark_count != 0);
  }
  return last_effect_ptr;
}



/*
