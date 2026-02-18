/* WORK COPY: effect_spawn_explosion_burst */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* effect_spawn_explosion_burst @ 0042f6c0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns explosion burst and shockwave particles */

void effect_spawn_explosion_burst(float *pos, float scale)

{
  float *burst_pos_ptr;
  int iVar1;
  int iVar2;
  uint rng_value;
  
  burst_pos_ptr = pos;
  _effect_template_scale_step = scale * 25.0;
  _effect_template_color_r = 0x3f19999a;
  _effect_template_flags = 0x19;
  _effect_template_color_g = 0x3f19999a;
  _effect_template_color_b = 0x3f19999a;
  _effect_template_color_a = 0x3f800000;
  _effect_template_lifetime = 0.35;
  _effect_template_age = -0.1;
  _effect_template_half_width = 0x42000000;
  _effect_template_half_height = 0x42000000;
  _effect_template_rotation = 0.0;
  effect_template_vel_x = 0.0;
  effect_template_vel_y = 0.0;
  effect_spawn(1,pos);
  _effect_template_color_b = 0x3dcccccd;
  _effect_template_color_r = 0x3dcccccd;
  _effect_template_flags = 0x5d;
  _effect_template_color_g = 0x3dcccccd;
  _effect_template_color_a = 0x3f800000;
  _effect_template_rotation = 0.0;
  effect_template_vel_x = 0.0;
  effect_template_vel_y = 0.0;
  if (3 < _config_detail_preset) {
    pos = (float *)0x0;
    do {
      _effect_template_half_width = 0x42000000;
      _effect_template_half_height = 0x42000000;
      _effect_template_age = (float)(int)pos * 0.2 - 0.5;
      _effect_template_lifetime = (float)(int)pos * 0.2 + 0.6;
      iVar1 = crt_rand();
      _effect_template_rotation_step = 1.4;
      _effect_template_rotation = (float)(iVar1 % 0x266) * 0.02;
      _effect_template_scale_step = scale * 5.0;
      effect_spawn(0x11,burst_pos_ptr);
      pos = (float *)((int)pos + 1);
    } while ((int)pos < 2);
  }
  _effect_template_scale_step = scale * 45.0;
  _effect_template_color_r = 0x3f800000;
  _effect_template_flags = 0x19;
  _effect_template_color_g = 0x3f800000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_a = 0x3f800000;
  _effect_template_age = 0.0;
  _effect_template_lifetime = 0.3;
  _effect_template_half_width = 0x42000000;
  _effect_template_half_height = 0x42000000;
  _effect_template_rotation = 0.0;
  effect_template_vel_x = 0.0;
  effect_template_vel_y = 0.0;
  effect_spawn(0,burst_pos_ptr);
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_r = 0x3f800000;
  _effect_template_flags = 0x1d;
  _effect_template_color_g = 0x3f800000;
  _effect_template_color_a = 0x3f800000;
  _effect_template_lifetime = 0.7;
  _effect_template_age = 0.0;
  _effect_template_half_width = 0x42000000;
  _effect_template_half_height = 0x42000000;
  if (_config_detail_preset < 2) {
    iVar1 = 1;
  }
  else {
    iVar1 = (3 < _config_detail_preset) + 3;
  }
  for (; iVar1 != 0; iVar1 = iVar1 + -1) {
    iVar2 = crt_rand();
    _effect_template_rotation = (float)(iVar2 % 0x13a) * 0.02;
    rng_value = crt_rand();
    effect_template_vel_x = (float)(int)((rng_value & 0x3f) * 2 + -0x40);
    rng_value = crt_rand();
    effect_template_vel_y = (float)(int)((rng_value & 0x3f) * 2 + -0x40);
    iVar2 = crt_rand();
    _effect_template_scale_step = (float)(iVar2 - 3U & 7) * scale;
    iVar2 = crt_rand();
    _effect_template_rotation_step = (float)(iVar2 + 3U & 7);
    effect_spawn(0xc,burst_pos_ptr);
  }
  return;
}



/*
