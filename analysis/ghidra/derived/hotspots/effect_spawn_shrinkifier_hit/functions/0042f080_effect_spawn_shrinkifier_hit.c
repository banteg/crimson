/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_shrinkifier_hit */
/* function_mapped: effect_spawn_shrinkifier_hit */
/* address: 0x0042f080 */
/* byte_range: [934952, 936773) */
/* effect_spawn_shrinkifier_hit @ 0042f080 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns shrinkifier impact effects: one core pulse (effect id 1) plus detail-scaled debris (effect
   id 0) */

void * __cdecl effect_spawn_shrinkifier_hit(float *pos)

{
  uint uVar1;
  int iVar2;
  void *pvVar3;
  int iVar4;
  
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
  iVar4 = 4;
  pvVar3 = _config_detail_preset;
  if ((int)_config_detail_preset < 3) {
    iVar4 = 2;
  }
  for (; iVar4 != 0; iVar4 = iVar4 + -1) {
    uVar1 = crt_rand();
    _effect_template_rotation = (float)(uVar1 & 0x7f) * 0.049087387;
    uVar1 = crt_rand();
    effect_template_vel_x = (float)(int)((uVar1 & 0x7f) - 0x40) * 1.4;
    uVar1 = crt_rand();
    effect_template_vel_y = (float)(int)((uVar1 & 0x7f) - 0x40) * 1.4;
    iVar2 = crt_rand();
    _effect_template_scale_step = (float)(iVar2 % 100) * 0.01 + 0.1;
    pvVar3 = effect_spawn(0,pos);
  }
  return pvVar3;
}



/*
