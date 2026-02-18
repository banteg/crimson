/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_ion_hit_sparks */
/* function_mapped: effect_spawn_ion_hit_sparks */
/* address: 0x0042f540 */
/* byte_range: [940290, 941891) */
/* effect_spawn_ion_hit_sparks @ 0042f540 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns detail-scaled ion impact sparks (effect id 0) around the hit position */

void * effect_spawn_ion_hit_sparks(float *pos, float scale)

{
  float fVar1;
  void *pvVar2;
  uint uVar3;
  int iVar4;
  void *pvVar5;
  longlong lVar6;
  
  fVar1 = scale * 0.8;
  _effect_template_color_r = 0x3ecccccd;
  _effect_template_lifetime = fVar1 * 0.7;
  _effect_template_color_a = 0x3f000000;
  _effect_template_flags = 0x1d;
  _effect_template_color_g = 0x3f000000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_age = 0;
  if (1.1 < _effect_template_lifetime) {
    _effect_template_lifetime = 1.1;
  }
  _effect_template_half_width = fVar1 * 32.0;
  _effect_template_half_height = _effect_template_half_width;
  lVar6 = __ftol();
  pvVar2 = (void *)lVar6;
  if (_config_detail_preset < 3) {
    pvVar2 = (void *)((int)pvVar2 / 2);
  }
  pvVar5 = pvVar2;
  if (0 < (int)pvVar2) {
    do {
      uVar3 = crt_rand();
      _effect_template_rotation = (float)(uVar3 & 0x7f) * 0.049087387;
      uVar3 = crt_rand();
      effect_template_vel_x = (float)(int)((uVar3 & 0x7f) - 0x40) * fVar1 * 1.4;
      uVar3 = crt_rand();
      effect_template_vel_y = (float)(int)((uVar3 & 0x7f) - 0x40) * fVar1 * 1.4;
      iVar4 = crt_rand();
      _effect_template_scale_step = ((float)(iVar4 % 100) * 0.01 + 0.1) * fVar1;
      pvVar2 = effect_spawn(0,pos);
      pvVar5 = (void *)((int)pvVar5 + -1);
    } while (pvVar5 != (void *)0x0);
  }
  return pvVar2;
}



/*
