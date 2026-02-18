/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_burst */
/* function_mapped: effect_spawn_burst */
/* address: 0x0042ef60 */
/* byte_range: [933864, 934979) */
/* effect_spawn_burst @ 0042ef60 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* generic burst loop for effect id 0 */

void effect_spawn_burst(float *pos, int count)

{
  uint uVar1;
  int iVar2;
  
  _effect_template_color_r = 0x3ecccccd;
  _effect_template_flags = 0x1d;
  _effect_template_color_g = 0x3f000000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_a = 0x3f000000;
  _effect_template_age = 0;
  _effect_template_lifetime = 0x3f000000;
  _effect_template_half_width = 0x42000000;
  _effect_template_half_height = 0x42000000;
  if (0 < count) {
    do {
      uVar1 = crt_rand();
      _effect_template_rotation = (float)(uVar1 & 0x7f) * 0.049087387;
      uVar1 = crt_rand();
      effect_template_vel_x = (float)(int)((uVar1 & 0x7f) - 0x40);
      uVar1 = crt_rand();
      effect_template_vel_y = (float)(int)((uVar1 & 0x7f) - 0x40);
      iVar2 = crt_rand();
      _effect_template_scale_step = (float)(iVar2 % 100) * 0.01 + 0.1;
      effect_spawn(0,pos);
      count = count + -1;
    } while (count != 0);
  }
  return;
}



/*
