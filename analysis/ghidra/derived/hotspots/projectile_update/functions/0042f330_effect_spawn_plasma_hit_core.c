/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_plasma_hit_core */
/* function_mapped: effect_spawn_plasma_hit_core */
/* address: 0x0042f330 */
/* byte_range: [937656, 938545) */
/* effect_spawn_plasma_hit_core @ 0042f330 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns the plasma cannon hit core pulse (effect id 1) with custom lifetime/age */

void * effect_spawn_plasma_hit_core(float *pos, float scale_step, float lifetime)

{
  void *pvVar1;
  
  _effect_template_scale_step = scale_step * 45.0;
  _effect_template_color_b = 0x3e99999a;
  _effect_template_color_r = 0x3f666666;
  _effect_template_color_g = 0x3f19999a;
  _effect_template_flags = 0x19;
  _effect_template_color_a = 0x3f800000;
  _effect_template_age = 0x3dcccccd;
  _effect_template_lifetime = lifetime;
  _effect_template_half_width = 0x40800000;
  _effect_template_half_height = 0x40800000;
  _effect_template_rotation = 0;
  effect_template_vel_x = 0;
  effect_template_vel_y = 0;
  pvVar1 = effect_spawn(1,pos);
  return pvVar1;
}



/*
