/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_ion_hit_core */
/* function_mapped: effect_spawn_ion_hit_core */
/* address: 0x0042f270 */
/* byte_range: [936771, 937658) */
/* effect_spawn_ion_hit_core @ 0042f270 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns the ion hit core pulse (effect id 1); used by ion minigun/rifle/cannon impacts */

void * effect_spawn_ion_hit_core(float *pos, float scale_step, float lifetime)

{
  void *pvVar1;
  
  _effect_template_lifetime = lifetime * 0.8;
  _effect_template_color_g = 0x3f19999a;
  _effect_template_scale_step = scale_step * 45.0;
  _effect_template_color_r = 0x3f19999a;
  _effect_template_flags = 0x19;
  _effect_template_color_b = 0x3f666666;
  _effect_template_color_a = 0x3f800000;
  _effect_template_age = 0;
  _effect_template_half_width = 0x40800000;
  _effect_template_half_height = 0x40800000;
  _effect_template_rotation = 0;
  effect_template_vel_x = 0;
  effect_template_vel_y = 0;
  pvVar1 = effect_spawn(1,pos);
  return pvVar1;
}



/*
