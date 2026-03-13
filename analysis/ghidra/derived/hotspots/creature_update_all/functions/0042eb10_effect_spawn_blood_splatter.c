/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_blood_splatter */
/* function_mapped: effect_spawn_blood_splatter */
/* address: 0x0042eb10 */
/* byte_range: [929346, 930902) */
/* effect_spawn_blood_splatter @ 0042eb10 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns blood splatter particles (effect id 7) */

void effect_spawn_blood_splatter(float *pos, float angle, float age)

{
  uint uVar1;
  int iVar2;
  float10 fVar3;
  float10 fVar4;
  float10 fVar5;
  
  if (config_violence_disabled == '\0') {
    _effect_template_lifetime = 0.25 - age;
    fVar3 = (float10)angle + (float10)3.1415927;
    _effect_template_color_r = 0x3f800000;
    _effect_template_color_g = 0x3f800000;
    fVar4 = (float10)fcos(fVar3);
    _effect_template_flags = 0xc9;
    _effect_template_color_b = 0x3f800000;
    _effect_template_color_a = 0x3f000000;
    _effect_template_scale_step = 0.0;
    _effect_template_age = age;
    iVar2 = 2;
    fVar5 = (float10)fsin(fVar3);
    do {
      uVar1 = crt_rand();
      _effect_template_rotation = (float)(int)((uVar1 & 0x3f) - 0x20) * 0.1 + (float)fVar3;
      uVar1 = crt_rand();
      _effect_template_half_width = (float)((uVar1 & 7) + 1);
      _effect_template_half_height = _effect_template_half_width;
      uVar1 = crt_rand();
      effect_template_vel_x = (float)((uVar1 & 0x3f) + 100) * (float)fVar4;
      uVar1 = crt_rand();
      _effect_template_rotation_step = 0;
      effect_template_vel_y = (float)((uVar1 & 0x3f) + 100) * (float)fVar5;
      uVar1 = crt_rand();
      _effect_template_scale_step = (float)(uVar1 & 0x7f) * 0.03 + 0.1;
      effect_spawn(7,pos);
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return;
}



/*
