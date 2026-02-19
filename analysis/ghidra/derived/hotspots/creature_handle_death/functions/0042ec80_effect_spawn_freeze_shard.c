/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_freeze_shard */
/* function_mapped: effect_spawn_freeze_shard */
/* address: 0x0042ec80 */
/* byte_range: [930900, 932343) */
/* effect_spawn_freeze_shard @ 0042ec80 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* spawns a random freeze shard effect (ids 8..10) around the given angle */

void effect_spawn_freeze_shard(float *pos, float angle)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  float10 fVar4;
  
  _effect_template_color_r = 0x3f800000;
  _effect_template_flags = 0x1cd;
  _effect_template_color_g = 0x3f800000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_a = 0x3f000000;
  uVar2 = crt_rand();
  _effect_template_age = 0;
  _effect_template_half_width = 8.0;
  _effect_template_half_height = 8.0;
  _effect_template_lifetime = (float)(uVar2 & 0xf) * 0.01 + 0.2;
  fVar1 = angle + 3.1415927;
  iVar3 = crt_rand();
  _effect_template_rotation = (float)(iVar3 % 100) * 0.01 + fVar1;
  iVar3 = crt_rand();
  _effect_template_half_width = (float)(iVar3 % 5 + 7);
  fVar4 = (float10)fcos((float10)fVar1);
  effect_template_vel_x = (float)(fVar4 * (float10)114.0);
  fVar4 = (float10)fsin((float10)fVar1);
  effect_template_vel_y = (float)(fVar4 * (float10)114.0);
  _effect_template_half_height = _effect_template_half_width;
  iVar3 = crt_rand();
  _effect_template_rotation_step = ((float)(iVar3 % 0x14) * 0.1 - 1.0) * 4.0;
  uVar2 = crt_rand();
  _effect_template_scale_step = (float)(int)-(uVar2 & 0xf) * 0.1;
  iVar3 = crt_rand();
  effect_spawn(iVar3 % 3 + 8,pos);
  return;
}



/*
