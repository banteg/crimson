/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn_freeze_shatter */
/* function_mapped: effect_spawn_freeze_shatter */
/* address: 0x0042ee00 */
/* byte_range: [932341, 933841) */
/* effect_spawn_freeze_shatter @ 0042ee00 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* four-way shatter burst (id 0xe) plus extra freeze shards */

void effect_spawn_freeze_shatter(float *pos, float angle)

{
  int iVar1;
  int iVar2;
  float10 fVar3;
  undefined4 local_14;
  
  _effect_template_color_r = 0x3f800000;
  _effect_template_flags = 0x5d;
  _effect_template_color_g = 0x3f800000;
  _effect_template_color_b = 0x3f800000;
  _effect_template_color_a = 0x3f000000;
  _effect_template_age = 0;
  _effect_template_lifetime = 0x3f8ccccd;
  _effect_template_scale_step = 0;
  local_14 = 0;
  do {
    fVar3 = (float10)local_14 * (float10)1.5707964 + (float10)angle;
    _effect_template_rotation = (float)fVar3;
    fVar3 = (float10)fcos(fVar3);
    effect_template_vel_x = (float)(fVar3 * (float10)42.0);
    fVar3 = (float10)fsin((float10)_effect_template_rotation);
    effect_template_vel_y = (float)(fVar3 * (float10)42.0);
    iVar1 = crt_rand();
    _effect_template_half_width = (float)(iVar1 % 10 + 0x12);
    _effect_template_half_height = _effect_template_half_width;
    iVar1 = crt_rand();
    _effect_template_rotation_step = ((float)(iVar1 % 0x14) * 0.1 - 1.0) * 1.9;
    effect_spawn(0xe,pos);
    local_14 = local_14 + 1;
  } while (local_14 < 4);
  iVar1 = 4;
  do {
    iVar2 = crt_rand();
    effect_spawn_freeze_shard(pos,(float)(iVar2 % 0x264) * 0.01);
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}



/*
