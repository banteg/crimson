/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: effect_spawn */
/* function_mapped: effect_spawn */
/* address: 0x0042e120 */
/* byte_range: [920066, 925273) */
/* effect_spawn @ 0042e120 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* allocates an effect entry and assigns quad UVs */

void * effect_spawn(int effect_id, float *pos)

{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  float *pfVar7;
  float *pfVar8;
  
  if (_config_detail_preset < 3) {
    uVar4 = effect_spawn_detail_skip_counter & 1;
    effect_spawn_detail_skip_counter = effect_spawn_detail_skip_counter + 1;
    if (uVar4 != 0) {
      return &DAT_004ab270;
    }
  }
  iVar2 = (&effect_id_table)[effect_id].size_code;
  iVar3 = (&effect_id_table)[effect_id].frame;
  pfVar5 = effect_free_list_head;
  pfVar7 = (float *)effect_free_list_head[0x2e];
  if ((float *)effect_free_list_head[0x2e] == (float *)0x0) {
    pfVar5 = (float *)&DAT_004ab270;
    pfVar7 = effect_free_list_head;
  }
  effect_free_list_head = pfVar7;
  pfVar7 = (float *)&effect_template_vel_x;
  pfVar8 = pfVar5 + 3;
  for (iVar6 = 0xf; iVar6 != 0; iVar6 = iVar6 + -1) {
    *pfVar8 = *pfVar7;
    pfVar7 = pfVar7 + 1;
    pfVar8 = pfVar8 + 1;
  }
  *pfVar5 = *pos;
  pfVar5[1] = pos[1];
  *(char *)(pfVar5 + 2) = (char)effect_id;
  if (iVar2 == 0x10) {
    pfVar5[0x17] = (&effect_uv16)[iVar3].u;
    pfVar5[0x18] = (&effect_uv16)[iVar3].v;
    fVar1 = -_effect_template_half_height;
    pfVar5[0x12] = -_effect_template_half_width;
    pfVar5[0x13] = fVar1;
    fVar1 = (&effect_uv16)[iVar3].v;
    pfVar5[0x1e] = _effect_uv_step_16 + (&effect_uv16)[iVar3].u;
    pfVar5[0x1f] = fVar1;
    fVar1 = -_effect_template_half_height;
    pfVar5[0x19] = _effect_template_half_width;
    pfVar5[0x1a] = fVar1;
    fVar1 = _effect_uv_step_16 + (&effect_uv16)[iVar3].v;
    pfVar5[0x25] = _effect_uv_step_16 + (&effect_uv16)[iVar3].u;
    pfVar5[0x26] = fVar1;
    fVar1 = _effect_template_half_height;
    pfVar5[0x20] = _effect_template_half_width;
    pfVar5[0x21] = fVar1;
    fVar1 = _effect_uv_step_16 + (&effect_uv16)[iVar3].v;
    pfVar5[0x2c] = (&effect_uv16)[iVar3].u;
    pfVar5[0x2d] = fVar1;
    fVar1 = _effect_template_half_height;
    pfVar5[0x27] = -_effect_template_half_width;
    pfVar5[0x28] = fVar1;
    return pfVar5;
  }
  if (iVar2 == 0x20) {
    pfVar5[0x17] = (&effect_uv8)[iVar3].u;
    pfVar5[0x18] = (&effect_uv8)[iVar3].v;
    fVar1 = -_effect_template_half_height;
    pfVar5[0x12] = -_effect_template_half_width;
    pfVar5[0x13] = fVar1;
    fVar1 = (&effect_uv8)[iVar3].v;
    pfVar5[0x1e] = _effect_uv_step_8 + (&effect_uv8)[iVar3].u;
    pfVar5[0x1f] = fVar1;
    fVar1 = -_effect_template_half_height;
    pfVar5[0x19] = _effect_template_half_width;
    pfVar5[0x1a] = fVar1;
    fVar1 = _effect_uv_step_8 + (&effect_uv8)[iVar3].v;
    pfVar5[0x25] = _effect_uv_step_8 + (&effect_uv8)[iVar3].u;
    pfVar5[0x26] = fVar1;
    fVar1 = _effect_template_half_height;
    pfVar5[0x20] = _effect_template_half_width;
    pfVar5[0x21] = fVar1;
    fVar1 = _effect_uv_step_8 + (&effect_uv8)[iVar3].v;
    pfVar5[0x2c] = (&effect_uv8)[iVar3].u;
    pfVar5[0x2d] = fVar1;
    fVar1 = _effect_template_half_height;
    pfVar5[0x27] = -_effect_template_half_width;
    pfVar5[0x28] = fVar1;
    return pfVar5;
  }
  if (iVar2 != 0x40) {
    if (iVar2 == 0x80) {
      pfVar5[0x17] = (&effect_uv2)[iVar3].u;
      pfVar5[0x18] = (&effect_uv2)[iVar3].v;
      fVar1 = -_effect_template_half_height;
      pfVar5[0x12] = -_effect_template_half_width;
      pfVar5[0x13] = fVar1;
      fVar1 = (&effect_uv2)[iVar3].v;
      pfVar5[0x1e] = _effect_uv_step_2 + (&effect_uv2)[iVar3].u;
      pfVar5[0x1f] = fVar1;
      fVar1 = -_effect_template_half_height;
      pfVar5[0x19] = _effect_template_half_width;
      pfVar5[0x1a] = fVar1;
      fVar1 = _effect_uv_step_2 + (&effect_uv2)[iVar3].v;
      pfVar5[0x25] = _effect_uv_step_2 + (&effect_uv2)[iVar3].u;
      pfVar5[0x26] = fVar1;
      fVar1 = _effect_template_half_height;
      pfVar5[0x20] = _effect_template_half_width;
      pfVar5[0x21] = fVar1;
      fVar1 = _effect_uv_step_2 + (&effect_uv2)[iVar3].v;
      pfVar5[0x2c] = (&effect_uv2)[iVar3].u;
      pfVar5[0x2d] = fVar1;
      fVar1 = _effect_template_half_height;
      pfVar5[0x27] = -_effect_template_half_width;
      pfVar5[0x28] = fVar1;
    }
    return pfVar5;
  }
  pfVar5[0x17] = (&effect_uv4)[iVar3].u;
  pfVar5[0x18] = (&effect_uv4)[iVar3].v;
  fVar1 = -_effect_template_half_height;
  pfVar5[0x12] = -_effect_template_half_width;
  pfVar5[0x13] = fVar1;
  fVar1 = (&effect_uv4)[iVar3].v;
  pfVar5[0x1e] = _effect_uv_step_4 + (&effect_uv4)[iVar3].u;
  pfVar5[0x1f] = fVar1;
  fVar1 = -_effect_template_half_height;
  pfVar5[0x19] = _effect_template_half_width;
  pfVar5[0x1a] = fVar1;
  fVar1 = _effect_uv_step_4 + (&effect_uv4)[iVar3].v;
  pfVar5[0x25] = _effect_uv_step_4 + (&effect_uv4)[iVar3].u;
  pfVar5[0x26] = fVar1;
  fVar1 = _effect_template_half_height;
  pfVar5[0x20] = _effect_template_half_width;
  pfVar5[0x21] = fVar1;
  fVar1 = _effect_uv_step_4 + (&effect_uv4)[iVar3].v;
  pfVar5[0x2c] = (&effect_uv4)[iVar3].u;
  pfVar5[0x2d] = fVar1;
  fVar1 = _effect_template_half_height;
  pfVar5[0x27] = -_effect_template_half_width;
  pfVar5[0x28] = fVar1;
  return pfVar5;
}



/*
