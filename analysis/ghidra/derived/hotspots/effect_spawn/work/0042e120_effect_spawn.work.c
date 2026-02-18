/* WORK COPY: effect_spawn */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* effect_spawn @ 0042e120 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* allocates an effect entry and assigns quad UVs */

void * effect_spawn(int effect_id, float *pos)

{
  float fVar1;
  int size_code;
  int frame_idx;
  uint detail_skip_bit;
  float *effect_ptr;
  int copy_word_idx;
  float *pfVar7;
  float *effect_write_ptr;
  
  if (_config_detail_preset < 3) {
    detail_skip_bit = effect_spawn_detail_skip_counter & 1;
    effect_spawn_detail_skip_counter = effect_spawn_detail_skip_counter + 1;
    if (detail_skip_bit != 0) {
      return &DAT_004ab270;
    }
  }
  size_code = (&effect_id_table)[effect_id].size_code;
  frame_idx = (&effect_id_table)[effect_id].frame;
  effect_ptr = effect_free_list_head;
  pfVar7 = (float *)effect_free_list_head[0x2e];
  if ((float *)effect_free_list_head[0x2e] == (float *)0x0) {
    effect_ptr = (float *)&DAT_004ab270;
    pfVar7 = effect_free_list_head;
  }
  effect_free_list_head = pfVar7;
  pfVar7 = (float *)&effect_template_vel_x;
  effect_write_ptr = effect_ptr + 3;
  for (copy_word_idx = 0xf; copy_word_idx != 0; copy_word_idx = copy_word_idx + -1) {
    *effect_write_ptr = *pfVar7;
    pfVar7 = pfVar7 + 1;
    effect_write_ptr = effect_write_ptr + 1;
  }
  *effect_ptr = *pos;
  effect_ptr[1] = pos[1];
  *(char *)(effect_ptr + 2) = (char)effect_id;
  if (size_code == 0x10) {
    effect_ptr[0x17] = (&effect_uv16)[frame_idx].u;
    effect_ptr[0x18] = (&effect_uv16)[frame_idx].v;
    fVar1 = -_effect_template_half_height;
    effect_ptr[0x12] = -_effect_template_half_width;
    effect_ptr[0x13] = fVar1;
    fVar1 = (&effect_uv16)[frame_idx].v;
    effect_ptr[0x1e] = _effect_uv_step_16 + (&effect_uv16)[frame_idx].u;
    effect_ptr[0x1f] = fVar1;
    fVar1 = -_effect_template_half_height;
    effect_ptr[0x19] = _effect_template_half_width;
    effect_ptr[0x1a] = fVar1;
    fVar1 = _effect_uv_step_16 + (&effect_uv16)[frame_idx].v;
    effect_ptr[0x25] = _effect_uv_step_16 + (&effect_uv16)[frame_idx].u;
    effect_ptr[0x26] = fVar1;
    fVar1 = _effect_template_half_height;
    effect_ptr[0x20] = _effect_template_half_width;
    effect_ptr[0x21] = fVar1;
    fVar1 = _effect_uv_step_16 + (&effect_uv16)[frame_idx].v;
    effect_ptr[0x2c] = (&effect_uv16)[frame_idx].u;
    effect_ptr[0x2d] = fVar1;
    fVar1 = _effect_template_half_height;
    effect_ptr[0x27] = -_effect_template_half_width;
    effect_ptr[0x28] = fVar1;
    return effect_ptr;
  }
  if (size_code == 0x20) {
    effect_ptr[0x17] = (&effect_uv8)[frame_idx].u;
    effect_ptr[0x18] = (&effect_uv8)[frame_idx].v;
    fVar1 = -_effect_template_half_height;
    effect_ptr[0x12] = -_effect_template_half_width;
    effect_ptr[0x13] = fVar1;
    fVar1 = (&effect_uv8)[frame_idx].v;
    effect_ptr[0x1e] = _effect_uv_step_8 + (&effect_uv8)[frame_idx].u;
    effect_ptr[0x1f] = fVar1;
    fVar1 = -_effect_template_half_height;
    effect_ptr[0x19] = _effect_template_half_width;
    effect_ptr[0x1a] = fVar1;
    fVar1 = _effect_uv_step_8 + (&effect_uv8)[frame_idx].v;
    effect_ptr[0x25] = _effect_uv_step_8 + (&effect_uv8)[frame_idx].u;
    effect_ptr[0x26] = fVar1;
    fVar1 = _effect_template_half_height;
    effect_ptr[0x20] = _effect_template_half_width;
    effect_ptr[0x21] = fVar1;
    fVar1 = _effect_uv_step_8 + (&effect_uv8)[frame_idx].v;
    effect_ptr[0x2c] = (&effect_uv8)[frame_idx].u;
    effect_ptr[0x2d] = fVar1;
    fVar1 = _effect_template_half_height;
    effect_ptr[0x27] = -_effect_template_half_width;
    effect_ptr[0x28] = fVar1;
    return effect_ptr;
  }
  if (size_code != 0x40) {
    if (size_code == 0x80) {
      effect_ptr[0x17] = (&effect_uv2)[frame_idx].u;
      effect_ptr[0x18] = (&effect_uv2)[frame_idx].v;
      fVar1 = -_effect_template_half_height;
      effect_ptr[0x12] = -_effect_template_half_width;
      effect_ptr[0x13] = fVar1;
      fVar1 = (&effect_uv2)[frame_idx].v;
      effect_ptr[0x1e] = _effect_uv_step_2 + (&effect_uv2)[frame_idx].u;
      effect_ptr[0x1f] = fVar1;
      fVar1 = -_effect_template_half_height;
      effect_ptr[0x19] = _effect_template_half_width;
      effect_ptr[0x1a] = fVar1;
      fVar1 = _effect_uv_step_2 + (&effect_uv2)[frame_idx].v;
      effect_ptr[0x25] = _effect_uv_step_2 + (&effect_uv2)[frame_idx].u;
      effect_ptr[0x26] = fVar1;
      fVar1 = _effect_template_half_height;
      effect_ptr[0x20] = _effect_template_half_width;
      effect_ptr[0x21] = fVar1;
      fVar1 = _effect_uv_step_2 + (&effect_uv2)[frame_idx].v;
      effect_ptr[0x2c] = (&effect_uv2)[frame_idx].u;
      effect_ptr[0x2d] = fVar1;
      fVar1 = _effect_template_half_height;
      effect_ptr[0x27] = -_effect_template_half_width;
      effect_ptr[0x28] = fVar1;
    }
    return effect_ptr;
  }
  effect_ptr[0x17] = (&effect_uv4)[frame_idx].u;
  effect_ptr[0x18] = (&effect_uv4)[frame_idx].v;
  fVar1 = -_effect_template_half_height;
  effect_ptr[0x12] = -_effect_template_half_width;
  effect_ptr[0x13] = fVar1;
  fVar1 = (&effect_uv4)[frame_idx].v;
  effect_ptr[0x1e] = _effect_uv_step_4 + (&effect_uv4)[frame_idx].u;
  effect_ptr[0x1f] = fVar1;
  fVar1 = -_effect_template_half_height;
  effect_ptr[0x19] = _effect_template_half_width;
  effect_ptr[0x1a] = fVar1;
  fVar1 = _effect_uv_step_4 + (&effect_uv4)[frame_idx].v;
  effect_ptr[0x25] = _effect_uv_step_4 + (&effect_uv4)[frame_idx].u;
  effect_ptr[0x26] = fVar1;
  fVar1 = _effect_template_half_height;
  effect_ptr[0x20] = _effect_template_half_width;
  effect_ptr[0x21] = fVar1;
  fVar1 = _effect_uv_step_4 + (&effect_uv4)[frame_idx].v;
  effect_ptr[0x2c] = (&effect_uv4)[frame_idx].u;
  effect_ptr[0x2d] = fVar1;
  fVar1 = _effect_template_half_height;
  effect_ptr[0x27] = -_effect_template_half_width;
  effect_ptr[0x28] = fVar1;
  return effect_ptr;
}



/*
