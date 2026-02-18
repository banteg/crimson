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
  float frame_u;
  float frame_v;
  float uv_step;
  float half_height_neg;
  float half_height_pos;
  int size_code;
  int frame_idx;
  uint detail_skip_bit;
  float *effect_ptr;
  int copy_word_idx;
  float *next_free_effect_ptr;
  float *template_read_ptr;
  float *effect_write_ptr;
  
  /* Low detail presets skip every other spawn to reduce overdraw. */
  if (_config_detail_preset < 3) {
    detail_skip_bit = effect_spawn_detail_skip_counter & 1;
    effect_spawn_detail_skip_counter = effect_spawn_detail_skip_counter + 1;
    if (detail_skip_bit != 0) {
      return &DAT_004ab270;
    }
  }
  size_code = (&effect_id_table)[effect_id].size_code;
  frame_idx = (&effect_id_table)[effect_id].frame;
  /* Pop one entry from the free list and clone the active effect template payload. */
  effect_ptr = effect_free_list_head;
  next_free_effect_ptr = (float *)effect_free_list_head[0x2e];
  if ((float *)effect_free_list_head[0x2e] == (float *)0x0) {
    effect_ptr = (float *)&DAT_004ab270;
    next_free_effect_ptr = effect_free_list_head;
  }
  effect_free_list_head = next_free_effect_ptr;
  template_read_ptr = (float *)&effect_template_vel_x;
  effect_write_ptr = effect_ptr + 3;
  for (copy_word_idx = 0xf; copy_word_idx != 0; copy_word_idx = copy_word_idx + -1) {
    *effect_write_ptr = *template_read_ptr;
    template_read_ptr = template_read_ptr + 1;
    effect_write_ptr = effect_write_ptr + 1;
  }
  *effect_ptr = *pos;
  effect_ptr[1] = pos[1];
  *(char *)(effect_ptr + 2) = (char)effect_id;
  half_height_neg = -_effect_template_half_height;
  half_height_pos = _effect_template_half_height;
  /* Size-code dispatch picks UV atlas table/step while writing the same quad layout. */
  if (size_code == 0x10) {
    /* 16x16 atlas lane. */
    frame_u = (&effect_uv16)[frame_idx].u;
    frame_v = (&effect_uv16)[frame_idx].v;
    uv_step = _effect_uv_step_16;
    effect_ptr[0x17] = frame_u;
    effect_ptr[0x18] = frame_v;
    effect_ptr[0x12] = -_effect_template_half_width;
    effect_ptr[0x13] = half_height_neg;
    effect_ptr[0x1e] = uv_step + frame_u;
    effect_ptr[0x1f] = frame_v;
    effect_ptr[0x19] = _effect_template_half_width;
    effect_ptr[0x1a] = half_height_neg;
    effect_ptr[0x25] = uv_step + frame_u;
    effect_ptr[0x26] = uv_step + frame_v;
    effect_ptr[0x20] = _effect_template_half_width;
    effect_ptr[0x21] = half_height_pos;
    effect_ptr[0x2c] = frame_u;
    effect_ptr[0x2d] = uv_step + frame_v;
    effect_ptr[0x27] = -_effect_template_half_width;
    effect_ptr[0x28] = half_height_pos;
    return effect_ptr;
  }
  if (size_code == 0x20) {
    /* 8x8 atlas lane. */
    frame_u = (&effect_uv8)[frame_idx].u;
    frame_v = (&effect_uv8)[frame_idx].v;
    uv_step = _effect_uv_step_8;
    effect_ptr[0x17] = frame_u;
    effect_ptr[0x18] = frame_v;
    effect_ptr[0x12] = -_effect_template_half_width;
    effect_ptr[0x13] = half_height_neg;
    effect_ptr[0x1e] = uv_step + frame_u;
    effect_ptr[0x1f] = frame_v;
    effect_ptr[0x19] = _effect_template_half_width;
    effect_ptr[0x1a] = half_height_neg;
    effect_ptr[0x25] = uv_step + frame_u;
    effect_ptr[0x26] = uv_step + frame_v;
    effect_ptr[0x20] = _effect_template_half_width;
    effect_ptr[0x21] = half_height_pos;
    effect_ptr[0x2c] = frame_u;
    effect_ptr[0x2d] = uv_step + frame_v;
    effect_ptr[0x27] = -_effect_template_half_width;
    effect_ptr[0x28] = half_height_pos;
    return effect_ptr;
  }
  if (size_code != 0x40) {
    if (size_code == 0x80) {
      /* 2x2 atlas lane. */
      frame_u = (&effect_uv2)[frame_idx].u;
      frame_v = (&effect_uv2)[frame_idx].v;
      uv_step = _effect_uv_step_2;
      effect_ptr[0x17] = frame_u;
      effect_ptr[0x18] = frame_v;
      effect_ptr[0x12] = -_effect_template_half_width;
      effect_ptr[0x13] = half_height_neg;
      effect_ptr[0x1e] = uv_step + frame_u;
      effect_ptr[0x1f] = frame_v;
      effect_ptr[0x19] = _effect_template_half_width;
      effect_ptr[0x1a] = half_height_neg;
      effect_ptr[0x25] = uv_step + frame_u;
      effect_ptr[0x26] = uv_step + frame_v;
      effect_ptr[0x20] = _effect_template_half_width;
      effect_ptr[0x21] = half_height_pos;
      effect_ptr[0x2c] = frame_u;
      effect_ptr[0x2d] = uv_step + frame_v;
      effect_ptr[0x27] = -_effect_template_half_width;
      effect_ptr[0x28] = half_height_pos;
    }
    return effect_ptr;
  }
  /* 4x4 atlas lane. */
  frame_u = (&effect_uv4)[frame_idx].u;
  frame_v = (&effect_uv4)[frame_idx].v;
  uv_step = _effect_uv_step_4;
  effect_ptr[0x17] = frame_u;
  effect_ptr[0x18] = frame_v;
  effect_ptr[0x12] = -_effect_template_half_width;
  effect_ptr[0x13] = half_height_neg;
  effect_ptr[0x1e] = uv_step + frame_u;
  effect_ptr[0x1f] = frame_v;
  effect_ptr[0x19] = _effect_template_half_width;
  effect_ptr[0x1a] = half_height_neg;
  effect_ptr[0x25] = uv_step + frame_u;
  effect_ptr[0x26] = uv_step + frame_v;
  effect_ptr[0x20] = _effect_template_half_width;
  effect_ptr[0x21] = half_height_pos;
  effect_ptr[0x2c] = frame_u;
  effect_ptr[0x2d] = uv_step + frame_v;
  effect_ptr[0x27] = -_effect_template_half_width;
  effect_ptr[0x28] = half_height_pos;
  return effect_ptr;
}



/*
