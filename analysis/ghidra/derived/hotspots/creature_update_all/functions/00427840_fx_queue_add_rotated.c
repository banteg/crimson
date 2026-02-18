/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: fx_queue_add_rotated */
/* function_mapped: fx_queue_add_rotated */
/* address: 0x00427840 */
/* byte_range: [792666, 794219) */
/* fx_queue_add_rotated @ 00427840 */

/* pushes a rotated sprite into DAT_004aaf3c (capped at 0x40); returns 1 on success */

int fx_queue_add_rotated(float *pos, float *rgba, float rotation, float scale, int effect_id)

{
  undefined4 in_EAX;
  float fVar1;
  uint3 uVar2;
  
  uVar2 = (uint3)((uint)in_EAX >> 8);
  fVar1 = (float)CONCAT31(uVar2,terrain_texture_failed);
  if (terrain_texture_failed == '\0') {
    if (fx_queue_rotated == 0x3f) {
      return (uint)uVar2 << 8;
    }
    (&fx_rotated_color_r)[fx_queue_rotated * 4] = *rgba;
    (&fx_rotated_color_g)[fx_queue_rotated * 4] = rgba[1];
    (&fx_rotated_color_b)[fx_queue_rotated * 4] = rgba[2];
    (&fx_rotated_color_a)[fx_queue_rotated * 4] = rgba[3];
    if (*(float *)((int)cv_terrainBodiesTransparency + 0xc) == 0.0) {
      fVar1 = (float)(&fx_rotated_color_a)[fx_queue_rotated * 4] * 0.8;
    }
    else {
      fVar1 = (1.0 / *(float *)((int)cv_terrainBodiesTransparency + 0xc)) *
              (float)(&fx_rotated_color_a)[fx_queue_rotated * 4];
    }
    (&fx_rotated_color_a)[fx_queue_rotated * 4] = fVar1;
    (&fx_rotated_rotation)[fx_queue_rotated] = rotation;
    (&fx_rotated_effect_id)[fx_queue_rotated] = effect_id;
    (&fx_rotated_scale)[fx_queue_rotated] = scale;
    (&fx_rotated_pos_x)[fx_queue_rotated * 2] = *pos;
    fVar1 = pos[1];
    (&fx_rotated_pos_y)[fx_queue_rotated * 2] = fVar1;
    fx_queue_rotated = fx_queue_rotated + 1;
    if (0x3f < fx_queue_rotated) {
      fx_queue_rotated = 0x3f;
    }
  }
  return CONCAT31((int3)((uint)fVar1 >> 8),1);
}
