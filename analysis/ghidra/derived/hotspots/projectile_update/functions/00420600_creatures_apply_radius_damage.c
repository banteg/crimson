/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creatures_apply_radius_damage */
/* function_mapped: creatures_apply_radius_damage */
/* address: 0x00420600 */
/* byte_range: [654664, 655488) */
/* creatures_apply_radius_damage @ 00420600 */

/* applies damage to creatures within radius using FUN_004207c0 */

void creatures_apply_radius_damage(float *pos, float radius, float damage, int damage_type)

{
  float fVar1;
  float fVar2;
  creature_t *pcVar3;
  int creature_id;
  float local_8 [2];
  
  local_8[0] = 0.0;
  local_8[1] = 0.0;
  creature_id = 0;
  pcVar3 = &creature_pool;
  do {
    if (((pcVar3->active != '\0') &&
        (fVar1 = pcVar3->pos_x - *pos, fVar2 = pcVar3->pos_y - pos[1],
        SQRT(fVar2 * fVar2 + fVar1 * fVar1) - radius < pcVar3->size * 0.14285715 + 3.0)) &&
       (5.0 < pcVar3->lifecycle_stage)) {
      creature_apply_damage(creature_id,damage,damage_type,local_8);
    }
    pcVar3 = pcVar3 + 1;
    creature_id = creature_id + 1;
  } while ((int)pcVar3 < 0x4aa338);
  return;
}
