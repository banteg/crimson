/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_find_in_radius */
/* function_mapped: creature_find_in_radius */
/* address: 0x004206a0 */
/* byte_range: [655492, 656239) */
/* creature_find_in_radius @ 004206a0 */

/* returns the first creature index in range, or -1 */

int creature_find_in_radius(float *pos, float radius, int start_index)

{
  float fVar1;
  float fVar2;
  creature_t *pcVar3;
  
  if (start_index < 0x180) {
    pcVar3 = &creature_pool + start_index;
    do {
      if (pcVar3->active != '\0') {
        fVar1 = pcVar3->pos_x - *pos;
        fVar2 = pcVar3->pos_y - pos[1];
        if (SQRT(fVar2 * fVar2 + fVar1 * fVar1) - radius < pcVar3->size * 0.14285715 + 3.0) {
          if (5.0 < pcVar3->lifecycle_stage) {
            return start_index;
          }
        }
      }
      pcVar3 = pcVar3 + 1;
      start_index = start_index + 1;
    } while ((int)pcVar3 < 0x4aa338);
  }
  return -1;
}
