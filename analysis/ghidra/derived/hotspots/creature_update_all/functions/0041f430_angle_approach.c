/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: angle_approach */
/* function_mapped: angle_approach */
/* address: 0x0041f430 */
/* byte_range: [628994, 630045) */
/* angle_approach @ 0041f430 */

/* wraps angle into [0,2pi] and steps toward target using shortest arc */

void angle_approach(float *angle, float target, float rate)

{
  float fVar1;
  float fVar2;
  float fVar3;
  
  fVar1 = *angle;
  while (fVar1 < 0.0) {
    fVar1 = *angle + 6.2831855;
    *angle = fVar1;
  }
  fVar1 = *angle;
  while (6.2831855 < fVar1) {
    fVar1 = *angle - 6.2831855;
    *angle = fVar1;
  }
  fVar2 = ABS(target - *angle);
  fVar1 = *angle;
  if (*angle < target) {
    fVar1 = target;
  }
  fVar3 = *angle;
  if (target < *angle) {
    fVar3 = target;
  }
  fVar3 = ABS((6.2831855 - fVar1) + fVar3);
  fVar1 = fVar3;
  if (fVar2 < fVar3) {
    fVar1 = fVar2;
  }
  if (1.0 < fVar1) {
    fVar1 = 1.0;
  }
  if (fVar2 <= fVar3) {
    fVar1 = frame_dt * fVar1 * rate;
    if (*angle < target) {
      *angle = fVar1 + *angle;
      return;
    }
  }
  else {
    fVar1 = frame_dt * fVar1 * rate;
    if (target < *angle) {
      *angle = fVar1 + *angle;
      return;
    }
  }
  *angle = *angle - fVar1;
  return;
}
