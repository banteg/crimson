/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: player_heading_approach_target */
/* function_mapped: player_heading_approach_target */
/* address: 0x00413540 */
/* byte_range: [399991, 401710) */
/* player_heading_approach_target @ 00413540 */

/* wraps heading to [0,2pi], turns toward target_heading, and returns shortest angular distance */

float player_heading_approach_target(float target_heading)

{
  float fVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  
  iVar2 = render_overlay_player_index;
  fVar1 = (&player_state_table)[render_overlay_player_index].heading;
  while (fVar1 < 0.0) {
    fVar1 = (&player_state_table)[iVar2].heading + 6.2831855;
    (&player_state_table)[iVar2].heading = fVar1;
  }
  fVar1 = (&player_state_table)[iVar2].heading;
  while (6.2831855 < fVar1) {
    fVar1 = (&player_state_table)[iVar2].heading - 6.2831855;
    (&player_state_table)[iVar2].heading = fVar1;
  }
  fVar3 = ABS(target_heading - (&player_state_table)[iVar2].heading);
  fVar1 = (&player_state_table)[iVar2].heading;
  if ((&player_state_table)[iVar2].heading < target_heading) {
    fVar1 = target_heading;
  }
  fVar4 = (&player_state_table)[iVar2].heading;
  if (target_heading < (&player_state_table)[iVar2].heading) {
    fVar4 = target_heading;
  }
  fVar4 = ABS((6.2831855 - fVar1) + fVar4);
  fVar1 = fVar4;
  if (fVar3 < fVar4) {
    fVar1 = fVar3;
  }
  if (fVar3 <= fVar4) {
    if ((&player_state_table)[iVar2].heading < target_heading) {
      player_heading_turn_delta = frame_dt * fVar1 * 5.0;
      goto LAB_00413686;
    }
  }
  else if (target_heading < (&player_state_table)[iVar2].heading) {
    player_heading_turn_delta = frame_dt * fVar1 * 5.0;
    goto LAB_00413686;
  }
  player_heading_turn_delta = frame_dt * fVar1 * -5.0;
LAB_00413686:
  (&player_state_table)[iVar2].heading =
       player_heading_turn_delta + (&player_state_table)[iVar2].heading;
  return fVar1;
}
