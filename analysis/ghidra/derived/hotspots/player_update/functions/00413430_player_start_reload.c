/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: player_start_reload */
/* function_mapped: player_start_reload */
/* address: 0x00413430 */
/* byte_range: [398457, 399987) */
/* player_start_reload @ 00413430 */

/* starts reload for the active player, sets timers, and plays SFX. Runtime capture (2026-02-06
   gameplay_state_capture): dominant sfx_play_panned id is 35 (15/20). */

void player_start_reload(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  
  if (((char)(&player_state_table)[render_overlay_player_index].reload_active == '\0') ||
     ((iVar3 = perk_count_get(perk_id_ammunition_within), iVar3 == 0 &&
      (iVar3 = perk_count_get(perk_id_regression_bullets), iVar3 == 0)))) {
    iVar3 = render_overlay_player_index;
    if ((char)(&player_state_table)[render_overlay_player_index].reload_active == '\0') {
      sfx_play_panned((float)(&weapon_table)
                             [(&player_state_table)[render_overlay_player_index].weapon_id].
                             reload_sfx_id);
      iVar3 = render_overlay_player_index;
      *(undefined1 *)&(&player_state_table)[render_overlay_player_index].reload_active = 1;
    }
    iVar2 = perk_id_fastloader;
    fVar1 = (&weapon_table)[(&player_state_table)[iVar3].weapon_id].reload_time;
    (&player_state_table)[iVar3].reload_timer = fVar1;
    if (0 < player_state_table.perk_counts[iVar2]) {
      (&player_state_table)[iVar3].reload_timer = fVar1 * 0.7;
    }
    if (0.0 < bonus_weapon_power_up_timer) {
      (&player_state_table)[iVar3].reload_timer = (&player_state_table)[iVar3].reload_timer * 0.6;
    }
    (&player_state_table)[iVar3].reload_timer_max = (&player_state_table)[iVar3].reload_timer;
  }
  return;
}
