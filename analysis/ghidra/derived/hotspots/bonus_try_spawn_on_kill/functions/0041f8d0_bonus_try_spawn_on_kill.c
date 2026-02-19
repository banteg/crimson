/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: bonus_try_spawn_on_kill */
/* function_mapped: bonus_try_spawn_on_kill */
/* address: 0x0041f8d0 */
/* byte_range: [633913, 637724) */
/* bonus_try_spawn_on_kill @ 0041f8d0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* decides whether to drop a bonus on kill (mode/perk rules) and spawns pickup burst */

void bonus_try_spawn_on_kill(float *pos)

{
  int iVar1;
  bonus_entry_t *pbVar2;
  bonus_entry_t *pbVar3;
  uint uVar4;
  int iVar5;
  
  if (config_game_mode == GAME_MODE_TYPO_SHOOTER) {
    return;
  }
  if (demo_mode_active != '\0') {
    return;
  }
  if (config_game_mode == GAME_MODE_RUSH) {
    return;
  }
  if (config_game_mode == GAME_MODE_TUTORIAL) {
    return;
  }
  if (((player_state_table.weapon_id == 1) ||
      ((player2_weapon_id == 1 && (_config_player_count == 2)))) &&
     (iVar1 = crt_rand(), ((byte)iVar1 & 3) < 3)) {
    pbVar2 = bonus_spawn_at_pos(pos);
    pbVar2->bonus_id = BONUS_ID_WEAPON;
    iVar1 = weapon_pick_random_available();
    (pbVar2->time).amount = iVar1;
    if (iVar1 == 1) {
      iVar1 = weapon_pick_random_available();
      (pbVar2->time).amount = iVar1;
    }
    iVar1 = 0;
    if (pbVar2->bonus_id != BONUS_ID_POINTS) {
      pbVar3 = bonus_pool;
      do {
        if (pbVar3->bonus_id == pbVar2->bonus_id) {
          iVar1 = iVar1 + 1;
        }
        pbVar3 = pbVar3 + 1;
      } while ((int)pbVar3 < 0x482b08);
      if (1 < iVar1) goto LAB_0041f998;
    }
    if (((pbVar2->time).amount == 1) ||
       (iVar1 = perk_count_get(perk_id_my_favourite_weapon), iVar1 != 0)) {
LAB_0041f998:
      pbVar2->bonus_id = BONUS_ID_NONE;
      return;
    }
  }
  else {
    iVar1 = crt_rand();
    if ((iVar1 % 9 != 1) &&
       ((player_state_table.weapon_id != 1 || (iVar1 = crt_rand(), iVar1 % 5 != 1)))) {
      iVar1 = perk_count_get(perk_id_bonus_magnet);
      if (iVar1 == 0) {
        return;
      }
      iVar1 = crt_rand();
      if (iVar1 % 10 != 2) {
        return;
      }
    }
    pbVar2 = bonus_spawn_at_pos(pos);
    if ((pbVar2->bonus_id == BONUS_ID_WEAPON) &&
       (SQRT((pos[1] - player_state_table.pos_y) * (pos[1] - player_state_table.pos_y) +
             (*pos - player_state_table.pos_x) * (*pos - player_state_table.pos_x)) < 56.0)) {
      pbVar2->bonus_id = BONUS_ID_POINTS;
      (pbVar2->time).amount = 100;
    }
    iVar1 = 0;
    if (pbVar2->bonus_id != BONUS_ID_POINTS) {
      pbVar3 = bonus_pool;
      do {
        if (pbVar3->bonus_id == pbVar2->bonus_id) {
          iVar1 = iVar1 + 1;
        }
        pbVar3 = pbVar3 + 1;
      } while ((int)pbVar3 < 0x482b08);
      if (1 < iVar1) goto LAB_0041fa76;
    }
    if ((pbVar2->time).amount == player_state_table.weapon_id) {
LAB_0041fa76:
      pbVar2->bonus_id = BONUS_ID_NONE;
      return;
    }
  }
  if ((pbVar2 != (bonus_entry_t *)0x0) && (pbVar2 != &bonus_pool_sentinel)) {
    _effect_template_color_r = 0x3ecccccd;
    _effect_template_flags = 0x1d;
    _effect_template_color_g = 0x3f000000;
    _effect_template_color_b = 0x3f800000;
    _effect_template_color_a = 0x3f000000;
    _effect_template_lifetime = 0x3f000000;
    _effect_template_half_width = 0x42000000;
    _effect_template_half_height = 0x42000000;
    iVar1 = 0x10;
    do {
      uVar4 = crt_rand();
      _effect_template_rotation = (float)(uVar4 & 0x7f) * 0.049087387;
      uVar4 = crt_rand();
      uVar4 = uVar4 & 0x8000007f;
      if ((int)uVar4 < 0) {
        uVar4 = (uVar4 - 1 | 0xffffff80) + 1;
      }
      effect_template_vel_x = (float)(int)(uVar4 - 0x40);
      uVar4 = crt_rand();
      uVar4 = uVar4 & 0x8000007f;
      if ((int)uVar4 < 0) {
        uVar4 = (uVar4 - 1 | 0xffffff80) + 1;
      }
      effect_template_vel_y = (float)(int)(uVar4 - 0x40);
      iVar5 = crt_rand();
      _effect_template_scale_step = (float)(iVar5 % 100) * 0.01 + 0.1;
      effect_spawn(0,pos);
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  return;
}
