/* source: analysis/ghidra/raw/crimsonland.exe_decompiled.c */
/* function_original: creature_apply_damage */
/* function_mapped: creature_apply_damage */
/* address: 0x004207c0 */
/* byte_range: [657086, 661265) */
/* creature_apply_damage @ 004207c0 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* applies damage + impulse, handles death side effects; returns 1 when killed */

int creature_apply_damage(int creature_id, float damage, int damage_type, float *impulse)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  float *pfVar5;
  
  (&creature_pool)[creature_id].hit_flash_timer = 0.2;
  if (damage_type == 1) {
    iVar2 = perk_count_get(perk_id_uranium_filled_bullets);
    if (iVar2 != 0) {
      damage = damage + damage;
    }
    iVar2 = perk_count_get(perk_id_living_fortress);
    if ((iVar2 != 0) && (0 < _config_player_count)) {
      pfVar5 = &player_state_table.living_fortress_timer;
      iVar2 = _config_player_count;
      do {
        if (0.0 < pfVar5[-0x20]) {
          damage = (*pfVar5 * 0.05 + 1.0) * damage;
        }
        pfVar5 = pfVar5 + 0xd8;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = perk_count_get(perk_id_barrel_greaser);
    if (iVar2 != 0) {
      damage = damage * 1.4;
    }
    iVar2 = perk_count_get(perk_id_doctor);
    if (iVar2 != 0) {
      damage = damage * 1.2;
    }
    if (((&creature_pool)[creature_id].flags & 4) == 0) {
      uVar3 = crt_rand();
      fVar1 = ((float)(int)((uVar3 & 0x7f) - 0x40) * 0.002) /
              ((&creature_pool)[creature_id].size * 0.025);
      if (1.5707964 < fVar1) {
        fVar1 = 1.5707964;
      }
      (&creature_pool)[creature_id].heading = fVar1 + (&creature_pool)[creature_id].heading;
    }
  }
  else if ((damage_type == 7) && (iVar2 = perk_count_get(perk_id_ion_gun_master), iVar2 != 0)) {
    damage = damage * 1.2;
  }
  if ((&creature_pool)[creature_id].health <= 0.0) {
    (&creature_pool)[creature_id].lifecycle_stage =
         (&creature_pool)[creature_id].lifecycle_stage - frame_dt * 15.0;
  }
  else {
    if ((damage_type == 4) && (iVar2 = perk_count_get(perk_id_pyromaniac), iVar2 != 0)) {
      damage = damage * 1.5;
      crt_rand();
    }
    (&creature_pool)[creature_id].health = (&creature_pool)[creature_id].health - damage;
    (&creature_pool)[creature_id].vel_x = (&creature_pool)[creature_id].vel_x - *impulse;
    (&creature_pool)[creature_id].vel_y = (&creature_pool)[creature_id].vel_y - impulse[1];
    if ((&creature_pool)[creature_id].health <= 0.0) {
      (&creature_pool)[creature_id].lifecycle_stage =
           (&creature_pool)[creature_id].lifecycle_stage - frame_dt;
      creature_handle_death(creature_id,true);
      fVar1 = impulse[1];
      (&creature_pool)[creature_id].vel_x =
           (&creature_pool)[creature_id].vel_x - (*impulse + *impulse);
      (&creature_pool)[creature_id].vel_y = (&creature_pool)[creature_id].vel_y - (fVar1 + fVar1);
      if (((&creature_pool)[creature_id].flags & 0x10) == 0) {
        uVar3 = crt_rand();
        uVar3 = uVar3 & 0x80000003;
        if ((int)uVar3 < 0) {
          uVar3 = (uVar3 - 1 | 0xfffffffc) + 1;
        }
        sfx_play_panned((float)creature_type_table[(&creature_pool)[creature_id].type_id].sfx_bank_a
                               [uVar3]);
      }
      else {
        _effect_template_color_r = 0x3f4ccccd;
        _effect_template_flags = 0x1d;
        _effect_template_color_g = 0x3f4ccccd;
        _effect_template_color_b = 0x3e99999a;
        _effect_template_color_a = 0x3f000000;
        _effect_template_lifetime = 0x3f333333;
        _effect_template_half_width = 0x42100000;
        _effect_template_half_height = 0x42100000;
        iVar2 = 5;
        do {
          uVar3 = crt_rand();
          _effect_template_rotation = (float)(uVar3 & 0x7f) * 0.049087387;
          uVar3 = crt_rand();
          effect_template_vel_x = (float)(int)((uVar3 & 0x7f) - 0x40);
          uVar3 = crt_rand();
          effect_template_vel_y = (float)(int)((uVar3 & 0x7f) - 0x40);
          iVar4 = crt_rand();
          _effect_template_scale_step = (float)(iVar4 % 0x8c) * 0.01 + 0.3;
          effect_spawn(0,&(&creature_pool)[creature_id].pos_x);
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
    }
  }
  if (0.0 < (&creature_pool)[creature_id].health) {
    return 0;
  }
  return 1;
}
