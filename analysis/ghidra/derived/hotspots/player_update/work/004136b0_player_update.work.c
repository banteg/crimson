/* WORK COPY: player_update */
/*
  Use this file for variable renames and section comments.
  Keep branch labels and address anchors intact for parity tracing.
*/
/* player_update @ 004136b0 */

/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* per-player gameplay update: movement, firing, status timers, and effects. Runtime capture
   (2026-02-06 gameplay_state_capture): dominant sfx_play_panned ids are 34 and 37 (with secondary
   30). */

void player_update(void)

{
  float *spread_heat_ptr;
  float fVar2;
  float fVar3;
  bool bVar4;
  bool bVar5;
  player_state_t *player_ptr;
  int player_idx;
  bool bVar8;
  uint rng_value;
  int iVar10;
  int iVar11;
  float *pfVar12;
  creature_t *creature_ptr;
  float *unaff_EBP;
  float fVar14;
  int iVar15;
  float *player_pos_ptr;
  float10 fVar17;
  float10 fVar18;
  longlong lVar19;
  float fVar20;
  projectile_type_id_t projectile_type;
  float local_40;
  float local_3c;
  float local_38;
  float local_30 [2];
  float local_28;
  float player_start_pos_y;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  player_idx = render_overlay_player_index;
  if (console_open_flag != '\0') {
    return;
  }
  player_aim_screen_x[render_overlay_player_index * 2] = ui_mouse_x;
  player_aim_screen_x[player_idx * 2 + 1] = ui_mouse_y;
  local_28 = (&player_state_table)[player_idx].pos_x;
  player_pos_ptr = &(&player_state_table)[player_idx].pos_x;
  player_start_pos_y = (&player_state_table)[player_idx].pos_y;
  if ((&player_state_table)[player_idx].health <= 0.0) {
    (&player_state_table)[player_idx].death_timer =
         (&player_state_table)[player_idx].death_timer - frame_dt * 20.0;
    return;
  }
  if (0.0 < (&player_state_table)[player_idx].speed_bonus_timer) {
    (&player_state_table)[player_idx].speed_multiplier =
         (&player_state_table)[player_idx].speed_multiplier + 1.0;
  }
  if ((((&player_state_table)[player_idx].low_health_timer != 100.0) &&
      ((&player_state_table)[player_idx].health < 20.0)) &&
     (fVar14 = (&player_state_table)[player_idx].low_health_timer - frame_dt,
     (&player_state_table)[player_idx].low_health_timer = fVar14, fVar14 < 0.0)) {
    fVar17 = (float10)fcos(((float10)(&player_state_table)[player_idx].aim_heading + (float10)1.5707964)
                           - (float10)0.5);
    fVar18 = (float10)fsin(((float10)(&player_state_table)[player_idx].aim_heading + (float10)1.5707964)
                           - (float10)0.5);
    fVar14 = (&player_state_table)[player_idx].aim_heading;
    local_18 = (float)(fVar17 * (float10)-6.0 + (float10)*player_pos_ptr);
    local_14 = (float)(fVar18 * (float10)-6.0) + (&player_state_table)[player_idx].pos_y;
    effect_spawn_blood_splatter(&local_18,fVar14,0.0);
    effect_spawn_blood_splatter(&local_18,fVar14,0.0);
    effect_spawn_blood_splatter(&local_18,fVar14,0.0);
    rng_value = crt_rand();
    sfx_play_panned((float)((rng_value & 1) + sfx_bloodspill_01));
    (&player_state_table)[player_idx].low_health_timer = 1.0;
  }
  spread_heat_ptr = &(&player_state_table)[player_idx].muzzle_flash_alpha;
  fVar14 = *spread_heat_ptr - (frame_dt + frame_dt);
  *spread_heat_ptr = fVar14;
  if (fVar14 < 0.0) {
    *spread_heat_ptr = 0.0;
  }
  if (bonus_weapon_power_up_timer <= 0.0) {
    fVar14 = (&player_state_table)[player_idx].shot_cooldown - frame_dt;
  }
  else {
    fVar14 = (&player_state_table)[player_idx].shot_cooldown - frame_dt * 1.5;
  }
  (&player_state_table)[player_idx].shot_cooldown = fVar14;
  if ((&player_state_table)[player_idx].shot_cooldown < 0.0) {
    (&player_state_table)[player_idx].shot_cooldown = 0.0;
  }
  iVar10 = perk_count_get(perk_id_man_bomb);
  if (iVar10 == 0) {
    (&player_state_table)[player_idx].man_bomb_timer = 0.0;
  }
  else {
    fVar14 = frame_dt + (&player_state_table)[player_idx].man_bomb_timer;
    (&player_state_table)[player_idx].man_bomb_timer = fVar14;
    if (perk_man_bomb_trigger_interval_s < fVar14) {
      if (*(float *)((int)cv_friendlyFire + 0xc) == 0.0) {
        iVar10 = -100;
      }
      else {
        iVar10 = -1 - render_overlay_player_index;
      }
      local_38 = 0.0;
      do {
        iVar15 = iVar10;
        if (((uint)local_38 & 1) == 0) {
          projectile_type = PROJECTILE_TYPE_ION_MINIGUN;
          iVar11 = crt_rand();
        }
        else {
          projectile_type = PROJECTILE_TYPE_ION_RIFLE;
          iVar11 = crt_rand();
        }
        projectile_spawn(player_pos_ptr,((float)(int)local_38 * 0.7853982 + (float)(iVar11 % 0x32) * 0.01)
                                 - 0.25,projectile_type,iVar15);
        local_38 = (float)((int)local_38 + 1);
      } while ((int)local_38 < 8);
      sfx_play_panned(sfx_explosion_small);
      (&player_state_table)[player_idx].man_bomb_timer =
           (&player_state_table)[player_idx].man_bomb_timer - perk_man_bomb_trigger_interval_s;
      perk_man_bomb_trigger_interval_s = 4.0;
    }
  }
  iVar10 = perk_count_get(perk_id_living_fortress);
  if (iVar10 == 0) {
    (&player_state_table)[player_idx].living_fortress_timer = 0.0;
  }
  else {
    fVar14 = frame_dt + (&player_state_table)[player_idx].living_fortress_timer;
    (&player_state_table)[player_idx].living_fortress_timer = fVar14;
    if (30.0 < fVar14) {
      (&player_state_table)[player_idx].living_fortress_timer = 30.0;
    }
  }
  iVar10 = perk_count_get(perk_id_fire_caugh);
  if (iVar10 == 0) {
    (&player_state_table)[player_idx].fire_cough_timer = 0.0;
  }
  else {
    fVar14 = frame_dt + (&player_state_table)[player_idx].fire_cough_timer;
    (&player_state_table)[player_idx].fire_cough_timer = fVar14;
    if (perk_fire_cough_trigger_interval_s < fVar14) {
      if (*(float *)((int)cv_friendlyFire + 0xc) == 0.0) {
        local_40 = -NAN;
      }
      else {
        local_40 = (float)(-1 - render_overlay_player_index);
      }
      sfx_play_panned((float)fire_bullets_primary_shot_sfx_id);
      sfx_play_panned((float)fire_bullets_secondary_shot_sfx_id);
      iVar10 = render_overlay_player_index;
      local_38 = (&player_state_table)[player_idx].aim_heading;
      fVar17 = ((float10)local_38 - (float10)1.5707964) - (float10)0.150915;
      fVar18 = (float10)fcos(fVar17);
      local_1c = (&player_state_table)[render_overlay_player_index].aim_y;
      local_20 = (&player_state_table)[render_overlay_player_index].aim_x;
      player_ptr = &player_state_table + render_overlay_player_index;
      local_18 = (float)(fVar18 * (float10)16.0);
      fVar17 = (float10)fsin(fVar17);
      local_14 = (float)(fVar17 * (float10)16.0);
      local_c = local_1c - (&player_state_table)[render_overlay_player_index].pos_y;
      local_10 = local_20 - player_ptr->pos_x;
      local_30[0] = vec2_length(&local_10);
      local_30[0] = local_30[0] * 0.5;
      rng_value = crt_rand();
      fVar14 = (float)(rng_value & 0x1ff) * 0.012271847;
      rng_value = crt_rand();
      fVar17 = (float10)local_30[0] * (float10)(&player_state_table)[iVar10].spread_heat *
               (float10)(rng_value & 0x1ff) * (float10)0.001953125;
      fVar18 = (float10)fcos((float10)fVar14);
      local_20 = (float)(fVar18 * fVar17 + (float10)local_20);
      fVar18 = (float10)fsin((float10)fVar14);
      local_1c = (float)(fVar18 * fVar17 + (float10)local_1c);
      pfVar12 = vec2_sub(&player_ptr->pos_x,local_30,&local_20,unaff_EBP);
      fVar17 = (float10)fpatan((float10)pfVar12[1],(float10)*pfVar12);
      local_30[0] = (float)(fVar17 - (float10)1.5707964);
      local_c = local_14 + (&player_state_table)[player_idx].pos_y;
      local_10 = local_18 + *player_pos_ptr;
      projectile_spawn(&local_10,local_30[0],PROJECTILE_TYPE_FIRE_BULLETS,(int)local_40);
      fVar17 = (float10)fcos((float10)local_38);
      local_10 = (float)(fVar17 * (float10)25.0);
      fVar17 = (float10)fsin((float10)local_38);
      local_c = (float)(fVar17 * (float10)25.0);
      local_14 = local_14 + (&player_state_table)[player_idx].pos_y;
      local_18 = local_18 + *player_pos_ptr;
      iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
      (&sprite_effect_pool)[iVar10].color_r = 0.5;
      (&sprite_effect_pool)[iVar10].color_g = 0.5;
      (&sprite_effect_pool)[iVar10].color_b = 0.5;
      (&sprite_effect_pool)[iVar10].color_a = 0.413;
      (&player_state_table)[player_idx].fire_cough_timer =
           (&player_state_table)[player_idx].fire_cough_timer - perk_fire_cough_trigger_interval_s;
      rng_value = crt_rand();
      local_30[0] = (float)(rng_value & 0x80000003);
      if ((int)local_30[0] < 0) {
        local_30[0] = (float)(((int)local_30[0] - 1U | 0xfffffffc) + 1);
      }
      perk_fire_cough_trigger_interval_s = (float)(int)local_30[0] + 2.0;
    }
  }
  iVar10 = perk_count_get(perk_id_hot_tempered);
  if (iVar10 == 0) {
    (&player_state_table)[player_idx].hot_tempered_timer = 0.0;
  }
  else {
    fVar14 = frame_dt + (&player_state_table)[player_idx].hot_tempered_timer;
    (&player_state_table)[player_idx].hot_tempered_timer = fVar14;
    if (perk_hot_tempered_trigger_interval_s < fVar14) {
      if (*(float *)((int)cv_friendlyFire + 0xc) == 0.0) {
        iVar10 = -100;
      }
      else {
        iVar10 = -1 - render_overlay_player_index;
      }
      local_38 = 0.0;
      do {
        if (((uint)local_38 & 1) == 0) {
          projectile_type = PROJECTILE_TYPE_PLASMA_MINIGUN;
        }
        else {
          projectile_type = PROJECTILE_TYPE_PLASMA_RIFLE;
        }
        projectile_spawn(player_pos_ptr,(float)(int)local_38 * 0.7853982,projectile_type,iVar10);
        local_38 = (float)((int)local_38 + 1);
      } while ((int)local_38 < 8);
      sfx_play_panned(sfx_explosion_small);
      (&player_state_table)[player_idx].hot_tempered_timer =
           (&player_state_table)[player_idx].hot_tempered_timer - perk_hot_tempered_trigger_interval_s;
      rng_value = crt_rand();
      local_30[0] = (float)(rng_value & 0x80000007);
      if ((int)local_30[0] < 0) {
        local_30[0] = (float)(((int)local_30[0] - 1U | 0xfffffff8) + 1);
      }
      perk_hot_tempered_trigger_interval_s = (float)(int)local_30[0] + 2.0;
    }
  }
  if (player_spread_damping_gate <= 0.0) {
    player_spread_damping_scalar = frame_dt * 0.8 + player_spread_damping_scalar;
    if (1.0 < player_spread_damping_scalar) {
      player_spread_damping_scalar = 1.0;
    }
  }
  else {
    player_spread_damping_scalar = player_spread_damping_scalar - frame_dt;
    if (player_spread_damping_scalar < 0.3) {
      player_spread_damping_scalar = 0.3;
    }
  }
  fVar14 = (&player_state_table)[player_idx].speed_multiplier;
  local_18 = 0.0;
  local_14 = 0.0;
  (&player_state_table)[player_idx].move_dx = 0.0;
  (&player_state_table)[player_idx].move_dy = 0.0;
  if (time_scale_active != '\0') {
    frame_dt = (0.6 / _time_scale_factor) * frame_dt;
  }
  if (((demo_mode_active == '\0') &&
      (*(int *)(&config_player_mode_flags + render_overlay_player_index * 4) != 5)) &&
     (*(int *)(&config_aim_scheme + render_overlay_player_index * 4) != 5)) {
LAB_00413f2d:
    iVar10 = *(int *)(&config_player_mode_flags + render_overlay_player_index * 4);
    if (iVar10 == 5) goto LAB_00414c7f;
    if (iVar10 == 4) {
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(_config_key_reload);
      if ((char)iVar10 != '\0') {
        local_14 = player_aim_screen_x[render_overlay_player_index * 2 + 1] - _camera_offset_y;
        local_18 = player_aim_screen_x[render_overlay_player_index * 2] - _camera_offset_x;
        (&player_state_table)[player_idx].move_target_x = local_18;
        (&player_state_table)[player_idx].move_target_y = local_14;
      }
      if ((&player_state_table)[player_idx].move_target_x != -1.0) {
        fVar17 = (float10)(&player_state_table)[player_idx].pos_y -
                 (float10)(&player_state_table)[player_idx].move_target_y;
        fVar18 = (float10)*player_pos_ptr - (float10)(&player_state_table)[player_idx].move_target_x;
        if ((float10)20.0 < SQRT(fVar17 * fVar17 + fVar18 * fVar18)) {
          fVar17 = (float10)fpatan(fVar17,fVar18);
          fVar17 = fVar17 - (float10)1.5707964;
          if (fVar17 < (float10)0.0) {
            do {
              fVar17 = fVar17 + (float10)6.2831855;
            } while (fVar17 < (float10)0.0);
          }
          local_38 = (float)fVar17;
          if (fVar17 != (float10)-1.0) {
            fVar20 = player_heading_approach_target(local_38);
            if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
              fVar2 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
              (&player_state_table)[player_idx].move_speed = fVar2;
              if (2.0 < fVar2) {
                (&player_state_table)[player_idx].move_speed = 2.0;
              }
            }
            else {
              if ((&player_state_table)[player_idx].move_speed < 2.0) {
                (&player_state_table)[player_idx].move_speed =
                     frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
              }
              fVar2 = frame_dt + (&player_state_table)[player_idx].move_speed;
              (&player_state_table)[player_idx].move_speed = fVar2;
              if (2.8 < fVar2) {
                (&player_state_table)[player_idx].move_speed = 2.8;
              }
            }
            if (((&player_state_table)[player_idx].weapon_id == 7) &&
               (0.8 < (&player_state_table)[player_idx].move_speed)) {
              (&player_state_table)[player_idx].move_speed = 0.8;
            }
            fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading -
                                   (float10)1.5707964);
            (&player_state_table)[player_idx].move_dx =
                 (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                         (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
            fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading -
                                   (float10)1.5707964);
            (&player_state_table)[player_idx].move_dy =
                 (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                         (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
            local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
            local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
            goto LAB_00414f1c;
          }
        }
      }
      fVar20 = (&player_state_table)[player_idx].move_speed - frame_dt * 15.0;
      (&player_state_table)[player_idx].move_speed = fVar20;
      if (fVar20 < 0.0) {
        (&player_state_table)[player_idx].move_speed = 0.0;
      }
      fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dx =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dy =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
      local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
      goto LAB_00414f1c;
    }
    if (iVar10 == 3) {
      fVar17 = (float10)(*grim_interface_ptr->vtable->grim_get_config_float)
                                  ((&player_state_table)[player_idx].input.axis_move_y);
      fVar14 = (float)-fVar17;
      fVar17 = (float10)(*grim_interface_ptr->vtable->grim_get_config_float)
                                  ((&player_state_table)[player_idx].input.axis_move_x);
      local_20 = (float)-fVar17;
      local_1c = local_38;
      if (0.2 < SQRT(local_38 * local_38 + local_20 * local_20)) {
        vec2_normalize_dispatch(&local_20,&local_20);
        fVar17 = (float10)fpatan((float10)local_1c,(float10)local_20);
        fVar17 = fVar17 - (float10)1.5707964;
        if (fVar17 < (float10)0.0) {
          do {
            fVar17 = fVar17 + (float10)6.2831855;
          } while (fVar17 < (float10)0.0);
        }
        local_38 = (float)fVar17;
        if (fVar17 != (float10)-1.0) {
          fVar20 = player_heading_approach_target(local_38);
          if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
            fVar2 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
            (&player_state_table)[player_idx].move_speed = fVar2;
            if (2.0 < fVar2) {
              (&player_state_table)[player_idx].move_speed = 2.0;
            }
          }
          else {
            if ((&player_state_table)[player_idx].move_speed < 2.0) {
              (&player_state_table)[player_idx].move_speed =
                   frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
            }
            fVar2 = frame_dt + (&player_state_table)[player_idx].move_speed;
            (&player_state_table)[player_idx].move_speed = fVar2;
            if (2.8 < fVar2) {
              (&player_state_table)[player_idx].move_speed = 2.8;
            }
          }
          if (((&player_state_table)[player_idx].weapon_id == 7) &&
             (0.8 < (&player_state_table)[player_idx].move_speed)) {
            (&player_state_table)[player_idx].move_speed = 0.8;
          }
          fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dx =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                       (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
          fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dy =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                       (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
          local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
          local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
          goto LAB_00414f1c;
        }
      }
      fVar20 = (&player_state_table)[player_idx].move_speed - frame_dt * 15.0;
      (&player_state_table)[player_idx].move_speed = fVar20;
      if (fVar20 < 0.0) {
        (&player_state_table)[player_idx].move_speed = 0.0;
      }
      fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dx =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dy =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
      local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
      goto LAB_00414f1c;
    }
    if (iVar10 == 1) {
      bVar4 = false;
      if ((&player_state_table)[player_idx].turn_speed < 1.0) {
        (&player_state_table)[player_idx].turn_speed = 1.0;
      }
      if (7.0 < (&player_state_table)[player_idx].turn_speed) {
        (&player_state_table)[player_idx].turn_speed = 7.0;
      }
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.turn_key_left);
      if ((char)iVar10 == '\0') {
        if (_config_player_count == 1) {
          iVar10 = (*grim_interface_ptr->vtable->grim_is_key_down)
                             (CONCAT31((int3)((uint)iVar10 >> 8),
                                       (undefined1)player_alt_turn_key_left));
          if ((char)iVar10 != '\0') goto LAB_00414520;
        }
        iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                           ((&player_state_table)[player_idx].input.turn_key_right);
        if ((char)iVar10 != '\0') {
LAB_004144dc:
          fVar14 = frame_dt * 10.0 + (&player_state_table)[player_idx].turn_speed;
          (&player_state_table)[player_idx].turn_speed = fVar14;
          (&player_state_table)[player_idx].heading =
               fVar14 * frame_dt * 0.5 + (&player_state_table)[player_idx].heading;
          fVar14 = frame_dt * (&player_state_table)[player_idx].turn_speed * 0.5 +
                   (&player_state_table)[player_idx].aim_heading;
          goto LAB_00414562;
        }
        if (_config_player_count == 1) {
          iVar10 = (*grim_interface_ptr->vtable->grim_is_key_down)
                             (CONCAT31((int3)((uint)iVar10 >> 8),
                                       (undefined1)player_alt_turn_key_right));
          if ((char)iVar10 != '\0') goto LAB_004144dc;
        }
      }
      else {
LAB_00414520:
        fVar14 = frame_dt * 10.0 + (&player_state_table)[player_idx].turn_speed;
        (&player_state_table)[player_idx].turn_speed = fVar14;
        (&player_state_table)[player_idx].heading =
             (&player_state_table)[player_idx].heading - fVar14 * frame_dt * 0.5;
        fVar14 = (&player_state_table)[player_idx].aim_heading -
                 frame_dt * (&player_state_table)[player_idx].turn_speed * 0.5;
LAB_00414562:
        (&player_state_table)[player_idx].aim_heading = fVar14;
        bVar4 = true;
      }
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.move_key_forward);
      if ((char)iVar10 == '\0') {
        if (_config_player_count == 1) {
          iVar10 = (*grim_interface_ptr->vtable->grim_is_key_down)
                             (CONCAT31((int3)((uint)iVar10 >> 8),
                                       (undefined1)player_alt_move_key_forward));
          if ((char)iVar10 != '\0') goto LAB_00414750;
        }
        iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                           ((&player_state_table)[player_idx].input.move_key_backward);
        if ((char)iVar10 == '\0') {
          if (_config_player_count == 1) {
            iVar10 = (*grim_interface_ptr->vtable->grim_is_key_down)
                               (CONCAT31((int3)((uint)iVar10 >> 8),
                                         (undefined1)player_alt_move_key_backward));
            if ((char)iVar10 != '\0') goto LAB_0041467b;
          }
          if (!bVar4) {
            (&player_state_table)[player_idx].turn_speed = 1.0;
          }
          fVar14 = (&player_state_table)[player_idx].move_speed - frame_dt * 15.0;
          (&player_state_table)[player_idx].move_speed = fVar14;
          if (fVar14 < 0.0) {
            (&player_state_table)[player_idx].move_speed = 0.0;
          }
          fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dx =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                      (float10)25.0);
          fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dy =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                      (float10)25.0);
          local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
          local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
        }
        else {
LAB_0041467b:
          if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
            fVar14 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
            (&player_state_table)[player_idx].move_speed = fVar14;
            if (2.0 < fVar14) {
              (&player_state_table)[player_idx].move_speed = 2.0;
            }
          }
          else {
            if ((&player_state_table)[player_idx].move_speed < 2.0) {
              (&player_state_table)[player_idx].move_speed =
                   frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
            }
            fVar14 = frame_dt + (&player_state_table)[player_idx].move_speed;
            (&player_state_table)[player_idx].move_speed = fVar14;
            if (2.8 < fVar14) {
              (&player_state_table)[player_idx].move_speed = 2.8;
            }
          }
          local_38 = -1.0;
          fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dx =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                      (float10)-25.0);
          fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964)
          ;
          (&player_state_table)[player_idx].move_dy =
               (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                      (float10)-25.0);
          local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
          local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
        }
      }
      else {
LAB_00414750:
        if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
          fVar14 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
          (&player_state_table)[player_idx].move_speed = fVar14;
          if (2.0 < fVar14) {
            (&player_state_table)[player_idx].move_speed = 2.0;
          }
        }
        else {
          if ((&player_state_table)[player_idx].move_speed < 2.0) {
            (&player_state_table)[player_idx].move_speed =
                 frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
          }
          fVar14 = frame_dt + (&player_state_table)[player_idx].move_speed;
          (&player_state_table)[player_idx].move_speed = fVar14;
          if (2.8 < fVar14) {
            (&player_state_table)[player_idx].move_speed = 2.8;
          }
        }
        if (((&player_state_table)[player_idx].weapon_id == 7) &&
           (0.8 < (&player_state_table)[player_idx].move_speed)) {
          (&player_state_table)[player_idx].move_speed = 0.8;
        }
        fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dx =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                    (float10)25.0);
        fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dy =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)1.0 *
                    (float10)25.0);
        local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
        local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
      }
      player_apply_move_with_spawn_avoidance(render_overlay_player_index,player_pos_ptr,&local_10);
      fVar14 = local_38 * (&player_state_table)[player_idx].move_speed * frame_dt;
      goto LAB_00414f2d;
    }
    if (iVar10 == 2) {
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.turn_key_left);
      if (((char)iVar10 == '\0') && (_config_player_count == 1)) {
        (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_left);
      }
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.turn_key_right);
      if (((char)iVar10 == '\0') && (_config_player_count == 1)) {
        (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_right);
      }
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.move_key_forward);
      if (((((char)iVar10 != '\0') ||
           ((_config_player_count == 1 &&
            (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_move_key_forward)
            , (char)iVar10 != '\0')))) &&
          (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                              ((&player_state_table)[player_idx].input.turn_key_left),
          (char)iVar10 == '\0')) &&
         ((((_config_player_count != 1 ||
            (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_left),
            (char)iVar10 == '\0')) &&
           (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                               ((&player_state_table)[player_idx].input.turn_key_right),
           (char)iVar10 == '\0')) && (_config_player_count == 1)))) {
        (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_right);
      }
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                         ((&player_state_table)[player_idx].input.move_key_backward);
      if (((char)iVar10 == '\0') &&
         ((_config_player_count != 1 ||
          (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_move_key_backward),
          (char)iVar10 == '\0')))) {
        fVar20 = (&player_state_table)[player_idx].move_speed - frame_dt * 15.0;
        (&player_state_table)[player_idx].move_speed = fVar20;
        if (fVar20 < 0.0) {
          (&player_state_table)[player_idx].move_speed = 0.0;
        }
        fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dx =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                    (float10)25.0);
        fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dy =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                    (float10)25.0);
        local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
        local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
      }
      else {
        iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                           ((&player_state_table)[player_idx].input.turn_key_left);
        if (((char)iVar10 == '\0') &&
           ((_config_player_count != 1 ||
            (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_left),
            (char)iVar10 == '\0')))) {
          iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                             ((&player_state_table)[player_idx].input.turn_key_right);
          if (((char)iVar10 == '\0') &&
             ((_config_player_count != 1 ||
              (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(player_alt_turn_key_right)
              , (char)iVar10 == '\0')))) {
            local_40 = 3.1415927;
          }
          else {
            local_40 = 2.3561945;
          }
        }
        else {
          local_40 = 3.926991;
        }
        fVar20 = player_heading_approach_target(local_40);
        (&player_state_table)[player_idx].aim_heading =
             player_heading_turn_delta + (&player_state_table)[player_idx].aim_heading;
        if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
          fVar2 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
          (&player_state_table)[player_idx].move_speed = fVar2;
          if (2.0 < fVar2) {
            (&player_state_table)[player_idx].move_speed = 2.0;
          }
        }
        else {
          if ((&player_state_table)[player_idx].move_speed < 2.0) {
            (&player_state_table)[player_idx].move_speed =
                 frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
          }
          fVar2 = frame_dt + (&player_state_table)[player_idx].move_speed;
          (&player_state_table)[player_idx].move_speed = fVar2;
          if (2.8 < fVar2) {
            (&player_state_table)[player_idx].move_speed = 2.8;
          }
        }
        if (((&player_state_table)[player_idx].weapon_id == 7) &&
           (0.8 < (&player_state_table)[player_idx].move_speed)) {
          (&player_state_table)[player_idx].move_speed = 0.8;
        }
        fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dx =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                     (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
        fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
        (&player_state_table)[player_idx].move_dy =
             (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                     (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
        local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
        local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
      }
      player_apply_move_with_spawn_avoidance(render_overlay_player_index,player_pos_ptr,&local_10);
      (&player_state_table)[player_idx].move_phase =
           frame_dt * (&player_state_table)[player_idx].move_speed * 19.0 +
           (&player_state_table)[player_idx].move_phase;
    }
  }
  else {
    if ((&player_state_table)[player_idx].auto_target < 0) {
      (&player_state_table)[player_idx].auto_target = 0;
    }
    iVar10 = (&player_state_table)[player_idx].auto_target;
    if (((&creature_pool)[iVar10].active == '\0') || ((&creature_pool)[iVar10].health <= 0.0)) {
      fVar20 = 100000.0;
    }
    else {
      fVar20 = (&player_state_table)[player_idx].pos_y - (&creature_pool)[iVar10].pos_y;
      fVar2 = *player_pos_ptr - (&creature_pool)[iVar10].pos_x;
      fVar20 = SQRT(fVar20 * fVar20 + fVar2 * fVar2);
    }
    iVar10 = 0;
    creature_ptr = &creature_pool;
    do {
      if (((creature_ptr->active != '\0') && (0.0 < creature_ptr->health)) &&
         (fVar3 = (&player_state_table)[player_idx].pos_y - creature_ptr->pos_y,
         fVar2 = *player_pos_ptr - creature_ptr->pos_x, local_30[0] = SQRT(fVar3 * fVar3 + fVar2 * fVar2),
         local_30[0] < fVar20 - 64.0)) {
        (&player_state_table)[player_idx].auto_target = iVar10;
        fVar20 = local_30[0];
      }
      creature_ptr = creature_ptr + 1;
      iVar10 = iVar10 + 1;
    } while ((int)creature_ptr < 0x4aa338);
    if (demo_mode_active == '\0') goto LAB_00413f2d;
LAB_00414c7f:
    if (((&player_state_table)[player_idx].auto_target < 0) ||
       ((&creature_pool)[(&player_state_table)[player_idx].auto_target].health <= 0.0)) {
      fVar17 = (float10)fpatan((float10)(&player_state_table)[player_idx].pos_y - (float10)512.0,
                               (float10)*player_pos_ptr - (float10)512.0);
      fVar17 = fVar17 + (float10)3.1415927;
    }
    else {
      fVar20 = (&player_state_table)[player_idx].pos_y - 512.0;
      if (SQRT(fVar20 * fVar20 + (*player_pos_ptr - 512.0) * (*player_pos_ptr - 512.0)) <= 300.0) {
        local_14 = (&player_state_table)[player_idx].pos_y -
                   (&creature_pool)[(&player_state_table)[player_idx].auto_target].pos_y;
        local_18 = *player_pos_ptr - (&creature_pool)[(&player_state_table)[player_idx].auto_target].pos_x;
      }
      else {
        local_14 = (&player_state_table)[player_idx].pos_y - 512.0;
        local_18 = *player_pos_ptr - 512.0;
      }
      fVar17 = (float10)fpatan((float10)local_14,(float10)local_18);
      fVar17 = fVar17 - (float10)1.5707964;
      local_20 = local_18;
      local_1c = local_14;
    }
    if (fVar17 == (float10)-1.0) {
      fVar20 = (&player_state_table)[player_idx].move_speed - frame_dt * 15.0;
      (&player_state_table)[player_idx].move_speed = fVar20;
      if (fVar20 < 0.0) {
        (&player_state_table)[player_idx].move_speed = 0.0;
      }
      fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dx =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dy =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed * (float10)fVar14 *
                  (float10)25.0);
      local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
      local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
    }
    else {
      fVar20 = player_heading_approach_target((float)fVar17);
      if (player_state_table.perk_counts[perk_id_long_distance_runner] < 1) {
        fVar2 = frame_dt * 5.0 + (&player_state_table)[player_idx].move_speed;
        (&player_state_table)[player_idx].move_speed = fVar2;
        if (2.0 < fVar2) {
          (&player_state_table)[player_idx].move_speed = 2.0;
        }
      }
      else {
        if ((&player_state_table)[player_idx].move_speed < 2.0) {
          (&player_state_table)[player_idx].move_speed =
               frame_dt * 4.0 + (&player_state_table)[player_idx].move_speed;
        }
        fVar2 = frame_dt + (&player_state_table)[player_idx].move_speed;
        (&player_state_table)[player_idx].move_speed = fVar2;
        if (2.8 < fVar2) {
          (&player_state_table)[player_idx].move_speed = 2.8;
        }
      }
      if (((&player_state_table)[player_idx].weapon_id == 7) &&
         (0.8 < (&player_state_table)[player_idx].move_speed)) {
        (&player_state_table)[player_idx].move_speed = 0.8;
      }
      fVar17 = (float10)fcos((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dx =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                   (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
      fVar17 = (float10)fsin((float10)(&player_state_table)[player_idx].heading - (float10)1.5707964);
      (&player_state_table)[player_idx].move_dy =
           (float)(fVar17 * (float10)(&player_state_table)[player_idx].move_speed *
                   (float10)(3.1415927 - fVar20) * (float10)fVar14 * (float10)7.957747);
      local_c = frame_dt * (&player_state_table)[player_idx].move_dy;
      local_10 = frame_dt * (&player_state_table)[player_idx].move_dx;
    }
LAB_00414f1c:
    player_apply_move_with_spawn_avoidance(render_overlay_player_index,player_pos_ptr,&local_10);
    fVar14 = frame_dt * (&player_state_table)[player_idx].move_speed;
LAB_00414f2d:
    (&player_state_table)[player_idx].move_phase =
         fVar14 * 19.0 + (&player_state_table)[player_idx].move_phase;
  }
  if (time_scale_active != '\0') {
    frame_dt = _time_scale_factor * frame_dt * 1.6666666;
  }
  iVar10 = perk_count_get(perk_id_sharpshooter);
  if (iVar10 == 0) {
    fVar14 = (&player_state_table)[player_idx].spread_heat - frame_dt * 0.4;
    (&player_state_table)[player_idx].spread_heat = fVar14;
    if (fVar14 < 0.01) {
      (&player_state_table)[player_idx].spread_heat = 0.01;
    }
  }
  else {
    fVar14 = (&player_state_table)[player_idx].spread_heat - (frame_dt + frame_dt);
    (&player_state_table)[player_idx].spread_heat = fVar14;
    if (fVar14 < 0.25) {
      (&player_state_table)[player_idx].spread_heat = 0.25;
    }
    (&player_state_table)[player_idx].spread_heat = 0.02;
  }
  iVar10 = perk_count_get(perk_id_anxious_loader);
  if ((((iVar10 != 0) && (iVar10 = input_primary_just_pressed(), (char)iVar10 != '\0')) &&
      (0.0 < (&player_state_table)[player_idx].reload_timer)) &&
     (fVar14 = (&player_state_table)[player_idx].reload_timer - 0.05,
     (&player_state_table)[player_idx].reload_timer = fVar14, fVar14 <= 0.0)) {
    (&player_state_table)[player_idx].reload_timer = frame_dt * 0.8;
  }
  if (((&player_state_table)[player_idx].reload_timer - frame_dt < 0.0) &&
     (0.0 <= (&player_state_table)[player_idx].reload_timer)) {
    (&player_state_table)[player_idx].ammo = (&player_state_table)[player_idx].clip_size;
  }
  local_38 = 1.0;
  if ((*player_pos_ptr == local_28) && ((&player_state_table)[player_idx].pos_y == player_start_pos_y)) {
    iVar10 = perk_count_get(perk_id_stationary_reloader);
    if (iVar10 != 0) {
      local_38 = 3.0;
    }
  }
  else {
    (&player_state_table)[player_idx].man_bomb_timer = 0.0;
    (&player_state_table)[player_idx].living_fortress_timer = 0.0;
  }
  iVar10 = perk_count_get(perk_id_angry_reloader);
  if (((iVar10 == 0) || ((&player_state_table)[player_idx].reload_timer_max <= 0.5)) ||
     (fVar14 = (&player_state_table)[player_idx].reload_timer_max * 0.5,
     (&player_state_table)[player_idx].reload_timer <= fVar14)) {
    (&player_state_table)[player_idx].reload_timer =
         (&player_state_table)[player_idx].reload_timer - local_38 * frame_dt;
  }
  else {
    fVar20 = (&player_state_table)[player_idx].reload_timer - local_38 * frame_dt;
    (&player_state_table)[player_idx].reload_timer = fVar20;
    if (fVar20 <= fVar14) {
      bonus_spawn_guard._0_1_ = 1;
      if (*(float *)((int)cv_friendlyFire + 0xc) == 0.0) {
        local_38 = -NAN;
      }
      else {
        local_38 = (float)(-1 - render_overlay_player_index);
      }
      lVar19 = __ftol();
      fVar14 = (float)(7 - (int)lVar19);
      local_3c = 0.0;
      local_30[0] = fVar14;
      if (0 < (int)fVar14) {
        local_30[0] = 6.2831855 / (float)(int)fVar14;
        do {
          projectile_spawn(player_pos_ptr,(float)(int)local_3c * local_30[0] + 0.1,
                           PROJECTILE_TYPE_PLASMA_MINIGUN,(int)local_38);
          local_3c = (float)((int)local_3c + 1);
        } while ((int)local_3c < (int)fVar14);
      }
      bonus_spawn_guard._0_1_ = 0;
      sfx_play_panned(sfx_explosion_small);
    }
  }
  if ((&player_state_table)[player_idx].reload_timer < 0.0) {
    (&player_state_table)[player_idx].reload_timer = 0.0;
  }
  if ((((demo_mode_active == '\0') &&
       (iVar10 = perk_count_get(perk_id_alternate_weapon), iVar10 == 0)) &&
      ((*(int *)(&config_player_mode_flags + render_overlay_player_index * 4) != 4 &&
       ((iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(_config_key_reload),
        (char)iVar10 != '\0' && ((&player_state_table)[player_idx].reload_timer == 0.0)))))) &&
     (_config_player_count == 1)) {
    player_start_reload();
  }
  bVar4 = false;
  if ((demo_mode_active == '\0') &&
     (iVar10 = *(int *)(&config_aim_scheme + render_overlay_player_index * 4), iVar10 != 5)) {
    if (iVar10 == 0) {
      local_14 = player_aim_screen_x[render_overlay_player_index * 2 + 1] - _camera_offset_y;
      local_18 = player_aim_screen_x[render_overlay_player_index * 2] - _camera_offset_x;
      (&player_state_table)[player_idx].aim_x = local_18;
      (&player_state_table)[player_idx].aim_y = local_14;
    }
    else {
      if (iVar10 != 4) {
        if (iVar10 == 3) {
          fVar17 = (float10)player_aim_screen_x[render_overlay_player_index * 2 + 1] -
                   (float10)200.0;
          local_20 = player_aim_screen_x[render_overlay_player_index * 2] - 200.0;
          local_1c = (float)fVar17;
          if ((local_20 != 0.0) || (fVar17 != (float10)0.0)) {
            fVar17 = (float10)fpatan(fVar17,(float10)local_20);
            (&player_state_table)[player_idx].aim_heading = (float)(fVar17 + (float10)1.5707964);
            fVar17 = (fVar17 + (float10)1.5707964) - (float10)1.5707964;
            local_30[0] = (float)fVar17;
            fVar17 = (float10)fcos(fVar17);
            fVar18 = (float10)fsin((float10)local_30[0]);
            local_c = (float)fVar18;
            local_14 = local_c * 60.0 + (&player_state_table)[player_idx].pos_y;
            local_18 = (float)(fVar17 * (float10)60.0 + (float10)*player_pos_ptr);
            (&player_state_table)[player_idx].aim_x = local_18;
            (&player_state_table)[player_idx].aim_y = local_14;
          }
          if (30.0 < SQRT(local_20 * local_20 + local_1c * local_1c)) {
            vec2_normalize_dispatch(&local_20,&local_20);
            iVar10 = render_overlay_player_index;
            local_c = local_1c * 30.0;
            local_18 = local_20 * 30.0 + 200.0;
            local_14 = local_c + 200.0;
            player_aim_screen_x[render_overlay_player_index * 2] = local_18;
            player_aim_screen_x[iVar10 * 2 + 1] = local_14;
          }
        }
        else if (iVar10 == 1) {
          if ((*(int *)(&config_player_mode_flags + render_overlay_player_index * 4) == 1) ||
             (*(int *)(&config_player_mode_flags + render_overlay_player_index * 4) == 2)) {
            iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                               ((&player_state_table)[player_idx].input.aim_key_right);
            if ((char)iVar10 != '\0') {
              (&player_state_table)[player_idx].aim_heading =
                   frame_dt * 3.0 + (&player_state_table)[player_idx].aim_heading;
            }
            iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                               ((&player_state_table)[player_idx].input.aim_key_left);
            if ((char)iVar10 != '\0') {
              (&player_state_table)[player_idx].aim_heading =
                   (&player_state_table)[player_idx].aim_heading - frame_dt * 3.0;
            }
            fVar17 = (float10)(&player_state_table)[player_idx].aim_heading - (float10)1.5707964;
            local_30[0] = (float)fVar17;
            fVar17 = (float10)fcos(fVar17);
            fVar18 = (float10)fsin((float10)local_30[0]);
            local_c = (float)fVar18;
            local_14 = local_c * 60.0 + (&player_state_table)[player_idx].pos_y;
            local_18 = (float)(fVar17 * (float10)60.0 + (float10)*player_pos_ptr);
            (&player_state_table)[player_idx].aim_x = local_18;
            (&player_state_table)[player_idx].aim_y = local_14;
          }
        }
        else {
          bVar8 = input_aim_pov_left_active();
          if (bVar8) {
            (&player_state_table)[player_idx].aim_heading =
                 (&player_state_table)[player_idx].aim_heading - frame_dt * 4.0;
          }
          bVar8 = input_aim_pov_right_active();
          if (bVar8) {
            (&player_state_table)[player_idx].aim_heading =
                 frame_dt * 4.0 + (&player_state_table)[player_idx].aim_heading;
          }
          fVar17 = (float10)(&player_state_table)[player_idx].aim_heading - (float10)1.5707964;
          local_30[0] = (float)fVar17;
          fVar17 = (float10)fcos(fVar17);
          fVar18 = (float10)fsin((float10)local_30[0]);
          local_c = (float)fVar18;
          local_14 = local_c * 60.0 + (&player_state_table)[player_idx].pos_y;
          local_18 = (float)(fVar17 * (float10)60.0 + (float10)*player_pos_ptr);
          (&player_state_table)[player_idx].aim_x = local_18;
          (&player_state_table)[player_idx].aim_y = local_14;
        }
        goto LAB_0041572e;
      }
      (*grim_interface_ptr->vtable->grim_get_config_float)
                ((&player_state_table)[player_idx].input.axis_aim_y);
      fVar17 = (float10)(*grim_interface_ptr->vtable->grim_get_config_float)
                                  ((&player_state_table)[player_idx].input.axis_aim_x);
      local_20 = (float)fVar17;
      local_1c = local_38;
      local_38 = SQRT(local_38 * local_38 + local_20 * local_20);
      if (1.0 < local_38) {
        local_38 = 1.0;
      }
      vec2_normalize_dispatch(&local_20,&local_20);
      fVar14 = local_38 * *(float *)((int)cv_padAimDistMul + 0xc) + 42.0;
      local_10 = fVar14 * local_20;
      local_14 = fVar14 * local_1c + (&player_state_table)[player_idx].pos_y;
      local_18 = local_10 + *player_pos_ptr;
      (&player_state_table)[player_idx].aim_x = local_18;
      (&player_state_table)[player_idx].aim_y = local_14;
    }
    fVar17 = (float10)fpatan((float10)(&player_state_table)[player_idx].pos_y -
                             (float10)(&player_state_table)[player_idx].aim_y,
                             (float10)*player_pos_ptr - (float10)(&player_state_table)[player_idx].aim_x);
    (&player_state_table)[player_idx].aim_heading = (float)(fVar17 - (float10)1.5707964);
  }
  else {
    pfVar12 = &(&player_state_table)[player_idx].aim_x;
    local_1c = (&creature_pool)[(&player_state_table)[player_idx].auto_target].pos_y -
               (&player_state_table)[player_idx].aim_y;
    local_20 = (&creature_pool)[(&player_state_table)[player_idx].auto_target].pos_x - *pfVar12;
    fVar14 = SQRT(local_1c * local_1c + local_20 * local_20);
    if (4.0 <= fVar14) {
      vec2_normalize_dispatch(&local_20,&local_20);
      fVar20 = fVar14 * 6.0 * frame_dt;
      local_10 = local_20 * fVar20;
      *pfVar12 = local_10 + *pfVar12;
      (&player_state_table)[player_idx].aim_y = fVar20 * local_1c + (&player_state_table)[player_idx].aim_y;
    }
    else {
      iVar10 = (&player_state_table)[player_idx].auto_target;
      *pfVar12 = (&creature_pool)[iVar10].pos_x;
      (&player_state_table)[player_idx].aim_y = (&creature_pool)[iVar10].pos_y;
    }
    if ((fVar14 < 128.0) &&
       (0.0 < (&creature_pool)[(&player_state_table)[player_idx].auto_target].health)) {
      bVar4 = true;
    }
  }
LAB_0041572e:
  fVar17 = (float10)fpatan((float10)(&player_state_table)[player_idx].pos_y -
                           (float10)(&player_state_table)[player_idx].aim_y,
                           (float10)*player_pos_ptr - (float10)(&player_state_table)[player_idx].aim_x);
  pfVar12 = &(&player_state_table)[player_idx].shot_cooldown;
  bVar8 = false;
  bVar5 = false;
  (&player_state_table)[player_idx].aim_heading = (float)(fVar17 - (float10)1.5707964);
  if ((*pfVar12 <= 0.0) && ((&player_state_table)[player_idx].reload_timer == 0.0)) {
    bVar8 = true;
    *(undefined1 *)&(&player_state_table)[player_idx].reload_active = 0;
  }
  if (((*pfVar12 <= 0.0) && (0 < (&player_state_table)[player_idx].experience)) &&
     ((iVar10 = perk_count_get(perk_id_regression_bullets), iVar10 != 0 ||
      (iVar10 = perk_count_get(perk_id_ammunition_within), iVar10 != 0)))) {
    bVar5 = true;
  }
  iVar10 = perk_count_get(perk_id_alternate_weapon);
  if (iVar10 != 0) {
    if (((player_alt_weapon_swap_cooldown_ms < 1) ||
        (player_alt_weapon_swap_cooldown_ms = player_alt_weapon_swap_cooldown_ms - frame_dt_ms,
        player_alt_weapon_swap_cooldown_ms < 1)) &&
       (iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(_config_key_reload),
       (char)iVar10 != '\0')) {
      iVar10 = (&player_state_table)[player_idx].alt_weapon_id;
      (&player_state_table)[player_idx].alt_weapon_id = (&player_state_table)[player_idx].weapon_id;
      (&player_state_table)[player_idx].weapon_id = iVar10;
      fVar14 = (&player_state_table)[player_idx].alt_clip_size;
      (&player_state_table)[player_idx].alt_clip_size = (&player_state_table)[player_idx].clip_size;
      (&player_state_table)[player_idx].clip_size = fVar14;
      iVar10 = (&player_state_table)[player_idx].alt_reload_active;
      *(char *)&(&player_state_table)[player_idx].alt_reload_active =
           (char)(&player_state_table)[player_idx].reload_active;
      *(char *)&(&player_state_table)[player_idx].reload_active = (char)iVar10;
      fVar14 = (&player_state_table)[player_idx].alt_ammo;
      (&player_state_table)[player_idx].alt_ammo = (&player_state_table)[player_idx].ammo;
      (&player_state_table)[player_idx].ammo = fVar14;
      fVar14 = (&player_state_table)[player_idx].alt_reload_timer;
      (&player_state_table)[player_idx].alt_reload_timer = (&player_state_table)[player_idx].reload_timer;
      (&player_state_table)[player_idx].reload_timer = fVar14;
      fVar14 = (&player_state_table)[player_idx].alt_shot_cooldown;
      (&player_state_table)[player_idx].alt_shot_cooldown = *pfVar12;
      *pfVar12 = fVar14;
      fVar14 = (&player_state_table)[player_idx].alt_reload_timer_max;
      (&player_state_table)[player_idx].alt_reload_timer_max =
           (&player_state_table)[player_idx].reload_timer_max;
      (&player_state_table)[player_idx].reload_timer_max = fVar14;
      sfx_play_panned((float)(&weapon_table)[(&player_state_table)[player_idx].weapon_id].reload_sfx_id);
      *pfVar12 = *pfVar12 + 0.1;
      player_alt_weapon_swap_cooldown_ms = 200;
    }
    else {
      iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(_config_key_reload);
      if ((char)iVar10 == '\0') {
        player_alt_weapon_swap_cooldown_ms = 0;
      }
    }
  }
  if ((!bVar8) && (!bVar5)) goto LAB_0041753e;
  fVar14 = (&player_state_table)[player_idx].aim_heading;
  iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)
                     ((&player_state_table)[player_idx].input.fire_key);
  if (((char)iVar10 == '\0') && (!bVar4)) goto LAB_0041753e;
  survival_reward_fire_seen = 1;
  if (!bVar8) {
    iVar10 = perk_count_get(perk_id_regression_bullets);
    if (iVar10 == 0) {
      iVar10 = perk_count_get(perk_id_ammunition_within);
      if (iVar10 != 0) {
        if ((&weapon_ammo_class)[(&player_state_table)[player_idx].weapon_id * 0x1f] == 1) {
          fVar20 = 0.15;
        }
        else {
          fVar20 = 1.0;
        }
        player_take_damage(render_overlay_player_index,fVar20);
      }
    }
    else if ((&weapon_ammo_class)[(&player_state_table)[player_idx].weapon_id * 0x1f] == 1) {
      lVar19 = __ftol();
      (&player_state_table)[player_idx].experience = (int)lVar19;
    }
    else {
      lVar19 = __ftol();
      (&player_state_table)[player_idx].experience = (int)lVar19;
    }
    if ((&player_state_table)[player_idx].experience < 0) {
      (&player_state_table)[player_idx].experience = 0;
    }
  }
  fVar20 = (float)((float10)fVar14 - (float10)1.5707964);
  fVar17 = ((float10)fVar14 - (float10)1.5707964) - (float10)0.150915;
  fVar18 = (float10)fcos(fVar17);
  local_20 = (float)(fVar18 * (float10)16.0);
  fVar17 = (float10)fsin(fVar17);
  local_1c = (float)(fVar17 * (float10)16.0);
  if (((&weapon_table)[(&player_state_table)[player_idx].weapon_id].flags & 1) != 0) {
    rng_value = crt_rand();
    local_30[0] = (float)(rng_value & 0x3f);
    fVar2 = (float)(int)local_30[0] * 0.01 + fVar14;
    rng_value = crt_rand();
    local_30[0] = (float)(rng_value & 0x3f);
    local_10 = 1.0;
    local_c = 1.0;
    uStack_8 = 0x3f800000;
    uStack_4 = 0x3f19999a;
    _effect_template_color_r = 0x3f800000;
    _effect_template_flags = 0x1c5;
    fVar17 = (float10)(int)local_30[0] * (float10)0.022727273 + (float10)1.0;
    fVar18 = (float10)fcos((float10)fVar2);
    _effect_template_color_g = 0x3f800000;
    _effect_template_color_b = 0x3f800000;
    _effect_template_color_a = 0x3f19999a;
    _effect_template_lifetime = 0x3e19999a;
    _effect_template_age = 0;
    local_18 = (float)(fVar18 * fVar17);
    fVar18 = (float10)fsin((float10)fVar2);
    local_14 = (float)(fVar18 * fVar17);
    rng_value = crt_rand();
    _effect_template_half_height = 0x40000000;
    local_30[0] = (float)((rng_value & 0x3f) - 0x20);
    _effect_template_half_width = 0x40000000;
    _effect_template_rotation = (float)(int)local_30[0] * 0.1;
    effect_template_vel_x = local_18 * 100.0;
    effect_template_vel_y = local_14 * 100.0;
    iVar10 = crt_rand();
    _effect_template_scale_step = 0;
    local_30[0] = (float)(iVar10 % 0x14);
    _effect_template_rotation_step = ((float)(int)local_30[0] * 0.1 - 1.0) * 14.0;
    local_c = local_1c + (&player_state_table)[player_idx].pos_y;
    local_10 = local_20 + *player_pos_ptr;
    effect_spawn(0x12,&local_10);
  }
  if (1.0 < *spread_heat_ptr) {
    *spread_heat_ptr = 1.0;
  }
  iVar10 = render_overlay_player_index;
  local_38 = 1.0;
  if (*(float *)((int)cv_friendlyFire + 0xc) == 0.0) {
    iVar15 = -100;
  }
  else {
    iVar15 = -1 - render_overlay_player_index;
  }
  local_14 = (&player_state_table)[render_overlay_player_index].aim_y;
  local_18 = (&player_state_table)[render_overlay_player_index].aim_x;
  local_c = local_14 - (&player_state_table)[render_overlay_player_index].pos_y;
  local_10 = local_18 - (&player_state_table)[render_overlay_player_index].pos_x;
  local_28 = vec2_length(&local_10);
  local_28 = local_28 * 0.5;
  rng_value = crt_rand();
  local_30[0] = (float)(rng_value & 0x1ff);
  fVar2 = (float)(int)local_30[0];
  rng_value = crt_rand();
  local_30[0] = (float)(rng_value & 0x1ff);
  fVar17 = (float10)local_28 * (float10)(&player_state_table)[iVar10].spread_heat *
           (float10)(int)local_30[0] * (float10)0.001953125;
  fVar18 = (float10)fcos((float10)(fVar2 * 0.012271847));
  local_18 = (float)(fVar18 * fVar17 + (float10)local_18);
  fVar18 = (float10)fsin((float10)(fVar2 * 0.012271847));
  fVar17 = (float10)fpatan((float10)(&player_state_table)[iVar10].pos_y -
                           (fVar18 * fVar17 + (float10)local_14),
                           (float10)(&player_state_table)[iVar10].pos_x - (float10)local_18);
  fVar2 = (float)(fVar17 - (float10)1.5707964);
  iVar10 = (*grim_interface_ptr->vtable->grim_is_key_active)(0x22);
  if ((char)iVar10 != '\0') {
    (&player_state_table)[player_idx].fire_bullets_timer = 10.0;
  }
  if ((&player_state_table)[player_idx].fire_bullets_timer <= 0.0) {
    (&player_state_table)[player_idx].shot_cooldown =
         (&weapon_table)[(&player_state_table)[player_idx].weapon_id].shot_cooldown;
    *spread_heat_ptr = (&weapon_table)[(&player_state_table)[player_idx].weapon_id].spread_heat + *spread_heat_ptr;
    iVar10 = (&player_state_table)[player_idx].weapon_id;
    iVar11 = crt_rand();
    sfx_play_panned((float)(iVar11 % (&weapon_table)[iVar10].shot_sfx_variant_count +
                           (&weapon_table)[iVar10].shot_sfx_base_id));
    iVar10 = (&player_state_table)[player_idx].weapon_id;
    if (iVar10 == 0x18) {
      local_c = local_1c + (&player_state_table)[player_idx].pos_y;
      local_10 = local_20 + *player_pos_ptr;
      projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_SHRINKIFIER,iVar15);
      fVar17 = (float10)fcos((float10)fVar14);
      local_10 = (float)(fVar17 * (float10)25.0);
      fVar18 = (float10)fsin((float10)fVar14);
      local_c = (float)(fVar18 * (float10)25.0);
      local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
      local_18 = local_20 + *player_pos_ptr;
      iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
      (&sprite_effect_pool)[iVar10].color_r = 0.5;
      (&sprite_effect_pool)[iVar10].color_g = 0.5;
      (&sprite_effect_pool)[iVar10].color_b = 0.5;
      (&sprite_effect_pool)[iVar10].color_a = 0.23;
      local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
      local_18 = local_20 + *player_pos_ptr;
LAB_0041600e:
      local_3c = (float)fVar18;
      local_40 = (float)fVar17;
      local_c = local_3c * 15.0;
      local_10 = local_40 * 15.0;
      iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
      (&sprite_effect_pool)[iVar10].color_r = 0.5;
      (&sprite_effect_pool)[iVar10].color_g = 0.5;
      (&sprite_effect_pool)[iVar10].color_b = 0.5;
      (&sprite_effect_pool)[iVar10].color_a = 0.213;
    }
    else {
      if (iVar10 == 1) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PISTOL,iVar15);
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.23;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        goto LAB_0041600e;
      }
      if (iVar10 == 2) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.23;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.213;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_ASSAULT_RIFLE,iVar15);
      }
      else if (iVar10 == 3) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.25;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        local_3c = 1.68156e-44;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.223;
        do {
          projectile_type = PROJECTILE_TYPE_SHOTGUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 200 + -100);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.0013 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 100);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.0;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 0x14) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)15.0);
        fVar17 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar17 * (float10)15.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        local_3c = 5.60519e-45;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.223;
        do {
          projectile_type = PROJECTILE_TYPE_SHOTGUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 200 + -100);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.0013 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 100);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.0;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 4) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.26;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        local_3c = 1.68156e-44;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.233;
        do {
          projectile_type = PROJECTILE_TYPE_SHOTGUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 200 + -100);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.004 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 100);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.0;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 8) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        fx_spawn_particle(&local_10,fVar20,&(&player_state_table)[player_idx].move_dx,1.0);
        local_38 = 0.1;
      }
      else if (iVar10 == 0x10) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_particle(&local_10,fVar20,&(&player_state_table)[player_idx].move_dx,1.0);
        if (iVar10 != -1) {
          *(undefined1 *)&(&particle_pool)[iVar10].style_id = 2;
        }
        local_38 = 0.1;
      }
      else if (iVar10 == 0xf) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_particle(&local_10,fVar20,&(&player_state_table)[player_idx].move_dx,1.0);
        if (iVar10 != -1) {
          *(undefined1 *)&(&particle_pool)[iVar10].style_id = 1;
        }
        local_38 = 0.05;
      }
      else if (iVar10 == 5) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.23;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.213;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_SUBMACHINE_GUN,iVar15);
      }
      else if (iVar10 == 9) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PLASMA_RIFLE,iVar15);
      }
      else if (iVar10 == 10) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2 - 0.31415927,PROJECTILE_TYPE_PLASMA_RIFLE,iVar15);
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2 - 0.5235988,PROJECTILE_TYPE_PLASMA_MINIGUN,iVar15);
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PLASMA_RIFLE,iVar15);
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2 + 0.5235988,PROJECTILE_TYPE_PLASMA_MINIGUN,iVar15);
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2 + 0.31415927,PROJECTILE_TYPE_PLASMA_RIFLE,iVar15);
      }
      else if (iVar10 == 0x13) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PULSE_GUN,iVar15);
      }
      else if (iVar10 == 0x19) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_BLADE_GUN,iVar15);
      }
      else if (iVar10 == 0x1d) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_SPLITTER_GUN,iVar15);
      }
      else if (iVar10 == 0x15) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_ION_RIFLE,iVar15);
      }
      else if (iVar10 == 0x16) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_ION_MINIGUN,iVar15);
      }
      else if (iVar10 == 0x17) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_ION_CANNON,iVar15);
      }
      else if (iVar10 == 0x1c) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PLASMA_CANNON,iVar15);
      }
      else if (iVar10 == 0x1f) {
        local_3c = 1.12104e-44;
        do {
          projectile_type = PROJECTILE_TYPE_ION_MINIGUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 200 + -100);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.0026 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 0x50);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.4;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 0xb) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PLASMA_MINIGUN,iVar15);
      }
      else if (iVar10 == 0x1e) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.33;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        local_3c = 8.40779e-45;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.263;
        do {
          projectile_type = PROJECTILE_TYPE_GAUSS_GUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 200 + -100);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.002 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 0x50);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.4;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 6) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.33;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.263;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_GAUSS_GUN,iVar15);
      }
      else if (iVar10 == 0xc) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.34;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.283;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        fx_spawn_secondary_projectile(&local_10,fVar2,SECONDARY_PROJECTILE_TYPE_ROCKET);
      }
      else if (iVar10 == 0x11) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.34;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.283;
        fVar14 = (&player_state_table)[player_idx].ammo * 1.0471976;
        fVar20 = 0.0;
        local_3c = (fVar2 - 3.1415927) - fVar14 * (&player_state_table)[player_idx].ammo * 0.5;
        if (0.0 < (&player_state_table)[player_idx].ammo) {
          do {
            local_c = local_1c + (&player_state_table)[player_idx].pos_y;
            local_10 = local_20 + *player_pos_ptr;
            fx_spawn_secondary_projectile
                      (&local_10,local_3c,SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
            local_3c = local_3c + fVar14;
            fVar20 = (float)((int)fVar20 + 1);
            local_28 = fVar20;
          } while ((float)(int)fVar20 < (&player_state_table)[player_idx].ammo);
        }
        local_38 = (&player_state_table)[player_idx].ammo;
      }
      else if (iVar10 == 0x12) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar17 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar17 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.34;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        fx_spawn_secondary_projectile(&local_10,fVar2,SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN);
      }
      else if (iVar10 == 0xd) {
        fVar17 = (float10)fcos((float10)fVar14);
        local_10 = (float)(fVar17 * (float10)25.0);
        fVar18 = (float10)fsin((float10)fVar14);
        local_c = (float)(fVar18 * (float10)25.0);
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,1.0);
        local_10 = (float)fVar17 * 15.0;
        local_c = (float)fVar18 * 15.0;
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.31;
        local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
        local_18 = local_20 + *player_pos_ptr;
        iVar10 = fx_spawn_sprite(&local_18,&local_10,2.0);
        (&sprite_effect_pool)[iVar10].color_r = 0.5;
        (&sprite_effect_pool)[iVar10].color_g = 0.5;
        (&sprite_effect_pool)[iVar10].color_b = 0.5;
        (&sprite_effect_pool)[iVar10].color_a = 0.243;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        fx_spawn_secondary_projectile(&local_10,fVar2,SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET);
      }
      else if (iVar10 == 7) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PISTOL,iVar15);
      }
      else if (iVar10 == 0xe) {
        local_3c = 1.96182e-44;
        do {
          projectile_type = PROJECTILE_TYPE_PLASMA_MINIGUN;
          local_c = local_1c + (&player_state_table)[player_idx].pos_y;
          local_10 = local_20 + *player_pos_ptr;
          iVar10 = iVar15;
          rng_value = crt_rand();
          local_28 = (float)((rng_value & 0xff) - 0x80);
          iVar10 = projectile_spawn(&local_10,(float)(int)local_28 * 0.002 + fVar2,projectile_type,iVar10);
          iVar11 = crt_rand();
          local_28 = (float)(iVar11 % 100);
          local_3c = (float)((int)local_3c + -1);
          projectile_pool[iVar10].pos.tail.vy.speed_scale = (float)(int)local_28 * 0.01 + 1.0;
        } while (local_3c != 0.0);
      }
      else if (iVar10 == 0x29) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_PLAGUE_SPREADER,iVar15);
      }
      else if (iVar10 == 0x2b) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,fVar2,PROJECTILE_TYPE_RAINBOW_GUN,iVar15);
      }
      else if (iVar10 == 0x2a) {
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        fx_spawn_particle_slow(&local_10,fVar2 - 1.5707964);
        local_38 = 0.15;
      }
    }
    iVar10 = perk_count_get(perk_id_sharpshooter);
    if (iVar10 == 0) {
      (&player_state_table)[player_idx].spread_heat =
           (&weapon_table)[(&player_state_table)[player_idx].weapon_id].spread_heat * 1.3 +
           (&player_state_table)[player_idx].spread_heat;
    }
    if (bonus_reflex_boost_timer <= 0.0) {
      (&player_state_table)[player_idx].ammo = (&player_state_table)[player_idx].ammo - local_38;
    }
  }
  else {
    sfx_play_panned((float)fire_bullets_primary_shot_sfx_id);
    sfx_play_panned((float)fire_bullets_secondary_shot_sfx_id);
    if ((&weapon_table)[(&player_state_table)[player_idx].weapon_id].pellet_count == 1) {
      (&player_state_table)[player_idx].shot_cooldown = fire_bullets_fallback_shot_cooldown;
      fVar20 = fire_bullets_fallback_spread_heat;
    }
    else {
      (&player_state_table)[player_idx].shot_cooldown =
           (&weapon_table)[(&player_state_table)[player_idx].weapon_id].shot_cooldown;
      fVar20 = (&weapon_table)[(&player_state_table)[player_idx].weapon_id].spread_heat;
    }
    iVar10 = 0;
    *spread_heat_ptr = fVar20 + *spread_heat_ptr;
    if (0 < (&weapon_table)[(&player_state_table)[player_idx].weapon_id].pellet_count) {
      do {
        iVar11 = crt_rand();
        local_28 = (float)(iVar11 % 200 + -100) * 0.0015 + fVar2;
        local_c = local_1c + (&player_state_table)[player_idx].pos_y;
        local_10 = local_20 + *player_pos_ptr;
        projectile_spawn(&local_10,local_28,PROJECTILE_TYPE_FIRE_BULLETS,iVar15);
        iVar10 = iVar10 + 1;
      } while (iVar10 < (&weapon_table)[(&player_state_table)[player_idx].weapon_id].pellet_count);
    }
    fVar17 = (float10)fcos((float10)fVar14);
    local_10 = (float)(fVar17 * (float10)25.0);
    fVar17 = (float10)fsin((float10)fVar14);
    local_c = (float)(fVar17 * (float10)25.0);
    local_14 = local_1c + (&player_state_table)[player_idx].pos_y;
    local_18 = local_20 + *player_pos_ptr;
    iVar15 = fx_spawn_sprite(&local_18,&local_10,1.0);
    iVar10 = perk_id_sharpshooter;
    (&sprite_effect_pool)[iVar15].color_r = 0.5;
    (&sprite_effect_pool)[iVar15].color_g = 0.5;
    (&sprite_effect_pool)[iVar15].color_b = 0.5;
    (&sprite_effect_pool)[iVar15].color_a = 0.413;
    iVar10 = perk_count_get(iVar10);
    if (iVar10 == 0) {
      (&player_state_table)[player_idx].spread_heat =
           fire_bullets_fallback_spread_heat * 1.3 + (&player_state_table)[player_idx].spread_heat;
    }
  }
  if (0.48 < (&player_state_table)[player_idx].spread_heat) {
    (&player_state_table)[player_idx].spread_heat = 0.48;
  }
  if (0 < player_state_table.perk_counts[perk_id_fastshot]) {
    (&player_state_table)[player_idx].shot_cooldown = (&player_state_table)[player_idx].shot_cooldown * 0.88;
  }
  if (0 < player_state_table.perk_counts[perk_id_sharpshooter]) {
    (&player_state_table)[player_idx].shot_cooldown = (&player_state_table)[player_idx].shot_cooldown * 1.05;
  }
  if ((&player_state_table)[player_idx].ammo <= 0.0) {
    player_start_reload();
  }
LAB_0041753e:
  fVar14 = (&player_state_table)[player_idx].move_phase;
  while (14.0 < fVar14) {
    fVar14 = (&player_state_table)[player_idx].move_phase - 14.0;
    (&player_state_table)[player_idx].move_phase = fVar14;
  }
  fVar14 = (&player_state_table)[player_idx].move_phase;
  while (fVar14 < 0.0) {
    fVar14 = (&player_state_table)[player_idx].move_phase + 14.0;
    (&player_state_table)[player_idx].move_phase = fVar14;
  }
  if (0.0 < (&player_state_table)[player_idx].speed_bonus_timer) {
    (&player_state_table)[player_idx].speed_multiplier =
         (&player_state_table)[player_idx].speed_multiplier - 1.0;
  }
  fVar14 = (&player_state_table)[player_idx].size * 0.5;
  if (*player_pos_ptr < fVar14) {
    *player_pos_ptr = fVar14;
  }
  if ((float)_terrain_texture_width - fVar14 < *player_pos_ptr) {
    *player_pos_ptr = (float)_terrain_texture_width - fVar14;
  }
  player_pos_ptr = &(&player_state_table)[player_idx].pos_y;
  if ((&player_state_table)[player_idx].pos_y < fVar14) {
    *player_pos_ptr = fVar14;
  }
  if ((float)_terrain_texture_height - fVar14 < *player_pos_ptr) {
    *player_pos_ptr = (float)_terrain_texture_height - fVar14;
  }
  if (0.8 < *spread_heat_ptr) {
    *spread_heat_ptr = 0.8;
  }
  return;
}
