// Included in the firing branch of player_update for 1.3.0 and 1.4.0.
// Rebuild the world-space muzzle for each spawn, including every pellet.
float forward = heading - half_pi;
float angle = forward - .150915f;
vec2f_t muzzle = {(float)cos(angle) * 16.f, (float)sin(angle) * 16.f};
vec2f_t shell;
float dir_x = (float)cos(heading);
shell.x = (crt_rand() % 10) * dir_x * .5f;
float dir_y = (float)sin(heading);
shell.y = (crt_rand() % 10) * dir_y * .5f;
shell += P.position;
if (P.muzzle_flash > 1) P.muzzle_flash = 1;
float ammo = 1;
if (P.weapon == 1) {
    projectile_spawn(position_ptr(muzzle + P.position),
                     ((crt_rand() % 200 - 100) * P.spread * .001f + heading), 4);

    {
        float puff_y = dir_y * 25.f;
        vec2f_t velocity = {dir_x * 25.f, puff_y};
        int slot = fx_spawn_sprite(position_ptr(muzzle + P.position), &velocity, 1.f);
        sprite_effect_pool[slot].color.r = .5f;
        sprite_effect_pool[slot].color.g = .5f;
        sprite_effect_pool[slot].color.b = .5f;
        sprite_effect_pool[slot].color.a = .23f;
    }
    muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .213f);
    shot_sound(2);
    fx_queue_add_shell(&shell);
    P.cooldown = .7117f;
    P.muzzle_flash += FREEWARE_EDITION == 10300 ? .12f : .22f;
} else if (P.weapon == 2) {

    muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .23f);
    muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .213f);
    projectile_spawn(position_ptr(muzzle + P.position), (crt_rand() % 200 - 100) * P.spread * .001f + heading,
                     1);
    shot_sound(7);
    fx_queue_add_shell(&shell);
    P.cooldown = .117f;
    P.muzzle_flash += .07f;
} else if (P.weapon == 3) {

    muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .25f);
    muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .223f);
    int pellets_left = 12;
    do {
        int slot = projectile_spawn(position_ptr(muzzle + P.position),
                                    (crt_rand() % 200 - 100) * .0013f + heading, 2);
        projectile_pool[slot].fields.speed_scale = (crt_rand() % 100) * .01f + 1;
    } while (--pellets_left);
    shot_sound(15);
    fx_queue_add_shell(&shell);
    P.cooldown = .688117f;
    P.muzzle_flash += .12f;
} else if (P.weapon == 4) {

    muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .26f);
    muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .233f);
    int pellets_left = FREEWARE_EDITION == 10300 ? 16 : 12;
    do {
        int slot = projectile_spawn(position_ptr(muzzle + P.position),
                                    (crt_rand() % 200 - 100) * .0033f + heading, 2);
        projectile_pool[slot].fields.speed_scale = (crt_rand() % 100) * .01f + 1;
    } while (--pellets_left);
    shot_sound(15);
    fx_queue_add_shell(&shell);
    P.cooldown = .788117f;
    P.muzzle_flash = (P.muzzle_flash + .12f);
} else if (P.weapon == 5) {
    fx_spawn_particle(position_ptr(muzzle + P.position), forward, &P.movement, 1);
    shot_sound(14);
    ammo = FREEWARE_EDITION == 10300 ? .15f : .1f;
    P.cooldown = .008113f;
} else if (P.weapon == 15) {
    int slot = fx_spawn_particle(position_ptr(muzzle + P.position), forward, &P.movement, 1);
    if (slot != -1) particle_pool[slot].style_id = 1;
    shot_sound(14);
    ammo = .05f;
    P.cooldown = .006113f;
} else if (P.weapon == 6) {

    muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .23f);
    muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .213f);
    projectile_spawn(position_ptr(muzzle + P.position), (crt_rand() % 20 - 10) * P.spread * .003f + heading,
                     2);
    shot_sound(26);
    fx_queue_add_shell(&shell);
    P.cooldown = .088117f;
    P.muzzle_flash += .082f;
} else if (P.weapon == 7) {
    projectile_spawn(position_ptr(muzzle + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading),
                     7);
    shot_sound(8);
    fx_queue_add_shell(&shell);
    P.cooldown = .2908117f;
    P.muzzle_flash += .182f;
} else if (P.weapon == 8) {
    projectile_spawn(position_ptr(muzzle + P.position),
                     (crt_rand() % 20 - 10) * P.spread * .003f + heading - .31415927f, 7);
    projectile_spawn(position_ptr(muzzle + P.position), (crt_rand() % 20 - 10) * P.spread * .003f + heading,
                     7);
    projectile_spawn(position_ptr(muzzle + P.position),
                     (crt_rand() % 20 - 10) * P.spread * .003f + heading + .31415927f, 7);
    shot_sound(8);
    fx_queue_add_shell(&shell);
    P.cooldown = .6408117f;
    P.muzzle_flash += .32f;
} else if (P.weapon == 9) {
    projectile_spawn(position_ptr(muzzle + P.position), ((crt_rand() % 20 - 10) * P.spread * .003f + heading),
                     9);
    shot_sound(FREEWARE_EDITION == 10300 ? 8 : 12);
    fx_queue_add_shell(&shell);
    P.cooldown = .10908117f;
    P.muzzle_flash += .097f;
} else {
    if (P.weapon == 10) {

        muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .33f);
        muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .263f);
        projectile_spawn(position_ptr(muzzle + P.position),
                         (crt_rand() % 20 - 10) * P.spread * .003f + heading, 10);
        shot_sound(8);
        fx_queue_add_shell(&shell);
        P.cooldown = .9508117f;
    } else if (P.weapon == 11) {

        muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .34f);
        muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .283f);
        fx_spawn_secondary_projectile(position_ptr(muzzle + P.position),
                                      (crt_rand() % 20 - 10) * P.spread * .003f + heading,
                                      (secondary_projectile_type_id_t)1);
        shot_sound(20);
        P.cooldown = .7408117f;
    } else if (P.weapon == 12) {

        muzzle_smoke(muzzle, dir_x * 25.0f, (float)(dir_y * 25.0f), 1.0f, .31f);
        muzzle_smoke(muzzle, dir_x * 15.0f, (float)(dir_y * 15.0f), 2.0f, .243f);
        fx_spawn_secondary_projectile(position_ptr(muzzle + P.position),
                                      (crt_rand() % 20 - 10) * P.spread * .003f + heading,
                                      (secondary_projectile_type_id_t)2);
        shot_sound(20);
        P.cooldown = .3108117f;
    } else {
        if (P.weapon == 13) {
            projectile_spawn(position_ptr(muzzle + P.position),
                             ((crt_rand() % 20 - 10) * P.spread * .012f + heading), 4);
            shot_sound(26);
            fx_queue_add_shell(&shell);
            P.cooldown = .07f;
            P.muzzle_flash += .062f;
        } else if (P.weapon == 14) {
            int pellets_left = 14;
            do {
                int slot = projectile_spawn(position_ptr(muzzle + P.position),
                                            (crt_rand() % 200 - 100) * .0013f + heading, 9);
                projectile_pool[slot].fields.speed_scale = (crt_rand() % 100) * .01f + 1;
            } while (--pellets_left);
            shot_sound(15);
            fx_queue_add_shell(&shell);
            P.cooldown = .288117f;
            P.muzzle_flash += .1f;
        } else if (P.weapon == 17 && (FREEWARE_EDITION == 10300 || freeware_secret_weapon_unlocked)) {
            projectile_spawn(position_ptr(muzzle + P.position),
                             ((crt_rand() % 20 - 10) * P.spread * .012f + heading), 17);
            shot_sound(8);
            fx_queue_add_shell(&shell);
            P.cooldown = .2f;
            P.muzzle_flash += .04f;
        }
#if FREEWARE_EDITION >= 10400
        else if (P.weapon == 18 && freeware_secret_weapon_unlocked) {
            if (!freeware_rainbow_enabled || !freeware_rainbow_armed || P.health >= 5) return;
            shot_sound(8);
            if (P.health >= 5) return;
            fx_queue_add_shell(&shell);
            P.cooldown = .2f;
            P.muzzle_flash += .09f;
            if (P.health >= 5) return;
            projectile_spawn(position_ptr(muzzle + P.position),
                             ((crt_rand() % 20 - 10) * P.spread * .012f + heading), 18);
        } else if (P.weapon == 19) {
            fx_spawn_particle_slow(position_ptr(muzzle + P.position), forward, &P.movement);
            ammo = .15f;
            P.cooldown = .1613f;
        }
#endif
        // Only weapons 10–12 apply the common large muzzle flash below.
        goto finished_shot;
    }
    P.muzzle_flash += .42f;
}
finished_shot:
if (P.perks[perk_id_sharpshooter] <= 0) P.spread += time_scale_factor * frame_dt * 150;
if (P.spread > time_scale_factor * 2) P.spread = time_scale_factor * 2;
P.spread *= time_scale_factor;
if (P.perks[perk_id_ammo_maniac] > 0) ammo *= .8f;
P.ammo -= ammo;
if (P.perks[perk_id_fastshot] > 0) P.cooldown *= .88f;
if (P.perks[perk_id_sharpshooter] > 0) P.cooldown *= 1.05f;
if (P.ammo <= 0) start_reload();
