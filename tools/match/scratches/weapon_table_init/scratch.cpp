#include <string.h>

#include "crimsonland_gameplay.h"

typedef struct weapon_native_entry_t {
    int ammo_class;
    char name[0x40];
    unsigned char unlocked;
    unsigned char _pad0[3];
    int clip_size;
    float shot_cooldown;
    float reload_time;
    float spread_heat;
    unsigned char _pad1[4];
    int shot_sfx_base_id;
    int shot_sfx_variant_count;
    int reload_sfx_id;
    int hud_icon_id;
    int flags;
    float travel_budget;
    float damage_scale;
    int pellet_count;
} weapon_native_entry_t;

extern "C" {
extern weapon_native_entry_t weapon_ammo_class[];

extern int sfx_pistol_fire;
extern int sfx_pistol_reload;
extern int sfx_shotgun_fire;
extern int sfx_shotgun_reload;
extern int sfx_autorifle_fire;
extern int sfx_autorifle_reload;
extern int sfx_gauss_fire;
extern int sfx_hrpm_fire;
extern int sfx_shock_fire;
extern int sfx_plasmaminigun_fire;
extern int sfx_plasmashotgun_fire;
extern int sfx_pulse_fire;
extern int sfx_flamer_fire_01;
extern int sfx_shock_fire_alt;
extern int sfx_shockminigun_fire;
extern int sfx_shock_reload;
extern int sfx_rocket_fire;
extern int sfx_rocketmini_fire;
extern int sfx_autorifle_reload_alt;
extern int sfx_explosion_large;
extern int sfx_bloodspill_01;
}

#define W(id) weapon_ammo_class[(id)]

extern "C" void weapon_table_init(void)
{
    int weapon_id;

    for (weapon_id = 0; weapon_id < 64; ++weapon_id) {
        W(weapon_id).hud_icon_id = weapon_id - 1;
        W(weapon_id).pellet_count = 1;
    }
    W(WEAPON_ID_NONE).hud_icon_id = 0;

    W(WEAPON_ID_PLASMA_RIFLE).travel_budget = 30.0f;
    W(WEAPON_ID_PLASMA_MINIGUN).travel_budget = 35.0f;
    W(WEAPON_ID_ION_RIFLE).travel_budget = 15.0f;
    W(WEAPON_ID_ION_MINIGUN).travel_budget = 20.0f;
    W(WEAPON_ID_ION_CANNON).travel_budget = 10.0f;
    W(WEAPON_ID_PLASMA_CANNON).travel_budget = 10.0f;
    W(WEAPON_ID_PULSE_GUN).travel_budget = 20.0f;
    W(WEAPON_ID_GAUSS_GUN).travel_budget = 215.0f;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).travel_budget = 15.0f;
    W(WEAPON_ID_RAINBOW_GUN).travel_budget = 10.0f;
    W(WEAPON_ID_SHOTGUN).travel_budget = 60.0f;
    W(WEAPON_ID_PISTOL).travel_budget = 55.0f;
    W(WEAPON_ID_ASSAULT_RIFLE).travel_budget = 50.0f;
    W(WEAPON_ID_BLADE_GUN).travel_budget = 20.0f;
    W(WEAPON_ID_BLADE_GUN).damage_scale = 11.0f;
    W(WEAPON_ID_FIRE_BULLETS).travel_budget = 60.0f;
    W(WEAPON_ID_FIRE_BULLETS).damage_scale = 0.25f;
    W(WEAPON_ID_SPIDER_PLASMA).travel_budget = 10.0f;
    W(WEAPON_ID_SPIDER_PLASMA).damage_scale = 0.5f;
    W(WEAPON_ID_PLASMA_RIFLE).damage_scale = 5.0f;
    W(WEAPON_ID_PLASMA_MINIGUN).damage_scale = 2.1f;
    W(WEAPON_ID_ION_RIFLE).damage_scale = 3.0f;
    W(WEAPON_ID_ION_MINIGUN).damage_scale = 1.4f;
    W(WEAPON_ID_ION_CANNON).damage_scale = 16.7f;
    W(WEAPON_ID_PLASMA_CANNON).damage_scale = 28.0f;
    W(WEAPON_ID_PULSE_GUN).damage_scale = 1.0f;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).damage_scale = 0.0f;
    W(WEAPON_ID_SHOTGUN).damage_scale = 1.2f;
    W(WEAPON_ID_PISTOL).damage_scale = 4.1f;
    W(WEAPON_ID_SHRINKIFIER_5K).damage_scale = 0.0f;

    strcpy(W(WEAPON_ID_FIRE_BULLETS).name, "Fire bullets");
    W(WEAPON_ID_FIRE_BULLETS).flags = 1;
    W(WEAPON_ID_FIRE_BULLETS).clip_size = 112;
    W(WEAPON_ID_FIRE_BULLETS).shot_cooldown = 0.14f;
    W(WEAPON_ID_FIRE_BULLETS).reload_time = 1.2f;
    W(WEAPON_ID_FIRE_BULLETS).spread_heat = 0.22f;
    W(WEAPON_ID_FIRE_BULLETS).shot_sfx_base_id = sfx_autorifle_fire;
    W(WEAPON_ID_FIRE_BULLETS).reload_sfx_id = sfx_pistol_reload;

    strcpy(W(WEAPON_ID_PISTOL).name, "Pistol");
    W(WEAPON_ID_PISTOL).flags = 5;
    W(WEAPON_ID_PISTOL).clip_size = 12;
    W(WEAPON_ID_PISTOL).shot_cooldown = 0.7117f;
    W(WEAPON_ID_PISTOL).reload_time = 1.2f;
    W(WEAPON_ID_PISTOL).spread_heat = 0.22f;
    W(WEAPON_ID_PISTOL).shot_sfx_base_id = sfx_pistol_fire;
    W(WEAPON_ID_PISTOL).reload_sfx_id = sfx_pistol_reload;

    strcpy(W(WEAPON_ID_ASSAULT_RIFLE).name, "Assault Rifle");
    W(WEAPON_ID_ASSAULT_RIFLE).flags = 1;
    W(WEAPON_ID_ASSAULT_RIFLE).clip_size = 25;
    W(WEAPON_ID_ASSAULT_RIFLE).shot_cooldown = 0.117f;
    W(WEAPON_ID_ASSAULT_RIFLE).reload_time = 1.2f;
    W(WEAPON_ID_ASSAULT_RIFLE).spread_heat = 0.09f;
    W(WEAPON_ID_ASSAULT_RIFLE).shot_sfx_base_id = sfx_autorifle_fire;
    W(WEAPON_ID_ASSAULT_RIFLE).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_SHOTGUN).name, "Shotgun");
    W(WEAPON_ID_SHOTGUN).clip_size = 12;
    W(WEAPON_ID_SHOTGUN).pellet_count = 12;
    W(WEAPON_ID_SHOTGUN).flags = 1;
    W(WEAPON_ID_SHOTGUN).shot_cooldown = 0.85f;
    W(WEAPON_ID_SHOTGUN).reload_time = 1.9f;
    W(WEAPON_ID_SHOTGUN).spread_heat = 0.27f;
    W(WEAPON_ID_SHOTGUN).shot_sfx_base_id = sfx_shotgun_fire;
    W(WEAPON_ID_SHOTGUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_SAWED_OFF_SHOTGUN).name, "Sawed-off Shotgun");
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).clip_size = 12;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).pellet_count = 12;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).flags = 1;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).shot_cooldown = 0.87f;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).reload_time = 1.9f;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).spread_heat = 0.13f;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).shot_sfx_base_id = sfx_shotgun_fire;
    W(WEAPON_ID_SAWED_OFF_SHOTGUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_JACKHAMMER).name, "Jackhammer");
    W(WEAPON_ID_JACKHAMMER).flags = 1;
    W(WEAPON_ID_JACKHAMMER).clip_size = 16;
    W(WEAPON_ID_JACKHAMMER).shot_cooldown = 0.14f;
    W(WEAPON_ID_JACKHAMMER).reload_time = 3.0f;
    W(WEAPON_ID_JACKHAMMER).spread_heat = 0.16f;
    W(WEAPON_ID_JACKHAMMER).pellet_count = 4;
    W(WEAPON_ID_JACKHAMMER).shot_sfx_base_id = sfx_shotgun_fire;
    W(WEAPON_ID_JACKHAMMER).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_SUBMACHINE_GUN).name, "Submachine Gun");
    W(WEAPON_ID_SUBMACHINE_GUN).flags = 5;
    W(WEAPON_ID_SUBMACHINE_GUN).clip_size = 30;
    W(WEAPON_ID_SUBMACHINE_GUN).shot_cooldown = 0.088117f;
    W(WEAPON_ID_SUBMACHINE_GUN).reload_time = 1.2f;
    W(WEAPON_ID_SUBMACHINE_GUN).spread_heat = 0.082f;
    W(WEAPON_ID_SUBMACHINE_GUN).shot_sfx_base_id = sfx_hrpm_fire;
    W(WEAPON_ID_SUBMACHINE_GUN).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_FLAMETHROWER).name, "Flamethrower");
    W(WEAPON_ID_FLAMETHROWER).flags = 8;
    W(WEAPON_ID_FLAMETHROWER).shot_sfx_variant_count = 2;
    W(WEAPON_ID_FLAMETHROWER).clip_size = 30;
    W(WEAPON_ID_FLAMETHROWER).shot_cooldown = 0.008113f;
    W(WEAPON_ID_FLAMETHROWER).reload_time = 2.0f;
    W(WEAPON_ID_FLAMETHROWER).spread_heat = 0.015f;
    W(WEAPON_ID_FLAMETHROWER).shot_sfx_base_id = sfx_flamer_fire_01;
    W(WEAPON_ID_FLAMETHROWER).ammo_class = 1;
    W(WEAPON_ID_FLAMETHROWER).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_PLASMA_RIFLE).name, "Plasma Rifle");
    W(WEAPON_ID_PLASMA_RIFLE).clip_size = 20;
    W(WEAPON_ID_PLASMA_RIFLE).shot_cooldown = 0.2908117f;
    W(WEAPON_ID_PLASMA_RIFLE).reload_time = 1.2f;
    W(WEAPON_ID_PLASMA_RIFLE).spread_heat = 0.182f;
    W(WEAPON_ID_PLASMA_RIFLE).shot_sfx_base_id = sfx_shock_fire;
    W(WEAPON_ID_PLASMA_RIFLE).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_MULTI_PLASMA).name, "Multi-Plasma");
    W(WEAPON_ID_MULTI_PLASMA).clip_size = 8;
    W(WEAPON_ID_MULTI_PLASMA).shot_cooldown = 0.6208117f;
    W(WEAPON_ID_MULTI_PLASMA).reload_time = 1.4f;
    W(WEAPON_ID_MULTI_PLASMA).spread_heat = 0.32f;
    W(WEAPON_ID_MULTI_PLASMA).shot_sfx_base_id = sfx_shock_fire;
    W(WEAPON_ID_MULTI_PLASMA).pellet_count = 3;
    W(WEAPON_ID_MULTI_PLASMA).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_PLASMA_MINIGUN).name, "Plasma Minigun");
    W(WEAPON_ID_PLASMA_MINIGUN).clip_size = 30;
    W(WEAPON_ID_PLASMA_MINIGUN).shot_cooldown = 0.11f;
    W(WEAPON_ID_PLASMA_MINIGUN).reload_time = 1.3f;
    W(WEAPON_ID_PLASMA_MINIGUN).spread_heat = 0.097f;
    W(WEAPON_ID_PLASMA_MINIGUN).shot_sfx_base_id = sfx_plasmaminigun_fire;
    W(WEAPON_ID_PLASMA_MINIGUN).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_GAUSS_GUN).name, "Gauss Gun");
    W(WEAPON_ID_GAUSS_GUN).flags = 1;
    W(WEAPON_ID_GAUSS_GUN).clip_size = 6;
    W(WEAPON_ID_GAUSS_GUN).shot_cooldown = 0.6f;
    W(WEAPON_ID_GAUSS_GUN).reload_time = 1.6f;
    W(WEAPON_ID_GAUSS_GUN).spread_heat = 0.42f;
    W(WEAPON_ID_GAUSS_GUN).shot_sfx_base_id = sfx_gauss_fire;
    W(WEAPON_ID_GAUSS_GUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_ROCKET_LAUNCHER).name, "Rocket Launcher");
    W(WEAPON_ID_ROCKET_LAUNCHER).flags = 8;
    W(WEAPON_ID_ROCKET_LAUNCHER).clip_size = 5;
    W(WEAPON_ID_ROCKET_LAUNCHER).shot_cooldown = 0.7408117f;
    W(WEAPON_ID_ROCKET_LAUNCHER).reload_time = 1.2f;
    W(WEAPON_ID_ROCKET_LAUNCHER).spread_heat = 0.42f;
    W(WEAPON_ID_ROCKET_LAUNCHER).shot_sfx_base_id = sfx_rocket_fire;
    W(WEAPON_ID_ROCKET_LAUNCHER).reload_sfx_id = sfx_autorifle_reload_alt;
    W(WEAPON_ID_ROCKET_LAUNCHER).ammo_class = 2;

    strcpy(W(WEAPON_ID_SEEKER_ROCKETS).name, "Seeker Rockets");
    W(WEAPON_ID_SEEKER_ROCKETS).flags = 8;
    W(WEAPON_ID_SEEKER_ROCKETS).clip_size = 8;
    W(WEAPON_ID_SEEKER_ROCKETS).shot_cooldown = 0.3108117f;
    W(WEAPON_ID_SEEKER_ROCKETS).reload_time = 1.2f;
    W(WEAPON_ID_SEEKER_ROCKETS).spread_heat = 0.32f;
    W(WEAPON_ID_SEEKER_ROCKETS).shot_sfx_base_id = sfx_rocket_fire;
    W(WEAPON_ID_SEEKER_ROCKETS).reload_sfx_id = sfx_autorifle_reload_alt;
    W(WEAPON_ID_SEEKER_ROCKETS).ammo_class = 2;

    strcpy(W(WEAPON_ID_MEAN_MINIGUN).name, "Mean Minigun");
    W(WEAPON_ID_MEAN_MINIGUN).flags = 3;
    W(WEAPON_ID_MEAN_MINIGUN).clip_size = 120;
    W(WEAPON_ID_MEAN_MINIGUN).shot_cooldown = 0.09f;
    W(WEAPON_ID_MEAN_MINIGUN).reload_time = 4.0f;
    W(WEAPON_ID_MEAN_MINIGUN).spread_heat = 0.062f;
    W(WEAPON_ID_MEAN_MINIGUN).shot_sfx_base_id = sfx_autorifle_fire;
    W(WEAPON_ID_MEAN_MINIGUN).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_PLASMA_SHOTGUN).name, "Plasma Shotgun");
    W(WEAPON_ID_PLASMA_SHOTGUN).clip_size = 8;
    W(WEAPON_ID_PLASMA_SHOTGUN).shot_cooldown = 0.48f;
    W(WEAPON_ID_PLASMA_SHOTGUN).reload_time = 3.1f;
    W(WEAPON_ID_PLASMA_SHOTGUN).spread_heat = 0.11f;
    W(WEAPON_ID_PLASMA_SHOTGUN).shot_sfx_base_id = sfx_plasmashotgun_fire;
    W(WEAPON_ID_PLASMA_SHOTGUN).pellet_count = 14;
    W(WEAPON_ID_PLASMA_SHOTGUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_BLOW_TORCH).name, "Blow Torch");
    W(WEAPON_ID_BLOW_TORCH).flags = 8;
    W(WEAPON_ID_BLOW_TORCH).shot_sfx_variant_count = 2;
    W(WEAPON_ID_BLOW_TORCH).clip_size = 30;
    W(WEAPON_ID_BLOW_TORCH).shot_cooldown = 0.006113f;
    W(WEAPON_ID_BLOW_TORCH).reload_time = 1.5f;
    W(WEAPON_ID_BLOW_TORCH).spread_heat = 0.01f;
    W(WEAPON_ID_BLOW_TORCH).shot_sfx_base_id = sfx_flamer_fire_01;
    W(WEAPON_ID_BLOW_TORCH).ammo_class = 1;
    W(WEAPON_ID_BLOW_TORCH).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_HR_FLAMER).name, "HR Flamer");
    W(WEAPON_ID_HR_FLAMER).flags = 8;
    W(WEAPON_ID_HR_FLAMER).shot_sfx_variant_count = 2;
    W(WEAPON_ID_HR_FLAMER).clip_size = 30;
    W(WEAPON_ID_HR_FLAMER).shot_cooldown = 0.0085f;
    W(WEAPON_ID_HR_FLAMER).reload_time = 1.8f;
    W(WEAPON_ID_HR_FLAMER).spread_heat = 0.01f;
    W(WEAPON_ID_HR_FLAMER).shot_sfx_base_id = sfx_flamer_fire_01;
    W(WEAPON_ID_HR_FLAMER).ammo_class = 1;
    W(WEAPON_ID_HR_FLAMER).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_MINI_ROCKET_SWARMERS).name, "Mini-Rocket Swarmers");
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).flags = 8;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).clip_size = 5;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).shot_cooldown = 1.8f;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).reload_time = 1.8f;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).spread_heat = 0.12f;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).shot_sfx_base_id = sfx_rocket_fire;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).reload_sfx_id = sfx_autorifle_reload_alt;
    W(WEAPON_ID_MINI_ROCKET_SWARMERS).ammo_class = 2;

    strcpy(W(WEAPON_ID_ROCKET_MINIGUN).name, "Rocket Minigun");
    W(WEAPON_ID_ROCKET_MINIGUN).flags = 8;
    W(WEAPON_ID_ROCKET_MINIGUN).clip_size = 16;
    W(WEAPON_ID_ROCKET_MINIGUN).shot_cooldown = 0.12f;
    W(WEAPON_ID_ROCKET_MINIGUN).reload_time = 1.8f;
    W(WEAPON_ID_ROCKET_MINIGUN).spread_heat = 0.12f;
    W(WEAPON_ID_ROCKET_MINIGUN).shot_sfx_base_id = sfx_rocketmini_fire;
    W(WEAPON_ID_ROCKET_MINIGUN).reload_sfx_id = sfx_autorifle_reload_alt;
    W(WEAPON_ID_ROCKET_MINIGUN).ammo_class = 2;

    strcpy(W(WEAPON_ID_PULSE_GUN).name, "Pulse Gun");
    W(WEAPON_ID_PULSE_GUN).flags = 8;
    W(WEAPON_ID_PULSE_GUN).clip_size = 16;
    W(WEAPON_ID_PULSE_GUN).shot_cooldown = 0.1f;
    W(WEAPON_ID_PULSE_GUN).reload_time = 0.1f;
    W(WEAPON_ID_PULSE_GUN).spread_heat = 0.0f;
    W(WEAPON_ID_PULSE_GUN).shot_sfx_base_id = sfx_pulse_fire;
    W(WEAPON_ID_PULSE_GUN).ammo_class = 3;
    W(WEAPON_ID_PULSE_GUN).reload_sfx_id = sfx_autorifle_reload;

    strcpy(W(WEAPON_ID_ION_RIFLE).name, "Ion Rifle");
    W(WEAPON_ID_ION_RIFLE).flags = 8;
    W(WEAPON_ID_ION_RIFLE).clip_size = 8;
    W(WEAPON_ID_ION_RIFLE).shot_cooldown = 0.4f;
    W(WEAPON_ID_ION_RIFLE).reload_time = 1.35f;
    W(WEAPON_ID_ION_RIFLE).spread_heat = 0.112f;
    W(WEAPON_ID_ION_RIFLE).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_ION_RIFLE).ammo_class = 4;
    W(WEAPON_ID_ION_RIFLE).reload_sfx_id = sfx_shock_reload;

    strcpy(W(WEAPON_ID_ION_MINIGUN).name, "Ion Minigun");
    W(WEAPON_ID_ION_MINIGUN).flags = 8;
    W(WEAPON_ID_ION_MINIGUN).clip_size = 20;
    W(WEAPON_ID_ION_MINIGUN).shot_cooldown = 0.1f;
    W(WEAPON_ID_ION_MINIGUN).reload_time = 1.8f;
    W(WEAPON_ID_ION_MINIGUN).spread_heat = 0.09f;
    W(WEAPON_ID_ION_MINIGUN).shot_sfx_base_id = sfx_shockminigun_fire;
    W(WEAPON_ID_ION_MINIGUN).ammo_class = 4;
    W(WEAPON_ID_ION_MINIGUN).reload_sfx_id = sfx_shock_reload;

    strcpy(W(WEAPON_ID_ION_CANNON).name, "Ion Cannon");
    W(WEAPON_ID_ION_CANNON).clip_size = 3;
    W(WEAPON_ID_ION_CANNON).shot_cooldown = 1.0f;
    W(WEAPON_ID_ION_CANNON).reload_time = 3.0f;
    W(WEAPON_ID_ION_CANNON).spread_heat = 0.68f;
    W(WEAPON_ID_ION_CANNON).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_ION_CANNON).ammo_class = 4;
    W(WEAPON_ID_ION_CANNON).reload_sfx_id = sfx_shock_reload;

    strcpy(W(WEAPON_ID_ION_SHOTGUN).name, "Ion Shotgun");
    W(WEAPON_ID_ION_SHOTGUN).flags = 1;
    W(WEAPON_ID_ION_SHOTGUN).clip_size = 10;
    W(WEAPON_ID_ION_SHOTGUN).shot_cooldown = 0.85f;
    W(WEAPON_ID_ION_SHOTGUN).reload_time = 1.9f;
    W(WEAPON_ID_ION_SHOTGUN).spread_heat = 0.27f;
    W(WEAPON_ID_ION_SHOTGUN).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_ION_SHOTGUN).pellet_count = 8;
    W(WEAPON_ID_ION_SHOTGUN).ammo_class = 4;
    W(WEAPON_ID_ION_SHOTGUN).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_ION_SHOTGUN).hud_icon_id = 31;

    strcpy(W(WEAPON_ID_GAUSS_SHOTGUN).name, "Gauss Shotgun");
    W(WEAPON_ID_GAUSS_SHOTGUN).flags = 1;
    W(WEAPON_ID_GAUSS_SHOTGUN).clip_size = 4;
    W(WEAPON_ID_GAUSS_SHOTGUN).shot_cooldown = 1.05f;
    W(WEAPON_ID_GAUSS_SHOTGUN).reload_time = 2.1f;
    W(WEAPON_ID_GAUSS_SHOTGUN).spread_heat = 0.27f;
    W(WEAPON_ID_GAUSS_SHOTGUN).shot_sfx_base_id = sfx_gauss_fire;
    W(WEAPON_ID_GAUSS_SHOTGUN).ammo_class = 0;
    W(WEAPON_ID_GAUSS_SHOTGUN).reload_sfx_id = sfx_shotgun_reload;
    W(WEAPON_ID_GAUSS_SHOTGUN).hud_icon_id = 30;

    strcpy(W(WEAPON_ID_PLASMA_CANNON).name, "Plasma Cannon");
    W(WEAPON_ID_PLASMA_CANNON).clip_size = 3;
    W(WEAPON_ID_PLASMA_CANNON).shot_cooldown = 0.9f;
    W(WEAPON_ID_PLASMA_CANNON).reload_time = 2.7f;
    W(WEAPON_ID_PLASMA_CANNON).spread_heat = 0.6f;
    W(WEAPON_ID_PLASMA_CANNON).shot_sfx_base_id = sfx_shock_fire;
    W(WEAPON_ID_PLASMA_CANNON).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_PLASMA_CANNON).hud_icon_id = 25;

    strcpy(W(WEAPON_ID_EVIL_SCYTHE).name, "Evil Scythe");
    W(WEAPON_ID_EVIL_SCYTHE).clip_size = 3;
    W(WEAPON_ID_EVIL_SCYTHE).shot_cooldown = 1.0f;
    W(WEAPON_ID_EVIL_SCYTHE).reload_time = 3.0f;
    W(WEAPON_ID_EVIL_SCYTHE).spread_heat = 0.68f;
    W(WEAPON_ID_EVIL_SCYTHE).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_EVIL_SCYTHE).ammo_class = 4;
    W(WEAPON_ID_EVIL_SCYTHE).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_EVIL_SCYTHE).hud_icon_id = 25;

    strcpy(W(WEAPON_ID_FLAMEBURST).name, "Flameburst");
    W(WEAPON_ID_FLAMEBURST).clip_size = 60;
    W(WEAPON_ID_FLAMEBURST).shot_cooldown = 0.02f;
    W(WEAPON_ID_FLAMEBURST).reload_time = 3.0f;
    W(WEAPON_ID_FLAMEBURST).spread_heat = 0.18f;
    W(WEAPON_ID_FLAMEBURST).shot_sfx_base_id = sfx_flamer_fire_01;
    W(WEAPON_ID_FLAMEBURST).ammo_class = 4;
    W(WEAPON_ID_FLAMEBURST).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_FLAMEBURST).hud_icon_id = 29;

    strcpy(W(WEAPON_ID_RAYGUN).name, "RayGun");
    W(WEAPON_ID_RAYGUN).clip_size = 12;
    W(WEAPON_ID_RAYGUN).shot_cooldown = 0.7f;
    W(WEAPON_ID_RAYGUN).reload_time = 2.0f;
    W(WEAPON_ID_RAYGUN).spread_heat = 0.38f;
    W(WEAPON_ID_RAYGUN).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_RAYGUN).ammo_class = 4;
    W(WEAPON_ID_RAYGUN).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_RAYGUN).hud_icon_id = 30;

    strcpy(W(WEAPON_ID_SPLITTER_GUN).name, "Splitter Gun");
    W(WEAPON_ID_SPLITTER_GUN).clip_size = 6;
    W(WEAPON_ID_SPLITTER_GUN).shot_cooldown = 0.7f;
    W(WEAPON_ID_SPLITTER_GUN).reload_time = 2.2f;
    W(WEAPON_ID_SPLITTER_GUN).spread_heat = 0.28f;
    W(WEAPON_ID_SPLITTER_GUN).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_SPLITTER_GUN).ammo_class = 0;
    W(WEAPON_ID_SPLITTER_GUN).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_SPLITTER_GUN).damage_scale = 6.0f;
    W(WEAPON_ID_SPLITTER_GUN).travel_budget = 30.0f;

    strcpy(W(WEAPON_ID_SHRINKIFIER_5K).name, "Shrinkifier 5k");
    W(WEAPON_ID_SHRINKIFIER_5K).flags = 8;
    W(WEAPON_ID_SHRINKIFIER_5K).clip_size = 8;
    W(WEAPON_ID_SHRINKIFIER_5K).shot_cooldown = 0.21f;
    W(WEAPON_ID_SHRINKIFIER_5K).reload_time = 1.22f;
    W(WEAPON_ID_SHRINKIFIER_5K).spread_heat = 0.04f;
    W(WEAPON_ID_SHRINKIFIER_5K).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_SHRINKIFIER_5K).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_SHRINKIFIER_5K).hud_icon_id = 23;

    strcpy(W(WEAPON_ID_BLADE_GUN).name, "Blade Gun");
    W(WEAPON_ID_BLADE_GUN).flags = 8;
    W(WEAPON_ID_BLADE_GUN).clip_size = 6;
    W(WEAPON_ID_BLADE_GUN).shot_cooldown = 0.35f;
    W(WEAPON_ID_BLADE_GUN).reload_time = 3.5f;
    W(WEAPON_ID_BLADE_GUN).spread_heat = 0.04f;
    W(WEAPON_ID_BLADE_GUN).shot_sfx_base_id = sfx_shock_fire_alt;
    W(WEAPON_ID_BLADE_GUN).reload_sfx_id = sfx_shock_reload;
    W(WEAPON_ID_BLADE_GUN).hud_icon_id = 24;

    strcpy(W(WEAPON_ID_PLAGUE_SPREADER_GUN).name, "Plague Sphreader Gun");
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).flags = 8;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).clip_size = 5;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).shot_cooldown = 0.2f;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).reload_time = 1.2f;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).spread_heat = 0.04f;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_PLAGUE_SPREADER_GUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_RAINBOW_GUN).name, "Rainbow Gun");
    W(WEAPON_ID_RAINBOW_GUN).flags = 8;
    W(WEAPON_ID_RAINBOW_GUN).clip_size = 10;
    W(WEAPON_ID_RAINBOW_GUN).shot_cooldown = 0.2f;
    W(WEAPON_ID_RAINBOW_GUN).reload_time = 1.2f;
    W(WEAPON_ID_RAINBOW_GUN).spread_heat = 0.09f;
    W(WEAPON_ID_RAINBOW_GUN).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_RAINBOW_GUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_GRIM_WEAPON).name, "Grim Weapon");
    W(WEAPON_ID_GRIM_WEAPON).clip_size = 3;
    W(WEAPON_ID_GRIM_WEAPON).shot_cooldown = 0.5f;
    W(WEAPON_ID_GRIM_WEAPON).reload_time = 1.2f;
    W(WEAPON_ID_GRIM_WEAPON).spread_heat = 0.4f;
    W(WEAPON_ID_GRIM_WEAPON).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_GRIM_WEAPON).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_BUBBLEGUN).name, "Bubblegun");
    W(WEAPON_ID_BUBBLEGUN).flags = 8;
    W(WEAPON_ID_BUBBLEGUN).clip_size = 15;
    W(WEAPON_ID_BUBBLEGUN).shot_cooldown = 0.1613f;
    W(WEAPON_ID_BUBBLEGUN).reload_time = 1.2f;
    W(WEAPON_ID_BUBBLEGUN).spread_heat = 0.05f;
    W(WEAPON_ID_BUBBLEGUN).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_BUBBLEGUN).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_SPIDER_PLASMA).name, "Spider Plasma");
    W(WEAPON_ID_SPIDER_PLASMA).flags = 8;
    W(WEAPON_ID_SPIDER_PLASMA).clip_size = 5;
    W(WEAPON_ID_SPIDER_PLASMA).shot_cooldown = 0.2f;
    W(WEAPON_ID_SPIDER_PLASMA).reload_time = 1.2f;
    W(WEAPON_ID_SPIDER_PLASMA).spread_heat = 0.04f;
    W(WEAPON_ID_SPIDER_PLASMA).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_SPIDER_PLASMA).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_TRANSMUTATOR).name, "Transmutator");
    W(WEAPON_ID_TRANSMUTATOR).flags = 9;
    W(WEAPON_ID_TRANSMUTATOR).clip_size = 50;
    W(WEAPON_ID_TRANSMUTATOR).shot_cooldown = 0.04f;
    W(WEAPON_ID_TRANSMUTATOR).reload_time = 5.0f;
    W(WEAPON_ID_TRANSMUTATOR).spread_heat = 0.04f;
    W(WEAPON_ID_TRANSMUTATOR).shot_sfx_base_id = sfx_bloodspill_01;
    W(WEAPON_ID_TRANSMUTATOR).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_BLASTER_R_300).name, "Blaster R-300");
    W(WEAPON_ID_BLASTER_R_300).flags = 9;
    W(WEAPON_ID_BLASTER_R_300).clip_size = 20;
    W(WEAPON_ID_BLASTER_R_300).shot_cooldown = 0.08f;
    W(WEAPON_ID_BLASTER_R_300).reload_time = 2.0f;
    W(WEAPON_ID_BLASTER_R_300).spread_heat = 0.05f;
    W(WEAPON_ID_BLASTER_R_300).shot_sfx_base_id = sfx_shock_fire;
    W(WEAPON_ID_BLASTER_R_300).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_NUKE_LAUNCHER).name, "Nuke Launcher");
    W(WEAPON_ID_NUKE_LAUNCHER).flags = 8;
    W(WEAPON_ID_NUKE_LAUNCHER).clip_size = 1;
    W(WEAPON_ID_NUKE_LAUNCHER).shot_cooldown = 4.0f;
    W(WEAPON_ID_NUKE_LAUNCHER).reload_time = 8.0f;
    W(WEAPON_ID_NUKE_LAUNCHER).spread_heat = 1.0f;
    W(WEAPON_ID_NUKE_LAUNCHER).shot_sfx_base_id = sfx_explosion_large;
    W(WEAPON_ID_NUKE_LAUNCHER).reload_sfx_id = sfx_shotgun_reload;

    strcpy(W(WEAPON_ID_LIGHTNING_RIFLE).name, "Lighting Rifle");
    W(WEAPON_ID_LIGHTNING_RIFLE).flags = 8;
    W(WEAPON_ID_LIGHTNING_RIFLE).clip_size = 500;
    W(WEAPON_ID_LIGHTNING_RIFLE).shot_cooldown = 4.0f;
    W(WEAPON_ID_LIGHTNING_RIFLE).reload_time = 8.0f;
    W(WEAPON_ID_LIGHTNING_RIFLE).spread_heat = 1.0f;
    W(WEAPON_ID_LIGHTNING_RIFLE).shot_sfx_base_id = sfx_explosion_large;
    W(WEAPON_ID_LIGHTNING_RIFLE).reload_sfx_id = sfx_shotgun_reload;
}
