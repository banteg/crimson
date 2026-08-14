#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern int startup_texture_load_stage;
extern int startup_texture_load_stage_count;
extern unsigned char startup_bootstrap_pending;
extern unsigned char terrain_texture_failed;
extern game_state_id_t game_state_id;

extern int world_arrow_marker_texture;
extern int bullet_trail_texture;
extern int bodyset_texture;
extern int projectile_texture;
extern int bonus_texture;
extern int particles_texture;
extern int ui_hud_life_indicator_texture;
extern int ui_hud_panel_texture;
extern int ui_hud_arrow_texture;
extern int ui_cursor_texture;
extern int ui_aim_texture;
extern int terrain_render_target;
extern int terrain_texture_handles;
extern int terrain_texture_layer_1;
extern int terrain_texture_layer_2;
extern int terrain_texture_layer_3;
extern int terrain_texture_layer_4;
extern int terrain_texture_layer_5;
extern int terrain_texture_layer_6;
extern int terrain_texture_layer_7;
extern int ui_text_level_complete_texture;
extern int ui_text_quest_texture;
extern int ui_digit_1_texture;
extern int ui_digit_2_texture;
extern int ui_digit_3_texture;
extern int ui_digit_4_texture;
extern int ui_digit_5_texture;
extern int ui_weapon_icons_texture;
extern int ui_clock_table_texture;
extern int ui_clock_pointer_texture;
extern int muzzle_flash_texture;
extern int projectile_bullet_texture;
extern int aim64_texture;

int texture_get_or_load(char *name, char *path);
int texture_get_or_load_alt(char *path);
}

#define CRIMSONLAND_USE_ORIGINAL_TEXTURES_OWNER
#include "crimsonland_textures_owner.h"

extern "C" int load_textures_step(void)
{
    if (startup_texture_load_stage == 0) {
        texture_get_or_load("GRIM_Font2", "load\\smallWhite.tga");
        texture_get_or_load("trooper", "game\\trooper.jaz");
        texture_get_or_load("zombie", "game\\zombie.jaz");
        texture_get_or_load("spider_sp1", "game\\spider_sp1.jaz");
        texture_get_or_load("spider_sp2", "game\\spider_sp2.jaz");
        texture_get_or_load("alien", "game\\alien.jaz");
        texture_get_or_load("lizard", "game\\lizard.jaz");
    }

    if (startup_texture_load_stage == 1) {
        world_arrow_marker_texture =
            texture_get_or_load("arrow", "load\\arrow.tga");
        texture_get_or_load("bullet_i", "load\\bullet16.tga");
        bullet_trail_texture =
            texture_get_or_load("bulletTrail", "load\\bulletTrail.tga");
        texture_get_or_load("bodyset", "game\\bodyset.jaz");
        bodyset_texture =
            grim_interface_ptr->grim_get_texture_handle("bodyset");
        projectile_texture =
            texture_get_or_load("projs", "game\\projs.jaz");
    }

    if (startup_texture_load_stage == 2) {
        texture_get_or_load("ui_iconAim", "ui\\ui_iconAim.jaz");
        texture_get_or_load("ui_buttonSm", "ui\\ui_button_64x32.jaz");
        texture_get_or_load("ui_buttonMd", "ui\\ui_button_128x32.jaz");
        texture_get_or_load("ui_checkOn", "ui\\ui_checkOn.jaz");
        texture_get_or_load("ui_checkOff", "ui\\ui_checkOff.jaz");
        texture_get_or_load("ui_rectOff", "ui\\ui_rectOff.jaz");
        texture_get_or_load("ui_rectOn", "ui\\ui_rectOn.jaz");
        texture_get_or_load("bonuses", "game\\bonuses.jaz");
    }

    if (startup_texture_load_stage == 3) {
        texture_get_or_load_alt("ui\\ui_indBullet.jaz");
        texture_get_or_load_alt("ui\\ui_indRocket.jaz");
        texture_get_or_load_alt("ui\\ui_indElectric.jaz");
        texture_get_or_load_alt("ui\\ui_indFire.jaz");
        bonus_texture =
            grim_interface_ptr->grim_get_texture_handle("bonuses");
        particles_texture = texture_get_or_load_alt("game\\particles.jaz");
    }

    if (startup_texture_load_stage == 4) {
        ui_hud_life_indicator_texture =
            texture_get_or_load_alt("ui\\ui_indLife.jaz");
        ui_hud_panel_texture =
            texture_get_or_load_alt("ui\\ui_indPanel.jaz");
        ui_hud_arrow_texture = texture_get_or_load_alt("ui\\ui_arrow.jaz");
        ui_cursor_texture = texture_get_or_load_alt("ui\\ui_cursor.jaz");
        ui_aim_texture = texture_get_or_load_alt("ui\\ui_aim.jaz");
    }

    if (startup_texture_load_stage == 5) {
        if (!terrain_texture_failed) {
            terrain_texture_handles =
                texture_get_or_load_alt("ter\\ter_q1_base.jaz");
            terrain_texture_layer_1 =
                texture_get_or_load_alt("ter\\ter_q1_tex1.jaz");
            terrain_texture_layer_2 =
                texture_get_or_load_alt("ter\\ter_q2_base.jaz");
            terrain_texture_layer_3 =
                texture_get_or_load_alt("ter\\ter_q2_tex1.jaz");
            terrain_texture_layer_4 =
                texture_get_or_load_alt("ter\\ter_q3_base.jaz");
            terrain_texture_layer_5 =
                texture_get_or_load_alt("ter\\ter_q3_tex1.jaz");
            terrain_texture_layer_6 =
                texture_get_or_load_alt("ter\\ter_q4_base.jaz");
            terrain_texture_layer_7 =
                texture_get_or_load_alt("ter\\ter_q4_tex1.jaz");
        } else {
            terrain_texture_handles =
                texture_get_or_load_alt("ter\\fb_q1.jaz");
            terrain_texture_layer_1 =
                texture_get_or_load_alt("ter\\fb_q2.jaz");
            terrain_texture_layer_2 =
                texture_get_or_load_alt("ter\\fb_q3.jaz");
            terrain_texture_layer_3 =
                texture_get_or_load_alt("ter\\fb_q4.jaz");
            terrain_render_target = terrain_texture_handles;
        }
    }

    if (startup_texture_load_stage == 6) {
        ui_text_level_complete_texture =
            texture_get_or_load_alt("ui\\ui_textLevComp.jaz");
        ui_text_quest_texture =
            texture_get_or_load_alt("ui\\ui_textQuest.jaz");
        ui_digit_1_texture = texture_get_or_load_alt("ui\\ui_num1.jaz");
        ui_digit_2_texture = texture_get_or_load_alt("ui\\ui_num2.jaz");
        ui_digit_3_texture = texture_get_or_load_alt("ui\\ui_num3.jaz");
        ui_digit_4_texture = texture_get_or_load_alt("ui\\ui_num4.jaz");
        ui_digit_5_texture = texture_get_or_load_alt("ui\\ui_num5.jaz");
    }

    if (startup_texture_load_stage == 7) {
        ui_weapon_icons_texture =
            texture_get_or_load("ui_wicons", "ui\\ui_wicons.jaz");
        texture_get_or_load("iGameUI", "ui\\ui_gameTop.jaz");
        texture_get_or_load("iHeart", "ui\\ui_lifeHeart.jaz");
        ui_clock_table_texture =
            texture_get_or_load_alt("ui\\ui_clockTable.jaz");
        ui_clock_pointer_texture =
            texture_get_or_load_alt("ui\\ui_clockPointer.jaz");
    }

    if (startup_texture_load_stage == 8) {
        muzzle_flash_texture =
            texture_get_or_load_alt("game\\muzzleFlash.jaz");
        texture_get_or_load("ui_dropOn", "ui\\ui_dropDownOn.jaz");
        texture_get_or_load("ui_dropOff", "ui\\ui_dropDownOff.jaz");
        if (!terrain_texture_failed) {
            terrain_render_target =
                grim_interface_ptr->grim_get_texture_handle("ground");
        }
    }

    if (startup_texture_load_stage == 9) {
        game_state_id = GAME_STATE_MAIN_MENU;
        projectile_bullet_texture =
            grim_interface_ptr->grim_get_texture_handle("bullet_i");
        aim64_texture =
            grim_interface_ptr->grim_get_texture_handle("aim64");
        startup_bootstrap_pending = 1;
    }

    startup_texture_load_stage_count = 11;
    ++startup_texture_load_stage;
    console_log_queue.flush_log("console.log");
    return startup_texture_load_stage >= 11;
}
