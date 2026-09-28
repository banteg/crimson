#include "crimsonland_audio.h"
#include "crimsonland_resource.h"

#include <mmsystem.h>

extern "C" void audio_init_sfx(void)
{
    int start_ms;
    int end_ms;
    int sample_count;

    if (config_blob.sound_disabled) {
        return;
    }

    audio_resource_pack_available = resource_pack_set("sfx.paq");
    if (audio_resource_pack_available) {
        console_printf(
            &console_log_queue,
            "...set sound resource paq 'sfx.paq'\n");
    } else {
        console_printf(
            &console_log_queue,
            "...failed to set sound resource paq 'sfx.paq'\n");
    }

    start_ms = timeGetTime();
    audio_asset_id_table[0] = sfx_load_sample("trooper_inPain_01.ogg");
    audio_asset_id_table[1] = sfx_load_sample("trooper_inPain_02.ogg");
    audio_asset_id_table[2] = sfx_load_sample("trooper_inPain_03.ogg");
    audio_asset_id_table[3] = sfx_load_sample("trooper_die_01.ogg");
    audio_asset_id_table[4] = sfx_load_sample("trooper_die_02.ogg");
    audio_asset_id_table[5] = sfx_load_sample("trooper_die_03.ogg");
    audio_asset_id_table[6] = sfx_load_sample("zombie_die_01.ogg");
    audio_asset_id_table[7] = sfx_load_sample("zombie_die_02.ogg");
    audio_asset_id_table[8] = sfx_load_sample("zombie_die_03.ogg");
    audio_asset_id_table[9] = sfx_load_sample("zombie_die_04.ogg");
    audio_asset_id_table[10] = sfx_load_sample("zombie_attack_01.ogg");
    audio_asset_id_table[11] = sfx_load_sample("zombie_attack_02.ogg");
    audio_asset_id_table[12] = sfx_load_sample("alien_die_01.ogg");
    audio_asset_id_table[13] = sfx_load_sample("alien_die_02.ogg");
    audio_asset_id_table[14] = sfx_load_sample("alien_die_03.ogg");
    audio_asset_id_table[15] = sfx_load_sample("alien_die_04.ogg");
    audio_asset_id_table[16] = sfx_load_sample("alien_attack_01.ogg");
    audio_asset_id_table[17] = sfx_load_sample("alien_attack_02.ogg");
    audio_asset_id_table[18] = sfx_load_sample("lizard_die_01.ogg");
    audio_asset_id_table[19] = sfx_load_sample("lizard_die_02.ogg");
    audio_asset_id_table[20] = sfx_load_sample("lizard_die_03.ogg");
    audio_asset_id_table[21] = sfx_load_sample("lizard_die_04.ogg");
    audio_asset_id_table[22] = sfx_load_sample("lizard_attack_01.ogg");
    audio_asset_id_table[23] = sfx_load_sample("lizard_attack_02.ogg");
    audio_asset_id_table[24] = sfx_load_sample("spider_die_01.ogg");
    audio_asset_id_table[25] = sfx_load_sample("spider_die_02.ogg");
    audio_asset_id_table[26] = sfx_load_sample("spider_die_03.ogg");
    audio_asset_id_table[27] = sfx_load_sample("spider_die_04.ogg");
    audio_asset_id_table[28] = sfx_load_sample("spider_attack_01.ogg");
    audio_asset_id_table[29] = sfx_load_sample("spider_attack_02.ogg");
    audio_asset_id_table[30] = sfx_load_sample("pistol_fire.ogg");
    audio_asset_id_table[31] = sfx_load_sample("pistol_reload.ogg");
    audio_asset_id_table[32] = sfx_load_sample("shotgun_fire.ogg");
    audio_asset_id_table[33] = sfx_load_sample("shotgun_reload.ogg");
    audio_asset_id_table[34] = sfx_load_sample("autorifle_fire.ogg");
    audio_asset_id_table[35] = sfx_load_sample("autorifle_reload.ogg");
    audio_asset_id_table[36] = sfx_load_sample("gauss_fire.ogg");
    audio_asset_id_table[38] = sfx_load_sample("hrpm_fire.ogg");
    audio_asset_id_table[39] = sfx_load_sample("shock_fire.ogg");
    audio_asset_id_table[40] = sfx_load_sample("plasmaMinigun_fire.ogg");
    audio_asset_id_table[41] = sfx_load_sample("plasmaShotgun_fire.ogg");
    audio_asset_id_table[42] = sfx_load_sample("pulse_fire.ogg");
    audio_asset_id_table[43] = sfx_load_sample("flamer_fire_01.ogg");
    audio_asset_id_table[44] = sfx_load_sample("flamer_fire_02.ogg");
    audio_asset_id_table[47] = sfx_load_sample("shock_reload.ogg");
    audio_asset_id_table[45] = sfx_load_sample("shock_fire.ogg");
    audio_asset_id_table[46] = sfx_load_sample("shockMinigun_fire.ogg");
    audio_asset_id_table[48] = sfx_load_sample("rocket_fire.ogg");
    audio_asset_id_table[49] = sfx_load_sample("rocketmini_fire.ogg");
    audio_asset_id_table[50] = sfx_load_sample("autorifle_reload.ogg");
    audio_asset_id_table[51] = sfx_load_sample("bullet_hit_01.ogg");
    audio_asset_id_table[52] = sfx_load_sample("bullet_hit_02.ogg");
    audio_asset_id_table[53] = sfx_load_sample("bullet_hit_03.ogg");
    audio_asset_id_table[54] = sfx_load_sample("bullet_hit_04.ogg");
    audio_asset_id_table[55] = sfx_load_sample("bullet_hit_05.ogg");
    audio_asset_id_table[56] = sfx_load_sample("bullet_hit_06.ogg");
    audio_asset_id_table[57] = sfx_load_sample("shock_hit_01.ogg");
    audio_asset_id_table[58] = sfx_load_sample("explosion_small.ogg");
    audio_asset_id_table[59] = sfx_load_sample("explosion_medium.ogg");
    audio_asset_id_table[60] = sfx_load_sample("explosion_large.ogg");
    audio_asset_id_table[61] = sfx_load_sample("shockwave.ogg");
    audio_asset_id_table[62] = sfx_load_sample("questHit.ogg");
    audio_asset_id_table[63] = sfx_load_sample("ui_bonus.ogg");

    audio_asset_id_table[64] = audio_asset_id_table[0];
    audio_asset_id_table[65] = audio_asset_id_table[0];
    audio_asset_id_table[66] = audio_asset_id_table[0];
    audio_asset_id_table[67] = sfx_load_sample("ui_buttonClick.ogg");
    audio_asset_id_table[68] = sfx_load_sample("ui_panelClick.ogg");
    audio_asset_id_table[69] = sfx_load_sample("ui_levelUp.ogg");
    audio_asset_id_table[70] = sfx_load_sample("ui_typeClick_01.ogg");
    audio_asset_id_table[71] = sfx_load_sample("ui_typeClick_02.ogg");
    audio_asset_id_table[72] = sfx_load_sample("ui_typeEnter.ogg");
    audio_asset_id_table[73] = sfx_load_sample("ui_clink_01.ogg");
    audio_asset_id_table[74] = sfx_load_sample("bloodSpill_01.ogg");
    audio_asset_id_table[75] = sfx_load_sample("bloodSpill_02.ogg");

    end_ms = timeGetTime();
    for (sample_count = 0; sample_count < 128; ++sample_count) {
        if (sfx_entry_table[sample_count].pcm_data == 0) {
            break;
        }
    }
    console_printf(
        &console_log_queue,
        "%d samples loaded to sound library in %.2f seconds.\n",
        sample_count,
        (end_ms - start_ms) * 0.001f);
}
