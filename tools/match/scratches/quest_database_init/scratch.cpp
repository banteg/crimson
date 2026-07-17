#include "crimsonland_gameplay.h"

extern "C" void quest_meta_init_entry(
    quest_meta_t *meta,
    int tier,
    int index,
    char *name);
extern "C" void quest_database_advance_slot(int *tier, int *index);
extern "C" quest_meta_t *quest_monster_vision_meta;

#define QUEST_BUILDER(name) \
    extern "C" void name(quest_spawn_entry_t *entries, int *count)

QUEST_BUILDER(quest_build_land_hostile);
QUEST_BUILDER(quest_build_minor_alien_breach);
QUEST_BUILDER(quest_build_target_practice);
QUEST_BUILDER(quest_build_frontline_assault);
QUEST_BUILDER(quest_build_alien_dens);
QUEST_BUILDER(quest_build_the_random_factor);
QUEST_BUILDER(quest_build_spider_wave_syndrome);
QUEST_BUILDER(quest_build_alien_squads);
QUEST_BUILDER(quest_build_nesting_grounds);
QUEST_BUILDER(quest_build_8_legged_terror);
QUEST_BUILDER(quest_build_everred_pastures);
QUEST_BUILDER(quest_build_spider_spawns);
QUEST_BUILDER(quest_build_arachnoid_farm);
QUEST_BUILDER(quest_build_two_fronts);
QUEST_BUILDER(quest_build_sweep_stakes);
QUEST_BUILDER(quest_build_evil_zombies_at_large);
QUEST_BUILDER(quest_build_survival_of_the_fastest);
QUEST_BUILDER(quest_build_land_of_lizards);
QUEST_BUILDER(quest_build_ghost_patrols);
QUEST_BUILDER(quest_build_spideroids);
QUEST_BUILDER(quest_build_the_blighting);
QUEST_BUILDER(quest_build_lizard_kings);
QUEST_BUILDER(quest_build_the_killing);
QUEST_BUILDER(quest_build_hidden_evil);
QUEST_BUILDER(quest_build_surrounded_by_reptiles);
QUEST_BUILDER(quest_build_the_lizquidation);
QUEST_BUILDER(quest_build_spiders_inc);
QUEST_BUILDER(quest_build_lizard_raze);
QUEST_BUILDER(quest_build_deja_vu);
QUEST_BUILDER(quest_build_zombie_masters);
QUEST_BUILDER(quest_build_major_alien_breach);
QUEST_BUILDER(quest_build_zombie_time);
QUEST_BUILDER(quest_build_lizard_zombie_pact);
QUEST_BUILDER(quest_build_the_collaboration);
QUEST_BUILDER(quest_build_the_massacre);
QUEST_BUILDER(quest_build_the_unblitzkrieg);
QUEST_BUILDER(quest_build_gauntlet);
QUEST_BUILDER(quest_build_syntax_terror);
QUEST_BUILDER(quest_build_the_annihilation);
QUEST_BUILDER(quest_build_the_end_of_all);
QUEST_BUILDER(quest_build_the_beating);
QUEST_BUILDER(quest_build_the_spanking_of_the_dead);
QUEST_BUILDER(quest_build_the_fortress);
QUEST_BUILDER(quest_build_the_gang_wars);
QUEST_BUILDER(quest_build_knee_deep_in_the_dead);
QUEST_BUILDER(quest_build_cross_fire);
QUEST_BUILDER(quest_build_army_of_three);
QUEST_BUILDER(quest_build_monster_blues);
QUEST_BUILDER(quest_build_nagolipoli);
QUEST_BUILDER(quest_build_the_gathering);

#undef QUEST_BUILDER

#define ADD_QUEST(title, weapon, limit, builder_fn)                         \
    quest_meta_init_entry(                                                  \
        &quest_selected_meta[tier * 10 + index],                            \
        tier + 1,                                                           \
        index + 1,                                                          \
        title);                                                             \
    quest_meta_cursor->start_weapon_id = weapon;                            \
    quest_meta_cursor->time_limit_ms = limit;                               \
    quest_meta_cursor->builder = builder_fn;                                \
    quest_database_advance_slot(&tier, &index)

extern "C" void quest_database_init(void)
{
    int index = 0;
    int tier = 0;

    ADD_QUEST("Land Hostile", 1, 120000, quest_build_land_hostile);
    ADD_QUEST("Minor Alien Breach", 1, 120000, quest_build_minor_alien_breach);
    ADD_QUEST("Target Practice", 1, 65000, quest_build_target_practice);
    ADD_QUEST("Frontline Assault", 1, 300000, quest_build_frontline_assault);
    ADD_QUEST("Alien Dens", 1, 180000, quest_build_alien_dens);
    ADD_QUEST("The Random Factor", 1, 300000, quest_build_the_random_factor);
    ADD_QUEST("Spider Wave Syndrome", 1, 240000, quest_build_spider_wave_syndrome);
    ADD_QUEST("Alien Squads", 1, 180000, quest_build_alien_squads);
    ADD_QUEST("Nesting Grounds", 1, 240000, quest_build_nesting_grounds);
    ADD_QUEST("8-legged Terror", 1, 240000, quest_build_8_legged_terror);
    ADD_QUEST("Everred Pastures", 1, 300000, quest_build_everred_pastures);
    ADD_QUEST("Spider Spawns", 1, 300000, quest_build_spider_spawns);
    ADD_QUEST("Arachnoid Farm", 1, 240000, quest_build_arachnoid_farm);
    ADD_QUEST("Two Fronts", 1, 240000, quest_build_two_fronts);
    ADD_QUEST("Sweep Stakes", 6, 35000, quest_build_sweep_stakes);
    ADD_QUEST("Evil Zombies At Large", 1, 180000, quest_build_evil_zombies_at_large);
    ADD_QUEST("Survival Of The Fastest", 5, 120000, quest_build_survival_of_the_fastest);
    ADD_QUEST("Land Of Lizards", 1, 180000, quest_build_land_of_lizards);
    ADD_QUEST("Ghost Patrols", 1, 180000, quest_build_ghost_patrols);
    ADD_QUEST("Spideroids", 1, 360000, quest_build_spideroids);
    ADD_QUEST("The Blighting", 1, 300000, quest_build_the_blighting);
    ADD_QUEST("Lizard Kings", 1, 180000, quest_build_lizard_kings);
    ADD_QUEST("The Killing", 1, 300000, quest_build_the_killing);

    quest_meta_init_entry(
        &quest_selected_meta[tier * 10 + index],
        tier + 1,
        index + 1,
        "Hidden Evil");
    quest_meta_cursor->start_weapon_id = 1;
    quest_meta_cursor->time_limit_ms = 300000;
    quest_meta_cursor->builder = quest_build_hidden_evil;
    quest_monster_vision_meta = quest_meta_cursor;
    quest_database_advance_slot(&tier, &index);

    ADD_QUEST("Surrounded By Reptiles", 1, 300000, quest_build_surrounded_by_reptiles);
    ADD_QUEST("The Lizquidation", 1, 300000, quest_build_the_lizquidation);
    ADD_QUEST("Spiders Inc.", 11, 300000, quest_build_spiders_inc);
    ADD_QUEST("Lizard Raze", 1, 300000, quest_build_lizard_raze);
    ADD_QUEST("Deja vu", 6, 120000, quest_build_deja_vu);
    ADD_QUEST("Zombie Masters", 1, 300000, quest_build_zombie_masters);
    ADD_QUEST("Major Alien Breach", 18, 300000, quest_build_major_alien_breach);
    ADD_QUEST("Zombie Time", 1, 300000, quest_build_zombie_time);
    ADD_QUEST("Lizard Zombie Pact", 1, 300000, quest_build_lizard_zombie_pact);
    ADD_QUEST("The Collaboration", 1, 360000, quest_build_the_collaboration);
    ADD_QUEST("The Massacre", 1, 300000, quest_build_the_massacre);
    ADD_QUEST("The Unblitzkrieg", 1, 600000, quest_build_the_unblitzkrieg);
    ADD_QUEST("Gauntlet", 1, 300000, quest_build_gauntlet);
    ADD_QUEST("Syntax Terror", 1, 300000, quest_build_syntax_terror);
    ADD_QUEST("The Annihilation", 1, 300000, quest_build_the_annihilation);
    ADD_QUEST("The End of All", 1, 480000, quest_build_the_end_of_all);
    ADD_QUEST("The Beating", 1, 480000, quest_build_the_beating);
    ADD_QUEST("The Spanking Of The Dead", 1, 480000, quest_build_the_spanking_of_the_dead);
    ADD_QUEST("The Fortress", 1, 480000, quest_build_the_fortress);
    ADD_QUEST("The Gang Wars", 1, 480000, quest_build_the_gang_wars);
    ADD_QUEST("Knee-deep in the Dead", 1, 480000, quest_build_knee_deep_in_the_dead);
    ADD_QUEST("Cross Fire", 1, 480000, quest_build_cross_fire);
    ADD_QUEST("Army of Three", 1, 480000, quest_build_army_of_three);
    ADD_QUEST("Monster Blues", 1, 480000, quest_build_monster_blues);
    ADD_QUEST("Nagolipoli", 1, 480000, quest_build_nagolipoli);
    ADD_QUEST("The Gathering", 1, 480000, quest_build_the_gathering);

    quest_selected_meta[0].unlock_weapon_id = 2;
    quest_selected_meta[1].unlock_weapon_id = 3;
    quest_selected_meta[2].unlock_weapon_id = 0;
    quest_selected_meta[3].unlock_weapon_id = 8;
    quest_selected_meta[4].unlock_weapon_id = 0;
    quest_selected_meta[5].unlock_weapon_id = 5;
    quest_selected_meta[6].unlock_weapon_id = 0;
    quest_selected_meta[7].unlock_weapon_id = 6;
    quest_selected_meta[8].unlock_weapon_id = 0;
    quest_selected_meta[9].unlock_weapon_id = 12;
    quest_selected_meta[10].unlock_weapon_id = 0;
    quest_selected_meta[11].unlock_weapon_id = 9;
    quest_selected_meta[12].unlock_weapon_id = 0;
    quest_selected_meta[13].unlock_weapon_id = 21;
    quest_selected_meta[14].unlock_weapon_id = 0;
    quest_selected_meta[15].unlock_weapon_id = 7;
    quest_selected_meta[16].unlock_weapon_id = 0;
    quest_selected_meta[17].unlock_weapon_id = 4;
    quest_selected_meta[18].unlock_weapon_id = 0;
    quest_selected_meta[19].unlock_weapon_id = 11;
    quest_selected_meta[20].unlock_weapon_id = 0;
    quest_selected_meta[21].unlock_weapon_id = 10;
    quest_selected_meta[22].unlock_weapon_id = 0;
    quest_selected_meta[23].unlock_weapon_id = 13;
    quest_selected_meta[24].unlock_weapon_id = 0;
    quest_selected_meta[25].unlock_weapon_id = 15;
    quest_selected_meta[26].unlock_weapon_id = 0;
    quest_selected_meta[27].unlock_weapon_id = 18;
    quest_selected_meta[28].unlock_weapon_id = 0;
    quest_selected_meta[29].unlock_weapon_id = 20;
    quest_selected_meta[30].unlock_weapon_id = 0;
    quest_selected_meta[31].unlock_weapon_id = 19;
    quest_selected_meta[32].unlock_weapon_id = 0;
    quest_selected_meta[33].unlock_weapon_id = 14;
    quest_selected_meta[34].unlock_weapon_id = 0;
    quest_selected_meta[35].unlock_weapon_id = 17;
    quest_selected_meta[36].unlock_weapon_id = 0;
    quest_selected_meta[37].unlock_weapon_id = 22;
    quest_selected_meta[38].unlock_weapon_id = 0;
    quest_selected_meta[39].unlock_weapon_id = 23;

    quest_selected_meta[0].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[1].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[2].unlock_perk_id = 28;
    quest_selected_meta[3].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[4].unlock_perk_id = 29;
    quest_selected_meta[5].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[6].unlock_perk_id = 30;
    quest_selected_meta[7].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[8].unlock_perk_id = 31;
    quest_selected_meta[9].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[10].unlock_perk_id = 32;
    quest_selected_meta[11].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[12].unlock_perk_id = 33;
    quest_selected_meta[13].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[14].unlock_perk_id = 34;
    quest_selected_meta[15].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[16].unlock_perk_id = 35;
    quest_selected_meta[17].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[18].unlock_perk_id = 36;
    quest_selected_meta[19].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[20].unlock_perk_id = 37;
    quest_selected_meta[21].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[22].unlock_perk_id = 38;
    quest_selected_meta[23].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[24].unlock_perk_id = 39;
    quest_selected_meta[25].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[26].unlock_perk_id = 40;
    quest_selected_meta[27].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[28].unlock_perk_id = 41;
    quest_selected_meta[29].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[30].unlock_perk_id = 42;
    quest_selected_meta[31].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[32].unlock_perk_id = 43;
    quest_selected_meta[33].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[34].unlock_perk_id = 44;
    quest_selected_meta[35].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[36].unlock_perk_id = 45;
    quest_selected_meta[37].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[38].unlock_perk_id = 46;
    quest_selected_meta[39].unlock_perk_id = perk_id_antiperk;

    quest_selected_meta[40].unlock_weapon_id = 31;
    quest_selected_meta[40].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[41].unlock_weapon_id = 0;
    quest_selected_meta[41].unlock_perk_id = 47;
    quest_selected_meta[42].unlock_weapon_id = 0;
    quest_selected_meta[42].unlock_perk_id = 48;
    quest_selected_meta[43].unlock_weapon_id = 30;
    quest_selected_meta[43].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[44].unlock_weapon_id = 0;
    quest_selected_meta[44].unlock_perk_id = 49;
    quest_selected_meta[45].unlock_weapon_id = 0;
    quest_selected_meta[45].unlock_perk_id = 50;
    quest_selected_meta[46].unlock_weapon_id = 0;
    quest_selected_meta[46].unlock_perk_id = perk_id_antiperk;
    quest_selected_meta[47].unlock_weapon_id = 0;
    quest_selected_meta[47].unlock_perk_id = 51;
    quest_selected_meta[48].unlock_weapon_id = 0;
    quest_selected_meta[48].unlock_perk_id = 52;
    quest_selected_meta[49].unlock_weapon_id = 28;
    quest_selected_meta[49].unlock_perk_id = perk_id_antiperk;
}

#undef ADD_QUEST
