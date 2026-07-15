#include "crimsonland_gameplay.h"

extern "C" {
extern int perk_id_antiperk;
extern int perk_id_bloody_mess_quick_learner;
extern int perk_id_sharpshooter;
extern int perk_id_fastloader;
extern int perk_id_lean_mean_exp_machine;
extern int perk_id_long_distance_runner;
extern int perk_id_pyrokinetic;
extern int perk_id_instant_winner;
extern int perk_id_grim_deal;
extern int perk_id_alternate_weapon;
extern int perk_id_plaguebearer;
extern int perk_id_evil_eyes;
extern int perk_id_ammo_maniac;
extern int perk_id_radioactive;
extern int perk_id_fastshot;
extern int perk_id_fatal_lottery;
extern int perk_id_random_weapon;
extern int perk_id_mr_melee;
extern int perk_id_anxious_loader;
extern int perk_id_final_revenge;
extern int perk_id_telekinetic;
extern int perk_id_perk_expert;
extern int perk_id_unstoppable;
extern int perk_id_regression_bullets;
extern int perk_id_infernal_contract;
extern int perk_id_poison_bullets;
extern int perk_id_dodger;
extern int perk_id_bonus_magnet;
extern int perk_id_uranium_filled_bullets;
extern int perk_id_doctor;
extern int perk_id_monster_vision;
extern int perk_id_hot_tempered;
extern int perk_id_bonus_economist;
extern int player_overlay_auto_target_line_perk_id;
extern int perk_id_thick_skinned;
extern int perk_id_barrel_greaser;
extern int perk_id_ammunition_within;
extern int perk_id_veins_of_poison;
extern int perk_id_toxic_avenger;
extern int perk_id_regeneration;
extern int perk_id_pyromaniac;
extern int perk_id_ninja;
extern int perk_id_highlander;
extern int perk_id_jinxed;
extern int perk_id_perk_master;
extern int perk_id_reflex_boosted;
extern int perk_id_greater_regeneration;
extern int perk_id_breathing_room;
extern int perk_id_death_clock;
extern int perk_id_my_favourite_weapon;
extern int perk_id_bandage;
extern int perk_id_angry_reloader;
extern int perk_id_ion_gun_master;
extern int perk_id_stationary_reloader;
extern int perk_id_man_bomb;
extern int perk_id_fire_caugh;
extern int perk_id_living_fortress;
extern int perk_id_tough_reloader;
extern int perk_id_lifeline_50_50;
extern int perk_id_max;
extern int perk_id_count;

extern char *perk_slot_1_name_wrapped_primary;
extern char *perk_slot_1_name_wrapped_alternate;
extern char *perk_slot_1_desc_wrapped_primary;
extern char *perk_slot_1_desc_wrapped_alternate;

void perks_rebuild_available(void);
}

#define SET_PERK(id_global, id_value, name_text, description_text)             \
    do {                                                                       \
        (id_global) = (id_value);                                              \
        perk_meta_table[(id_value)].name =                                     \
            wrap_text_to_width_alloc((name_text), 0x100);                      \
        perk_meta_table[(id_value)].description =                              \
            wrap_text_to_width_alloc((description_text), 0x100);               \
    } while (0)

extern "C" void perks_init_database(void)
{
    SET_PERK(
        perk_id_antiperk,
        0,
        "AntiPerk",
        "You shouldn't be seeing this..");

    perk_id_bloody_mess_quick_learner = 1;
    perk_slot_1_name_wrapped_primary =
        wrap_text_to_width_alloc("Bloody Mess", 0x100);
    perk_slot_1_desc_wrapped_primary = wrap_text_to_width_alloc(
        "More the merrier. More blood guarantees a 30% better experience. You spill more blood and gain more experience points.",
        0x100);
    perk_slot_1_name_wrapped_alternate =
        wrap_text_to_width_alloc("Quick Learner", 0x100);
    perk_slot_1_desc_wrapped_alternate = wrap_text_to_width_alloc(
        "You learn things faster than a regular Joe from now on gaining 30% more experience points from everything you do.",
        0x100);
    if (config_violence_disabled != 0) {
        perk_meta_table[perk_id_bloody_mess_quick_learner].name =
            perk_slot_1_name_wrapped_alternate;
        perk_meta_table[perk_id_bloody_mess_quick_learner].description =
            perk_slot_1_desc_wrapped_alternate;
    } else {
        perk_meta_table[perk_id_bloody_mess_quick_learner].name =
            perk_slot_1_name_wrapped_primary;
        perk_meta_table[perk_id_bloody_mess_quick_learner].description =
            perk_slot_1_desc_wrapped_primary;
    }

    SET_PERK(
        perk_id_sharpshooter,
        2,
        "Sharpshooter",
        "Miraculously your aiming improves drastically, but you take a little bit more time on actually firing the gun. If you order now, you also get a fancy LASER SIGHT without ANY charge!");
    SET_PERK(
        perk_id_fastloader,
        3,
        "Fastloader",
        "Man, you sure know how to load a gun.");
    SET_PERK(
        perk_id_lean_mean_exp_machine,
        4,
        "Lean Mean Exp Machine",
        "Why kill for experience when you can make some of your own for free! With this perk the experience just keeps flowing in at a constant rate.");
    SET_PERK(
        perk_id_long_distance_runner,
        5,
        "Long Distance Runner",
        "You move like a train that has feet and runs. You just need a little time to warm up. In other words you'll move faster the longer you run without stopping.");
    SET_PERK(
        perk_id_pyrokinetic,
        6,
        "Pyrokinetic",
        "You see flames everywhere. Bare aiming at creatures causes them to heat up.");
    SET_PERK(
        perk_id_instant_winner,
        7,
        "Instant Winner",
        "2500 experience points. Right away. Take it or leave it.");
    perk_meta_table[7].flags |= 4;

    perk_id_grim_deal = 8;
    perk_meta_table[8].flags = 0;
    perk_meta_table[8].name = wrap_text_to_width_alloc("Grim Deal", 0x100);
    perk_meta_table[8].description = wrap_text_to_width_alloc(
        "I'll make you a deal: I'll give you 18% more experience points, and you'll give me your life. So you'll die but score higher. Ponder that one for a sec.",
        0x100);

    perk_id_alternate_weapon = 9;
    perk_meta_table[9].flags = 1;
    perk_meta_table[9].name =
        wrap_text_to_width_alloc("Alternate Weapon", 0x100);
    perk_meta_table[9].description = wrap_text_to_width_alloc(
        "Ever fancied about having two weapons available for use? This might be your lucky day; with this perk you'll get an extra weapon slot for another gun! Carrying around two guns slows you down slightly though. (You can switch the weapon slots with RELOAD key)",
        0x100);

    SET_PERK(
        perk_id_plaguebearer,
        10,
        "Plaguebearer",
        "You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! (Monsters become resistant over time though.)");
    SET_PERK(
        perk_id_evil_eyes,
        11,
        "Evil Eyes",
        "No living (nor dead) can resist the hypnotic power of your eyes: monsters freeze still as you look at them!");
    SET_PERK(
        perk_id_ammo_maniac,
        12,
        "Ammo Maniac",
        "You squeeze and you push and you pack your clips with about 20% more ammo than a regular fellow. They call you Ammo Maniac with a deep respect in their voices.");
    SET_PERK(
        perk_id_radioactive,
        13,
        "Radioactive",
        "You are the Radioactive-man; you have that healthy green glow around you! Others don't like it though, it makes them sick and nauseous whenever near you. It does affect your social life a bit.");
    SET_PERK(
        perk_id_fastshot,
        14,
        "Fastshot",
        "Funny how you make your gun spit bullets faster than the next guy. Even the most professional of engineers are astonished.");

    perk_id_fatal_lottery = 15;
    perk_meta_table[15].flags = 4;
    perk_meta_table[15].name =
        wrap_text_to_width_alloc("Fatal Lottery", 0x100);
    perk_meta_table[15].description = wrap_text_to_width_alloc(
        "Fifty-fifty chance of dying OR gaining 10k experience points. Place your bets. Interested, anyone?",
        0x100);

    perk_id_random_weapon = 16;
    perk_meta_table[16].flags = 5;
    perk_meta_table[16].name =
        wrap_text_to_width_alloc("Random Weapon", 0x100);
    perk_meta_table[16].description =
        wrap_text_to_width_alloc("Here, have this weapon. No questions asked.", 0x100);

    SET_PERK(
        perk_id_mr_melee,
        17,
        "Mr. Melee",
        "You master the art of melee fighting. You don't just stand still when monsters come near -- you hit back. Hard.");
    SET_PERK(
        perk_id_anxious_loader,
        18,
        "Anxious Loader",
        "When you can't stand waiting your gun to be reloaded you can speed up the process by clicking your FIRE button repeatedly as fast as you can.");

    perk_id_final_revenge = 19;
    perk_meta_table[19].flags = 0;
    perk_meta_table[19].name =
        wrap_text_to_width_alloc("Final Revenge", 0x100);
    perk_meta_table[19].description = wrap_text_to_width_alloc(
        "Pick this and you'll get your revenge. It's a promise.", 0x100);

    SET_PERK(
        perk_id_telekinetic,
        20,
        "Telekinetic",
        "Picking up bonuses has never been so easy and FUN. You can pick up bonuses simply by aiming at them for a while. Ingenious.");
    SET_PERK(
        perk_id_perk_expert,
        21,
        "Perk Expert",
        "You sure know how to pick a perk -- most people just don't see that extra perk laying around. This gives you the opportunity to pick the freshest and shiniest perks from the top.");
    SET_PERK(
        perk_id_unstoppable,
        22,
        "Unstoppable",
        "Monsters can't slow you down with their nasty scratches and bites. It still hurts but you simply ignore the pain.");
    SET_PERK(
        perk_id_regression_bullets,
        23,
        "Regression Bullets",
        "Attempt to shoot with an empty clip leads to a severe loss of experience. But hey, whatever makes them go down, right?");
    SET_PERK(
        perk_id_infernal_contract,
        24,
        "Infernal Contract",
        "In exchange for your soul, a dark stranger is offering you three (3) new perks. To collect his part of the bargain soon enough, your health is reduced to a near-death status. Just sign down here below this pentagram..");
    SET_PERK(
        perk_id_poison_bullets,
        25,
        "Poison Bullets",
        "You tend to explicitly treat each of your bullets with rat poison. You do it for good luck, but it seems to have other side effects too.");
    SET_PERK(
        perk_id_dodger,
        26,
        "Dodger",
        "It seems so stupid just to take the hits. Each time a monster attacks you you have a chance to dodge the attack.");
    SET_PERK(
        perk_id_bonus_magnet,
        27,
        "Bonus Magnet",
        "You somehow seem to lure all kinds of bonuses to appear around you more often.");
    SET_PERK(
        perk_id_uranium_filled_bullets,
        28,
        "Uranium Filled Bullets",
        "Your bullets have a nice creamy uranium filling. Yummy. Now that's gotta hurt the monsters more, right?");
    SET_PERK(
        perk_id_doctor,
        29,
        "Doctor",
        "With a single glance you can tell the medical condition of, well, anything. Also, being a doctor, you know exactly what hurts the most enabling you to do slightly more damage with your attacks.");
    SET_PERK(
        perk_id_monster_vision,
        30,
        "Monster Vision",
        "With your newly enhanced senses you can see all bad energy VERY clearly. That's got to be enough.");
    SET_PERK(
        perk_id_hot_tempered,
        31,
        "Hot Tempered",
        "It literally boils inside you. That's exactly why you need to let it out once in a while, unfortunately for those near you.");
    SET_PERK(
        perk_id_bonus_economist,
        32,
        "Bonus Economist",
        "Your bonus power-ups last 50% longer than they normally would.");
    player_overlay_auto_target_line_perk_id = 0;

    SET_PERK(
        perk_id_thick_skinned,
        33,
        "Thick Skinned",
        "Trade 1/3 of your health for only receiving 2/3rds damage on attacks.");
    SET_PERK(
        perk_id_barrel_greaser,
        34,
        "Barrel Greaser",
        "After studying a lot of physics and friction you've come up with a way to make your bullets fly faster. More speed, more damage.");
    SET_PERK(
        perk_id_ammunition_within,
        35,
        "Ammunition Within",
        "Empty clip doesn't prevent you from shooting with a weapon; instead the ammunition is drawn from your health while you are reloading.");
    SET_PERK(
        perk_id_veins_of_poison,
        36,
        "Veins of Poison",
        "A strong poison runs through your veins. Monsters taking a bite of you are eventually to experience an agonizing death.");
    SET_PERK(
        perk_id_toxic_avenger,
        37,
        "Toxic Avenger",
        "You started out just by being poisonous. The next logical step for you is to become highly toxic -- the ULTIMATE TOXIC AVENGER. Most monsters touching you will just drop dead within seconds!");
    perk_meta_table[37].prerequisite = perk_id_veins_of_poison;
    SET_PERK(
        perk_id_regeneration,
        38,
        "Regeneration",
        "Your health replenishes but very slowly. What more there is to say?");
    SET_PERK(
        perk_id_pyromaniac,
        39,
        "Pyromaniac",
        "You just enjoy using fire as your Tool of Destruction and you're good at it too; your fire based weapons do a lot more damage.");
    SET_PERK(
        perk_id_ninja,
        40,
        "Ninja",
        "You've taken your dodging abilities to the next level; monsters have really hard time hitting you.");
    perk_meta_table[40].prerequisite = perk_id_dodger;

    perk_id_highlander = 41;
    perk_meta_table[41].flags = 0;
    perk_meta_table[41].name = wrap_text_to_width_alloc("Highlander", 0x100);
    perk_meta_table[41].description = wrap_text_to_width_alloc(
        "You are immortal. Well, almost immortal. Instead of actually losing health on attacks you've got a 10% chance of just dropping dead whenever a monster attacks you. There really can be only one, you know.",
        0x100);

    SET_PERK(
        perk_id_jinxed,
        42,
        "Jinxed",
        "Things happen near you. Strangest things. Creatures just drop dead and accidents happen. Beware.");
    SET_PERK(
        perk_id_perk_master,
        43,
        "Perk Master",
        "Being the Perk Expert taught you a few things and now you are ready to take your training to the next level doubling the ability effect.");
    perk_meta_table[43].prerequisite = perk_id_perk_expert;
    SET_PERK(
        perk_id_reflex_boosted,
        44,
        "Reflex Boosted",
        "To you the world seems to go on about 10% slower than to an average person. It can be rather irritating sometimes, but it does give you a chance to react better.");
    SET_PERK(
        perk_id_greater_regeneration,
        45,
        "Greater Regeneration",
        "Your health replenishes faster than ever.");
    perk_meta_table[45].prerequisite = perk_id_regeneration;

    perk_id_breathing_room = 46;
    perk_meta_table[46].flags = 2;
    perk_meta_table[46].name =
        wrap_text_to_width_alloc("Breathing Room", 0x100);
    perk_meta_table[46].description = wrap_text_to_width_alloc(
        "Trade 2/3rds of your health for the killing of every single creature on the screen. No, you don't get the experience.",
        0x100);

    SET_PERK(
        perk_id_death_clock,
        47,
        "Death Clock",
        "You die exactly in 30 seconds. You can't escape your destiny, but feel free to go on a spree. Tick, tock.");
    SET_PERK(
        perk_id_my_favourite_weapon,
        48,
        "My Favourite Weapon",
        "You've grown very fond of your piece. You polish it all the time and talk nice to it, your precious. (+2 clip size, no more random weapon bonuses) ");
    SET_PERK(
        perk_id_bandage,
        49,
        "Bandage",
        "Here, eat this bandage and you'll feel a lot better in no time. (restores up to 50% health)");
    SET_PERK(
        perk_id_angry_reloader,
        50,
        "Angry Reloader",
        "You hate it when you run out of shots. You HATE HATE HATE reloading your gun. Lucky for you, and strangely enough, your hate materializes as Mighty Balls of Fire. Or more like Quite Decent Balls of Fire, but it's still kinda neat, huh?");
    SET_PERK(
        perk_id_ion_gun_master,
        51,
        "Ion Gun Master",
        "You're good with ion weapons. You're so good that not only your shots do slightly more damage but your ion blast radius is also increased.");
    SET_PERK(
        perk_id_stationary_reloader,
        52,
        "Stationary Reloader",
        "It's incredibly hard to reload your piece while moving around, you've noticed. In fact, realizing that, when you don't move a (leg) muscle you can reload the gun THREE TIMES FASTER!");
    SET_PERK(
        perk_id_man_bomb,
        53,
        "Man Bomb",
        "You have the ability to go boom for you are the MAN BOMB. Going boom requires a lot of concentration and standing completely still for a few seconds.");
    SET_PERK(
        perk_id_fire_caugh,
        54,
        "Fire Caugh",
        "You have a fireball stuck in your throat. Repeatedly. Mind your manners.");
    SET_PERK(
        perk_id_living_fortress,
        55,
        "Living Fortress",
        "It comes a time in each man's life when you'd just rather not move anymore. Being living fortress not moving comes with extra benefits as well. You do the more damage the longer you stand still.");
    SET_PERK(
        perk_id_tough_reloader,
        56,
        "Tough Reloader",
        "Damage received during reloading a weapon is halved.");
    SET_PERK(
        perk_id_lifeline_50_50,
        57,
        "Lifeline 50-50",
        "The computer removes half of the wrong monsters for you. You don't gain any experience.");

    perk_id_max = 57;
    perk_id_count = 58;
    perks_rebuild_available();
}
