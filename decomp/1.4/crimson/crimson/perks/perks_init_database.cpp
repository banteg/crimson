#include "crimsonland_metadata.h"
#include "grim2d_cpp.h"

extern "C" {
extern perk_meta_cpp_t perk_meta_table[CL_BUILD < 10400 ? 32 : 48];
extern IGrim2D_cpp *grim_interface_ptr;
int crt_rand();
char *wrap_text_to_width_alloc(char *text, int width);
extern int perk_id_count, perk_id_reserved_22, perk_id_reserved_33, freeware_hint_ids[7];
extern int perk_id_test;
extern int perk_id_bloody_mess;
extern int perk_id_almost_invisible;
extern int perk_id_sharpshooter;
extern int perk_id_long_distance_runner;
extern int perk_id_fastloader;
extern int perk_id_lean_mean_exp_machine;
extern int perk_id_spontaneously_combusteous;
extern int perk_id_instant_winner;
extern int perk_id_grim_deal;
extern int perk_id_plaguebearer;
extern int perk_id_ammo_maniac;
extern int perk_id_radioactive;
extern int perk_id_berserk_attack;
extern int perk_id_timebender;
extern int perk_id_fastshot;
extern int perk_id_reflex_boosted;
extern int perk_id_see_health;
extern int perk_id_jinxed;
extern int perk_id_evil_eyes;
extern int perk_id_fatal_lottery;
extern int perk_id_weapon_assault_rifle;
extern int perk_id_weapon_shotgun;
extern int perk_id_anxious_loader;
extern int perk_id_final_revenge;
extern int perk_id_infernal_contract;
extern int perk_id_perk_expert;
}

static __forceinline void register_perk(int &id, int index, char *name, char *description, bool available_in_coop = true) {
    id = index;
#if CL_BUILD >= 10300
    if (!available_in_coop)
        perk_meta_table[index].available = 0;
#endif
    perk_meta_table[index].texture = grim_interface_ptr->grim_get_texture_handle("perks01");
    perk_meta_table[index].frame = crt_rand() % 4;
    perk_meta_table[index].name = wrap_text_to_width_alloc(name, 25);
    perk_meta_table[index].description = wrap_text_to_width_alloc(description, 25);
}

#if CL_BUILD == 10400
static __forceinline void register_hint(int &id, int index) {
    id = index;
    perk_meta_table[index].name = wrap_text_to_width_alloc("Corrupted Hint", 25);
    perk_meta_table[index].description = wrap_text_to_width_alloc(
        "The message seems to be a bit corrupted though and doesn't necessarely mean anything. "
        "(Randomly replaced letters)", 25);
    perk_meta_table[index].secret = 1;
}
#endif

extern "C" void perks_init_database() {
    int index = 0;
#if CL_BUILD == 10400
    register_perk(perk_id_test, index++, "Test perk",
        "You shouldn't be seeing this..");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_bloody_mess, index++, "Bloody Mess",
        "More the merrier. More blood guarantees better experience. You spill more blood and gain more "
        "experience points.");
#else
    register_perk(perk_id_bloody_mess, index++, "Bloody Mess",
        "More the merrier. More blood guarantees a better experience. You spill more blood and gain "
        "more experience points.");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_almost_invisible, index++, "Almost Invisible Man",
        "Invisibility phases in and out, Creatures see less of you when you're more invisible.");
#else
    register_perk(perk_id_almost_invisible, index++, "Almost Invisible Man",
        "Your invisibility ability phases in and out, Creatures see less of you when you're more "
        "invisible.");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_sharpshooter, index++, "Sharpshooter",
        "You are the one who shoots sharps. Miraculously your aiming improves drastically.");
#elif CL_BUILD == 10300
    register_perk(perk_id_sharpshooter, index++, "Sharpshooter",
        "You are the one who shoots sharps. Miraculously your aiming improves drastically, but you take"
        " a little bit more time on actually firing the gun. Less than you would think. If you order "
        "now, you also get a fancy LASER SIGHT without ANY charge!");
#else
    register_perk(perk_id_sharpshooter, index++, "Sharpshooter",
        "You are the one who shoots sharps. Miraculously your aiming improves drastically, but you take"
        " a little bit more time on actually firing the gun. If you order now, you also get a fancy "
        "LASER SIGHT without ANY charge!");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_long_distance_runner, index++, "Long Distance Runner",
        "You are run like a train that has feet and runs. You just need a bit time to warm up. In other"
        " words you'll move faster the longer you run without stopping.");
#else
    register_perk(perk_id_long_distance_runner, index++, "Long Distance Runner",
        "You run like a train that has feet and runs. You just need a bit time to warm up. In other "
        "words you'll move faster the longer you run without stopping.");
#endif
#if CL_BUILD < 10400
    register_perk(perk_id_fastloader, index++, "Fastloader",
        "You were BORN to load a gun! You just can't believe how fast you do it before you see it with "
        "your own eyes.");
#else
    register_perk(perk_id_fastloader, index++, "Fastloader",
        "Man you sure know how to load a gun.");
#endif
#if CL_BUILD == 10300
    register_perk(perk_id_lean_mean_exp_machine, index++, "Lean Mean Exp Machine",
        "Why kill for experience when you can make some of your own at home -- for free! With this perk"
        " the experience just keeps flowing in at a constant rate.");
#elif CL_BUILD == 10400
    register_perk(perk_id_lean_mean_exp_machine, index++, "Lean Mean Exp Machine",
        "Why kill for experience when you can make some of your own for free! With this perk the "
        "experience just keeps flowing in at a constant rate.");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_spontaneously_combusteous, index++, "Spontaneously Combusteous",
        "Well you don't light up but you make other burn. Bare aiming at creature MAY cause it to burst"
        " into flames and instantly burn to death.");
#else
    register_perk(perk_id_spontaneously_combusteous, index++, "Spontaneously Combusteous",
        "Well you don't light up but you make other burn. Bare aiming at creature causes them to heat "
        "up.");
#endif
    register_perk(perk_id_instant_winner, index++, "Instant Winner",
        "2500 experience points. Right away. Take it or leave it.");
#if CL_BUILD == 10002
    register_perk(perk_id_grim_deal, index++, "Grim Deal",
        "I'll make you a deal: I give you 6666 experience points, and you give me your life. So you die"
        " but propably score high. Pounder that one.");
#else
    register_perk(perk_id_grim_deal, index++, "Grim Deal",
        "I'll make you a deal: I give you 6667 experience points, and you give me your life. So you die"
        " but propably score high. Pounder that one.", false);
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_plaguebearer, index++, "Plaquebearer",
        "You carry a horrible disease. Good for you: you are immune, bad for them: it is contagious!");
#elif CL_BUILD == 10300
    register_perk(perk_id_plaguebearer, index++, "Plaguebearer",
        "You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! "
        "They do, however, become immune over time.");
#else
    register_perk(perk_id_plaguebearer, index++, "Plaguebearer",
        "You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! "
        "(Monsters too become immune over time.)");
#endif
#if CL_BUILD == 10300
    register_perk(perk_id_ammo_maniac, index++, "Ammo Maniac",
        "You squeeze and you push and you pack your clips with about 20% more ammo than a regular "
        "fellow. They all call you Ammo Maniac with a deep respect in their voices.");
#elif CL_BUILD == 10400
    register_perk(perk_id_ammo_maniac, index++, "Ammo Maniac",
        "You squeeze and you push and you pack your clips with about 20% more ammo than a regular "
        "fellow. They call you Ammo Maniac with a deep respect in their voices.");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_radioactive, index++, "Radioactive",
        "You are the Radioactiveman! You have that healthy green glow around you. Others don't like it "
        "though, it makes them sick and nauseous.");
#elif CL_BUILD == 10300
    register_perk(perk_id_radioactive, index++, "Radioactive",
        "You are the Radioactive-man! You have that healthy green glow around you. Others don't like it"
        " though, it makes them sick and nauseous.");
#else
    register_perk(perk_id_radioactive, index++, "Radioactive",
        "You are the Radioactive-man, you have that healthy green glow around you. Others don't like it"
        " though, it makes them sick and nauseous whenever near you.");
#endif
#if CL_BUILD < 10400
    register_perk(perk_id_berserk_attack, index++, "Berserk Attack",
        "Every once in a while you go berserk and just start shooting madly at everyone you see. Good "
        "thing for you is you have no idea where does the ammo come from and how does your gun work "
        "that fast. Strange indeed.");
#else
    register_perk(perk_id_berserk_attack, index++, "Berserk Attack",
        "Every once in a while you go berserk and just start shooting madly at everyone you see with a "
        "gun you don't have. Not only that, but you seem to be invulnerable during these acts of "
        "violence. Strange indeed.", false);
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_timebender, index++, "Timebender",
        "Time freezes at your will, you are the master of Bullet Time (tm). Nobody should mess with "
        "time too much or severe retregression may occure! (right mouse button down bends time)");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_fastshot, index++, "Fastshot",
        "Funny how you make your gun spit bullets faster than the next guy. Even the most professional "
        "of engineers (AMK) are astonished.");
#elif CL_BUILD == 10300
    register_perk(perk_id_fastshot, index++, "Fastshot",
        "Funny how you make your gun spit bullets faster than the next guy. Even the most professional "
        "of engineers (AMK) are astonished. [Calm down you AMK ppl, it means nothing :]");
#else
    register_perk(perk_id_fastshot, index++, "Fastshot",
        "Funny how you make your gun spit bullets faster than the next guy. Even the most professional "
        "of engineers are astonished.");
#endif
#if CL_BUILD == 10002
    register_perk(perk_id_reflex_boosted, index++, "Reflex Boosted",
        "To you the world seems to go on 5% slower than to an average person. Can be rather irritating "
        "some times.");
#elif CL_BUILD == 10300
    register_perk(perk_id_reflex_boosted, index++, "Reflex Boosted",
        "To you the world seems to go on 5% slower than to an average person. It can be rather "
        "irritating some times.");
#else
    register_perk(perk_id_reflex_boosted, index++, "Reflex Boosted",
        "To you the world seems to go on about 5% slower than to an average person. It can be rather "
        "irritating sometimes.");
#endif
    register_perk(perk_id_see_health, index++, "Doctor",
        "With a single glance you can tell the medical condition of, well, anyone. Also, being a "
        "doctor, you know exactly what hurts the most..");
#if CL_BUILD == 10002
    register_perk(perk_id_jinxed, index++, "Jinxed",
        "Things happen near you. Strangest things. Creatures just drop dead and accidents happen.");
#else
    register_perk(perk_id_jinxed, index++, "Jinxed",
        "Things happen near you. Strangest things. Creatures just drop dead and accidents happen. "
        "Beware.");
#endif
#if CL_BUILD == 10300
    register_perk(perk_id_evil_eyes, index++, "Evil Eye",
        "(aka Ice Gaze) You have really really mean eyes: monsters freeze still as you look at them.");
#elif CL_BUILD == 10400
    register_perk(perk_id_evil_eyes, index++, "Evil Eyes",
        "(aka Ice Gaze) You have really really mean eyes: monsters freeze still as you look at them.");
#endif
#if CL_BUILD == 10400
    register_perk(perk_id_fatal_lottery, index++, "Fatal Lottery",
        "Fifty-fifty chance of dying OR gaining 10k experience points. Interested, anyone?", false);
#endif
#if CL_BUILD == 10400
    register_perk(perk_id_weapon_assault_rifle, index++, "Weapon perk: Assault rifle",
        "Here, have this upgraded assault rifle. No questions asked.", false);
#endif
#if CL_BUILD == 10400
    register_perk(perk_id_weapon_shotgun, index++, "Weapon perk: Shotgun",
        "Here, have this modified shotgun. No questions asked.", false);
#endif
#if CL_BUILD >= 10300
    register_perk(perk_id_anxious_loader, index++, "Anxious Loader",
        "When you can't stand waiting your gun to be reloaded you can speed up the process by clicking "
        "your FIRE button repeatedly as fast as you can.");
#endif
#if CL_BUILD == 10300
    register_perk(perk_id_final_revenge, index++, "Final Revenge",
        "Pick this and you'll get your revenge. I promise.", false);
#elif CL_BUILD == 10400
    register_perk(perk_id_final_revenge, index++, "Final Revenge",
        "Pick this and you'll get your revenge. It's a promise.", false);
#endif
#if CL_BUILD == 10300
    register_perk(perk_id_infernal_contract, index++, "Infernal Contract",
        "In exchance for your soul, a dark stranger is offering to up you three (3) experience levels. "
        "That means three new perks but no exp.pts. To collect his part of the bargain soon enough, "
        "your health is reduced to a near-death status. Just sign down here below this pentagram..", false);
#elif CL_BUILD == 10400
    register_perk(perk_id_infernal_contract, index++, "Infernal Contract",
        "In exchance for your soul, a dark stranger is offering you three (3) experience levels. That "
        "means three new perks but no exp.pts. To collect his part of the bargain soon enough, your "
        "health is reduced to a near-death status. Just sign down here below this pentagram..", false);
#endif
#if CL_BUILD >= 10300
    register_perk(perk_id_perk_expert, index++, "Perk Expert",
        "You sure know how to pick a perk -- most people just don't see those extra two perks laying "
        "around. This gives you the opportunity to pick the freshest and shiniest perks from the top.");
#endif
#if CL_BUILD == 10400
    register_hint(freeware_hint_ids[0], index++);
    register_hint(freeware_hint_ids[1], index++);
    register_hint(freeware_hint_ids[2], index++);
    register_hint(freeware_hint_ids[3], index++);
    register_hint(freeware_hint_ids[4], index++);
    register_hint(freeware_hint_ids[5], index++);
    register_hint(freeware_hint_ids[6], index++);
#endif
    perk_id_count = index - 1;
#if CL_BUILD == 10300
    perk_id_reserved_22 = index;
#elif CL_BUILD == 10400
    perk_id_reserved_33 = index;
#endif
}
