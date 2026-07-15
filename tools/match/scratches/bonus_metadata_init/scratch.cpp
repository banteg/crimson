#include "crimsonland_gameplay.h"

extern "C" void bonus_metadata_init(void)
{
    bonus_meta_table[BONUS_ID_POINTS].label = strdup_malloc("Points");
    bonus_meta_table[BONUS_ID_POINTS].description =
        wrap_text_to_width_alloc("You gain some experience points.", 256);
    bonus_meta_table[BONUS_ID_POINTS].icon_id = 12;
    bonus_meta_table[BONUS_ID_POINTS].default_amount = 500;
    bonus_meta_table[BONUS_ID_POINTS].enabled = 1;

    bonus_meta_table[BONUS_ID_WEAPON].label = strdup_malloc("Weapon");
    bonus_meta_table[BONUS_ID_WEAPON].description =
        wrap_text_to_width_alloc("You get a new weapon.", 256);
    bonus_meta_table[BONUS_ID_WEAPON].icon_id = -1;
    bonus_meta_table[BONUS_ID_WEAPON].default_amount = 3;

    bonus_meta_table[BONUS_ID_NUKE].label = strdup_malloc("Nuke");
    bonus_meta_table[BONUS_ID_NUKE].description =
        wrap_text_to_width_alloc("An amazing explosion of ATOMIC power.", 256);
    bonus_meta_table[BONUS_ID_NUKE].icon_id = 1;

    bonus_meta_table[BONUS_ID_DOUBLE_EXPERIENCE].label =
        strdup_malloc("Double Experience");
    bonus_meta_table[BONUS_ID_DOUBLE_EXPERIENCE].description =
        wrap_text_to_width_alloc(
            "Every experience point you get is doubled when this bonus is active.",
            256);
    bonus_meta_table[BONUS_ID_DOUBLE_EXPERIENCE].icon_id = 4;

    bonus_meta_table[BONUS_ID_FIREBLAST].label = strdup_malloc("Fireblast");
    bonus_meta_table[BONUS_ID_FIREBLAST].description =
        wrap_text_to_width_alloc("Fireballs all over the place.", 256);
    bonus_meta_table[BONUS_ID_FIREBLAST].icon_id = 2;

    bonus_meta_table[BONUS_ID_SHOCK_CHAIN].label = strdup_malloc("Shock Chain");
    bonus_meta_table[BONUS_ID_SHOCK_CHAIN].description =
        wrap_text_to_width_alloc("Chain of shocks shock the crowd.", 256);
    bonus_meta_table[BONUS_ID_SHOCK_CHAIN].icon_id = 3;

    bonus_meta_table[BONUS_ID_REFLEX_BOOST].label = strdup_malloc("Reflex Boost");
    bonus_meta_table[BONUS_ID_REFLEX_BOOST].description =
        wrap_text_to_width_alloc(
            "You get more time to react as the game slows down.", 256);
    bonus_meta_table[BONUS_ID_REFLEX_BOOST].icon_id = 5;
    bonus_meta_table[BONUS_ID_REFLEX_BOOST].default_amount = 3;

    bonus_meta_table[BONUS_ID_SHIELD].label = strdup_malloc("Shield");
    bonus_meta_table[BONUS_ID_SHIELD].description =
        wrap_text_to_width_alloc("Force field protects you for a while.", 256);
    bonus_meta_table[BONUS_ID_SHIELD].icon_id = 6;
    bonus_meta_table[BONUS_ID_SHIELD].default_amount = 7;

    bonus_meta_table[BONUS_ID_FREEZE].label = strdup_malloc("Freeze");
    bonus_meta_table[BONUS_ID_FREEZE].description =
        wrap_text_to_width_alloc("Monsters are frozen.", 256);
    bonus_meta_table[BONUS_ID_FREEZE].icon_id = 8;
    bonus_meta_table[BONUS_ID_FREEZE].default_amount = 5;

    bonus_meta_table[BONUS_ID_SPEED].label = strdup_malloc("Speed");
    bonus_meta_table[BONUS_ID_SPEED].description =
        wrap_text_to_width_alloc(
            "Your movement speed increases for a while.", 256);
    bonus_meta_table[BONUS_ID_SPEED].icon_id = 9;
    bonus_meta_table[BONUS_ID_SPEED].default_amount = 8;

    bonus_meta_table[BONUS_ID_ENERGIZER].label = strdup_malloc("Energizer");
    bonus_meta_table[BONUS_ID_ENERGIZER].description =
        wrap_text_to_width_alloc(
            "Suddenly monsters run away from you and you can eat them.", 256);
    bonus_meta_table[BONUS_ID_ENERGIZER].icon_id = 10;
    bonus_meta_table[BONUS_ID_ENERGIZER].default_amount = 8;

    bonus_meta_table[BONUS_ID_WEAPON_POWER_UP].label =
        strdup_malloc("Weapon Power Up");
    bonus_meta_table[BONUS_ID_WEAPON_POWER_UP].description =
        wrap_text_to_width_alloc(
            "Your firerate and load time increase for a short period.", 256);
    bonus_meta_table[BONUS_ID_WEAPON_POWER_UP].icon_id = 7;
    bonus_meta_table[BONUS_ID_WEAPON_POWER_UP].default_amount = 10;

    bonus_meta_table[BONUS_ID_FIRE_BULLETS].label = strdup_malloc("Fire Bullets");
    bonus_meta_table[BONUS_ID_FIRE_BULLETS].description =
        wrap_text_to_width_alloc("For few seconds -- make them count.", 256);
    bonus_meta_table[BONUS_ID_FIRE_BULLETS].icon_id = 11;
    bonus_meta_table[BONUS_ID_FIRE_BULLETS].default_amount = 4;

    bonus_meta_table[BONUS_ID_MEDIKIT].label = strdup_malloc("MediKit");
    bonus_meta_table[BONUS_ID_MEDIKIT].description =
        wrap_text_to_width_alloc("You regain some of your health..", 256);
    bonus_meta_table[BONUS_ID_MEDIKIT].icon_id = 14;
    bonus_meta_table[BONUS_ID_MEDIKIT].default_amount = 10;
}
