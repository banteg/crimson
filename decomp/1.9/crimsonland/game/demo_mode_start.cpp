#include "crimsonland_gameplay.h"

extern "C" unsigned char demo_purchase_screen_active;
extern "C" int demo_variant_index;
extern "C" int quest_spawn_timeline;
extern "C" unsigned char screen_fade_ramp_flag;

extern "C" void gameplay_reset_state(void);
extern "C" void demo_setup_variant_0(void);
extern "C" void demo_setup_variant_1(void);
extern "C" void demo_setup_variant_2(void);
extern "C" void demo_setup_variant_3(void);
extern "C" void demo_purchase_interstitial_begin(void);

extern "C" void demo_mode_start(void)
{
    if (game_state_id != GAME_STATE_GAMEPLAY) {
        game_state_set(GAME_STATE_GAMEPLAY);
    }

    demo_purchase_screen_active = 0;
    demo_mode_active = 1;
    gameplay_reset_state();
    config_game_mode = GAME_MODE_SURVIVAL;

    if (demo_variant_index == 0) {
        demo_setup_variant_0();
    } else if (demo_variant_index == 1) {
        demo_setup_variant_1();
    } else if (demo_variant_index == 2) {
        demo_setup_variant_2();
    } else if (demo_variant_index == 3) {
        demo_setup_variant_3();
    } else if (demo_variant_index == 4) {
        demo_setup_variant_0();
    } else {
        demo_purchase_interstitial_begin();
    }

    quest_spawn_timeline = 0;
    screen_fade_ramp_flag = 0;
    demo_variant_index = (demo_variant_index + 1) % 6;
}
