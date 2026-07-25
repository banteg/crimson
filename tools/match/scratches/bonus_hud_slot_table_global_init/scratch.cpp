#include "crimsonland_gameplay.h"

class bonus_hud_slot_cpp_t : public bonus_hud_slot_t {
public:
    bonus_hud_slot_cpp_t(void)
    {
        slide.unused_five = 5.0f;
        active = 0;
        slide.slide_x = 0.0f;
        slide.icon_id = 1;
        slide.label = "Empty";
        slide.unused_one = 1.0f;
    }
};

bonus_hud_slot_cpp_t bonus_hud_slot_table[0x10];
