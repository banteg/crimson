#include <new.h>

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

struct bonus_hud_slot_array_t {
    bonus_hud_slot_cpp_t entries[0x10];
};

extern bonus_hud_slot_cpp_t bonus_hud_slot_table[0x10];

extern "C" void bonus_hud_slot_table_global_init(void)
{
    __assume(bonus_hud_slot_table != 0);
    new (bonus_hud_slot_table) bonus_hud_slot_array_t;
}
