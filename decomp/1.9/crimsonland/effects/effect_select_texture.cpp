#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" void effect_select_texture(int effect_id)
{
    int size_code = effect_id_table[effect_id].size_code;
    int frame = effect_id_table[effect_id].frame;

    if (size_code == 0x10) {
        grim_interface_ptr->grim_set_atlas_frame(0x10, frame);
    } else if (size_code == 0x20) {
        grim_interface_ptr->grim_set_atlas_frame(0x08, frame);
    } else if (size_code == 0x40) {
        grim_interface_ptr->grim_set_atlas_frame(0x04, frame);
    } else if (size_code == 0x80) {
        grim_interface_ptr->grim_set_atlas_frame(0x02, frame);
    }
}
