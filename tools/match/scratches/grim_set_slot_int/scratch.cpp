#include "grim2d_cpp.h"
#include "grim_slot_state.h"

void IGrim2D_cpp::grim_set_slot_int(int index, int value)
{
    grim_slot_ints[index] = value;
}
