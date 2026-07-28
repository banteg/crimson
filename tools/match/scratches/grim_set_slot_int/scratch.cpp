#include "grim2d_cpp.h"
#include "grim_slot_state.h"

float IGrim2D_cpp::grim_get_slot_float(int index)
{
    return grim_slot_floats[index];
}

int IGrim2D_cpp::grim_get_slot_int(int index)
{
    return grim_slot_ints[index];
}

void IGrim2D_cpp::grim_set_slot_float(int index, float value)
{
    grim_slot_floats[index] = value;
}

void IGrim2D_cpp::grim_set_slot_int(int index, int value)
{
    grim_slot_ints[index] = value;
}
