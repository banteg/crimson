#include "grim_slot_state.h"

// The native storage analysis bounds each array to its own 0x200-byte region.
// Keep concrete storage in a sortable subsection for the reference-layout link.
#pragma data_seg(".data$M")
int grim_slot_ints[128] = {0};
float grim_slot_floats[128] = {0};
#pragma data_seg()
