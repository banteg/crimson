// crimson.exe 1.4.0, 0x4169c0. Each row occupies 50 of the texture's 256 pixels.
#include "freeware_ui.h"
extern "C" void freeware_hud_set_row(int row) { ui140::uv(0, row * .1953125f, 1, (row + 1) * .1953125f); }
