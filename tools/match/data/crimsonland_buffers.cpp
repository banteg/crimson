// Existing recovered types and array bounds; reference extents are checked by the compiler.
#include "crimsonland_types.h"

extern "C" {
char console_input_buf[1024];
char console_tokenize_buf[1024];
credits_line_table_t credits_line_table;
char mods_menu_filenames[32][64];
char mods_menu_display_names[32][64];
effect_color_t fx_rotated_color_r[64];
char highscore_screen_score_line_buffers[10][164];
char typo_target_name_table[384][64];
}
