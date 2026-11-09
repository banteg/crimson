// sfx_system_init clears all three arrays before the first sample is loaded.
#include "cl_build.h"
#if CL_BUILD >= 10300
#include "../../../decomp/1.4/crimson/crimson/game/freeware_config.h"
#endif

extern "C" {
void *freeware_sfx_samples[64];
unsigned char freeware_sfx_state[64];
float sfx_cooldown_table[64];

#if CL_BUILD >= 10300
// fwrite in freeware_save_config writes this release's complete record.
freeware_config_t config_blob;
#endif

#if CL_BUILD == 10400
// console_input_poll bounds the cursor at 1024. console_cmd_exec writes
// the last terminator at offset 511 after reading a script line.
char console_input_buf[1024];
char console_exec_line_buf[512];
int console_input_cursor;
unsigned char console_input_ready;
int console_cmd_argc;
#endif
}
