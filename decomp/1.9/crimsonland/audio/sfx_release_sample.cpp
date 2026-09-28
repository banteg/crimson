#include "crimsonland_audio.h"

extern "C" unsigned char sfx_release_sample(int sfx_id)
{
    if (sfx_id < 0 || sfx_id >= 128) {
        return 0;
    }
    if (sfx_entry_table[sfx_id].pcm_data == 0) {
        return 0;
    }
    sfx_release_entry(&sfx_entry_table[sfx_id]);
    return 1;
}
