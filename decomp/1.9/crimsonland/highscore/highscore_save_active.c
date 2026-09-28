#include "crimsonland_highscore.h"

void highscore_save_active(void)
{
    highscore_save_record(&highscore_active_record);
}
