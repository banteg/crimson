#include "crimsonland_gameplay.h"

extern "C" void bonus_pool_sentinel_global_init(void)
{
    bonus_pool_sentinel.bonus_id = BONUS_ID_NONE;
}
