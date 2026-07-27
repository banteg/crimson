#include <new.h>

#include "crimsonland_metadata.h"

struct bonus_meta_array_t {
    bonus_meta_cpp_t entries[15];
};

extern bonus_meta_cpp_t bonus_meta_table[15];

extern "C" void bonus_meta_table_init(void)
{
    __assume(bonus_meta_table != 0);
    new (bonus_meta_table) bonus_meta_array_t;
}
