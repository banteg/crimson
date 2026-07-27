#include <new.h>

#include "crimsonland_metadata.h"

struct perk_meta_array_t {
    perk_meta_cpp_t entries[128];
};

extern perk_meta_cpp_t perk_meta_table[128];

extern "C" void perk_meta_table_init(void)
{
    __assume(perk_meta_table != 0);
    new (perk_meta_table) perk_meta_array_t;
}
