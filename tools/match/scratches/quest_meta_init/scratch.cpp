#include <new.h>

#include "crimsonland_metadata.h"

struct quest_meta_array_t {
    quest_meta_cpp_t entries[50];
};

extern quest_meta_cpp_t quest_selected_meta[50];

extern "C" void quest_meta_init(void)
{
    __assume(quest_selected_meta != 0);
    new (quest_selected_meta) quest_meta_array_t;
}
