#ifndef CRIMSONLAND_METADATA_H
#define CRIMSONLAND_METADATA_H

#include "cl_build.h"

extern "C" void crt_free(void *ptr);

class quest_meta_cpp_t {
public:
    quest_meta_cpp_t(void);
    ~quest_meta_cpp_t(void);

    int tier;
    int index;
    int time_limit_ms;
    char *name;
    int terrain_id;
    int terrain_id_b;
    int terrain_id_c;
    void (*builder)(void);
    int unlock_perk_id;
    int unlock_weapon_id;
    int start_weapon_id;
};

class bonus_meta_cpp_t {
public:
    bonus_meta_cpp_t(void);
    ~bonus_meta_cpp_t(void);

    char *label;
    char *description;
    int icon_id;
    unsigned char enabled;
    unsigned char _pad0[3];
    int default_amount;
};

class perk_meta_cpp_t {
public:
    perk_meta_cpp_t(void);
    ~perk_meta_cpp_t(void);

    char *name;
    char *description;
#if CL_BUILD >= 10900
    int flags;
    unsigned char available;
    unsigned char _pad0[3];
    int prerequisite;
#elif CL_BUILD >= 10300
    int reserved_08;
    int flags;
    unsigned char available;
    unsigned char available_default;
    unsigned char _pad0[2];
#else
    int flags;
    unsigned char available;
    unsigned char _pad0[3];
#endif
};

#endif
