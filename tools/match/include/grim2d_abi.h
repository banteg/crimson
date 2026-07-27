#ifndef GRIM2D_ABI_H
#define GRIM2D_ABI_H

#include <stddef.h>

#include "grim2d_cpp.h"

/*
 * Linker-pilot ABI contract. The analyzer-facing C header intentionally uses
 * simplified call signatures; native calls use the recovered C++ interface.
 */
struct grim2d_vtable_layout_t {
    void *slots_0_through_6[7];
    void *grim_apply_settings;
    void *grim_set_config_var;
    void *grim_get_config_var;
    void *slots_10_through_79[70];
    void *grim_draw_text_mono_fmt;
    void *grim_draw_text_small;
    void *grim_draw_text_small_fmt;
    void *grim_measure_text_width;
};

struct grim2d_alignment_probe_t {
    char lead;
    void *value;
};

typedef IGrim2D_cpp *(__cdecl *grim_get_interface_fn)(void);
typedef bool (IGrim2D_cpp::*grim_apply_settings_fn)(void);
typedef void (IGrim2D_cpp::*grim_set_config_var_fn)(
    unsigned int id,
    grim_config_value_t value);
typedef grim_config_value_t (IGrim2D_cpp::*grim_get_config_var_fn)(int id);
typedef void (IGrim2D_cpp::*grim_draw_text_mono_fmt_fn)(
    float x,
    float y,
    char *fmt,
    ...);

extern "C" IGrim2D_cpp *__cdecl GRIM__GetInterface(void);

#endif
