#include "grim2d_abi.h"

#define GRIM_ABI_ASSERT(name, condition) \
    typedef char grim_abi_assert_##name[(condition) ? 1 : -1]

struct grim_char_alignment_probe_t {
    char prefix;
    char value;
};

struct grim_unsigned_int_alignment_probe_t {
    char prefix;
    unsigned int value;
};

struct grim_unsigned_long_alignment_probe_t {
    char prefix;
    unsigned long value;
};

GRIM_ABI_ASSERT(pointer_is_32_bit, sizeof(void *) == 4);
GRIM_ABI_ASSERT(int_is_32_bit, sizeof(int) == 4);
GRIM_ABI_ASSERT(unsigned_int_is_32_bit, sizeof(unsigned int) == 4);
GRIM_ABI_ASSERT(long_is_32_bit, sizeof(long) == 4);
GRIM_ABI_ASSERT(unsigned_long_is_32_bit, sizeof(unsigned long) == 4);
GRIM_ABI_ASSERT(float_is_32_bit, sizeof(float) == 4);
GRIM_ABI_ASSERT(bool_is_one_byte, sizeof(bool) == 1);

GRIM_ABI_ASSERT(config_value_is_16_bytes, sizeof(grim_config_value_t) == 0x10);
GRIM_ABI_ASSERT(
    config_words_start_at_zero,
    offsetof(grim_config_value_t, words) == 0);
GRIM_ABI_ASSERT(
    config_words_fill_record,
    sizeof(((grim_config_value_t *)0)->words) == 0x10);
GRIM_ABI_ASSERT(config_word_is_32_bit, sizeof(((grim_config_value_t *)0)->words[0]) == 4);
GRIM_ABI_ASSERT(interface_is_one_vptr, sizeof(IGrim2D_cpp) == 4);
GRIM_ABI_ASSERT(vtable_is_84_slots, sizeof(grim2d_vtable_layout_t) == 0x150);
GRIM_ABI_ASSERT(
    apply_settings_slot_is_0x1c,
    offsetof(grim2d_vtable_layout_t, grim_apply_settings) == 0x1c);
GRIM_ABI_ASSERT(
    set_config_slot_is_0x20,
    offsetof(grim2d_vtable_layout_t, grim_set_config_var) == 0x20);
GRIM_ABI_ASSERT(
    get_config_slot_is_0x24,
    offsetof(grim2d_vtable_layout_t, grim_get_config_var) == 0x24);
GRIM_ABI_ASSERT(
    mono_fmt_slot_is_0x140,
    offsetof(grim2d_vtable_layout_t, grim_draw_text_mono_fmt) == 0x140);
GRIM_ABI_ASSERT(
    small_fmt_slot_is_0x148,
    offsetof(grim2d_vtable_layout_t, grim_draw_text_small_fmt) == 0x148);
GRIM_ABI_ASSERT(
    final_slot_is_0x14c,
    offsetof(grim2d_vtable_layout_t, grim_measure_text_width) == 0x14c);
GRIM_ABI_ASSERT(
    default_pointer_alignment_is_four,
    offsetof(grim2d_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_char_alignment_is_one,
    offsetof(grim_char_alignment_probe_t, value) == 1);
GRIM_ABI_ASSERT(
    default_unsigned_int_alignment_is_four,
    offsetof(grim_unsigned_int_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_unsigned_long_alignment_is_four,
    offsetof(grim_unsigned_long_alignment_probe_t, value) == 4);

GRIM_ABI_ASSERT(factory_pointer_is_32_bit, sizeof(grim_get_interface_fn) == 4);
GRIM_ABI_ASSERT(member_pointer_is_32_bit, sizeof(grim_apply_settings_fn) == 4);

static grim_get_interface_fn grim_abi_factory = &GRIM__GetInterface;
static grim_apply_settings_fn grim_abi_apply_settings =
    &IGrim2D_cpp::grim_apply_settings;
static grim_set_config_var_fn grim_abi_set_config =
    &IGrim2D_cpp::grim_set_config_var;
static grim_get_config_var_fn grim_abi_get_config =
    &IGrim2D_cpp::grim_get_config_var;
static grim_draw_text_mono_fmt_fn grim_abi_mono_fmt =
    &IGrim2D_cpp::grim_draw_text_mono_fmt;
