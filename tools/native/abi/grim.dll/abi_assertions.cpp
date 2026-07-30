#include "grim_d3d8.h"

#include "grim2d_abi.h"
#include "crimsonland_types.h"
#include "grim_joystick_state.h"

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

struct grim_float_alignment_probe_t {
    char prefix;
    float value;
};

struct grim_int_alignment_probe_t {
    char prefix;
    int value;
};

struct grim_bool_alignment_probe_t {
    char prefix;
    bool value;
};

struct grim_unsigned_short_alignment_probe_t {
    char prefix;
    unsigned short value;
};

struct grim_adapter_identifier_alignment_probe_t {
    char prefix;
    D3DADAPTER_IDENTIFIER8 value;
};

struct grim_present_parameters_alignment_probe_t {
    char prefix;
    D3DPRESENT_PARAMETERS value;
};

struct grim_my_app_layout_t {
    bool active;
    unsigned char padding_01[3];
    int last_tick_ms;
    int tick_remainder_ms;
    int height;
    int width;
    void *field_14;
    void *field_18;
    HGDIOBJ bitmap;
    void *field_20;
    void *field_24;
    bool field_28;
    bool field_29;
};

struct grim_my_app_alignment_probe_t {
    char prefix;
    grim_my_app_layout_t value;
};

union grim_client_rect_layout_t {
    RECT rect;
    struct {
        bool enabled;
        unsigned char padding[3];
        LONG top;
        LONG right;
        LONG bottom;
    } state;
};

struct grim_client_rect_alignment_probe_t {
    char prefix;
    grim_client_rect_layout_t value;
};

struct grim_window_class_alignment_probe_t {
    char prefix;
    WNDCLASSEXA value;
};

struct grim_device_caps_alignment_probe_t {
    char prefix;
    D3DCAPS8 value;
};

struct grim_system_time_alignment_probe_t {
    char prefix;
    SYSTEMTIME value;
};

struct grim_guid_alignment_probe_t {
    char prefix;
    GUID value;
};

struct grim_mouse_state_layout_t {
    LONG x;
    LONG y;
    LONG z;
    BYTE buttons[8];
};

struct grim_mouse_state_alignment_probe_t {
    char prefix;
    grim_mouse_state_layout_t value;
};

struct grim_config_value_alignment_probe_t {
    char prefix;
    grim_config_value_t value;
};

struct grim_config_blob_alignment_probe_t {
    char prefix;
    crimson_cfg_t value;
};

struct grim_joystick_state_alignment_probe_t {
    char prefix;
    GrimJoystickState value;
};

struct grim_keyboard_event_layout_t {
    unsigned long dwOfs;
    unsigned long dwData;
    unsigned long dwTimeStamp;
    unsigned long dwSequence;
    unsigned long uAppData;
};

struct grim_keyboard_event_alignment_probe_t {
    char prefix;
    grim_keyboard_event_layout_t value;
};

struct grim_uv_layout_t {
    float u;
    float v;
};

struct grim_uv_alignment_probe_t {
    char prefix;
    grim_uv_layout_t value;
};

GRIM_ABI_ASSERT(pointer_is_32_bit, sizeof(void *) == 4);
GRIM_ABI_ASSERT(codec_vtable_is_four_slots, sizeof(void *[4]) == 0x10);
GRIM_ABI_ASSERT(int_is_32_bit, sizeof(int) == 4);
GRIM_ABI_ASSERT(unsigned_int_is_32_bit, sizeof(unsigned int) == 4);
GRIM_ABI_ASSERT(long_is_32_bit, sizeof(long) == 4);
GRIM_ABI_ASSERT(unsigned_long_is_32_bit, sizeof(unsigned long) == 4);
GRIM_ABI_ASSERT(unsigned_short_is_16_bit, sizeof(unsigned short) == 2);
GRIM_ABI_ASSERT(float_is_32_bit, sizeof(float) == 4);
GRIM_ABI_ASSERT(bool_is_one_byte, sizeof(bool) == 1);
GRIM_ABI_ASSERT(
    adapter_identifier_is_0x42c,
    sizeof(D3DADAPTER_IDENTIFIER8) == 0x42c);
GRIM_ABI_ASSERT(
    present_parameters_is_0x34,
    sizeof(D3DPRESENT_PARAMETERS) == 0x34);
GRIM_ABI_ASSERT(my_app_is_0x2c, sizeof(grim_my_app_layout_t) == 0x2c);
GRIM_ABI_ASSERT(
    client_rect_is_0x10,
    sizeof(grim_client_rect_layout_t) == 0x10);
GRIM_ABI_ASSERT(window_class_is_0x30, sizeof(WNDCLASSEXA) == 0x30);
GRIM_ABI_ASSERT(device_caps_is_0xd4, sizeof(D3DCAPS8) == 0xd4);
GRIM_ABI_ASSERT(system_time_is_0x10, sizeof(SYSTEMTIME) == 0x10);
GRIM_ABI_ASSERT(guid_is_0x10, sizeof(GUID) == 0x10);
GRIM_ABI_ASSERT(
    mouse_state_is_0x14,
    sizeof(grim_mouse_state_layout_t) == 0x14);
GRIM_ABI_ASSERT(
    mouse_buttons_are_0x08,
    sizeof(((grim_mouse_state_layout_t *)0)->buttons) == 0x08);
GRIM_ABI_ASSERT(
    mouse_buttons_start_at_0x0c,
    offsetof(grim_mouse_state_layout_t, buttons) == 0x0c);
GRIM_ABI_ASSERT(
    dither_pattern_is_0x80,
    sizeof(float[32]) == 0x80);
GRIM_ABI_ASSERT(dxt_float_table_8_is_0x20, sizeof(float[8]) == 0x20);
GRIM_ABI_ASSERT(dxt_float_table_6_is_0x18, sizeof(float[6]) == 0x18);
GRIM_ABI_ASSERT(dxt_float_table_4_is_0x10, sizeof(float[4]) == 0x10);
GRIM_ABI_ASSERT(dxt_float_table_3_is_0x0c, sizeof(float[3]) == 0x0c);
GRIM_ABI_ASSERT(
    dxt_uint_table_8_is_0x20,
    sizeof(unsigned int[8]) == 0x20);
GRIM_ABI_ASSERT(
    dxt_uint_table_6_is_0x18,
    sizeof(unsigned int[6]) == 0x18);
GRIM_ABI_ASSERT(
    dxt_uint_table_4_is_0x10,
    sizeof(unsigned int[4]) == 0x10);
GRIM_ABI_ASSERT(
    dxt_uint_table_3_is_0x0c,
    sizeof(unsigned int[3]) == 0x0c);
GRIM_ABI_ASSERT(
    joystick_buttons_are_0x80,
    sizeof(((GrimJoystickState *)0)->rgbButtons) == 0x80);
GRIM_ABI_ASSERT(
    joystick_buttons_start_at_0x30,
    offsetof(GrimJoystickState, rgbButtons) == 0x30);

GRIM_ABI_ASSERT(config_value_is_16_bytes, sizeof(grim_config_value_t) == 0x10);
GRIM_ABI_ASSERT(
    config_words_start_at_zero,
    offsetof(grim_config_value_t, words) == 0);
GRIM_ABI_ASSERT(
    config_words_fill_record,
    sizeof(((grim_config_value_t *)0)->words) == 0x10);
GRIM_ABI_ASSERT(config_word_is_32_bit, sizeof(((grim_config_value_t *)0)->words[0]) == 4);
GRIM_ABI_ASSERT(config_blob_is_0x480_bytes, sizeof(crimson_cfg_t) == 0x480);
GRIM_ABI_ASSERT(joystick_state_is_0x110_bytes, sizeof(GrimJoystickState) == 0x110);
GRIM_ABI_ASSERT(
    keyboard_event_is_0x14_bytes,
    sizeof(grim_keyboard_event_layout_t) == 0x14);
GRIM_ABI_ASSERT(uv_is_8_bytes, sizeof(grim_uv_layout_t) == 8);
GRIM_ABI_ASSERT(uv_quad_is_0x20_bytes, sizeof(grim_uv_layout_t[4]) == 0x20);
GRIM_ABI_ASSERT(uv_table_is_0x800_bytes, sizeof(grim_uv_layout_t[256]) == 0x800);
GRIM_ABI_ASSERT(pointer_table_17_is_0x44_bytes, sizeof(void *[17]) == 0x44);
GRIM_ABI_ASSERT(pointer_table_256_is_0x400_bytes, sizeof(void *[256]) == 0x400);
GRIM_ABI_ASSERT(slot_table_128_is_0x200_bytes, sizeof(int[128]) == 0x200);
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
GRIM_ABI_ASSERT(
    default_float_alignment_is_four,
    offsetof(grim_float_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_int_alignment_is_four,
    offsetof(grim_int_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_bool_alignment_is_one,
    offsetof(grim_bool_alignment_probe_t, value) == 1);
GRIM_ABI_ASSERT(
    default_unsigned_short_alignment_is_two,
    offsetof(grim_unsigned_short_alignment_probe_t, value) == 2);
GRIM_ABI_ASSERT(
    default_adapter_identifier_alignment_is_four,
    offsetof(grim_adapter_identifier_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_present_parameters_alignment_is_four,
    offsetof(grim_present_parameters_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_my_app_alignment_is_four,
    offsetof(grim_my_app_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_client_rect_alignment_is_four,
    offsetof(grim_client_rect_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_window_class_alignment_is_four,
    offsetof(grim_window_class_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_device_caps_alignment_is_four,
    offsetof(grim_device_caps_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_system_time_alignment_is_two,
    offsetof(grim_system_time_alignment_probe_t, value) == 2);
GRIM_ABI_ASSERT(
    default_guid_alignment_is_four,
    offsetof(grim_guid_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_mouse_state_alignment_is_four,
    offsetof(grim_mouse_state_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_config_value_alignment_is_four,
    offsetof(grim_config_value_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_config_blob_alignment_is_four,
    offsetof(grim_config_blob_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_joystick_state_alignment_is_four,
    offsetof(grim_joystick_state_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_keyboard_event_alignment_is_four,
    offsetof(grim_keyboard_event_alignment_probe_t, value) == 4);
GRIM_ABI_ASSERT(
    default_uv_alignment_is_four,
    offsetof(grim_uv_alignment_probe_t, value) == 4);

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
