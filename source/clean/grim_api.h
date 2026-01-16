#pragma once

#include <stdbool.h>
#include <stdint.h>

// Provisional Grim2D vtable skeleton.
//
// NOTE: grim.dll methods are called via a vtable pointer at DAT_0048083c.
// The real calling convention is __thiscall on Windows; treat the first
// parameter as the implicit 'this' when calling from C.

typedef struct Grim2D Grim2D;
typedef struct Grim2DVtable Grim2DVtable;

struct Grim2DVtable {
    void (*fn_0x0)(void); // 0x0 (FUN_10005c80)
    void (*fn_0x4)(void); // 0x4 (FUN_10005c90)
    void (*fn_0x8)(void); // 0x8 (FUN_10005ca0)
    void (*fn_0xc)(void); // 0xc (FUN_10005cb0)
    void (*fn_0x10)(void); // 0x10 (FUN_10005d40)
    void (*fn_0x14)(void); // 0x14 (FUN_10005eb0)
    void (*fn_0x18)(void); // 0x18 (FUN_10005ff0)
    void (*fn_0x1c)(void); // 0x1c (FUN_10006020)
    void (*set_render_state)(uint32_t state, uint32_t value); // 0x20 (FUN_10006580)
    void (*fn_0x24)(void); // 0x24 (FUN_10006c30)
    void (*fn_0x28)(void); // 0x28 (FUN_10006ca0)
    void (*fn_0x2c)(void); // 0x2c (FUN_10006cb0)
    void (*fn_0x30)(void); // 0x30 (FUN_10006d50)
    void (*fn_0x34)(void); // 0x34 (FUN_10006e40)
    void (*fn_0x38)(void); // 0x38 (FUN_10006e50)
    void (*fn_0x3c)(void); // 0x3c (FUN_10006e60)
    void (*fn_0x40)(void); // 0x40 (FUN_10006e90)
    bool (*is_key_down)(uint32_t key); // 0x44 (FUN_10007320)
    bool (*was_key_pressed)(uint32_t key); // 0x48 (FUN_10007390)
    void (*fn_0x4c)(void); // 0x4c (FUN_10007330)
    int (*get_key_char)(void); // 0x50 (FUN_10005c40)
    void (*fn_0x54)(void); // 0x54 (FUN_10005c20)
    bool (*is_mouse_button_down)(int button); // 0x58 (FUN_10007410)
    void (*fn_0x5c)(void); // 0x5c (FUN_10007440)
    float (*get_mouse_wheel_delta)(void); // 0x60 (FUN_10007560)
    void (*fn_0x64)(void); // 0x64 (FUN_10007530)
    void (*fn_0x68)(void); // 0x68 (FUN_10007510)
    void (*fn_0x6c)(void); // 0x6c (FUN_10007520)
    void (*fn_0x70)(void); // 0x70 (FUN_100074d0)
    void (*fn_0x74)(void); // 0x74 (FUN_100074e0)
    void (*fn_0x78)(void); // 0x78 (FUN_100074f0)
    void (*fn_0x7c)(void); // 0x7c (FUN_10007500)
    bool (*is_key_active)(int key); // 0x80 (FUN_10006fe0)
    float (*get_config_float)(int id); // 0x84 (FUN_100071b0)
    void (*fn_0x88)(void); // 0x88 (FUN_100072c0)
    void (*fn_0x8c)(void); // 0x8c (FUN_100072d0)
    void (*fn_0x90)(void); // 0x90 (FUN_100072e0)
    void (*fn_0x94)(void); // 0x94 (FUN_10007300)
    void (*fn_0x98)(void); // 0x98 (FUN_10007580)
    void (*fn_0x9c)(void); // 0x9c (FUN_10007590)
    void (*fn_0xa0)(void); // 0xa0 (FUN_100075a0)
    void (*fn_0xa4)(void); // 0xa4 (FUN_100075b0)
    void (*fn_0xa8)(void); // 0xa8 (FUN_100075c0)
    bool (*create_texture)(const char *name, int width, int height); // 0xac (FUN_100075d0)
    void (*fn_0xb0)(void); // 0xb0 (FUN_10007790)
    bool (*load_texture)(const char *name, const char *path); // 0xb4 (FUN_100076e0)
    void (*fn_0xb8)(void); // 0xb8 (FUN_10007750)
    void (*fn_0xbc)(void); // 0xbc (FUN_10007700)
    int (*get_texture_handle)(const char *name); // 0xc0 (FUN_10007740)
    void (*bind_texture)(int handle, int stage); // 0xc4 (FUN_10007830)
    void (*fn_0xc8)(void); // 0xc8 (FUN_10007870)
    void (*fn_0xcc)(void); // 0xcc (FUN_100079b0)
    void (*fn_0xd0)(void); // 0xd0 (FUN_100078e0)
    void (*fn_0xd4)(void); // 0xd4 (FUN_10008f10)
    void (*fn_0xd8)(void); // 0xd8 (FUN_10007b90)
    void (*fn_0xdc)(void); // 0xdc (FUN_10007d40)
    void (*fn_0xe0)(void); // 0xe0 (FUN_100080b0)
    void (*fn_0xe4)(void); // 0xe4 (FUN_10008150)
    void (*fn_0xe8)(void); // 0xe8 (FUN_10007ac0)
    void (*fn_0xec)(void); // 0xec (FUN_100083c0)
    void (*fn_0xf0)(void); // 0xf0 (FUN_10007b20)
    void (*fn_0xf4)(void); // 0xf4 (FUN_10008e30)
    void (*fn_0xf8)(void); // 0xf8 (FUN_10008eb0)
    void (*set_rotation)(float radians); // 0xfc (FUN_10007f30)
    void (*set_uv)(float u0, float v0, float u1, float v1); // 0x100 (FUN_10008350)
    void (*set_atlas_frame)(int atlas, int frame); // 0x104 (FUN_10008230)
    void (*set_sub_rect)(int x, int y, int w, int h); // 0x108 (FUN_100082c0)
    void (*fn_0x10c)(void); // 0x10c (FUN_100083a0)
    void (*set_pivot)(const float *xy); // 0x110 (FUN_10008040)
    void (*set_color)(float r, float g, float b, float a); // 0x114 (FUN_10007f90)
    void (*fn_0x118)(void); // 0x118 (FUN_100081c0)
    void (*draw_quad)(float x, float y, float w, float h); // 0x11c (FUN_10008b10)
    void (*fn_0x120)(void); // 0x120 (FUN_10008720)
    void (*fn_0x124)(void); // 0x124 (FUN_10008750)
    void (*fn_0x128)(void); // 0x128 (FUN_100085c0)
    void (*fn_0x12c)(void); // 0x12c (FUN_10008680)
    void (*fn_0x130)(void); // 0x130 (FUN_10008430)
    void (*fn_0x134)(void); // 0x134 (FUN_100084e0)
    void (*fn_0x138)(void); // 0x138 (FUN_10009080)
    void (*fn_0x13c)(void); // 0x13c (FUN_100092b0)
    void (*fn_0x140)(void); // 0x140 (FUN_10009940)
    void (*draw_text)(float x, float y, const char *text); // 0x144 (FUN_10009730)
    void (*draw_text_box)(float x, float y, const char *text, ...); // 0x148 (FUN_10009980)
    int (*measure_text_width)(const char *text); // 0x14c (FUN_100096c0)
};

struct Grim2D {
    Grim2DVtable *vtbl;
};
