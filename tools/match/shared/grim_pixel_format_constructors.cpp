struct grim_pixel_format_base_t {
    void **vtable;

    grim_pixel_format_base_t(
        unsigned int *description, int bit_count, int channel_count);
};

#define DEFINE_PIXEL_FORMAT_CONSTRUCTOR(name, bit_count, channel_count)       \
    extern "C" void *grim_pixel_format_vtable_##name[];                       \
    struct grim_pixel_format_##name##_t : grim_pixel_format_base_t {          \
        grim_pixel_format_##name##_t(unsigned int *description);              \
    };                                                                         \
    grim_pixel_format_##name##_t::grim_pixel_format_##name##_t(               \
        unsigned int *description)                                             \
        : grim_pixel_format_base_t(description, bit_count, channel_count)      \
    {                                                                          \
        vtable = grim_pixel_format_vtable_##name;                              \
    }

DEFINE_PIXEL_FORMAT_CONSTRUCTOR(r8g8b8, 24, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a8r8g8b8, 32, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(x8r8g8b8, 32, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(r5g6b5, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(x1r5g5b5, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a1r5g5b5, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a4r4g4b4, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(r3g3b2, 8, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a8, 8, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a8r3g3b2, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(x4r4g4b4, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a2b10g10r10, 32, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(g16r16, 32, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a8p8, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(p8, 8, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(l8, 8, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a8l8, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a4l4, 8, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(v8u8, 16, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(l6v5u5, 16, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(x8l8v8u8, 32, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(q8w8v8u8, 32, 3)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(v16u16, 32, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(w11v11u10, 32, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(a2w10v10u10, 32, 2)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(d16_lockable, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(l16, 16, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(al16, 32, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(r16, 48, 1)
DEFINE_PIXEL_FORMAT_CONSTRUCTOR(ar16, 64, 1)

#undef DEFINE_PIXEL_FORMAT_CONSTRUCTOR

struct grim_pixel_format_dxt_base_t {
    void **vtable;

    grim_pixel_format_dxt_base_t(unsigned int *description);
};

#define DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(name)                              \
    extern "C" void *grim_pixel_format_vtable_##name[];                       \
    struct grim_pixel_format_##name##_t : grim_pixel_format_dxt_base_t {      \
        grim_pixel_format_##name##_t(unsigned int *description);              \
    };                                                                         \
    grim_pixel_format_##name##_t::grim_pixel_format_##name##_t(               \
        unsigned int *description)                                             \
        : grim_pixel_format_dxt_base_t(description)                            \
    {                                                                          \
        vtable = grim_pixel_format_vtable_##name;                              \
    }

DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(dxt1)
DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(dxt2)
DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(dxt3)
DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(dxt4)
DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR(dxt5)

#undef DEFINE_DXT_PIXEL_FORMAT_CONSTRUCTOR

struct grim_pixel_format_yuv_base_t {
    void **vtable;

    grim_pixel_format_yuv_base_t(unsigned int *description);
};

#define DEFINE_YUV_PIXEL_FORMAT_CONSTRUCTOR(name)                              \
    extern "C" void *grim_pixel_format_vtable_##name[];                       \
    struct grim_pixel_format_##name##_t : grim_pixel_format_yuv_base_t {      \
        grim_pixel_format_##name##_t(unsigned int *description);              \
    };                                                                         \
    grim_pixel_format_##name##_t::grim_pixel_format_##name##_t(               \
        unsigned int *description)                                             \
        : grim_pixel_format_yuv_base_t(description)                            \
    {                                                                          \
        vtable = grim_pixel_format_vtable_##name;                              \
    }

DEFINE_YUV_PIXEL_FORMAT_CONSTRUCTOR(uyvy)
DEFINE_YUV_PIXEL_FORMAT_CONSTRUCTOR(yuy2)

#undef DEFINE_YUV_PIXEL_FORMAT_CONSTRUCTOR
