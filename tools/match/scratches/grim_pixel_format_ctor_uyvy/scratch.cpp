struct grim_pixel_format_yuv_t {
    virtual void placeholder(void);

    grim_pixel_format_yuv_t(unsigned int *desc);
};

struct grim_pixel_format_uyvy_t : grim_pixel_format_yuv_t {
    virtual void placeholder(void);

    grim_pixel_format_uyvy_t(unsigned int *desc);
};

grim_pixel_format_uyvy_t::grim_pixel_format_uyvy_t(unsigned int *desc)
    : grim_pixel_format_yuv_t(desc)
{
}
