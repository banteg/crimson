struct grim_pixel_format_base_t {
    virtual void placeholder(void);

    grim_pixel_format_base_t(
        unsigned int *desc,
        unsigned int bits_per_pixel,
        unsigned int coord_mode);
};

struct grim_pixel_format_r5g6b5_t : grim_pixel_format_base_t {
    virtual void placeholder(void);

    grim_pixel_format_r5g6b5_t(unsigned int *desc);
};

grim_pixel_format_r5g6b5_t::grim_pixel_format_r5g6b5_t(
    unsigned int *desc)
    : grim_pixel_format_base_t(desc, 16, 1)
{
}
