struct grim_pixel_format_dxt_t {
    virtual void placeholder(void);

    grim_pixel_format_dxt_t(unsigned int *desc);
};

struct grim_pixel_format_dxt2_t : grim_pixel_format_dxt_t {
    virtual void placeholder(void);

    grim_pixel_format_dxt2_t(unsigned int *desc);
};

grim_pixel_format_dxt2_t::grim_pixel_format_dxt2_t(unsigned int *desc)
    : grim_pixel_format_dxt_t(desc)
{
}
