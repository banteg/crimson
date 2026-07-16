class grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_base_t();

protected:
    unsigned char fields[0x1068];
};

class grim_pixel_format_yuv_t : public grim_pixel_format_base_t {
public:
    virtual void quantize_color_key();
};

void grim_pixel_format_yuv_t::quantize_color_key()
{
}
