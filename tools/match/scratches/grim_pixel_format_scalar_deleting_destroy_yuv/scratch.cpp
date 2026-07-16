class grim_yuv_cache_entry_t {
private:
    float channels[4];
};

class grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_base_t();

protected:
    unsigned char fields[0x1068];
};

class grim_pixel_format_yuv_t : public grim_pixel_format_base_t {
public:
    virtual ~grim_pixel_format_yuv_t();

    int flush_yuv_cache(void);

private:
    grim_yuv_cache_entry_t *cache;
    unsigned char fields[0x2c];
};

grim_pixel_format_yuv_t::~grim_pixel_format_yuv_t()
{
    flush_yuv_cache();
    if (cache != 0) {
        delete[] cache;
    }
}
