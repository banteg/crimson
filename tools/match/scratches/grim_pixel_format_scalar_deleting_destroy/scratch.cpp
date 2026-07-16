void __cdecl operator delete(void *memory);

class grim_pixel_format_t {
public:
    virtual ~grim_pixel_format_t();

private:
    unsigned char fields[0x1048];
    void *converted_vertices;
};

grim_pixel_format_t::~grim_pixel_format_t()
{
    operator delete(converted_vertices);
}
