void __cdecl operator delete(void *allocation);

struct grim_vertex_space_converter_t {
    virtual ~grim_vertex_space_converter_t();
    void noop(unsigned int, unsigned int, unsigned int);

    unsigned char fields[0x1048];
    void *allocation;
};

grim_vertex_space_converter_t::~grim_vertex_space_converter_t()
{
    operator delete(allocation);
}

void grim_vertex_space_converter_t::noop(
    unsigned int, unsigned int, unsigned int)
{
}
