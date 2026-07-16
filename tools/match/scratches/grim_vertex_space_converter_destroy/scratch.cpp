void __cdecl operator delete(void *memory);

class grim_vertex_space_converter_t {
public:
    virtual ~grim_vertex_space_converter_t();

private:
    unsigned char fields[0x1048];
    void *converted_vertices;
};

grim_vertex_space_converter_t::~grim_vertex_space_converter_t()
{
    operator delete(converted_vertices);
}
