void __cdecl operator delete(void *allocation);

struct grim_vertex_space_converter_t {
    virtual ~grim_vertex_space_converter_t();

    unsigned char fields[0x104c];
};

struct grim_dxt_cache_entry_t {
    unsigned int value;
    void *allocation;
};

struct grim_pixel_format_dxt_t : grim_vertex_space_converter_t {
    virtual ~grim_pixel_format_dxt_t();

    unsigned char fields_1050[0x40];
    unsigned char *row_begin;
    unsigned int reserved_1094;
    unsigned char *row_end;
    unsigned int column_begin;
    unsigned int column_end;
    unsigned char fields_10a4[0x14];
    void *cache_data;
    unsigned int cache_active;
    grim_dxt_cache_entry_t *entries;
};

grim_pixel_format_dxt_t::~grim_pixel_format_dxt_t()
{
    grim_dxt_cache_entry_t *entry;
    register unsigned char *row;
    unsigned int column;

    if (cache_active == 0 || entries == 0) {
        goto release_cache;
    }

    entry = entries;
    column = column_begin;
    if (column < column_end) {
        do {
            row = row_begin;
            while (row < row_end) {
                operator delete(entry->allocation);
                ++entry;
                row += 4;
            }
            ++column;
        } while (column < column_end);
    }

release_cache:
    operator delete(cache_data);
    operator delete(entries);
}
