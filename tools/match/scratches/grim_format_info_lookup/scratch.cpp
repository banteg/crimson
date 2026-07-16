struct grim_format_info_t {
    int format;
    int fields[8];
};

extern grim_format_info_t grim_format_info_default;
extern grim_format_info_t grim_format_info_entries[];
extern grim_format_info_t *grim_format_info_end;

extern "C" grim_format_info_t *grim_format_info_lookup(int format)
{
    grim_format_info_t *entry = grim_format_info_entries;
    while (entry < grim_format_info_end) {
        if (format == entry->format) {
            return entry;
        }
        ++entry;
    }
    return &grim_format_info_default;
}
