#define DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(name)                               \
    struct name {                                                              \
        name();                                                                \
        void destroy_thunk();                                                  \
        virtual ~name();                                                       \
    };                                                                         \
    name::name()                                                               \
    {                                                                          \
    }

DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(grim_pixel_format_base_t)
DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(grim_pixel_format_dxt_base_t)
DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(grim_pixel_format_dxt_t)
DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(grim_pixel_format_yuv_base_t)
DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD(grim_pixel_format_yuv_t)

#undef DEFINE_VIRTUAL_DESTRUCTOR_SCAFFOLD

void grim_pixel_format_base_t::destroy_thunk()
{
    this->grim_pixel_format_base_t::~grim_pixel_format_base_t();
}

void grim_pixel_format_dxt_t::destroy_thunk()
{
    this->grim_pixel_format_dxt_t::~grim_pixel_format_dxt_t();
}

void grim_pixel_format_yuv_t::destroy_thunk()
{
    this->grim_pixel_format_yuv_t::~grim_pixel_format_yuv_t();
}
