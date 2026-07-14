#include "crimsonland_gameplay.h"

class bonus_meta_cpp_t {
public:
    ~bonus_meta_cpp_t(void);

    char *label;
    char *description;
    int icon_id;
    unsigned char enabled;
    unsigned char _pad0[3];
    int default_amount;
};

bonus_meta_cpp_t::~bonus_meta_cpp_t(void)
{
    if (label != 0) {
        crt_free(label);
    }
    if (description != 0) {
        crt_free(description);
    }
}
