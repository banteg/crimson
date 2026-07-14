#include <string.h>

#include "crimsonland_mod_api.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void *mod_api_cpp_t::mod_api_core_get_extension(char *extension)
{
    if (strcmp(extension, "GrimGFX") == 0) {
        return grim_interface_ptr;
    }
    if (strcmp(extension, "GrimSFX") == 0) {
        return 0;
    }
    if (strcmp(extension, "IDirect3D8") == 0) {
        return (void *)grim_interface_ptr->grim_get_config_var(0x51).words[3];
    }
    return 0;
}
