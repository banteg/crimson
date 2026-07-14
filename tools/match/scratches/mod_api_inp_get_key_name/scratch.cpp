#include "crimsonland_mod_api.h"

extern "C" char *input_key_name(int key);

char *mod_api_cpp_t::mod_api_inp_get_key_name(int key)
{
    return input_key_name(key);
}
