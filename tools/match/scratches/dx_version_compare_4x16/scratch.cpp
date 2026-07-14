extern "C" int dx_version_compare_4x16(
    unsigned int current_ls,
    unsigned int current_ms,
    unsigned int required_ls,
    unsigned int required_ms)
{
    if (current_ms > required_ms) {
        return 1;
    }
    if (current_ms < required_ms) {
        return -1;
    }
    if (current_ls > required_ls) {
        return 1;
    }
    if (current_ls < required_ls) {
        return -1;
    }
    return 0;
}
