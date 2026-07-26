extern "C" bool grim_zlib_status_is_error(int status)
{
    bool is_error;
    switch (status) {
    case 0:
        is_error = false;
        break;
    case 1:
        is_error = false;
        break;
    case 2:
        is_error = false;
        break;
    default:
        is_error = true;
        break;
    }
    return is_error;
}
