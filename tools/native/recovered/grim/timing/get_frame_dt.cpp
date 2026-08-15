extern "C" float grim_frame_dt;

extern "C" float grim_get_frame_dt(void)
{
    if (grim_frame_dt > 0.1f) {
        return 0.1f;
    }
    return grim_frame_dt;
}
