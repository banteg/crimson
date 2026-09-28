extern "C" void ui_draw_clock_gauge(
    int x, int y, int time_ms, float alpha);

extern "C" void ui_draw_clock_gauge_at(
    float *xy, float radius, float progress)
{
    if (progress <= 0.0f) {
        return;
    }

    ui_draw_clock_gauge(
        (int)xy[0],
        (int)xy[1],
        (int)(progress * 60000.0f),
        1.0f);
}
