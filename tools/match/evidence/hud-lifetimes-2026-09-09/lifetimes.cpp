struct vec2 {
    float x, y;
    vec2() {}
    vec2(float a, float b) : x(a), y(b) {}
};
extern "C" void observe(const vec2 *p);
extern "C" void outer(float y)
{
    vec2 position(27.0f, y);
    observe(&position);
    vec2 bar(64.0f, y);
    observe(&bar);
    position = vec2(80.0f, y);
    observe(&position);
}
extern "C" void split(float y)
{
    { vec2 position(27.0f, y); observe(&position); }
    { vec2 bar(64.0f, y); observe(&bar); }
    { vec2 position(80.0f, y); observe(&position); }
}
extern "C" void shared(float y)
{
    vec2 position(27.0f, y);
    observe(&position);
    position = vec2(64.0f, y);
    observe(&position);
    position = vec2(80.0f, y);
    observe(&position);
}
