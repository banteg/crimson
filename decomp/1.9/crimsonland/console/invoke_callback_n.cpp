struct callback_object_t {
    void invoke(void);
};

typedef void (callback_object_t::*member_callback_t)(void);

extern "C" void __stdcall invoke_callback_n(
    callback_object_t *cursor,
    int stride,
    int count,
    member_callback_t callback)
{
    while (--count >= 0) {
        (cursor->*callback)();
        cursor = (callback_object_t *)((char *)cursor + stride);
    }
}
