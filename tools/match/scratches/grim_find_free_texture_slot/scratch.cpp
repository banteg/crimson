extern void *grim_texture_slots;

extern "C" int grim_find_free_texture_slot(void)
{
    int index = 0;
    void **slot = &grim_texture_slots;

    while ((int)slot < (int)(&grim_texture_slots + 256)) {
        if (*slot == 0) {
            goto done;
        }
        ++slot;
        ++index;
    }
    index = -1;

done:
    return index;
}
