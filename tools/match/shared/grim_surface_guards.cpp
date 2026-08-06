struct grim_surface_t;
struct grim_device_t;

struct grim_surface_vtable_t {
    void *query_interface;
    void *add_ref;
    unsigned long (__stdcall *release)(grim_surface_t *self);
    void *slots_0c_24[7];
    long (__stdcall *unlock_rect)(grim_surface_t *self);
};

struct grim_surface_t {
    grim_surface_vtable_t *vtable;
};

struct grim_device_vtable_t {
    void *query_interface;
    void *add_ref;
    unsigned long (__stdcall *release)(grim_device_t *self);
    void *slots_0c_6c[25];
    long (__stdcall *copy_rects)(
        grim_device_t *self,
        grim_surface_t *source,
        const void *source_rects,
        unsigned int rect_count,
        grim_surface_t *destination,
        const void *destination_points);
};

struct grim_device_t {
    grim_device_vtable_t *vtable;
};

struct grim_surface_copy_guard_t {
    unsigned int flags;
    grim_surface_t *destination_surface;
    grim_surface_t *source_surface;
    grim_device_t *device;

    grim_surface_copy_guard_t();
    int release();
    int release_thunk();
};

grim_surface_copy_guard_t::grim_surface_copy_guard_t()
    : flags(0), destination_surface(0), source_surface(0), device(0)
{
}

int grim_surface_copy_guard_t::release()
{
    if (source_surface != 0) {
        source_surface->vtable->unlock_rect(source_surface);
    } else if (destination_surface != 0) {
        destination_surface->vtable->unlock_rect(destination_surface);
    }

    if (destination_surface != 0 && source_surface != 0 && device != 0
        && (flags & 1) == 0) {
        device->vtable->copy_rects(
            device, source_surface, 0, 0, destination_surface, 0);
    }

    if (source_surface != 0) {
        source_surface->vtable->release(source_surface);
        source_surface = 0;
    }
    if (device != 0) {
        device->vtable->release(device);
        device = 0;
    }
    destination_surface = 0;
    return 0;
}

int grim_surface_copy_guard_t::release_thunk()
{
    return release();
}

struct grim_surface_lock_guard_t {
    grim_surface_t *surface;

    grim_surface_lock_guard_t();
    int release();
    int release_thunk();
};

grim_surface_lock_guard_t::grim_surface_lock_guard_t() : surface(0)
{
}

int grim_surface_lock_guard_t::release()
{
    if (surface != 0) {
        surface->vtable->unlock_rect(surface);
    }
    surface = 0;
    return 0;
}

int grim_surface_lock_guard_t::release_thunk()
{
    return release();
}
