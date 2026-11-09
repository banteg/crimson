// Expand the point at the call site. VC6 gives each early temporary its own frame slot.
#if FREEWARE_EDITION == 10002
#define SPAWN_EDGE_POINT(name, x, y) spawned = creature_spawn_random(FramePoint102(x, y).address())
#else
#define SPAWN_EDGE_POINT(name, x, y) \
    vec2f_t name = {x, y}; \
    spawned = creature_spawn_random(&name)
#endif
unsigned char spawned = 0;
for (int attempt = 0; attempt < 100; ++attempt) {
    if (spawned)
        break;
    switch (crt_rand() % 4) {
    case 0: {
        SPAWN_EDGE_POINT(north, spawn_random_coord(freeware_arena_width), -40.f);
        break;
    }
    case 1: {
        SPAWN_EDGE_POINT(south, spawn_random_coord(freeware_arena_width), freeware_arena_height + 40.f);
        break;
    }
    case 2: {
        float y = spawn_random_coord(freeware_arena_height);
        SPAWN_EDGE_POINT(west, -40.f, y);
        break;
    }
    case 3: {
        float y = spawn_random_coord(freeware_arena_height);
        SPAWN_EDGE_POINT(east, freeware_arena_width + 40.f, y);
        break;
    }
    }
}
#undef SPAWN_EDGE_POINT
