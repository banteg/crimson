unsigned char spawned = 0;
for (int attempt = 0; attempt < 100; ++attempt) {
    if (spawned)
        break;
    switch (crt_rand() % 4) {
    case 0: {
        spawned = creature_spawn_random(FramePoint(spawn_random_coord(freeware_arena_width), -40.f).address());
        break;
    }
    case 1: {
        spawned = creature_spawn_random(FramePoint(spawn_random_coord(freeware_arena_width), freeware_arena_height + 40.f).address());
        break;
    }
    case 2: {
        float y = spawn_random_coord(freeware_arena_height);
        spawned = creature_spawn_random(FramePoint(-40.f, y).address());
        break;
    }
    case 3: {
        float y = spawn_random_coord(freeware_arena_height);
        spawned = creature_spawn_random(FramePoint(freeware_arena_width + 40.f, y).address());
        break;
    }
    }
}
