# fx_queue_random_color_destroy

Native target: `crimsonland.exe` at `0x00427830` (1 byte).

`fx_queue_add_random` registers this callback when its function-local color is
initialized. The four-float color owns no resources, so its generated
destructor is naturally empty and matches the sole native `ret` instruction.
