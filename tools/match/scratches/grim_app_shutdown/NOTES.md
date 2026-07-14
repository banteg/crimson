# grim_app_shutdown

The one-instruction function at `0x10003080` is the optimized `MyApp`
shutdown wrapper used by `grim_run_loop`. It tail-calls the GDI cleanup body at
`0x10002f60`.

The one native jump and its cleanup reference match exactly under MSVC 6.5
`/O2 /GB`.
