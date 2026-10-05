---
tags:
  - status-analysis
---

# Entrypoint trace
This page captures a top-down call trace starting at the PE entrypoint so we
can hang names and subsystems off a stable boot sequence.

## Entry address

- PE entrypoint VA: `0x00463026`
- Function: `start`, the VC6 SP6 `WinMainCRTStartup` from LIBCMT's
  `wincrt0.obj`, matched byte-exact against the archive member; it calls
  `crimsonland_main` as `WinMain`.

## Trace (depth 2, internal calls only)

```
- start -> crt_mt_init, crt_io_init, crt_build_argv, crt_fast_error_exit, crt_exit, crt_build_environ, crt_skip_program_name, crt_heap_init ...
  - crt_mt_init -> crt_init_locks, crt_init_thread_data (0x004654a5), crt_calloc (0x004667ac)
  - crt_io_init -> __amsg_exit, _malloc
  - crt_build_argv -> __amsg_exit, _malloc, crt_mbcs_init (0x0046d5c7), crt_parse_cmdline
  - crt_fast_error_exit -> crt_runtime_error_banner, crt_report_runtime_error
  - crt_exit -> crt_doexit
  - crt_build_environ -> _strlen, __amsg_exit, crt_strcpy (0x00465c30), crt_free_base, _malloc, crt_mbcs_init (0x0046d5c7)
  - crt_skip_program_name -> crt_ismbblead, crt_mbcs_init (0x0046d5c7)
  - crt_heap_init -> crt_sbh_init, crt_sbh_create_region, crt_heap_select
  - crt_get_environment_strings -> crt_free_base, _malloc, crt_bufcpy (0x004658f0)
  - crt_exception_filter -> crt_xcptlookup, crt_get_thread_data
  - crimsonland_main -> crt_srand (0x00461739), texture_get_or_load, crt_getcwd (0x0046248e), audio_shutdown_all, reg_write_dword, crt_free, game_load_status, console_flush_log ...
  - crt_run_initializers -> crt_fpmath, crt_call_fn_range
    - crt_init_locks
    - crt_init_thread_data (0x004654a5)
    - crt_calloc (0x004667ac) -> crt_old_sbh_alloc_block, crt_calloc_sbh_unlock_cleanup, crt_calloc_old_sbh_unlock_cleanup, crt_call_new_handler (0x00467e47), crt_lock, crt_sbh_alloc_block, _memset
    - __amsg_exit -> crt_runtime_error_banner, __exit, crt_report_runtime_error
    - _malloc -> __nh_malloc
    - crt_mbcs_init (0x0046d5c7) -> crt_setmbcp (0x0046d1ef)
    - crt_parse_cmdline
    - crt_runtime_error_banner -> crt_report_runtime_error
    - crt_report_runtime_error -> crt_strcat (0x00465c40), crt_message_box_a, _strlen, _strncpy, crt_strcpy (0x00465c30)
    - crt_doexit -> crt_exit_unlock, crt_exit_lock, crt_call_fn_range
    - _strlen
    - crt_strcpy (0x00465c30)
    - crt_free_base -> crt_free_sbh_unlock_cleanup, crt_sbh_find_block (0x004679d6), crt_sbh_find_region (0x00466c7b), crt_lock, crt_old_sbh_free_block, crt_free_old_sbh_unlock_cleanup, crt_sbh_free_block
    - crt_ismbblead -> crt_ismbbtype
    - crt_sbh_init
    - crt_sbh_create_region -> _memset
    - crt_heap_select -> crt_chkstk (0x0046cda0), _strchr, _strncmp, crt_strtol_l (0x0046cdcf), crt_get_linker_version, _strstr
    - crt_bufcpy (0x004658f0)
    - crt_xcptlookup
    - crt_get_thread_data -> __amsg_exit, crt_init_thread_data (0x004654a5), crt_calloc (0x004667ac)
    - crt_srand (0x00461739) -> crt_get_thread_data
    - texture_get_or_load -> console_printf
    - crt_getcwd (0x0046248e) -> crt_unlock, crt_lock, crt_getdcwd (0x004624b5)
    - audio_shutdown_all -> sfx_release_all, dsound_shutdown (0x0043bc20), music_release_all
    - reg_write_dword
    - crt_free -> crt_free_base
    - game_load_status -> game_build_path (0x00402bd0), play_time_load, crt_fopen (0x0046103f), crt_fseek (0x00461d91), crt_ftell (0x00461c0e), crt_fclose, game_save_status, console_printf ...
    - console_flush_log -> crt_fflush (0x00461448), game_build_path (0x00402bd0), crt_fopen (0x0046103f), crt_fclose, crt_fwrite (0x004615ae)
    - dx_get_version -> dx_get_version_fallback_from_files, crt_tolower (0x00461e9b), dx_get_version_from_dxdiag, crt_snprintf (0x00461e4a)
    - HlinkNavigateString
    - Direct3DCreate8
    - crt_time -> crt_mktime (0x00465da5)
    - console_register_command -> operator_new, strdup_malloc
    - grim_load_interface
    - console_register_cvar (0x00402350) -> crt_free, operator_new, strdup_malloc, console_cvar_find (0x00402480), crt_atof_l (0x004610da)
    - crt_fpmath -> crt_ms_p5_mp_test_fdiv, crt_cfltcvt_init, crt_set_default_precision
    - crt_call_fn_range
```

## Classic Windows entry sequence (ordered)

From `start` (`0x00463026`), the classic binary performs a short CRT/bootstrap
sequence and then enters the main game loop.

High-level call order:

1) `GetVersion` → populate version globals
2) `crt_heap_init(1)` → CRT heap init (small-block selection)
3) `crt_mt_init()` → CRT thread/TLS init
4) `crt_io_init()` → CRT file handle table init
5) `GetCommandLineA()` → stored in `crt_ansi_command_line`
6) `crt_get_environment_strings()` → environment block copy
7) `crt_build_argv()` → parse command line into argv/argc
8) `crt_build_environ()` → build `environ` from environment block
9) `crt_run_initializers()` → invoke CRT initializer ranges
10) `GetStartupInfoA()` → captures startup flags
11) `crt_skip_program_name()` → command-line tail after argv[0]
12) `GetModuleHandleA(NULL)`
13) `crimsonland_main()` (`0x0042c450`) → full game init/run/shutdown
14) `crt_exit(exit_code)` → exit handling
15) `crt_exception_filter(exception_code, exception_ptr)` → CRT exception filter

Notes:

- `crimsonland_main()` includes DirectX version checks, Grim2D loading, config
  load/apply, input/audio/renderer setup, and the game loop + shutdown.

## Pre-logo loading pipeline (inside `crimsonland_main`)

This is the simplified startup slice **before** the logo/splash assets are first
loaded. All callsites below are in `crimsonland_main` at `0x0042c450`
(`decomp/1.9/crimsonland/crimsonland/crimsonland_main.cpp`).

1) Seed + DirectX check:
   - `crt_time` → `crt_srand`.
   - `dx_get_version` → MessageBox + early exit when too old.
   - `Direct3DCreate8` used as a presence check, then released.
2) Core paths + logging:
   - `crt_getcwd` → `game_base_path`.
   - Console banner prints + `console_flush_log`.
3) Config file + console commands:
   - `config_ensure_file`.
   - Registers commands: `setGammaRamp`, `snd_addGameTune`, `generateterrain`,
     `telltimesurvived`, `setresourcepaq`, `loadtexture`, `openurl`,
     `sndfreqadjustment`.

4) Grim2D interface:
   - `grim_load_interface` (dev path), fallback to `grim.dll`.
   - The developer-hint print block after this call never runs: its guard,
     `grim_interface_ptr == grim_interface_ptr + 1`, is always false.

   - `register_core_cvars`.
5) Config + save bootstrap:
   - `config_load_presets`.
   - `game_load_status` + `play_time_load`.
6) Grim config dialog + settings:
   - `grim_apply_config` (`vtable +0x10`).
   - `config_sync_from_grim`, then `config_load_presets` again.
   - `grim_get_config_var` (`vtable +0x24`) reads texture scale, windowed flag,
     screen dimensions, and backend flags.

   - `grim_set_config_var` (`vtable +0x20`) repeated while applying settings (config/state IDs include D3D render state values).
7) Input + system init:
   - Logs: keyboard/mouse/joystick.
   - `grim_init_system` (`vtable +0x14`) → initializes D3D/input + loads
     `smallFnt.dat`. On failure, shows `grim_get_error_text` and exits.

8) Post-init setup:
   - `console_exec_line("exec autoexec.txt")`.
   - Registers `v_width` / `v_height` cvars from the screen size.
   - `init_audio_and_terrain`.
9) **Logo assets load (first appearance of splash resources)**:
   - `texture_get_or_load("backplasma", "load\\backplasma.jaz")`
   - `texture_get_or_load("mockup", "load\\mockup.jaz")`
   - `texture_get_or_load("logo_esrb", "load\\esrb_mature.jaz")`
   - `texture_get_or_load("loading", "load\\loading.jaz")`
   - `texture_get_or_load("cl_logo", "load\\logo_crimsonland.tga")`

The "pre-logo" phase ends at step 8; step 9 is the earliest point where the
logo/splash textures become available.

## Game startup init boundary

`crimsonland_main` installs `game_startup_init` (`0x0042b290`,
`decomp/1.9/crimsonland/crimsonland/game_startup_init.cpp`) as Grim's frame
callback (`grim_set_config_var(0x2d, ...)`); it owns the loading screen, the
intro music play/mute, and the theme switch. `game_startup_init_prelude` (`0x0042b090`,
`decomp/1.9/crimsonland/crimsonland/game_startup_init_prelude.cpp`) is a
separate function it calls once texture loading finishes.

The `crt_*` functions are byte-exact archive matches against the VC6 SP6
`LIBCMT.LIB` (see `analysis/library_provenance.json`).
