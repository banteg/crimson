---
tags:
  - status-analysis
---

# Entrypoint trace
Top-down call trace from the PE entrypoint through the VC6 CRT startup into
`crimsonland_main`. The game's own startup continues in
[Boot / Loading Sequence](boot-sequence.md).

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

`crimsonland_main` (`decomp/1.9/crimsonland/crimsonland/crimsonland_main.cpp`)
covers DirectX checks, Grim2D loading, config, input/audio/renderer setup, the
game loop and shutdown; [Boot / Loading Sequence](boot-sequence.md) walks it in
order.

The `crt_*` functions are byte-exact archive matches against the VC6 SP6
`LIBCMT.LIB` (see `analysis/library_provenance.json`).
