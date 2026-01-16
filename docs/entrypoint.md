# Entrypoint trace

**Status:** In progress

This page captures a top-down call trace starting at the PE entrypoint so we
can hang names and subsystems off a stable boot sequence.

## Entry address

- PE entrypoint VA: `0x00463026`
- Ghidra function: `entry` (`entry @ 00463026`)

## Regenerate trace

```
uv run python scripts/entrypoint_trace.py --depth 2 --skip-external
```

## Trace (depth 2, internal calls only)

```
- entry -> crt_mt_init, crt_get_environment_strings, crt_exit, FUN_00463153, crt_build_argv, crimsonland_main, crt_run_initializers, crt_exception_filter ...
  - crt_mt_init -> crt_init_locks, FUN_004667ac, FUN_004654a5
  - crt_get_environment_strings -> FUN_004658f0, FUN_004625c1, _malloc
  - crt_exit -> crt_doexit
  - FUN_00463153 -> crt_report_runtime_error, crt_runtime_error_banner
  - crt_build_argv -> __amsg_exit, crt_parse_cmdline, FUN_0046d5c7, _malloc
  - crimsonland_main -> HlinkNavigateString, FUN_0042a9f0, FUN_0041ccb0, Direct3DCreate8, FUN_00402350, FUN_004623b2, FUN_0041f1a0, FUN_0042a9c0 ...
  - crt_run_initializers -> crt_call_fn_range, FUN_00460cb8
  - crt_exception_filter -> crt_get_thread_data, FUN_00466a27
  - crt_io_init -> __amsg_exit, _malloc
  - crt_build_environ -> __amsg_exit, FUN_00465c30, FUN_004625c1, FUN_0046d5c7, _malloc, _strlen
  - crt_heap_init -> crt_sbh_create_region, crt_sbh_init, crt_heap_select
  - crt_skip_program_name -> FUN_0046d5c7, FUN_0046d1ad
    - crt_init_locks
    - FUN_004667ac -> FUN_00467e47, FUN_004668ce, FUN_00467a72, FUN_00466fcf, FUN_00466845, crt_lock, _memset
    - FUN_004654a5
    - FUN_004658f0
    - FUN_004625c1 -> FUN_00466ca6, FUN_0046262b, crt_lock, FUN_00466c7b, FUN_00467a2d, FUN_00462683, FUN_004679d6
    - _malloc -> __nh_malloc
    - crt_doexit -> crt_exit_lock, crt_call_fn_range, crt_exit_unlock
    - crt_report_runtime_error -> FUN_00465c40, FUN_0046d5e3, FUN_00465c30, _strlen, _strncpy
    - crt_runtime_error_banner -> crt_report_runtime_error
    - __amsg_exit -> crt_report_runtime_error, __exit, crt_runtime_error_banner
    - crt_parse_cmdline
    - FUN_0046d5c7 -> FUN_0046d1ef
    - HlinkNavigateString
    - FUN_0042a9f0 -> __ftol, FUN_00402860, console_printf, FUN_0043cf90
    - FUN_0041ccb0 -> FUN_0041cdb0, FUN_00461e4a, FUN_0041cfe0, FUN_00461e9b
    - Direct3DCreate8
    - FUN_00402350 -> strdup_malloc, operator_new, FUN_00402480, FUN_00460dc7, FUN_004610da
    - FUN_004623b2 -> FUN_00465da5
    - FUN_0041f1a0 -> FUN_00461af7, FUN_00402bd0, FUN_0046103f, FUN_00460e5d, FUN_00461d91, FUN_00461c0e, FUN_0041ec60
    - FUN_0042a9c0
    - FUN_0043d110 -> FUN_0043d070, FUN_0043d0d0, FUN_0043bc20
    - FUN_00402c00 -> FUN_00402350
    - FUN_0046248e -> FUN_004624b5, crt_unlock, crt_lock
    - FUN_004026e0 -> strdup_malloc, operator_new
    - FUN_00412a10 -> FUN_0042a980
    - FUN_00401940 -> FUN_00402580, strdup_malloc, FUN_00402750, console_printf, FUN_00402480, FUN_00460dc7, FUN_004610da
    - FUN_00402860 -> FUN_004615ae, FUN_00402bd0, FUN_00461448, FUN_0046103f, FUN_00460e5d
    - FUN_00412a80 -> FUN_0042a9c0, FUN_004615ae, FUN_00412c10, FUN_00412a10, FUN_00402bd0, FUN_0046103f, FUN_00460e5d, console_printf
    - FUN_00461739 -> crt_get_thread_data
    - crt_call_fn_range
    - FUN_00460cb8 -> FUN_00460cd0, FUN_004636e7, FUN_00463737
    - crt_get_thread_data -> __amsg_exit, FUN_004667ac, FUN_004654a5
    - FUN_00466a27
    - FUN_00465c30
    - _strlen
    - crt_sbh_create_region -> _memset
    - crt_sbh_init
    - crt_heap_select -> FUN_0046cda0, _strchr, _strncmp, FUN_0046cdcf, FUN_00466a61, _strstr
    - FUN_0046d1ad -> FUN_0046d1be
```

## Classic Windows entry sequence (ordered)

From `entry` (`0x00463026`), the classic binary performs a short CRT/bootstrap
sequence and then enters the main game loop.

High-level call order:

1) `GetVersion` → populate version globals
2) `crt_heap_init(1)` → CRT heap init (small-block selection)
3) `crt_mt_init()` → CRT thread/TLS init
4) `crt_io_init()` → CRT file handle table init
5) `GetCommandLineA()` → stored in `DAT_004db4e4`
6) `crt_get_environment_strings()` → environment block copy
7) `crt_build_argv()` → parse command line into argv/argc
8) `crt_build_environ()` → build `environ` from environment block
9) `crt_run_initializers()` → invoke CRT initializer ranges
10) `GetStartupInfoA()` → captures startup flags
11) `crt_skip_program_name()` → command-line tail after argv[0]
12) `GetModuleHandleA(NULL)`
13) `crimsonland_main()` (`FUN_0042c450`) → full game init/run/shutdown
14) `crt_exit(exit_code)` → exit handling
15) `crt_exception_filter(exception_code, exception_ptr)` → CRT exception filter

Notes:
- `crimsonland_main()` includes DirectX version checks, Grim2D loading, config
  load/apply, input/audio/renderer setup, and the game loop + shutdown.
- The early CRT cluster is now tagged as `crt_*` (heap/TLS/IO); confirm exact
  MSVCRT symbol names later.

## Modern Linux main trace (depth 2, internal calls only)

**Caveat:** the modern Linux build is a different engine (Nexus vs Grim2D) and
released much later. Use this trace only for loose orientation (naming ideas
and broad initialization phases). The classic Windows binary is the source of
truth for behavior and ordering.

```
uv run python scripts/entrypoint_trace.py \
  source/decompiled-modern/crimsonland_linux_135/crimsonland_calls.json \
  --entry main --depth 2 --skip-external
```

```
- main -> NXID_MainLoop, NXI_PreInit, NX_SDL_DetermineDeviceInfo, SDL_Init
  - NXID_MainLoop -> NEXUS_Shutdown, NXID_ProcessEvent, NXI_Frame, NXI_Init, NXI_SetGamepadButtonState, SDL_GameControllerClose, SDL_GameControllerGetAttached, SDL_GameControllerGetAxis ...
  - NXI_PreInit -> AppendFormatted, GetArrayOfSupportedResolutions, Init, Initialize, InitializePathsAndDirectories, NXID_DetermineDeviceInfo, NXID_InitImageLoader, NXI_AddPackages ...
  - NX_SDL_DetermineDeviceInfo -> SDL_GetDesktopDisplayMode, SDL_GetError, SDL_Log, __stack_chk_fail
  - SDL_Init
    - NEXUS_Shutdown -> Deinitialize, Free, GetSoundImpNull, NXID_DestroyWindow, NXI_ShutdownRendImp, NXT_DestroyMutex, NXT_PrintThreadInfos, NX_ShutdownExtensionModules ...
    - NXID_ProcessEvent -> NXID_ConvertKey, NXI_ActivateApp, NXI_SendEvent, NXI_SendKeyEvent, NXI_SendMouseEvent, __stack_chk_fail
    - NXI_Frame -> NXI_Frame
    - NXI_Init -> Format, GetSoundImpNull, NEXUS_SoundImp_GetInterface, NXID_CreateWindow, NXID_DestroyWindow, NXI_InitRendImp, NXI_ProductFeatureExists, NXI_SetupAutoscaling ...
    - NXI_SetGamepadButtonState -> NXI_SendEventQueued, __stack_chk_fail
    - SDL_GameControllerClose
    - SDL_GameControllerGetAttached
    - SDL_GameControllerGetAxis
    - SDL_GameControllerGetButton
    - SDL_GameControllerGetJoystick
    - SDL_GameControllerOpen
    - SDL_IsGameController
    - SDL_JoystickInstanceID
    - SDL_NumJoysticks
    - SDL_PollEvent
    - SDL_Quit
    - SetMaximumSize -> __cxa_throw_bad_array_new_length, operator.delete[], operator.new[]
    - __cxa_throw_bad_array_new_length
    - __stack_chk_fail
    - operator.delete[]
    - operator.new[]
    - AppendFormatted -> __stack_chk_fail, free, malloc, memcpy, nStringFormatDynamic, operator.delete[], strlen
    - GetArrayOfSupportedResolutions
    - Init -> DetermineLogFileName, NXI_ProductFeatureExists, NXT_GetDate, NX_fprintf, __stack_chk_fail, __strcpy_chk, free
    - Initialize -> malloc
    - InitializePathsAndDirectories -> CreateDirectory, Format, Set, SetFormatted, __stack_chk_fail, free
    - NXID_DetermineDeviceInfo -> SDL_GetDesktopDisplayMode, SDL_GetError, SDL_Log, __stack_chk_fail
    - NXID_InitImageLoader -> GetImageLoaderImp
    - NXI_AddPackages -> NXI_AddPackages
    - NXI_AddPackagesDefinedInProgramParameters -> NXI_AddPackages, NXI_SelectGFXPackage
    - NXI_CheckForMultipleProgramInstances
    - NXI_DetermineInitialScreenMode -> NXI_IsResolutionSupportedByDevice, NXI_ProductFeatureExists, NXI_SelectOptimalResolution, __stack_chk_fail
    - NXI_DetermineLocale -> AppendFormatted, free, malloc, memcpy, nStringDuplicate, strlen
    - NXI_DetermineOrientation
    - NXI_DetermineProgramParameters
    - NXI_FinalizeProgramNamesIdsAndDirectories -> __ctype_b_loc, __strcpy_chk, strlen
    - NXI_LoadProgImp -> Format, NXI_GetNullProg, NX_GetInterface, __snprintf_chk, __stack_chk_fail, free
    - NXI_LoadRendImp -> NXID_LoadRendImp, NXI_SetBasicInterface
    - NXI_ProductFeatureExists -> strlen, strstr
    - NXI_ReadProgramSettings -> Append, Format, GetArray, GetDatabase, GetNode, GetValue, NXI_AddManifest, NXI_GetPlatformIdFromString ...
    - NXI_RemoveResourcePackages -> Format, GetToken, __stack_chk_fail, free, malloc, memcpy, strchr, strlen
    - NXI_StateSetup -> NXI_SetBasicInterface, __stack_chk_fail, gettimeofday, memset, now
    - NXPI_ResolvePlatformInfo
    - NXT_CreateMutex -> malloc, memcpy, operator.new, pthread_mutex_init, strlen
    - NXT_InitThreads -> NXT_CreateMutex
    - NX_InitializeExtensionModules -> NXI_ProductFeatureExists, NX_InitializeExtensionModuleImplementations, NX_RegisterExtensionModule, NX_ResolveExtensionModuleImplementations, operator.new
    - free
    - nStringDuplicate -> malloc, memcpy, strlen
    - qsort
    - SDL_GetDesktopDisplayMode
    - SDL_GetError
    - SDL_Log
```
