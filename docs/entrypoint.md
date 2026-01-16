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
- entry -> FUN_00468a24, FUN_00465451, FUN_0046623d, FUN_00468913, FUN_00466bd6, FUN_0042c450, FUN_00462edd, FUN_004668e9 ...
  - FUN_00468a24 -> FUN_0046d5c7, FUN_00468abd, _malloc, __amsg_exit
  - FUN_00465451 -> FUN_00465842, FUN_004667ac, FUN_004654a5
  - FUN_0046623d -> _malloc, __amsg_exit
  - FUN_00468913 -> FUN_0046d5c7, FUN_0046d1ad
  - FUN_00466bd6 -> FUN_0046777a, FUN_00466a8e, FUN_00466c33
  - FUN_0042c450 -> Direct3DCreate8, FUN_0046248e, FUN_00412a80, FUN_0041dc80, FUN_00401940, FUN_00402350, FUN_00460dc7, FUN_0043d110 ...
  - FUN_00462edd -> FUN_00462eff
  - FUN_004668e9 -> FUN_004654b8, FUN_00466a27
  - FUN_0046896b -> _strlen, FUN_0046d5c7, FUN_00465c30, _malloc, __amsg_exit, FUN_004625c1
  - FUN_00462eb0 -> FUN_00462fb6, FUN_00460cb8
  - FUN_00468c71 -> _malloc, FUN_004625c1, FUN_004658f0
  - FUN_00463153 -> FUN_00468ddc, FUN_00468da3
    - FUN_0046d5c7 -> FUN_0046d1ef
    - FUN_00468abd
    - _malloc -> __nh_malloc
    - __amsg_exit -> __exit, FUN_00468ddc, FUN_00468da3
    - FUN_00465842
    - FUN_004667ac -> FUN_0046586b, FUN_004668ce, FUN_00467a72, FUN_00466845, FUN_00466fcf, FUN_00467e47, _memset
    - FUN_004654a5
    - FUN_0046d1ad -> FUN_0046d1be
    - FUN_0046777a -> _memset
    - FUN_00466a8e -> _strchr, FUN_0046cdcf, _strstr, FUN_00466a61, FUN_0046cda0, _strncmp
    - FUN_00466c33
    - Direct3DCreate8
    - FUN_0046248e -> FUN_0046586b, FUN_004658cc, FUN_004624b5
    - FUN_00412a80 -> FUN_00460e5d, FUN_004615ae, FUN_00412a10, FUN_0046103f, FUN_0042a9c0, FUN_00412c10, FUN_00402bd0, console_printf
    - FUN_0041dc80
    - FUN_00401940 -> strdup_malloc, FUN_00402750, FUN_00402580, FUN_004610da, FUN_00402480, FUN_00460dc7, console_printf
    - FUN_00402350 -> strdup_malloc, operator_new, FUN_004610da, FUN_00402480, FUN_00460dc7
    - FUN_00460dc7 -> FUN_004625c1
    - FUN_0043d110 -> FUN_0043d070, FUN_0043d0d0, FUN_0043bc20
    - FUN_0041ccb0 -> FUN_00461e4a, FUN_0041cdb0, FUN_0041cfe0, FUN_00461e9b
    - FUN_00402860 -> FUN_00460e5d, FUN_00461448, FUN_004615ae, FUN_0046103f, FUN_00402bd0
    - console_printf -> console_push_line, FUN_00461089
    - FUN_00402c00 -> FUN_00402350
    - FUN_00461739 -> FUN_004654b8
    - FUN_0041f1a0 -> FUN_00460e5d, FUN_00461c0e, FUN_0041ec60, FUN_0046103f, FUN_00461d91, FUN_00461af7, FUN_00402bd0
    - FUN_0041f130 -> FUN_00460e5d, FUN_004615ae, FUN_0046103f, FUN_00402bd0
    - FUN_004026e0 -> strdup_malloc, operator_new
    - FUN_00462eff -> FUN_00462fb6, FUN_00462fad, FUN_00462fa4
    - FUN_004654b8 -> FUN_004667ac, FUN_004654a5, __amsg_exit
    - FUN_00466a27
    - _strlen
    - FUN_00465c30
    - FUN_004625c1 -> FUN_0046586b, FUN_0046262b, FUN_00466ca6, FUN_00462683, FUN_00467a2d, FUN_00466c7b, FUN_004679d6
    - FUN_00462fb6
    - FUN_00460cb8 -> FUN_00463737, FUN_00460cd0, FUN_004636e7
    - FUN_004658f0
    - FUN_00468ddc -> _strlen, FUN_00465c30, FUN_0046d5e3, FUN_00465c40, _strncpy
    - FUN_00468da3 -> FUN_00468ddc
```

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
