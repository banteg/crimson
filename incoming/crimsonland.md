Based on the analysis of the decompiled code, here is a mapping of the identified functions, variables, and structures to more readable names, organized by subsystem.

### **Console & Input System**
The game features a Quake-style console for commands and variables (cvars).
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `DAT_0047e448` | `g_ConsoleInputBuf` | Buffer for current console input line |
| `DAT_0047ea54` | `g_ConsoleInputLen` | Current length of input string |
| `console_log_queue` | `g_Console` | Pointer to the main console object/struct |
| `FUN_004010f0` | `Console_ExecCallbackList` | Iterates a list of callbacks (used for initialization) |
| `FUN_00401170` | `Console_Create` | Allocates and initializes the console struct |
| `FUN_00401180` | `Console_RegisterCleanup` | Registers `atexit` cleanup |
| `FUN_004016e0` | `Console_Destroy` | Frees console memory |
| `FUN_00401dd0` | `Console_Render` | Draws the console overlay and text |

### **Game State & Logic**
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `config_blob` | `g_Config` | Main configuration structure |
| `config_blob.reserved0._20_4_` | `g_Config.PlayerCount` | Number of active players |
| `config_blob.reserved0._24_4_` | `g_Config.GameMode` | 1=Survival, 2=Rush, 3=Quest, 4=Typo |
| `game_state_id` | `g_GameState` | Current game state ID |
| `game_state_pending` | `g_NextGameState` | State to transition to |
| `render_pass_mode` | `g_IsGameActive` | Boolean flag for if gameplay is running |
| `player_state_table` | `g_Players` | Array of `player_t` structures (size 0xD8) |
| `creature_pool` | `g_Creatures` | Pool of `creature_t` structures |
| `projectile_pool` | `g_Projectiles` | Pool of `projectile_t` structures |
| `bonus_pool` | `g_Bonuses` | Pool of dropped bonuses |
| `quest_spawn_table` | `g_QuestWaves` | Array of spawn definitions for the current quest |
| `FUN_00403430` | `UI_MouseInRect` | Checks if mouse is within a specific rectangle |
| `FUN_00406350` | `Game_UpdateVictoryScreen` | Logic/Render for the "Congratulations" screen |
| `FUN_00406af0` | `Game_UpdateGenericMenu` | Generic update for paused/menu states |
| `FUN_004120b0` | `HighScore_ResetCurrent` | Resets the active highscore/session record |
| `FUN_00412190` | `Quest_Meta_Init` | Constructor for quest metadata array |
| `FUN_00412360` | `HighScore_InitSentinels` | Initializes memory for high score table |
| `FUN_00412940` | `Bonus_ResetAvailability` | Resets allowed bonuses |
| `FUN_0041fc80` | `Player_ResetAll` | Resets all players to default state |
| `FUN_00417640` | `Vec2_Sub` | `out = a - b` |
| `FUN_00417660` | `Vec2_Length` | Returns magnitude of vector |
| `FUN_0041e270` | `Vec2_Add` | `a += b` |

### **UI & Menu System**
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `ui_element_table_end` | `g_UIElements` | Array of UI element pointers |
| `ui_elements_timeline` | `g_UITime` | Animation timer for UI transitions |
| `ui_transition_direction` | `g_UITransitionDir` | 0=Out, 1=In |
| `FUN_00402d50` | `UI_RenderLoading` | Draws "Please wait..." |
| `FUN_00417a90` | `UI_Element_Init` | Constructor for UI elements |
| `FUN_00417ae0` | `UI_DrawTexturedQuad` | Helper to draw a sprite on screen |
| `FUN_0043d9b0` | `UI_UpdateWidgetRect` | Updates generic rectangular widgets |
| `FUN_004411c0` | `UI_DrawBox_Small` | Draws small outline box |
| `FUN_00441220` | `UI_DrawBox_Large` | Draws large outline box |
| `FUN_00441270` | `Format_RankString` | Returns "1st", "2nd", etc. |
| `FUN_004443c0` | `UI_UpdateProfileMenu` | Handles player profile selection menu |
| `FUN_00445310` | `Creature_IsNameTaken` | Checks if a generated name is in use |
| `FUN_00446150` | `UI_GetElementIndex` | Finds index of element in global table |

### **Graphics & Effects**
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `effect_pool_pos_x` | `g_Effects` | Pool of visual effects |
| `terrain_render_target` | `g_GroundLayer` | Render target for the ground/splatters |
| `terrain_texture_failed` | `g_SafeMode` | True if terrain generation failed |
| `FUN_00417b80` | `Terrain_Generate` | Generates the ground texture |
| `FUN_0042f080` | `Effect_SpawnBurst` | Spawns standard particle burst |
| `FUN_0042f270` | `Effect_SpawnShock` | Spawns electricity effect |
| `FUN_0042f3f0` | `Effect_SpawnBloodRing` | Spawns circular blood pattern |
| `FUN_0042f540` | `Effect_SpawnShockwave` | Spawns expanding ring effect |
| `FUN_0044fb50` | `UI_Layout_Calc` | Calculates positions for UI elements |

### **Audio System**
The game uses `dsound` for output and `vorbis` for compressed audio.
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `sfx_entry_table` | `g_SFXSamples` | Table of loaded sound effects |
| `music_entry_table` | `g_MusicTracks` | Table of loaded music streams |
| `sfx_cooldown_table` | `g_SFXCooldowns` | Prevents same sound playing too frequently |
| `FUN_0043b810` | `BufferReader_Reset` | Resets a memory reader stream |
| `FUN_0043baf0` | `DSound_Init` | Initializes DirectSound |

### **Initialization & Main Loop**
| Original Name | New Name | Description |
| :--- | :--- | :--- |
| `game_startup_init` | `Game_Startup` | Main initialization routine |
| `game_startup_init_prelude` | `Game_PreInit` | Early initialization |
| `load_textures_step` | `Game_LoadAssets` | Progressive asset loading (for progress bar) |
| `crimsonland_main` | `WinMain` | Entry point of the application |
| `console_hotkey_update` | `Game_Frame` | Main per-frame update loop called from `WinMain` |

### **Structure Definitions**
Based on usage:

**`vec2_t`**
```c
struct vec2_t {
    float x;
    float y;
};
```

**`player_t`** (approximate)
```c
struct player_t {
    float pos_x;       // 0x00
    float pos_y;       // 0x04
    // ...
    float aim_x;       // 0x...
    float aim_y;
    float heading;
    float move_speed;
    float health;      // 0xD8 offset implied by loop
    int weapon_id;
    int clip_size;
    int ammo;
    // ...
    int perk_counts[128]; // Large array at end
};
```

**`creature_t`**
```c
struct creature_t {
    int active;
    float pos_x;
    float pos_y;
    float vel_x;
    float vel_y;
    float heading;
    float health;
    float max_health;
    float size;
    float move_speed;
    float tint_r, tint_g, tint_b, tint_a;
    int type_id;
    // ...
};
```

**`bonus_entry_t`**
```c
struct bonus_entry_t {
    float pos_x;
    float pos_y;
    int bonus_id;
    float time_left;
    // ...
};
```

**`quest_spawn_entry_t`**
```c
struct quest_spawn_entry_t {
    float pos_x;
    float pos_y;
    int template_id;
    int trigger_time_ms;
    int count;
    // ...
};
```

**`ui_element_t`**
```c
struct ui_element_t {
    int active; // 0x00
    // ...
    int enabled;
    int counter_id;
    int counter_value;
    int counter_timer;
    void (*on_activate)(); // Function pointer
    // ...
};
```