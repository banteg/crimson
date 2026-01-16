I can read the two decompiled sources you uploaded:

* `/mnt/data/crimsonland.exe_decompiled.c` (game executable: a lot of gameplay + glue)
* `/mnt/data/grim.dll_decompiled.c` (the “Grim/Grim2D” engine DLL: rendering/input/config)

Note: the file-indexing tool reports that *some* previously-uploaded files have expired from its index. I can still analyze the two decompiled C files above (they’re present), but if you meant additional files beyond these two, you’ll need to re-upload them.

Below is a long, practical reverse‑engineering plan organized around what these files show you’ll need to understand. I’ll keep it focused on **complete behavioral understanding / clean reimplementation** (not bypassing licensing/DRM).

---

## What’s already clear from these decompilations

### Architectural split: game vs engine

* **`crimsonland.exe`** contains:

  * gameplay state machine (Survival / Quests / Typ-o-Shooter strings appear),
  * hardcoded perk definitions, quest templates, enemy setup, etc.,
  * sound system code that loads a *lot* of `.ogg` assets,
  * save/status and score/checksum logic,
  * a console/command system that runs `exec autoexec.txt` and `exec music_game_tunes.txt`,
  * lots of hardcoded “content tables” (enemies/perks/quests).

* **`grim.dll`** contains the core platform layer:

  * **Direct3D 8** device lifecycle, device restore, texture management, render states,
  * **DirectInput 8** init for keyboard/mouse/joystick (explicit errors for each),
  * a **config UI + config file** called `crimson_cfg` stored as a fixed-size blob (`0x480` bytes),
  * file loading helpers (e.g., `load_smallFnt.dat` is referenced),
  * the “Grim2D API” object that the EXE calls via a vtable.

### Formats & resources beyond what you already solved

You said you fully understand `.paq` and `.jaz`. Great. In the EXE code, I also see:

* **`music.paq`** and **`sfx.paq`** used as sound resource packs.
* heavy use of **`.ogg`** assets (dozens of samples + music tracks).
* at least one `.dat` file in the engine: `load_smallFnt.dat`.
* script-ish text files: `autoexec.txt`, `music_game_tunes.txt`.

### A concrete “surface area” to map

The EXE registers a small but important console surface:

* **Commands found (12):**
  `clear`, `cmdlist`, `extendconsole`, `generateterrain`, `loadtexture`, `minimizeconsole`, `openurl`, `setGammaRamp`, `setresourcepaq`, `snd_addGameTune`, `sndfreqadjustment`, `telltimesurvived`
* **Variables found (8):**
  `con_monoFont`, `cv_bodiesFade`, `cv_friendlyFire`, `cv_showFPS`, `cv_silentloads`, `cv_verbose`, `v_height`, `v_width`

These are excellent “anchors” for understanding initialization, subsystems, and data flow.

---

## The reverse engineering plan

### Phase 0 — Decide the endgame and guardrails (1–2 days of up-front work)

Even with full decompilation, “fully reverse engineer” can mean different deliverables. Pick what you’re actually shipping:

* **A documentation-grade understanding** (diagrams + format specs + behavior specs)
* **A clean-room reimplementation** (new engine + ported logic)
* **A compatibility layer** (reimplement Grim2D API so original logic can run)
* **A modern port** (rebuild gameplay with new renderer/input/audio, reuse assets legally)

Guardrails to establish early:

* Keep the work scoped to **interoperability / preservation / modding / research**.
* Avoid distributing proprietary assets or code you don’t own.
* If the game has trial/full gating, treat it as “behavior to document,” not something to defeat.

Deliverables to set up right away:

* A repo with `/docs`, `/tools`, `/engine`, `/game`, `/tests`.
* A naming convention for recovered structs/functions (e.g., `GrimSystem::LoadTexture`, `Game::InitPerks`, etc.).
* A “facts ledger”: every conclusion links back to evidence (decompiled snippet, runtime log, etc.).

---

### Phase 1 — Rebuild a high-level architecture map (goal: know *where* every system lives)

**Output:** a single diagram + module notes that describe the runtime flow.

1. **Write down the lifecycle as seen in EXE**
   From the EXE’s init path you can outline:

* create/load Grim interface (tries a dev entry point first, then `grim.dll`)
* load “config pre-sets” blob (also `0x480` bytes) into game globals
* load status/save blob (`0x26c` bytes from disk, obfuscated + checksum)
* call Grim config dialog (vtable method; returns success/failure)
* read config values back (safe mode flag, no sound flag, scaling factor…)
* initialize Grim system
* set resource packs, load core textures, start audio resource packs

2. **Document responsibilities by boundary**
   Create a one-page “ownership table”:

| System                             |                  In EXE |                   In grim.dll |
| ---------------------------------- | ----------------------: | ----------------------------: |
| Rendering API wrapper / D3D device |              calls only |                **implements** |
| Input polling                      | probably via Grim calls |              **DirectInput8** |
| UI drawing/layout                  |                **lots** |    assists (font/texture ops) |
| Audio (DirectSound + OGG decode)   |                 **yes** |               maybe partially |
| Resource pack mounting             |                 **yes** | may provide low-level file IO |
| Gameplay, quests, perks, enemies   |                 **yes** |                            no |
| Config UI & config persistence     |                   calls |                **implements** |

This avoids months of confusion later.

---

### Phase 2 — Recover the Grim2D API (the biggest leverage point)

**Output:** a header file `grim_api.h` (or C++ class) describing the vtable in *meaningful names* + notes.

Why this matters:

* The EXE calls Grim entirely through `(**(code **)(*DAT_... + offset))(...)`.
* Until you name these methods and their contracts, the rest stays foggy.

Approach:

1. **Enumerate every vtable offset used by the EXE**
   Scan `crimsonland.exe_decompiled.c` for patterns like `*DAT_0048083c + 0x??`.
   Make a list:

* offsets used for config (`+0x10` etc),
* resource loading (`+0xb4`, `+0xc0`),
* draw calls (`+0x100`, `+0x114`, `+0x11c`, `+0xf0`, `+0xe8`, …),
* input queries (`+0x44`, `+0x48`, `+0x50` appear in the console input code).

2. **For each offset, infer purpose from call sites**
   Example of high-confidence inference:

* EXE uses `(0x13,5)` and `(0x14,6)` patterns in rendering; those values match typical blend factors (`SRCALPHA`, `INVSRCALPHA`) even if Grim wraps them.
* EXE calls a “load” then “get handle” pattern:

  * `+0xb4` with `(name, filename)`
  * `+0xc0` with `(name)` returning an int handle (or -1 if missing)
    This appears both in general loading and in UI element loading where the `.jaz` extension is stripped to derive a resource name.

3. **Cross-reference with grim.dll implementation**
   In `grim.dll_decompiled.c`, identify:

* the config functions reading/writing `crimson_cfg` (`0x480` bytes),
* the initialization sequence that sets up input devices,
* the D3D lost-device restore logic and texture restore logic.

Even if you don’t get perfect 1:1 mapping immediately, you can:

* name methods by effect: `BeginFrame`, `EndFrame`, `SetColor`, `DrawQuad`, `BindTexture`, `IsKeyDown`, `GetKeyChar`, etc.
* later refine signatures (floats vs ints) once you test against runtime behavior.

4. **Define contracts**
   For each method, write:

* argument meaning,
* units (pixels? normalized UV? radians?),
* ownership rules (who frees textures),
* error behavior (-1? 0?).

This becomes the spec for either:

* reimplementing Grim on a new backend, or
* stubbing Grim to isolate gameplay.

---

### Phase 3 — Configuration and “hardcoded engine state”

**Output:** config format docs + an automated “diff tool” for config blobs.

You have *two* important fixed-size blobs in play:

1. **`crimson_cfg` (grim.dll)**

* grim.dll reads/writes a **0x480-byte** file named `crimson_cfg` (likely `crimson.cfg`).
* There’s a full configuration dialog populating resolution strings like:

  * `640x480x16`, `800x600x16`, `960x600x16 (wide)`, `1024x768x16`
  * windowed variants are present if a flag is enabled
  * 32-bit options appear if supported (it probes capability)

Plan:

* Run the config dialog, flip one setting at a time, and diff the 0x480 bytes.
* Map each field to semantics: fullscreen/windowed, width/height, bit depth, safe mode, input flags, etc.
* Confirm how the EXE retrieves config values (it reads multiple values from the API immediately after config).

2. **“config pre-sets” blob (EXE)**
   The EXE loads another `0x480` file as “config pre sets” and then copies chunks into arrays that look like:

* keybindings / control mapping (scancodes and/or DIK codes),
* gameplay defaults (friendly fire, show FPS, etc.),
* possibly UI behavior.

Plan:

* Identify the filename by runtime file I/O tracing (or by locating the string in the original binary).
* Same diff strategy: flip controls via UI (if available) or edit bytes and observe.

3. **Hardcoded tables**
   You already know this pain: perks, quests, enemies are hardcoded in the EXE. Don’t fight it manually—systematize it:

* Identify each table’s base address and stride (e.g., perks appear to be laid out in fixed-size records).
* Reconstruct a struct definition.
* Dump the table at runtime into JSON (even using the original game) so you have a canonical, versioned reference.

---

### Phase 4 — Resource pipeline beyond PAQ/JAZ (build a full asset manifest)

**Output:** a manifest like `assets_manifest.json` + loaders for each content type.

You’ve solved `.paq` and `.jaz`; the code tells you what to do next:

1. **Sound assets and sound packs**

* EXE explicitly mounts **`music.paq`** and **`sfx.paq`**.
* It loads **tons** of `.ogg` samples (aliens, trooper, bullet hits, explosions, UI clicks, etc.)
* It also loads music tracks like `music_intro.ogg`, `music_crimson_theme.ogg`, `music_crimsonquest.ogg`, etc.
* It runs `exec music_game_tunes.txt`, and there’s a console command `snd_addGameTune`.

Plan:

* Treat `music_game_tunes.txt` as a data-driven playlist spec. Reverse the grammar by reading how `snd_addGameTune` parses args.
* Document the sound system:

  * sample vs tune distinction,
  * max slots (arrays suggest fixed limits),
  * caching and unloading strategy,
  * volume and pitch controls (`sndfreqadjustment` exists).

2. **Fonts**
   grim.dll loads `load_smallFnt.dat`.
   Plan:

* Locate the file in the PAQs or on disk.
* Reverse the font format (glyph metrics, UVs, kerning maybe).
* Map it to how text rendering is done (EXE uses Grim calls to draw text at coordinates).

3. **Texture naming and lookup rules**
   There’s an important subtlety in how names are derived:

* UI `.jaz` loader strips the extension to create a resource name, then calls `Load(name, filename)`.
* Other textures sometimes use the same string for name and filename.

Plan:

* Standardize your reimplementation to mirror the original lookup rules:

  * “name key” vs “file path”
  * case sensitivity
  * directory separator normalization
* Build a tool that scans the EXE for all `s_*` resource references and outputs likely filenames/categories.

---

### Phase 5 — Console / command system (this becomes your introspection & automation backbone)

**Output:** complete console command list + argument grammar + ability to script reproducible runs.

The console system in the EXE is real (not just debug fluff):

* It parses input, finds either a **variable** or a **command**, then executes.
* It runs `exec autoexec.txt`, so scripting is part of normal boot.

Plan:

1. **Fully map the lexer/parser**

* Identify how it tokenizes (quotes? escapes? comments?).
* Identify the assignment form (it distinguishes query vs set; there’s a `DAT_0047f4cc == 2` branch that looks like “set var”).

2. **Catalog and document built-ins**
   Start with what we can already see registered:

* Commands: `setresourcepaq`, `loadtexture`, `generateterrain`, `openurl`, audio commands, console UI commands.
* Vars: `cv_verbose`, `cv_silentloads`, `cv_showFPS`, etc.

3. **Make it useful**
   In reverse engineering, this console can become your control plane:

* Add your own logging commands (in a custom build) *or* hook existing ones.
* Use scripts to create deterministic test scenarios: load a terrain seed, spawn known enemies, etc.

---

### Phase 6 — Game state machine and modes (Survival / Quests / Typ-o-Shooter)

**Output:** a clean “mode/state” diagram + per-mode update loops.

You want to identify:

* **Top-level states:** splash/logo, main menu, mode select, gameplay, pause, score screens, perk selection, etc.
* **Per-mode logic:**
  Survival spawn rules differ from quest objectives; Typ-o-Shooter likely changes input and scoring.

Plan:

1. **Find the “main loop”**

* Identify the update tick and render tick; locate delta-time source (`timeGetTime` usage appears in audio init; Grim likely provides frame timing too).

2. **Build a state transition table**
   For each state:

* entry function,
* exit function,
* update function,
* render function,
* triggers for transition.

3. **Validate via instrumentation**
   Run and log transitions:

* easiest is to hook the functions that print UI labels (menus) or the ones that load state-specific textures/music.

---

### Phase 7 — Entities, combat, and simulation core

**Output:** struct definitions + “rules of the world” document.

This is the largest “hardcoded” region in the EXE. The plan is to convert it into comprehensible, testable subsystems:

1. **Entity taxonomy**
   At minimum you’ll have:

* player
* monsters (zombie/lizard/spider/alien/trooper show up explicitly)
* bullets/projectiles
* pickups/perks
* particles/decals (blood spills, muzzle flashes)

For each entity type, identify:

* update step (movement),
* collision step,
* damage step,
* render step,
* spawn/despawn rules.

2. **Combat rules**
   Extract into a spec:

* weapon stats (fire rate, reload, spread, projectile speed, damage)
* monster stats (hp, speed, attack, hit reactions)
* perks (duration, effect, stacking rules)

  * In the EXE, perk definitions are clearly hardcoded with name + description + parameters.

3. **Randomness & determinism**
   If you want full fidelity, you need deterministic behavior:

* document where `_rand()` is used (perk selection, spawns, etc.)
* decide how to seed it per mode/quest
* build a “deterministic replay” harness (record inputs + seed, verify identical outputs)

---

### Phase 8 — Quests system (it’s table-driven but hardcoded)

**Output:** quest format spec + ability to define quests externally (optional).

What I can see:

* There’s a list of quest names (“Monster Blues”, “Nagolipoli”, “The Gathering”, etc.)
* Many quest setups are function pointers; there’s a fallback quest generator.
* Quest setup computes spawn schedules/objectives.

Plan:

1. **Extract the quest table**

* Identify the quest record struct: name, tier, index, callback pointer.
* Dump it into JSON with tier/index/name.

2. **For each quest callback**

* map its parameters (spawn points, wave timings, enemy type mix, objective thresholds).
* write a human-readable description:

  * “spawn X every Y ms until count Z”
  * “boss at time T”
  * “survive for N seconds”

3. **Separate “quest definition” from “quest runtime”**

* quest definition: static schedule/objectives
* quest runtime: counters, timers, failure/success conditions

Once you have this separation, externalizing quests becomes straightforward.

---

### Phase 9 — Persistence: saves/status, scores, unlocks

**Output:** save file spec + compatibility tests.

From the EXE:

* There is an obfuscated **status/save** file:

  * reads `0x268` bytes + 4-byte checksum = file size `0x26c`
  * transforms bytes and validates checksum
* There is also score data with checksums and “illegal score” warnings.

Plan:

1. **Identify what the status blob represents**
   It likely stores:

* unlocks, progress, last selected weapon/perk, or totals
* maybe registry mirrors (`sequence`, `dataPathId`, `transferFailed` keys are manipulated)

Method:

* Set a known value in-game (e.g., unlock something), save, diff the file.
* Repeat for multiple independent variables to map offsets.

2. **Highscore format**

* Identify where scores are stored (file name via I/O tracing).
* Map record length, fields (name, score, mode, timestamp), checksum rules.

3. **Compatibility test suite**

* Golden files: a set of save/score files from real gameplay sessions.
* Your parser must round-trip them without changes (unless you’re explicitly migrating).

---

### Phase 10 — UI, HUD, and UX fidelity

**Output:** UI layout spec + render order + input mapping for menus.

Because you understand `.jaz`, you can tie it directly to UI behaviors:

* UI elements load textures, compute UV rectangles, and then draw quads with Grim.
* There are lots of “hardcoded placements” (pixel constants, scale factor logic).

Plan:

1. **Catalog every UI screen**

* main menu
* options
* perk selection (“Press X to pick a perk” text appears)
* quest selection
* scoreboards
* in-game HUD: health, ammo, XP/level, timers, wave counters

2. **Map coordinate spaces**
   You need exact rules:

* screen center offsets are used often (values like `width * 0.5`, etc.)
* scaling factor (`DAT_004803b8`) affects rendering/logic

3. **Text rendering**

* Determine font(s): `GRIM_Font2` is referenced in EXE; `load_smallFnt.dat` in grim.dll.
* Identify text measurement and wrapping behavior.

---

### Phase 11 — Validation strategy (don’t “port by vibes”)

**Output:** objective equivalence checks.

To “fully reverse engineer,” you need repeatable validation:

1. **Frame capture / render call logs**

* Log texture bindings + draw calls and compare sequences between original and reimplementation.

2. **Deterministic simulation tests**

* fixed RNG seed
* scripted inputs (from console scripts)
* expected outputs: score at time T, enemy count at time T, player position at time T

3. **Audio event logs**

* when each sample plays, with what volume/pitch
* verify you trigger identical sound events in identical situations

4. **Binary compatibility layer tests (if doing a Grim shim)**

* Keep the EXE logic running against your replacement Grim and ensure it boots and reaches menus before you tackle full gameplay.

---

### Phase 12 — Optional but high-value: Make it data-driven (taming the hardcoded stuff)

This is how you stop the project from turning into a forever-maintenance nightmare.

Targets to externalize:

* perk definitions (name, description, duration, cooldown, effect)
* enemy archetypes (hp/speed/sounds/sprites)
* weapon definitions
* quest schedules/objectives
* input bindings defaults

Strategy:

* First: **extract** the hardcoded tables into JSON/YAML via a dumping tool.
* Second: add a loader that can override hardcoded defaults.
* Third: gradually flip the source of truth to the external files.

This keeps “original behavior” as the baseline while enabling mods and easier iteration.

---

## Practical next steps (the “do this next week” list)

1. **Create `grim_api.h`** and start naming vtable methods (even if partially).
2. **Diff the two 0x480 config-related blobs**:

   * grim.dll’s `crimson_cfg`
   * EXE’s “config pre-sets” file (identify filename via I/O tracing)
3. **Spec the status/save file** (0x26c) and map at least 5–10 fields.
4. **Extract a complete asset manifest** from the EXE strings:

   * all `.ogg` names
   * all `.jaz` references
   * any `.dat`/`.txt` used
5. **Document the console grammar** and verify all 12 commands with sample invocations in a script.
6. **Pick one vertical slice** and fully reverse it:

   * Example: “spawn one enemy type + one weapon + bullets + collisions + one sound + one UI HUD element”
   * This forces you to touch engine API, resources, simulation, and rendering in a controlled scope.

---

## If you want, I can also generate “working docs” artifacts from these sources

Without needing any more files, I can produce:

* a **draft Grim2D API method table** (offset → guessed name/signature → evidence),
* a **JSON list of detected console commands/cvars** (already partially extracted),
* a **JSON list of referenced `.ogg`** sample/tune names and `.jaz` identifiers from the EXE,
* a **save/status format starter spec** (structure + checksum/transform description).

If you upload (or re-upload) any of these, I can extend the plan into concrete specs/tools:

* a real `crimson_cfg` file from your install,
* the “config pre-sets” file,
* a sample save/status file and highscore file,
* one or two actual `.paq` archives (even though you know the format, it helps tie name→content).

---

Yes — **even if the modern builds use a different engine**, those exported symbol names can be *very* useful as a “Rosetta stone” for the classic version. I skimmed both of your CSVs and there are clear signs that a lot of the **same gameplay concepts and even some legacy API surface** still exist in the modern codebase.

### What I found in your exports that’s directly useful

Your symbol lists are large:

* Linux exports: **4,646** names
* Android exports: **5,024** names
* Overlap between them: **~3,224** names

More importantly, they include **names that line up with the classic Crimsonland/Grim world**:

#### 1) A Grim compatibility layer exists in the modern builds

These two are huge:

* `GrimNexus_GetInterface`
* `GRIM_LoadTexture`

That strongly suggests the modern code still has a **Grim-facing entry point** (or a compatibility wrapper) that adapts “old Grim-ish API” onto a newer internal engine (the “Nexus” / `NX_*` layer you also have tons of symbols for).

**Why this matters for classic reversing:**
In the classic game, the EXE loads the engine DLL and calls an exported “get interface” function, then calls through a vtable. If the modern build still has that same “interface-returning” shape, you can often recover:

* the *intended method names*
* the *grouping* of methods (render/input/audio/fs)
* sometimes even the *argument conventions* by reading the wrapper code

Even if the implementation changed, **the *contract* tends to remain similar**, and that’s exactly what you need to name and understand the classic vtable calls.

#### 2) Modern builds still expose the same major game subsystems by name

A few examples (there are many):

* **Perks**

  * `CORE_InitPerks`, `CORE_ApplyPerk`, `CORE_RandomizePerks`
  * `GAME_HandlePerks`, `GAME_PerkActive`, `GAME_UnlockPerks`
  * UI screens named around perks too (e.g., `screen_PickAPerk` initializers/destructors)

* **Quests**

  * `GAME_InitQuests`, `LoadQuests`, `SelectQuest`
  * `GAME_ExportQuestToXML`, `GAME_ExportQuestsToXML`
  * A big block of `QUEST_*` functions that look like *quest definitions* (e.g., `QUEST_Beetlemania`, `QUEST_Gauntlet`, etc.)

* **Survival**

  * `Crimsonland_InitializeSurvival`
  * `GAME_SurvivalFrame`, `GAME_SpawnCreatureSurvival`, `GAME_SpawnCreatureSurvivalWaves`

* **TypoShooter**

  * `Crimsonland_InitializeTyposhooter`
  * `CORE_TyposhooterDrawFrame`, `CORE_TyposhooterProcessEvent`
  * `GAME_TypoShooterFrame`, `GAME_TypoTrooperControl`

* **Terrain generation**

  * `GDI_GenerateTerrain`, `GDI_GenerateTerrainById`

That last one is a nice direct tie-in: your classic EXE has a `generateterrain` console command; modern has a clearly named terrain generator entry point.

#### 3) Modern “engine layer” symbols can help you name the classic Grim/engine calls

Modern exports include a *ton* of `NX_*` and `NXI_*` symbols like:

* Rendering-ish: `NX_DrawQuad`, `NX_DrawTextf`, etc.
* File system: `NX_FileSystem_Mount`, `NX_FileSystem_OpenFile`, `NX_FileSystem_ReadFile`, etc.
* Audio: `NX_Audio_PlaySound`, `NX_Audio_SetChannelFrequency`, etc.
* Console: `NX_AddConsoleAutocompletionString`, `nxConsole`

Even if classic uses Direct3D8 + DirectInput directly inside grim.dll, the **conceptual operations match**: draw quads, draw text, mount packages, open/read files, play sounds, etc.

So these names can provide a *target vocabulary* for your classic decompilation:

* instead of “FUN_00428a10”, you can label it “DrawQuad” / “LoadSound” / “InitPerks” / “QuestFrame”, etc., once you confirm by behavior.

---

## How to use these symbols to accelerate classic reversing (practical workflow)

### 1) Use them as a naming dictionary (fast win)

Take the modern symbols and use them to drive your *classic* renaming work:

* Start with high-confidence anchors:

  * `CORE_*`, `GAME_*`, `QUEST_*`, `TYPOSHOOTER_*`, `SND_*`, `GDI_*`, `GRIM_*`
* In the classic decompilation, search for:

  * references to perk/quest UI textures
  * quest name strings
  * the console command handlers (`generateterrain`, `loadtexture`, `snd_addGameTune`, etc.)
* Rename the handler functions to match the modern terms once verified.

This doesn’t require binary diffing; it’s just “use the modern names to guide what you call things.”

### 2) Use `GrimNexus_GetInterface` as a bridge to recover the classic Grim vtable meaning

If your modern decompilation includes code (not just exports), this is the best leverage:

* Find the implementation of `GrimNexus_GetInterface`
* Identify the interface object it returns (likely a struct/class with function pointers)
* Enumerate that vtable in the modern build
* Map each method to underlying `NX_*` calls inside the wrapper

That effectively gives you a **labeled Grim API**.

Then, in the classic EXE:

* you already have dozens of calls like `(**(code **)(*DAT_... + 0xb4))(...)`
* once you know what vtable slot `0xb4` corresponds to in the modern “Grim wrapper,” you can label it in classic too (or at least strongly hypothesize it, then verify by effect).

Even if the slot order changed between versions, the wrapper is still a goldmine for:

* expected method set,
* typical arguments,
* return/error conventions.

### 3) Use the modern `QUEST_*` list to map quest callbacks in classic

Your classic EXE has quest names as strings and a quest table with function pointers (hardcoded).

Modern exports include explicit quest function names.

A strong strategy is:

* extract the list of quest display names from classic
* match them to modern `QUEST_*` identifiers
* in classic, locate the function that references that quest string → that’s your quest setup routine
* rename accordingly

This can save a *ton* of time because quests otherwise look like “random spawn logic.”

### 4) Validate differences instead of assuming equivalence

Modern may have:

* balance changes,
* bug fixes,
* different RNG seeding,
* different asset pipeline (PNG/libpng shows up in modern exports; classic uses `.jaz`)

So treat modern symbols as:

* **names + structure hints**, not guaranteed identical behavior.

Whenever you “import” an idea from modern into classic, do a quick equivalence check:

* same inputs (seed, difficulty, time)
* compare output (spawn list, score curve, terrain pattern, etc.)

---

## What’s *not* that useful (or needs caution)

* **Platform/service features**: achievements, cloud, IAP, accounts (lots of `NX_Cloud_*`, `AchievementManager`, etc.). These likely didn’t exist in classic, so they won’t map.
* **Third-party library symbols**: `png_*`, compression internals, etc. Usually noise for your classic goal (unless you’re tracking asset pipeline changes).

