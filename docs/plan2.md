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

