Here’s what I see in **crimson2** right now (based on `docs/index.md`, `docs/metrics.md`, and the current runtime wiring in `src/`), and what I’d do next to keep momentum while minimizing rework.

## Where the port stands today

### What’s already strong / “feels like a game”

* **Boot → front-end loop is real**: `crimson game` runs through a proper boot path, loads config, brings up the **console overlay**, and lands in the **menu flow** (with audio, terrain, transitions). This is a huge foundation win because it’s the “spine” everything else attaches to.
* **Asset pipeline is done (PAQ/JAZ)**: extraction + conversion are working end-to-end (Parity ✅ in metrics).
* **Quest script logic is done (Parity ✅)**: all quest builders mirrored and validated, with CLI support (`crimson quests`).
* **Terrain renderer is close**: generation logic and rendering behavior are validated; you already have the right abstraction (`GroundRenderer`) plus decal baking helpers and `FxQueue` plumbing (`grim/fx_queue.py`, `crimson/effects.py`).
* **Menu system is substantially implemented**: panel positioning, slide animation, terrain stability across screens, and `fx_detail`-gated shadow pass are already in place (metrics: Menu 🚧/🚧).
* **Demo/attract UX work is well ahead**: upsell overlay + purchase screen + idle trigger exist; the remaining gap is the *simulation* behind it (metrics explicitly call out the “toy sim” still present).

### Gameplay core: you have many parts, but they’re not yet one cohesive “world”

You already have a lot of the hard logic in Python:

* **Player**: `player_update`, perks, bonuses, HUD systems exist (exercised in debug views).
* **Projectiles**: main pool + secondary pool are implemented, plus collision/damage patterns for several types.
* **Creatures**: spawn-plan builder exists, AI helpers exist, and there’s a minimal runtime pool (`CreaturePool`) that already handles movement/contact damage/spawn slots/death + bonus drops + FX queue hooks.

You even have a **playable survival debug loop** (`src/crimson/views/survival.py`) that wires together:

* player_update
* projectiles update
* creature update/spawns
* bonus pool updates
* perk selection UI
  …but it’s still rendering as **debug circles/lines**, not as “Crimsonland”.

So the *big story* is:
✅ systems exist in isolation and in debug loops
🚧 they still need to be unified into a single “real gameplay scene” with correct rendering + effects + integration into the main game flow

## The main bottleneck

Right now you effectively have *three* “world-ish” implementations:

1. **Menu ground / terrain** (real, using `GroundRenderer`)
2. **SurvivalView** (real-ish simulation, debug rendering)
3. **DemoView** (separate “toy sim” with its own creature/player structs)

This duplication is the biggest threat to velocity: every improvement risks being implemented twice.

## Suggested next steps (in the order I’d do them)

### 1) Build one reusable “GameWorld” / “GameplayScene” core

Create a single module/class that owns the authoritative runtime state for “in-game”:

* `GroundRenderer` + camera
* `GameplayState`
* players (`PlayerState[]`)
* `CreaturePool`
* bonus pool
* `FxQueue` + `FxQueueRotated`
* textures needed for FX baking (particles/bodyset)
* (later) audio hooks, score/hiscore hooks

Give it:

* `update(dt)`
* `draw()`

Then **both Survival and Demo should use this**, rather than their own bespoke loops.

Why this is the best next step:

* It converts your existing logic into a *product surface* you can iterate on.
* It eliminates reimplementing creature/projectile logic for demo later.
* It’s the cleanest bridge from “debug view works” → “the game works”.

Concrete refactor target:

* Move the sim bits currently living in `views/survival.py` into the shared world update.
* Keep SurvivalView as a thin wrapper that handles input/perk menu and calls `world.update/draw`.

### 2) Upgrade Survival from debug shapes to real rendering (vertical slice milestone)

This is the single highest-leverage milestone because it forces all the missing glue into place.

Replace:

* creature circles → creature sprite drawing
* projectile dots → projectile/effect sprites
* flat background → **terrain RT** + decals

You already have the ingredients:

* Creature animation math: `creature_anim_advance_phase`, `creature_anim_select_frame`
* Atlas slicing + effect atlas mapping (`crimson/atlas.py`, `crimson/effects_atlas.py`)
* Terrain + decal baking: `GroundRenderer.bake_decals`, `bake_fx_queues(...)`

A good “definition of done” for this step:

* Start Survival from the menu
* Move, shoot, enemies spawn and die
* **Blood decals** appear on the ground
* **Corpse decals** appear (from `FxQueueRotated`)
* HUD + perk prompt/selection works
* ESC returns cleanly to menu and stats increment

### 3) Wire FX queues into actual gameplay events (so terrain work pays off)

Right now `CreaturePool.update()` already supports `fx_queue` and `fx_queue_rotated` parameters and can emit decals on death. The missing piece is usually:

* making sure projectile hits / explosions push into `fx_queue`
* calling `bake_fx_queues()` at the right time (typically end-of-update or start-of-draw) on the active ground RT

Do this early, because:

* it “proves” the terrain pipeline in the real game loop
* it makes the game instantly feel closer to parity even if AI and balance aren’t perfect yet

### 4) Collapse DemoView onto the same world runtime (remove the toy sim)

Once Survival uses the shared world core, you can rebase demo mode onto it:

* Demo should become “Survival world + scripted spawn schedule + autopilot input”
* Keep the upsell overlay/purchase screen logic as-is
* Replace the internal `DemoCreature/DemoPlayer` types with `CreaturePool/PlayerState`

This will immediately:

* reduce maintenance load
* let demo mode benefit from every gameplay improvement “for free”
* make it easier to chase fidelity, because you’re not matching two different sims

### 5) Pick one “combat completeness” target and finish it end-to-end

After the vertical slice is rendering properly, you’ll hit the next wall: weapons and creatures are “mostly” there but not fully.

I’d recommend a tight target set:

* 3–5 common weapons (pistol, AR, shotgun, minigun, rocket launcher)
* 3–5 common creatures (zombie, lizard, alien, spiders)

For those, finish:

* projectile behaviors (including any special cases)
* correct damage scaling / pellet patterns / reload timing nuances
* creature movement + contact damage + death behavior
* basic SFX triggers (fire, reload, hit/death)

This creates a stable base to expand from.

### 6) Add 1–2 more parity harnesses like you did for terrain/quests

You’re already doing the right thing with fixtures and deterministic checks. The next two harnesses that pay off fastest are:

* **Spawn-plan parity fixtures** (you’ve started this — double down and expand coverage)
* **Projectile update fixtures** (given a seed + initial pool state, compare positions/hit results after N ticks)

This will keep you from “drifting” while you refactor into the shared world core.

### 7) Update docs/metrics to match reality as you go

Minor, but helpful:

* `docs/index.md` still says gameplay isn’t wired into `crimson game`, but you now have `SurvivalGameView` plumbing into the menu flow.
* Keeping those “Current state” blurbs accurate helps decision-making and onboarding.

## Quick priority summary

If you only do three things next, I’d do:

1. **Unify Survival + Demo + future modes behind one shared `GameWorld` runtime**
2. **Make Survival render real terrain + sprites + decals (vertical slice)**
3. **Port DemoView off the toy sim and onto that same world**

That path gives you the fastest route to “it looks and plays like Crimsonland” while protecting you from duplicated work.

If you want, I can also sketch a concrete module layout (files/classes) for the shared `GameWorld` so the refactor is straightforward and doesn’t fight your existing `GameLoopView` / `FrontView` structure.
