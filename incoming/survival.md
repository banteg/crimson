Here’s what I’m seeing in **crimson2** right now (based on `src/`), and what I’d do next to hit your stated milestone: **“wire the systems up and get Survival mode working.”**

## Where you are now

### You’re mostly past “stubs”

A quick audit of `src/**/*.py` shows very little “placeholder” code:

* **7** ellipsis “stubs”, but they’re **only Protocol interfaces** (`FrontView` + `grim.view.View`) — that’s normal scaffolding, not missing gameplay.
* **1** `NotImplementedError`, and it’s a *guard* in `crimson/creatures/spawn.py` for an unhandled spawn template id.
* **2** `TODO`s:

  * `crimson/game.py`: confirm demo idle threshold
  * `crimson/player_damage.py`: dodge perk RNG/thresholds

So: most of what’s “ported” is real logic, not empty shells.

### Survival is now actually wired into `crimson game`

This is a big integration milestone:

* `crimson/game.py` includes a `SurvivalGameView` wrapper that adapts the debug `SurvivalView` into the full game flow.
* The play-game menu has a `"start_survival"` action wired.

So your “systems wiring” goal is already partially achieved: **Survival is reachable through the main app loop**, not just standalone debug views.

### Core Survival loop exists and is coherent

`crimson/views/survival.py` is doing the right kind of work:

* player input → `player_update()` + `player_fire_weapon()`
* projectiles update
* creature pool update
* bonus pool update (including pickup → `bonus_apply`)
* survival progression (XP/level → perk selection)
* survival spawns:

  * milestone gates via `advance_survival_spawn_stage`
  * continuous wave spawns via `tick_survival_wave_spawns`

This is already a playable “vertical slice” even if the presentation is debug-y.

## What’s still “debug / subset” and will block a convincing Survival run

### 1) Survival is deterministic / not using the game’s RNG

* `GameplayState` defaults to `Crand(0xBEEF)`
* `SurvivalView.open()` reseeds to `0xBEEF` again

So every run is identical unless you change code.

**Why it matters:** it’ll feel “stuck” and it makes it harder to validate spawn pacing vs the original (because the original uses real RNG evolution and time).

### 2) Creature runtime is explicitly minimal (missing key Survival behaviors)

`crimson/creatures/runtime.py` says it’s intentionally minimal, and it shows:

Implemented:

* movement + AI target updates
* contact damage
* self-damage tick flags
* bonus-on-death + generic bonus drop
* spawn-slot ticking (child spawns while alive)

**Not implemented (but flagged in your spawn data and docs):**

* `CreatureFlags.SPLIT_ON_DEATH` (0x08)
* ranged attack flags:

  * `RANGED_ATTACK_SHOCK` (0x10)
  * `RANGED_ATTACK_VARIANT` (0x100)

These two (split + ranged) are *not optional* long-term; they’re core to enemy variety and difficulty curve in Survival.

### 3) Survival rendering is still placeholder

`SurvivalView.draw()` is circles/lines for:

* creatures
* player
* projectiles
* bonuses

But you clearly already have the pieces to render “for real”:

* ground rendering (`grim.terrain_render.GroundRenderer`, plus `views/ground.py`)
* sprite sheets (`views/sprites.py`)
* creature anim frame selection (`creatures/anim.py` + `views/animations.py`)
* projectile FX (`views/projectile_fx.py`)
* particles/effects atlas (`effects_atlas.py`, `grim/fx_queue.py`)

So the next integration step is less about “new reverse engineering” and more about **composing the renderers you’ve already built into Survival**.

### 4) Gameplay audio isn’t wired (only demo uses SFX)

Right now, `play_sfx` shows up in:

* `crimson/demo.py`
* grim audio modules

Survival doesn’t emit weapon fire/reload sounds, bonus pickup sounds, ranged enemy fire, etc.

### 5) Some systems are knowingly simplified

Examples that will bite you as Survival progresses:

* `crimson/projectiles.py` is a **subset/approx** port in places.
* Rocket Minigun is explicitly simplified to “1 rocket per shot (for now)” in gameplay.
* HUD XP progress bar explicitly labeled an approximation.
* `player_take_damage` is minimal (dodge perks TODO).

None of these prevent “a run that works,” but they’re the first things you’ll notice when you try to compare against the reference binary.

## Suggested next steps (prioritized to “Survival works”)

### 1) Make SurvivalView consume `GameState` (stop being a standalone debug island)

Right now the wrapper just instantiates `SurvivalView(ViewContext(assets_dir=...))`.

**Do this next:**

* Let `SurvivalView` accept (or be constructed with) a “runtime context”:

  * RNG seed / rng object (from `GameState.rng` or config seed)
  * difficulty / hardcore flags (from config / status)
  * audio handle (so it can emit events)
  * optionally the console logger for quick telemetry

**Concrete change points**

* `crimson/game.py`: in `SurvivalGameView.__init__`, pass `state` into SurvivalView (or a new `SurvivalRuntime` struct).
* `crimson/views/survival.py`: remove `self._state.rng.srand(0xBEEF)` and use injected seed/rng.

**Success criteria**

* Two consecutive Survival runs behave differently without code changes.
* You can reproduce a run with a known seed for testing.

---

### 2) Implement the missing creature combat flags (this is the #1 gameplay gap)

You already have the data model support:

* `CreatureState.attack_cooldown` exists
* spawn templates already set the relevant flags
* docs/creatures/update.md already describes the behavior

**Implement in `crimson/creatures/runtime.py` update loop:**

* decrement `attack_cooldown` each frame
* if <= 0 and has ranged flag:

  * aim at current target player
  * spawn projectile into `state.projectiles` (or secondary pool if appropriate)
  * reset cooldown (docs suggest `+ 1.0` seconds for the 0x10 shock case)

**You will probably also want to add fields to CreatureState:**

* `origin_template_id` (because you currently drop it in `_apply_init`, and it’s useful for death behaviors like split)
* `ranged_projectile_type` (since `CreatureInit` has it, but `_apply_init` doesn’t store it)

**Success criteria**

* Enemies with 0x10 / 0x100 flags visibly shoot.
* Survival difficulty curve starts resembling “not just melee kiting.”

---

### 3) Implement `SPLIT_ON_DEATH` (even if you start with a small mapping)

This is the other “enemy variety” mechanic you’ll feel immediately.

You have two practical paths:

**Fast unblock (recommended):**

* Start with a small mapping table for known split templates (ex: `SPIDER_SP2_SPLITTER_01`)
* On death, spawn N child creatures (smaller size, scaled max_hp)
* Use `build_spawn_plan(child_template, pos, heading, ...)` and materialize it

**Parity path:**

* Use the decompile of `creature_update_all` to derive:

  * child count
  * exact child template(s)
  * max_hp / size scaling rules

**Success criteria**

* Splitter enemies are no longer “just a bigger spider”; they produce children and change the fight.

---

### 4) Replace debug drawing in Survival with your existing render pipeline

Don’t rewrite rendering again — compose what you already have.

**Minimal “real-looking” Survival render stack**

* Ground: reuse `GroundRenderer` setup from `views/ground.py`
* Creatures: reuse anim frame selection (`creatures/anim.py`) and sprite atlas logic
* Projectiles + muzzle flash: reuse patterns from `views/projectile_fx.py`
* Bonuses: render from `game/bonuses.png` using the icon ids you already extracted
* FX: start feeding `FxQueue` / `FxQueueRotated` (creature runtime already supports taking them)

**Keep a debug toggle**

* e.g. `F1` = “debug circles” vs “sprite render”
  That lets you keep dev velocity while you port visuals.

**Success criteria**

* A Survival run *looks* like a game mode, not a debug sandbox.

---

### 5) Wire “gameplay events” into audio

Once ranged attacks and real rendering are in, missing audio becomes glaring.

Start with just:

* weapon fire / reload
* bonus pickup
* perk menu open / pick
* enemy ranged fire (shock)

You already have the audio subsystem in `grim/audio.py` and SFX mappings; Survival just needs to emit the events.

**Success criteria**

* Survival has basic sound feedback for core actions.

---

### 6) Add a deterministic headless Survival simulation harness

This will save you huge time while you tune parity.

Add a script (or test) that:

* seeds RNG
* runs the Survival update loop for X seconds without rendering
* asserts invariants:

  * no exceptions
  * player XP/level increases
  * creature count doesn’t explode unbounded
  * spawn stage advances
  * perk selection offers valid choices

**Success criteria**

* You can regression-test survival wiring in seconds.

---

### 7) Sync docs that are now misleading

Your code reality is ahead of some docs (for example, docs/index currently reads like Survival isn’t wired into `crimson game` yet, but it is via the wrapper).

Even if docs “can contain mistakes,” keeping “Current state” accurate prevents the team from chasing ghosts.

---

## If you want the tightest “next 3 commits” plan

1. **Inject GameState into Survival + remove hardcoded RNG seed**
2. **Implement ranged attacks in creature runtime (0x10 + 0x100)**
3. **Implement split-on-death for at least the splitter spider template(s)**

That gets you from “debug survival loop” → “Survival mode actually feels like Survival,” before you invest heavily in visuals/audio parity.

If you want, I can also point out the exact spots in `creatures/runtime.py` where the attack/split hooks should go (they’re cleanly local: right after AI/movement, and inside `_handle_death`).
