# Changelog

Releases before 0.11.0 are listed on [GitHub](https://github.com/banteg/crimson/releases).

## 0.12.0

### For players

#### Online leaderboard

- **[crimson.land](https://crimson.land)** is the port's online leaderboard, with boards for Survival, every quest, and every quest on hardcore. The server replays each run in full before its score counts.
- Tick **Ranked** at the bottom of the Play Game menu to play Survival or a quest for the boards. Ranked runs play the same for everyone, whatever your save holds: one player, the original's bugs fixed, every quest unlocked, no weapon history and a fresh seed. The view is capped at 1024x768, and computer-controlled movement or aim does not rank. Only finished runs count: a Survival death or a completed quest. [The ranked rules](https://crimson.banteg.xyz/rewrite/ranked-rules/) have the details.
- A ranked run uploads by itself once its results screen closes, under the name you typed there. Offline play is fine: runs wait on your computer and upload at the next launch, or every ten minutes while the game runs.
- There is no sign-up. The game makes a key on its first launch. `crimson identity show`, `export` and `import` show it or move it to another computer.
- The **Profile** button, shown in the Play Game menu while Ranked is ticked, opens your profile on crimson.land, signed in. From there you can link a GitHub, Discord or X account, so your handle shows next to your name and another computer's game can join your account. You can also unlink them, or delete the account with its runs.
- The high score screen's **Update scores** and **Show internet scores** work again, as in the original. Update scores sends your waiting runs, then shows the shown board's best runs in green beside your local scores. A local run that is on the board turns green.

#### Other changes

- F12 saves one screenshot per press, without a hitch, into the directory you started the game from, and logs its path.
- The end of a long run no longer stalls for seconds while its replay saves: replays save in the background and compress much faster.
- In quests, the spawn timeline after a death matches the original's.
- Replays are format 30 and name the program that recorded them. Replays recorded with 0.11 no longer load.

### Under the hood

- **crimson-core** verifies every movement and aim scheme, and Rush.
- **crimson.land** runs on Cloudflare Workers. It verifies uploads with the crimson-core WebAssembly build and checks the ranked rules, including that every aim point stays on screen. The site is a small Solid app in `service/`.
- crimson-core builds with Zig 0.17.

## 0.11.1

### For players

- Blood and corpses no longer land on the ground at double or half size, out of place, after the window's display scaling changes, for example when the window moves between a Retina and a regular monitor.
- A run ends the way it does in the original:
  - Rush, like the other modes, ends when the death animation finishes.
  - After death, bonuses stop updating, the quest timeline stops and Reflex Boosted's slowdown no longer applies.
- In one-player runs, the unused second player slot behaves as in the original: Infernal Contract sets its health to 0.1 like player one's, creatures stop targeting it once it is dead, and its death never sets off Final Revenge.
- Lean Mean Exp Machine's timer starts at 0 in a new run.
- Rush replays recorded with 0.11.0 end too early and may no longer verify.

### Under the hood

- **crimson-core.** The recovered C/C++ game code builds as a standalone simulator that replays runs. A CI gate checks that every bot stream and recorded fixture agrees with Python tick by tick, with the original's bugs either kept or fixed.
- **Zig port removed.** crimson-core replaces it as the verifier.

## 0.11.0

### For players

#### Controllers

- Modern gamepads (PlayStation, Xbox, Switch Pro and others that SDL knows) are detected automatically. A player still on the original default controls switches to twin-stick controls by pressing any button: left stick moves, right stick aims, R2/RT fires, L1/LB reloads, Triangle/Y picks a perk, Start pauses.
- Controls you customized are left alone; only bindings still at their defaults move to the controller layout. Options → Controls has a Reset button that restores the selected player's controls for the connected controller, or mouse and keyboard when none is connected.
- Every menu can be driven with the keyboard, as in the original: Tab and Shift+Tab move a highlighted focus, Enter activates and Escape goes back. A controller drives the same focus with the D-pad or left stick, Cross/A and Circle/B. The highlight stays visible while you use the controller, and every new screen starts on its first item.
- `crimson view gamepad` and the console command `gamepads` show what the game reads from each controller.
- The `cv_padAimDistMul` console variable scales how far the right stick reaches.

#### Display

- Fullscreen is borderless and letterboxed: the game keeps its aspect ratio at any screen size instead of switching the display mode. Alt+Enter toggles it in game.
- `--width`/`--height` set the game resolution and `--fullscreen`/`--windowed` the window mode; both are saved.
- Panels, buttons, text and the HUD are drawn at the original's pixel sizes at every resolution.
- Runs natively on Wayland (raylib 6).
- F12 saves a screenshot of the game area, as `shot_000.png`, `shot_001.png`, … in the game directory.
- The game pauses its updates and sound while the window is in the background.

#### Menus and high scores

- High scores have named lists, as in the original: add, open and delete your own lists.
- The high score browser has the Hardcore checkbox and arrow-key paging.
- F1 pauses the game and shows the original's key help panel; the port-only TAB pause is gone.
- After Esc or a death, the world keeps moving for half a second while the HUD fades out, as in the original.
- The level-up prompt follows the original's rules, and the tutorial opens its perks from that prompt.
- Numpad, Caps/Num/Scroll Lock, right Alt, Pause and the Windows keys can be bound, and keys use the original's names ("Ctrl", "Num +"). Holding Alt+Q quits from any screen.
- Keyboard routes to the credits puzzle and the secret's board.
- Many menu flows were fixed: the other-games menu works, Back from the Alien Zookeeper returns to the statistics, quest results come back after viewing the high scores, and clicking outside an open list closes it without picking a row.
- Play time in the statistics counts only time actually spent playing.
- `cv_friendlyFire` lets co-op players shoot each other. It applies from the next run and makes the run unranked.
- `cv_uiTransparency` fades the HUD and `cv_terrainBodiesTransparency` the corpses on the ground.

#### Gameplay accuracy

The port now matches the original much more closely, down to its rounding. Crimsonland runs its floating-point math at single precision, and the port now rounds the same way, one operation at a time. The ported code is checked against the original game's code, run instruction by instruction in an emulator. Hundreds of fixes went in across every system. Among the ones you might notice:

- Quest spawn positions, timers and hardcore variants match the original, and a hardcore completion also unlocks the normal quest.
- Perks: Death Clock blocks enemy projectiles, Thick Skinned has no health floor, Jinxed kills are not doubled by Double Experience, and Final Revenge, Man Bomb, Fire Cough and Radioactive match the original's damage and angles.
- Bonuses: Freeze shatters every corpse, both co-op players get a bonus picked up in the same frame, and Telekinetic pickups land before the level-up check.
- Creatures: split children and plague spread behave as in the original, and Energizer kills pay double XP like the original.
- Weapons fire, reload and spread like the original; the homing search has no range cap, and a manual reload starts whenever the key is held.
- Rendering: plasma cores and trails, laser beams, bloom, bonus icons, creature tints and corpse fades are restored.
- Sound: 16 voices, sounds start where the original plays them, a busy sample restarts on a random voice, and flamethrowers alternate between both samples.
- Typ-o-Shooter runs each frame like the original, with its shotgun and long-name handling.

#### Replays

- Replays are a new format (v29). Each one records the run's result, and `crimson replay verify` re-simulates the run and checks every tick. It also reports whether the run qualifies for ranking: full unlocks, maximum detail and violence on.
- Replays recorded with 0.10.0 or earlier can't be played back. Replays from later versions play and verify in any version that reads their format, with a warning when the recording version differs.
- The replay viewer's skip and fast-forward speeds work properly, and `crimson replay list` names Typ-o and tutorial replays.

#### Removed

- The shareware demo (`--demo`, the trial overlay and the purchase screen) and the attract mode it started. The original game ships as the full version only.

### Under the hood

- **Matching decompilation complete.** All 858 game and engine functions in `crimsonland.exe` and `grim.dll` come from recovered C/C++ that Visual C++ 6 compiles to the original machine code, instruction for instruction. Progress is on [decomp.dev](https://decomp.dev/banteg/crimson), which also measures 1.9.8 from the same source.
- **Native oracle.** Differential tests run the original functions under Unicorn and compare the port bit for bit (`CRIMSON_NATIVE_ORACLE=1`; a CI job runs them). It replaces the Frida capture pipeline, the WinDbg scripts and `--trace-rng`, which are removed.
- **x87 float model.** Deterministic code rounds per operation at the 24-bit precision Direct3D 8 leaves the FPU in; see the [float parity policy](https://crimson.banteg.xyz/rewrite/float-parity-policy/).
- **Replay format v11 → v29.**
  - Payloads are canonical msgpack: a run spec, the result and the ticks.
  - The run seed is the CRT state entering `gameplay_reset_state`.
  - Verification re-derives the result and reports a ranked verdict (verify schema 4).
  - Checkpoint sidecars are format 7. Each tick pins the CRC of the RNG call order, which replaces the separate `.rng` goldens.
- **Native-shaped port.** Large parts of the Python code now follow the original's structure: native-ordered death and update handlers, the shared effect template, the menu skeleton, keyboard focus and the controls schemes. The shareware and attract-mode paths were dropped. `src/` shrank by about 28,000 lines.
- **Tooling split.** Reverse-engineering tools moved to the `crimson-re` workspace package (`crimson match`, `crimson native` and `crimson dbg` in the dev environment); they are not part of the published package.
- **Zig port frozen.** Its verifier stays, but new work is deferred. Its tests run only with `--run-zig`. The [recovered-core spike](https://github.com/banteg/crimson/blob/master/tools/recovered_sim/README.md) (recovered C/C++ compiled to WASM) is the direction for a shared game and verifier.
- **Checks.** Ruff, ty and ast-grep rules replace import-linter, pylint and pytest-cov. CI also runs render tests under xvfb, the native oracle, decompilation progress and the recovered-sim spike.
- **Fixtures.** Controller runs re-recorded on v29 (quests 2.5, 2.10 and 4.10, a 16-perk survival run) join the Rush and Typ-o-Shooter fixtures.
