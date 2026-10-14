---
tags:
  - mechanics
  - systems
  - bugs
---

# Classic quirks

The original game's bugs, as a player meets them. The rewrite fixes most of
them by default; run it with `--preserve-bugs` to bring every fixed one
back. A few stay in both modes. The # column links each one's full write-up
in [Original bugs](../../rewrite/original-bugs.md); the last column links
the page that covers it.

## Gameplay

| # | Quirk | In the original | Rewrite | Page |
| ---: | --- | --- | --- | --- |
| [1](../../rewrite/original-bugs.md#1-bonus-drop-suppression-amount-current-weapon-id) | Gun-number drop bans | Some bonuses never drop while player 1 holds a matching gun: Nuke with the Pistol, Freeze with the Submachine Gun and more. | Fixed | [Bonuses](bonuses.md#suppression-rules) |
| [2](../../rewrite/original-bugs.md#2-greater-regeneration-has-no-runtime-effect) | Dud Greater Regeneration | Taking it does nothing. | Fixed: heals twice as fast as Regeneration | [Perks](../perks.md#45-greater-regeneration) |
| [3](../../rewrite/original-bugs.md#3-bandage-applies-a-health-multiplier-instead-of-a-heal) | Bandage multiplies | Health is multiplied by 1–50, so it nearly always fills up. | Fixed: heals 1–50 HP | [Perks](../perks.md#49-bandage) |
| [5](../../rewrite/original-bugs.md#5-stationary-reloader-can-finish-a-reload-without-refilling-ammo) | Empty reloads | A reload sped up by Stationary Reloader can finish with an empty clip: one shot per reload. | Fixed | [Perks](../perks.md#52-stationary-reloader) |
| [17](../../rewrite/original-bugs.md#17-mini-rocket-swarmers-spread-can-collapse-into-clumped-rockets) | Clumped swarmers | At some clip sizes, 6 with Ammo Maniac, every Mini-Rocket Swarmer flies on one heading. | Fixed: an even fan | [Weapons](../combat/weapons.md#17-mini-rocket-swarmers) |
| [18](../../rewrite/original-bugs.md#18-exact-zero-lethal-hits-skip-death-only-handling) | Quiet Highlander deaths | A Highlander death skips Final Revenge and the death sound. | Fixed | [Perks](../perks.md#19-final-revenge) |
| [20](../../rewrite/original-bugs.md#20-no-target-homing-lookups-silently-fall-back-to-creature-slot-0) | Homing at nothing | With nothing to chase, Shock Chain and Seeker Rockets steer at a leftover creature, dead or alive. | Fixed: they stop retargeting | — |
| [24](../../rewrite/original-bugs.md#24-holding-g-while-firing-grants-free-fire-bullets) | The G key | Holding G while firing grants 10 s of Fire Bullets. | Ignored | [Bonuses](bonuses.md#14-fire-bullets), [Secrets](secrets.md#holding-g) |
| [27](../../rewrite/original-bugs.md#27-enemy-projectiles-hurt-through-death-clock) | Leaky Death Clock | Enemy shots still hit for 10 during Death Clock. | Fixed | [Perks](../perks.md#47-death-clock) |
| [32](../../rewrite/original-bugs.md#32-projectile-slot-0-cannot-hit-the-player-at-first) | Ghost enemy shot | Until the session's first Shock Chain ends, an occasional enemy shot passes straight through you. | Fixed | — |
| [33](../../rewrite/original-bugs.md#33-a-bonus-carrier-can-drop-its-bonus-twice) | Double carrier drop | A bonus carrier killed twice over, as by a rocket and its blast, drops its bonus twice. | Fixed | — |
| [38](../../rewrite/original-bugs.md#38-quest-difficulty-leaks-into-survival-and-the-tutorial) | Quest difficulty leaks into Survival | A Hardcore box left ticked on the quest list toughens Survival's milestone waves and the Tutorial's creatures; quitting a retried quest from the pause menu eases them instead. Either way the run lands in the normal Survival table. | Fixed: both apply only to quests | [High scores](scores.md#hardcore-and-survival) |

## Co-op

Most co-op quirks come from the original reading player 1's state where it
meant the player in question.

| # | Quirk | In the original | Rewrite | Page |
| ---: | --- | --- | --- | --- |
| [6](../../rewrite/original-bugs.md#6-weapon-drop-proximity-conversion-checks-player-1-only) | Points conversion | Only player 1 standing near a Weapon drop turns it into Points. | Fixed | [Bonuses](bonuses.md#3-weapon) |
| [7](../../rewrite/original-bugs.md#7-regeneration-applies-to-player-1-only-in-co-op) | Regeneration | Heals only player 1, twice as fast with two players. | Fixed | [Perks](../perks.md#38-regeneration) |
| [8](../../rewrite/original-bugs.md#8-co-op-heart-pulse-speed-inherits-player-1-low-health-state) | Racing heart | Player 2's heart icon races whenever player 1 is low. | Fixed | — |
| [9](../../rewrite/original-bugs.md#9-co-op-damagedeath-sfx-guard-reads-player-1-health) | Silent hits | With player 1 dead, player 2's pain and death sounds can go missing. | Fixed | — |
| [11](../../rewrite/original-bugs.md#11-cursor-target-perks-read-player-1-aim-only-in-co-op) | Crosshair perks | Doctor, Pyrokinetic and Evil Eyes follow player 1's crosshair only. | Fixed | [Pyrokinetic](../perks.md#6-pyrokinetic), [Evil Eyes](../perks.md#11-evil-eyes), [Doctor](../perks.md#29-doctor) |
| [12](../../rewrite/original-bugs.md#12-jinxed-self-damage-always-hits-player-1-in-co-op) | Jinxed accidents | The 5 HP accident always hits player 1. | Fixed: a random living player | [Perks](../perks.md#42-jinxed) |
| [13](../../rewrite/original-bugs.md#13-fire-bullets-projectile-override-is-globally-coupled-in-co-op) | Shared Fire Bullets | Either player's Fire Bullets converts both players' shots. | Fixed | [Bonuses](bonuses.md#14-fire-bullets) |
| [14](../../rewrite/original-bugs.md#14-pyromaniac-offer-gating-checks-player-1-weapon-only-in-co-op) | Pyromaniac offer | Pyromaniac is offered only while player 1 holds the Flamethrower. | Fixed | [Perks](../perks.md#39-pyromaniac) |
| [15](../../rewrite/original-bugs.md#15-joystick-pov-aim-reads-player-1-pov-only-in-co-op) | Joystick hat | Player 2's hat aim reads player 1's hat. | Fixed | — |
| [16](../../rewrite/original-bugs.md#16-pistol-no-magnet-fallback-gate-checks-player-1-only-in-co-op) | Pistol drop bonus | The extra 1-in-5 drop roll for Pistol holders checks only player 1's gun. | Fixed | — |
| [19](../../rewrite/original-bugs.md#19-co-op-auto-target-replacement-reuses-mismatched-player-distances) | Computer targets | [Computer-controlled](secrets.md#hidden-control-schemes) players can stick to a worse target. | Fixed | — |
| [23](../../rewrite/original-bugs.md#23-plaguebearer-contact-immunity-activates-player-1-only-in-co-op) | Plaguebearer | Only player 1 infects creatures by touch. | Fixed | [Perks](../perks.md#10-plaguebearer) |

## Sights, sounds and menus

| # | Quirk | In the original | Rewrite | Page |
| ---: | --- | --- | --- | --- |
| [21](../../rewrite/original-bugs.md#21-trooper-death-sfx-bank-leaves-slot-3-uninitialized) | Death grunt | 1 trooper death in 4 plays a pain grunt instead of a death cry. | Fixed | — |
| [25](../../rewrite/original-bugs.md#25-re-picking-a-bonus-can-leave-its-hud-indicator-hidden-for-seconds) | Hidden bonus timer | Re-picking a bonus can leave its timer panel off-screen for seconds while it runs. | Fixed | — |
| [28](../../rewrite/original-bugs.md#28-bullet-heads-and-plasma-cores-are-never-visible) | Invisible bullets | Bullets show only their trails, plasma shots only their glow. | Fixed: bullets and pellets show heads | — |
| [29](../../rewrite/original-bugs.md#29-a-stray-click-picks-a-row-from-an-open-list) | Stray list clicks | With a list open, a click anywhere picks its last hovered row; on High scores that can switch the mode or filter. | Fixed | — |
| [30](../../rewrite/original-bugs.md#30-typ-o-shot-counts-carry-over-from-earlier-runs) | Typ-o hit % | Typed words carry over between Typ-o runs in one session. | Fixed: each run counts its own | [Typ-o-Shooter](../modes/typo-shooter.md#scoring) |
| [31](../../rewrite/original-bugs.md#31-a-resting-aim-stick-swings-the-aim-onto-the-player) | Resting aim stick | Letting go of the Dual Action Pad aim stick swings your gun to face left, and a drifting stick twitches it. | Fixed: a 0.2 dead zone | — |
| [34](../../rewrite/original-bugs.md#34-the-fire-bullets-glow-follows-the-last-projectile-slot) | Fire Bullets glow | Fire Bullets shots usually lack their glow; with the screen full of shots, every shot can glow. | Fixed | — |
| [35](../../rewrite/original-bugs.md#35-rocket-detonation-flashes-draw-the-whole-particle-atlas) | Rocket flash | Rocket blasts flash the whole effects sheet: a ring down-right, specks up-left. | Fixed: a soft glow | — |
| [36](../../rewrite/original-bugs.md#36-ion-chain-arcs-end-in-a-hard-cut) | Ion arcs | Ion chain arcs end in a straight cut across the creature. | Fixed: round ends | — |
| [39](../../rewrite/original-bugs.md#39-blood-splatters-and-corpse-shatters-exhaust-the-511-slot-effect-pool) | Missing pickup rings and bursts | Heavy blood from Bloody Mess or a large Freeze corpse shatter fills the effect pool, so pickup rings, hit cores and bursts vanish. | Fixed | — |

## Kept in both modes

| # | Quirk | In the original | Rewrite | Page |
| ---: | --- | --- | --- | --- |
| [4](../../rewrite/original-bugs.md#4-player-facing-text-quirks-documented-not-fixed) | Original text | Typos such as *Fire Caugh* and *Persistence will be rewared.* | Kept | — |
| [22](../../rewrite/original-bugs.md#22-the-killing-wave-picks-roll-rand-but-branch-on-the-wave-counter) | The Killing's order | Quest 3.3 runs a fixed cycle: the same edges in turn, nests on waves 5 and 10. | Kept | [Quests](../modes/quests.md#tier-3) |
| [37](../../rewrite/original-bugs.md#37-survival-spawning-grows-without-bound-after-fifteen-minutes) | Survival after 15:00 | Spawning grows without limit until the arena holds 384 creatures. | Kept | [Survival](../modes/survival.md#waves) |
| — | Swapped quest score files | Normal quest scores save to `questhcM_N.hi`, hardcore ones to `questM_N.hi`. | Kept | [High scores](scores.md#local-tables) |
| — | Typ-o score file | Typ-o has no file name of its own, so its scores save to `scores5\unknown.hi`. | Kept | [Local high scores](../../formats/highscores.md) |

## Not on the bug list yet

| Quirk | In the original | Rewrite | Page |
| --- | --- | --- | --- |
| Every run makes the table | Every run is saved. Past 99 runs, each new one replaces the weakest listed score, even when it scores lower. | A true top 100 | [High scores](scores.md#when-a-run-is-saved) |
| Formation tails | The last member of most rings, chains and grids is a 20 HP alien, and only it gets hardcore and retry scaling. | Kept | [Quests](../modes/quests.md#formations) |

Two entries in the bug list, 10 and 26, are left out because no player can
see them.
