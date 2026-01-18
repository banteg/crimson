# Perk ID map

Derived from `FUN_0042fd90` (perk database init). IDs are stored in `DAT_004c2b**`/`DAT_004c2c**`
constants; names and descriptions are filled via `FUN_0042fd00`.

Notes:

- `perk_id_bloody_mess_quick_learner (DAT_004c2b44)` selects between two perk definitions depending on `DAT_004807b4`.
- Flags live at `perk_flags_table (DAT_004c2c48) + id * 0x14` and gate availability in `perk_can_offer`:
  - `0x1` allows the perk when `_DAT_00480360 == 3`.
  - `0x2` allows the perk when `_DAT_0048035c == 2` (two-player mode).
  - `0x4` marks stackable perks (random selection accepts them even if already taken).
- `perk_prereq_table (DAT_004c2c50) + id * 0x14` stores prerequisite perk ids (checked via `perk_count_get`).
- Music track ids are initialized in `audio_init_music` (see [detangling notes](detangling.md)).


| ID | Const | Name | Description | Flags | Prereq |
| -- | -- | -- | -- | -- | -- |
| 0 | perk_id_antiperk (DAT_004c2b40) | AntiPerk | You shouldn't be seeing this.. |  |  |
| 1 | perk_id_bloody_mess_quick_learner (DAT_004c2b44) | Bloody Mess / Quick Learner | More the merrier. More blood guarantees a 30% better experience. You spill more blood and gain more experience points. / You learn things faster than a regular Joe from now on gaining 30% more experience points from everything you do. |  |  |
| 2 | perk_id_sharpshooter (DAT_004c2b48) | Sharpshooter | Miraculously your aiming improves drastically, but you take a little bit more time on actually firing the gun. If you order now, you also get a fancy LASER SIGHT without ANY charge! |  |  |
| 3 | perk_id_fastloader (DAT_004c2b5c) | Fastloader | Man, you sure know how to load a gun. |  |  |
| 4 | perk_id_lean_mean_exp_machine (DAT_004c2b84) | Lean Mean Exp Machine | Why kill for experience when you can make some of your own for free! With this perk the experience just keeps flowing in at a constant rate. |  |  |
| 5 | perk_id_long_distance_runner (DAT_004c2b54) | Long Distance Runner | You move like a train that has feet and runs. You just need a little time to warm up. In other words you'll move faster the longer you run without stopping. |  |  |
| 6 | perk_id_pyrokinetic (DAT_004c2b64) | Pyrokinetic | You see flames everywhere. Bare aiming at creatures causes them to heat up. |  |  |
| 7 | perk_id_instant_winner (DAT_004c2b4c) | Instant Winner | 2500 experience points. Right away. Take it or leave it. | 0x4 |  |
| 8 | perk_id_grim_deal (DAT_004c2b70) | Grim Deal | I'll make you a deal: I'll give you 18% more experience points, and you'll give me your life. So you'll die but score higher. Ponder that one for a sec. |  |  |
| 9 | perk_id_alternate_weapon (DAT_004c2b74) | Alternate Weapon | Ever fancied about having two weapons available for use? This might be your lucky day; with this perk you'll get an extra weapon slot for another gun! Carrying around two guns slows you down slightly though. (You can switch the weapon slots with RELOAD key) | 0x1 |  |
| 10 | perk_id_plaguebearer (DAT_004c2b78) | Plaguebearer | You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! (Monsters become resistant over time though.) |  | Sets `player_plaguebearer_active` (`DAT_004908b9`); creature update checks it to infect nearby monsters. |
| 11 | perk_id_evil_eyes (DAT_004c2b88) | Evil Eyes | No living (nor dead) can resist the hypnotic power of your eyes: monsters freeze still as you look at them! |  | Target creature index stored in `evil_eyes_target_creature` (`DAT_00490bbc`), set in `perks_update_effects`, read in `creature_update_all`. |
| 12 | perk_id_ammo_maniac (DAT_004c2b80) | Ammo Maniac | You squeeze and you push and you pack your clips with about 20% more ammo than a regular fellow. They call you Ammo Maniac with a deep respect in their voices. |  |  |
| 13 | perk_id_radioactive (DAT_004c2b7c) | Radioactive | You are the Radioactive-man; you have that healthy green glow around you! Others don't like it though, it makes them sick and nauseous whenever near you. It does affect your social life a bit. |  |  |
| 14 | perk_id_fastshot (DAT_004c2b50) | Fastshot | Funny how you make your gun spit bullets faster than the next guy. Even the most professional of engineers are astonished. |  |  |
| 15 | perk_id_fatal_lottery (DAT_004c2c08) | Fatal Lottery | Fifty-fifty chance of dying OR gaining 10k experience points. Place your bets. Interested, anyone? | 0x4 |  |
| 16 | perk_id_random_weapon (DAT_004c2c04) | Random Weapon | Here, have this weapon. No questions asked. | 0x5 |  |
| 17 | perk_id_mr_melee (DAT_004c2bac) | Mr. Melee | You master the art of melee fighting. You don't just stand still when monsters come near -- you hit back. Hard. |  |  |
| 18 | perk_id_anxious_loader (DAT_004c2b90) | Anxious Loader | When you can't stand waiting your gun to be reloaded you can speed up the process by clicking your FIRE button repeatedly as fast as you can. |  |  |
| 19 | perk_id_final_revenge (DAT_004c2b94) | Final Revenge | Pick this and you'll get your revenge. It's a promise. |  |  |
| 20 | perk_id_telekinetic (DAT_004c2bf8) | Telekinetic | Picking up bonuses has never been so easy and FUN. You can pick up bonuses simply by aiming at them for a while. Ingenious. |  |  |
| 21 | perk_id_perk_expert (DAT_004c2ba0) | Perk Expert | You sure know how to pick a perk -- most people just don't see that extra perk laying around. This gives you the opportunity to pick the freshest and shiniest perks from the top. |  |  |
| 22 | perk_id_unstoppable (DAT_004c2b98) | Unstoppable | Monsters can't slow you down with their nasty scratches and bites. It still hurts but you simply ignore the pain. |  |  |
| 23 | perk_id_regression_bullets (DAT_004c2bd0) | Regression Bullets | Attempt to shoot with an empty clip leads to a severe loss of experience. But hey, whatever makes them go down, right? |  |  |
| 24 | perk_id_infernal_contract (DAT_004c2b9c) | Infernal Contract | In exchange for your soul, a dark stranger is offering you three (3) new perks. To collect his part of the bargain soon enough, your health is reduced to a near-death status. Just sign down here below this pentagram.. |  |  |
| 25 | perk_id_poison_bullets (DAT_004c2bf4) | Poison Bullets | You tend to explicitly treat each of your bullets with rat poison. You do it for good luck, but it seems to have other side effects too. |  |  |
| 26 | perk_id_dodger (DAT_004c2bdc) | Dodger | It seems so stupid just to take the hits. Each time a monster attacks you you have a chance to dodge the attack. |  |  |
| 27 | perk_id_bonus_magnet (DAT_004c2ba8) | Bonus Magnet | You somehow seem to lure all kinds of bonuses to appear around you more often. |  |  |
| 28 | perk_id_uranium_filled_bullets (DAT_004c2c00) | Uranium Filled Bullets | Your bullets have a nice creamy uranium filling. Yummy. Now that's gotta hurt the monsters more, right? |  |  |
| 29 | perk_id_doctor (DAT_004c2b60) | Doctor | With a single glance you can tell the medical condition of, well, anything. Also, being a doctor, you know exactly what hurts the most enabling you to do slightly more damage with your attacks. |  |  |
| 30 | perk_id_monster_vision (DAT_004c2be8) | Monster Vision | With your newly enhanced senses you can see all bad energy VERY clearly. That's got to be enough. |  |  |
| 31 | perk_id_hot_tempered (DAT_004c2bfc) | Hot Tempered | It literally boils inside you. That's exactly why you need to let it out once in a while, unfortunately for those near you. |  |  |
| 32 | perk_id_bonus_economist (DAT_004c2bf0) | Bonus Economist | Your bonus power-ups last 50% longer than they normally would. |  |  |
| 33 | perk_id_thick_skinned (DAT_004c2bc0) | Thick Skinned | Trade 1/3 of your health for only receiving 2/3rds damage on attacks. |  |  |
| 34 | perk_id_barrel_greaser (DAT_004c2bec) | Barrel Greaser | After studying a lot of physics and friction you've come up with a way to make your bullets fly faster. More speed, more damage. |  |  |
| 35 | perk_id_ammunition_within (DAT_004c2bc8) | Ammunition Within | Empty clip doesn't prevent you from shooting with a weapon; instead the ammunition is drawn from your health while you are reloading. |  |  |
| 36 | perk_id_veins_of_poison (DAT_004c2bb8) | Veins of Poison | A strong poison runs through your veins. Monsters taking a bite of you are eventually to experience an agonizing death. |  |  |
| 37 | perk_id_toxic_avenger (DAT_004c2bbc) | Toxic Avenger | You started out just by being poisonous. The next logical step for you is to become highly toxic -- the ULTIMATE TOXIC AVENGER. Most monsters touching you will just drop dead within seconds! |  | perk_id_veins_of_poison (DAT_004c2bb8) (Veins of Poison) |
| 38 | perk_id_regeneration (DAT_004c2bb0) | Regeneration | Your health replenishes but very slowly. What more there is to say? |  |  |
| 39 | perk_id_pyromaniac (DAT_004c2bd4) | Pyromaniac | You just enjoy using fire as your Tool of Destruction and you're good at it too; your fire based weapons do a lot more damage. |  |  |
| 40 | perk_id_ninja (DAT_004c2be0) | Ninja | You've taken your dodging abilities to the next level; monsters have really hard time hitting you. |  | perk_id_dodger (DAT_004c2bdc) (Dodger) |
| 41 | perk_id_highlander (DAT_004c2bd8) | Highlander | You are immortal. Well, almost immortal. Instead of actually losing health on attacks you've got a 10% chance of just dropping dead whenever a monster attacks you. There really can be only one, you know. |  |  |
| 42 | perk_id_jinxed (DAT_004c2b68) | Jinxed | Things happen near you. Strangest things. Creatures just drop dead and accidents happen. Beware. |  |  |
| 43 | perk_id_perk_master (DAT_004c2ba4) | Perk Master | Being the Perk Expert taught you a few things and now you are ready to take your training to the next level doubling the ability effect. |  | perk_id_perk_expert (DAT_004c2ba0) (Perk Expert) |
| 44 | perk_id_reflex_boosted (DAT_004c2b58) | Reflex Boosted | To you the world seems to go on about 10% slower than to an average person. It can be rather irritating sometimes, but it does give you a chance to react better. |  |  |
| 45 | perk_id_greater_regeneration (DAT_004c2bb4) | Greater Regeneration | Your health replenishes faster than ever. |  | perk_id_regeneration (DAT_004c2bb0) (Regeneration) |
| 46 | perk_id_breathing_room (DAT_004c2bc4) | Breathing Room | Trade 2/3rds of your health for the killing of every single creature on the screen. No, you don't get the experience. | 0x2 |  |
| 47 | perk_id_death_clock (DAT_004c2c14) | Death Clock | You die exactly in 30 seconds. You can't escape your destiny, but feel free to go on a spree. Tick, tock. |  |  |
| 48 | perk_id_my_favourite_weapon (DAT_004c2c18) | My Favourite Weapon | You've grown very fond of your piece. You polish it all the time and talk nice to it, your precious. (+2 clip size, no more random weapon bonuses) |  |  |
| 49 | perk_id_bandage (DAT_004c2c1c) | Bandage | Here, eat this bandage and you'll feel a lot better in no time. (restores up to 50% health) |  |  |
| 50 | perk_id_angry_reloader (DAT_004c2c20) | Angry Reloader | You hate it when you run out of shots. You HATE HATE HATE reloading your gun. Lucky for you, and strangely enough, your hate materializes as Mighty Balls of Fire. Or more like Quite Decent Balls of Fire, but it's still kinda neat, huh? |  | Spawns a ring of projectile type `0x0b` when the reload timer crosses the half threshold. |
| 51 | perk_id_ion_gun_master (DAT_004c2c0c) | Ion Gun Master | You're good with ion weapons. You're so good that not only your shots do slightly more damage but your ion blast radius is also increased. |  |  |
| 52 | perk_id_stationary_reloader (DAT_004c2c10) | Stationary Reloader | It's incredibly hard to reload your piece while moving around, you've noticed. In fact, realizing that, when you don't move a (leg) muscle you can reload the gun THREE TIMES FASTER! |  |  |
| 53 | perk_id_man_bomb (DAT_004c2c24) | Man Bomb | You have the ability to go boom for you are the MAN BOMB. Going boom requires a lot of concentration and standing completely still for a few seconds. |  | Burst spawns projectile types `0x15/0x16`. |
| 54 | perk_id_fire_caugh (DAT_004c2c2c) | Fire Caugh | You have a fireball stuck in your throat. Repeatedly. Mind your manners. |  | Uses projectile type `0x2d` (see Fire Bullets in the atlas notes). |
| 55 | perk_id_living_fortress (DAT_004c2c28) | Living Fortress | It comes a time in each man's life when you'd just rather not move anymore. Being living fortress not moving comes with extra benefits as well. You do the more damage the longer you stand still. |  |  |
| 56 | perk_id_tough_reloader (DAT_004c2c30) | Tough Reloader | Damage received during reloading a weapon is halved. |  |  |
| 57 | perk_id_lifeline_50_50 (DAT_004c2be4) | Lifeline 50-50 | The computer removes half of the wrong monsters for you. You don't gain any experience. |  |  |
