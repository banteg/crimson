from __future__ import annotations

"""Perk ids extracted from perks_init_database (FUN_0042fd90)."""

from dataclasses import dataclass
from enum import IntEnum, IntFlag


class PerkFlags(IntFlag):
    MODE_3_ONLY = 0x1  # allow when _DAT_00480360 == 3
    TWO_PLAYER_ONLY = 0x2  # allow when _DAT_0048035c == 2
    STACKABLE = 0x4  # can be offered even if already owned


class PerkId(IntEnum):
    ANTIPERK = 0
    BLOODY_MESS_QUICK_LEARNER = 1
    SHARPSHOOTER = 2
    FASTLOADER = 3
    LEAN_MEAN_EXP_MACHINE = 4
    LONG_DISTANCE_RUNNER = 5
    PYROKINETIC = 6
    INSTANT_WINNER = 7
    GRIM_DEAL = 8
    ALTERNATE_WEAPON = 9
    PLAGUEBEARER = 10
    EVIL_EYES = 11
    AMMO_MANIAC = 12
    RADIOACTIVE = 13
    FASTSHOT = 14
    FATAL_LOTTERY = 15
    RANDOM_WEAPON = 16
    MR_MELEE = 17
    ANXIOUS_LOADER = 18
    FINAL_REVENGE = 19
    TELEKINETIC = 20
    PERK_EXPERT = 21
    UNSTOPPABLE = 22
    REGRESSION_BULLETS = 23
    INFERNAL_CONTRACT = 24
    POISON_BULLETS = 25
    DODGER = 26
    BONUS_MAGNET = 27
    URANIUM_FILLED_BULLETS = 28
    DOCTOR = 29
    MONSTER_VISION = 30
    HOT_TEMPERED = 31
    BONUS_ECONOMIST = 32
    THICK_SKINNED = 33
    BARREL_GREASER = 34
    AMMUNITION_WITHIN = 35
    VEINS_OF_POISON = 36
    TOXIC_AVENGER = 37
    REGENERATION = 38
    PYROMANIAC = 39
    NINJA = 40
    HIGHLANDER = 41
    JINXED = 42
    PERK_MASTER = 43
    REFLEX_BOOSTED = 44
    GREATER_REGENERATION = 45
    BREATHING_ROOM = 46
    DEATH_CLOCK = 47
    MY_FAVOURITE_WEAPON = 48
    BANDAGE = 49
    ANGRY_RELOADER = 50
    ION_GUN_MASTER = 51
    STATIONARY_RELOADER = 52
    MAN_BOMB = 53
    FIRE_CAUGH = 54
    LIVING_FORTRESS = 55
    TOUGH_RELOADER = 56
    LIFELINE_50_50 = 57


@dataclass(frozen=True, slots=True)
class PerkMeta:
    perk_id: PerkId
    const_name: str
    const_addr: str
    name: str
    description: str
    flags: PerkFlags | None
    prereq: tuple[PerkId, ...] = ()
    notes: str | None = None


PERK_TABLE = [
    PerkMeta(
        perk_id=PerkId.ANTIPERK,
        const_name="perk_id_antiperk",
        const_addr="DAT_004c2b40",
        name="AntiPerk",
        description="You shouldn't be seeing this..",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BLOODY_MESS_QUICK_LEARNER,
        const_name="perk_id_bloody_mess_quick_learner",
        const_addr="DAT_004c2b44",
        name="Bloody Mess",
        description="More the merrier. More blood guarantees a 30% better experience. You spill more blood and gain more experience points.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.SHARPSHOOTER,
        const_name="perk_id_sharpshooter",
        const_addr="DAT_004c2b48",
        name="Sharpshooter",
        description="Miraculously your aiming improves drastically, but you take a little bit more time on actually firing the gun. If you order now, you also get a fancy LASER SIGHT without ANY charge!",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.FASTLOADER,
        const_name="perk_id_fastloader",
        const_addr="DAT_004c2b5c",
        name="Fastloader",
        description="Man, you sure know how to load a gun.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.LEAN_MEAN_EXP_MACHINE,
        const_name="perk_id_lean_mean_exp_machine",
        const_addr="DAT_004c2b84",
        name="Lean Mean Exp Machine",
        description="Why kill for experience when you can make some of your own for free! With this perk the experience just keeps flowing in at a constant rate.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.LONG_DISTANCE_RUNNER,
        const_name="perk_id_long_distance_runner",
        const_addr="DAT_004c2b54",
        name="Long Distance Runner",
        description="You move like a train that has feet and runs. You just need a little time to warm up. In other words you'll move faster the longer you run without stopping.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.PYROKINETIC,
        const_name="perk_id_pyrokinetic",
        const_addr="DAT_004c2b64",
        name="Pyrokinetic",
        description="You see flames everywhere. Bare aiming at creatures causes them to heat up.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.INSTANT_WINNER,
        const_name="perk_id_instant_winner",
        const_addr="DAT_004c2b4c",
        name="Instant Winner",
        description="2500 experience points. Right away. Take it or leave it.",
        flags=PerkFlags.STACKABLE,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.GRIM_DEAL,
        const_name="perk_id_grim_deal",
        const_addr="DAT_004c2b70",
        name="Grim Deal",
        description="I'll make you a deal: I'll give you 18% more experience points, and you'll give me your life. So you'll die but score higher. Ponder that one for a sec.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.ALTERNATE_WEAPON,
        const_name="perk_id_alternate_weapon",
        const_addr="DAT_004c2b74",
        name="Alternate Weapon",
        description="Ever fancied about having two weapons available for use? This might be your lucky day; with this perk you'll get an extra weapon slot for another gun! Carrying around two guns slows you down slightly though. (You can switch the weapon slots with RELOAD key)",
        flags=PerkFlags.MODE_3_ONLY,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.PLAGUEBEARER,
        const_name="perk_id_plaguebearer",
        const_addr="DAT_004c2b78",
        name="Plaguebearer",
        description="You carry a horrible disease. Good for you: you are immune. Bad for them: it is contagious! (Monsters become resistant over time though.)",
        flags=None,
        prereq=(),
        notes="Sets `player_plaguebearer_active` (`DAT_004908b9`); creature update checks it to infect nearby monsters.",
    ),
    PerkMeta(
        perk_id=PerkId.EVIL_EYES,
        const_name="perk_id_evil_eyes",
        const_addr="DAT_004c2b88",
        name="Evil Eyes",
        description="No living (nor dead) can resist the hypnotic power of your eyes: monsters freeze still as you look at them!",
        flags=None,
        prereq=(),
        notes="Target creature index stored in `evil_eyes_target_creature` (`DAT_00490bbc`), set in `perks_update_effects`, read in `creature_update_all`.",
    ),
    PerkMeta(
        perk_id=PerkId.AMMO_MANIAC,
        const_name="perk_id_ammo_maniac",
        const_addr="DAT_004c2b80",
        name="Ammo Maniac",
        description="You squeeze and you push and you pack your clips with about 20% more ammo than a regular fellow. They call you Ammo Maniac with a deep respect in their voices.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.RADIOACTIVE,
        const_name="perk_id_radioactive",
        const_addr="DAT_004c2b7c",
        name="Radioactive",
        description="You are the Radioactive-man; you have that healthy green glow around you! Others don't like it though, it makes them sick and nauseous whenever near you. It does affect your social life a bit.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.FASTSHOT,
        const_name="perk_id_fastshot",
        const_addr="DAT_004c2b50",
        name="Fastshot",
        description="Funny how you make your gun spit bullets faster than the next guy. Even the most professional of engineers are astonished.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.FATAL_LOTTERY,
        const_name="perk_id_fatal_lottery",
        const_addr="DAT_004c2c08",
        name="Fatal Lottery",
        description="Fifty-fifty chance of dying OR gaining 10k experience points. Place your bets. Interested, anyone?",
        flags=PerkFlags.STACKABLE,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.RANDOM_WEAPON,
        const_name="perk_id_random_weapon",
        const_addr="DAT_004c2c04",
        name="Random Weapon",
        description="Here, have this weapon. No questions asked.",
        flags=PerkFlags.MODE_3_ONLY | PerkFlags.STACKABLE,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.MR_MELEE,
        const_name="perk_id_mr_melee",
        const_addr="DAT_004c2bac",
        name="Mr. Melee",
        description="You master the art of melee fighting. You don't just stand still when monsters come near -- you hit back. Hard.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.ANXIOUS_LOADER,
        const_name="perk_id_anxious_loader",
        const_addr="DAT_004c2b90",
        name="Anxious Loader",
        description="When you can't stand waiting your gun to be reloaded you can speed up the process by clicking your FIRE button repeatedly as fast as you can.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.FINAL_REVENGE,
        const_name="perk_id_final_revenge",
        const_addr="DAT_004c2b94",
        name="Final Revenge",
        description="Pick this and you'll get your revenge. It's a promise.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.TELEKINETIC,
        const_name="perk_id_telekinetic",
        const_addr="DAT_004c2bf8",
        name="Telekinetic",
        description="Picking up bonuses has never been so easy and FUN. You can pick up bonuses simply by aiming at them for a while. Ingenious.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.PERK_EXPERT,
        const_name="perk_id_perk_expert",
        const_addr="DAT_004c2ba0",
        name="Perk Expert",
        description="You sure know how to pick a perk -- most people just don't see that extra perk laying around. This gives you the opportunity to pick the freshest and shiniest perks from the top.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.UNSTOPPABLE,
        const_name="perk_id_unstoppable",
        const_addr="DAT_004c2b98",
        name="Unstoppable",
        description="Monsters can't slow you down with their nasty scratches and bites. It still hurts but you simply ignore the pain.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.REGRESSION_BULLETS,
        const_name="perk_id_regression_bullets",
        const_addr="DAT_004c2bd0",
        name="Regression Bullets",
        description="Attempt to shoot with an empty clip leads to a severe loss of experience. But hey, whatever makes them go down, right?",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.INFERNAL_CONTRACT,
        const_name="perk_id_infernal_contract",
        const_addr="DAT_004c2b9c",
        name="Infernal Contract",
        description="In exchange for your soul, a dark stranger is offering you three (3) new perks. To collect his part of the bargain soon enough, your health is reduced to a near-death status. Just sign down here below this pentagram..",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.POISON_BULLETS,
        const_name="perk_id_poison_bullets",
        const_addr="DAT_004c2bf4",
        name="Poison Bullets",
        description="You tend to explicitly treat each of your bullets with rat poison. You do it for good luck, but it seems to have other side effects too.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.DODGER,
        const_name="perk_id_dodger",
        const_addr="DAT_004c2bdc",
        name="Dodger",
        description="It seems so stupid just to take the hits. Each time a monster attacks you you have a chance to dodge the attack.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BONUS_MAGNET,
        const_name="perk_id_bonus_magnet",
        const_addr="DAT_004c2ba8",
        name="Bonus Magnet",
        description="You somehow seem to lure all kinds of bonuses to appear around you more often.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.URANIUM_FILLED_BULLETS,
        const_name="perk_id_uranium_filled_bullets",
        const_addr="DAT_004c2c00",
        name="Uranium Filled Bullets",
        description="Your bullets have a nice creamy uranium filling. Yummy. Now that's gotta hurt the monsters more, right?",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.DOCTOR,
        const_name="perk_id_doctor",
        const_addr="DAT_004c2b60",
        name="Doctor",
        description="With a single glance you can tell the medical condition of, well, anything. Also, being a doctor, you know exactly what hurts the most enabling you to do slightly more damage with your attacks.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.MONSTER_VISION,
        const_name="perk_id_monster_vision",
        const_addr="DAT_004c2be8",
        name="Monster Vision",
        description="With your newly enhanced senses you can see all bad energy VERY clearly. That's got to be enough.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.HOT_TEMPERED,
        const_name="perk_id_hot_tempered",
        const_addr="DAT_004c2bfc",
        name="Hot Tempered",
        description="It literally boils inside you. That's exactly why you need to let it out once in a while, unfortunately for those near you.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BONUS_ECONOMIST,
        const_name="perk_id_bonus_economist",
        const_addr="DAT_004c2bf0",
        name="Bonus Economist",
        description="Your bonus power-ups last 50% longer than they normally would.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.THICK_SKINNED,
        const_name="perk_id_thick_skinned",
        const_addr="DAT_004c2bc0",
        name="Thick Skinned",
        description="Trade 1/3 of your health for only receiving 2/3rds damage on attacks.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BARREL_GREASER,
        const_name="perk_id_barrel_greaser",
        const_addr="DAT_004c2bec",
        name="Barrel Greaser",
        description="After studying a lot of physics and friction you've come up with a way to make your bullets fly faster. More speed, more damage.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.AMMUNITION_WITHIN,
        const_name="perk_id_ammunition_within",
        const_addr="DAT_004c2bc8",
        name="Ammunition Within",
        description="Empty clip doesn't prevent you from shooting with a weapon; instead the ammunition is drawn from your health while you are reloading.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.VEINS_OF_POISON,
        const_name="perk_id_veins_of_poison",
        const_addr="DAT_004c2bb8",
        name="Veins of Poison",
        description="A strong poison runs through your veins. Monsters taking a bite of you are eventually to experience an agonizing death.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.TOXIC_AVENGER,
        const_name="perk_id_toxic_avenger",
        const_addr="DAT_004c2bbc",
        name="Toxic Avenger",
        description="You started out just by being poisonous. The next logical step for you is to become highly toxic -- the ULTIMATE TOXIC AVENGER. Most monsters touching you will just drop dead within seconds!",
        flags=None,
        prereq=(PerkId.VEINS_OF_POISON,),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.REGENERATION,
        const_name="perk_id_regeneration",
        const_addr="DAT_004c2bb0",
        name="Regeneration",
        description="Your health replenishes but very slowly. What more there is to say?",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.PYROMANIAC,
        const_name="perk_id_pyromaniac",
        const_addr="DAT_004c2bd4",
        name="Pyromaniac",
        description="You just enjoy using fire as your Tool of Destruction and you're good at it too; your fire based weapons do a lot more damage.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.NINJA,
        const_name="perk_id_ninja",
        const_addr="DAT_004c2be0",
        name="Ninja",
        description="You've taken your dodging abilities to the next level; monsters have really hard time hitting you.",
        flags=None,
        prereq=(PerkId.DODGER,),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.HIGHLANDER,
        const_name="perk_id_highlander",
        const_addr="DAT_004c2bd8",
        name="Highlander",
        description="You are immortal. Well, almost immortal. Instead of actually losing health on attacks you've got a 10% chance of just dropping dead whenever a monster attacks you. There really can be only one, you know.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.JINXED,
        const_name="perk_id_jinxed",
        const_addr="DAT_004c2b68",
        name="Jinxed",
        description="Things happen near you. Strangest things. Creatures just drop dead and accidents happen. Beware.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.PERK_MASTER,
        const_name="perk_id_perk_master",
        const_addr="DAT_004c2ba4",
        name="Perk Master",
        description="Being the Perk Expert taught you a few things and now you are ready to take your training to the next level doubling the ability effect.",
        flags=None,
        prereq=(PerkId.PERK_EXPERT,),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.REFLEX_BOOSTED,
        const_name="perk_id_reflex_boosted",
        const_addr="DAT_004c2b58",
        name="Reflex Boosted",
        description="To you the world seems to go on about 10% slower than to an average person. It can be rather irritating sometimes, but it does give you a chance to react better.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.GREATER_REGENERATION,
        const_name="perk_id_greater_regeneration",
        const_addr="DAT_004c2bb4",
        name="Greater Regeneration",
        description="Your health replenishes faster than ever.",
        flags=None,
        prereq=(PerkId.REGENERATION,),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BREATHING_ROOM,
        const_name="perk_id_breathing_room",
        const_addr="DAT_004c2bc4",
        name="Breathing Room",
        description="Trade 2/3rds of your health for the killing of every single creature on the screen. No, you don't get the experience.",
        flags=PerkFlags.TWO_PLAYER_ONLY,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.DEATH_CLOCK,
        const_name="perk_id_death_clock",
        const_addr="DAT_004c2c14",
        name="Death Clock",
        description="You die exactly in 30 seconds. You can't escape your destiny, but feel free to go on a spree. Tick, tock.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.MY_FAVOURITE_WEAPON,
        const_name="perk_id_my_favourite_weapon",
        const_addr="DAT_004c2c18",
        name="My Favourite Weapon",
        description="You've grown very fond of your piece. You polish it all the time and talk nice to it, your precious. (+2 clip size, no more random weapon bonuses)",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.BANDAGE,
        const_name="perk_id_bandage",
        const_addr="DAT_004c2c1c",
        name="Bandage",
        description="Here, eat this bandage and you'll feel a lot better in no time. (restores up to 50% health)",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.ANGRY_RELOADER,
        const_name="perk_id_angry_reloader",
        const_addr="DAT_004c2c20",
        name="Angry Reloader",
        description="You hate it when you run out of shots. You HATE HATE HATE reloading your gun. Lucky for you, and strangely enough, your hate materializes as Mighty Balls of Fire. Or more like Quite Decent Balls of Fire, but it's still kinda neat, huh?",
        flags=None,
        prereq=(),
        notes="Spawns a ring of projectile type `0x0b` when the reload timer crosses the half threshold.",
    ),
    PerkMeta(
        perk_id=PerkId.ION_GUN_MASTER,
        const_name="perk_id_ion_gun_master",
        const_addr="DAT_004c2c0c",
        name="Ion Gun Master",
        description="You're good with ion weapons. You're so good that not only your shots do slightly more damage but your ion blast radius is also increased.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.STATIONARY_RELOADER,
        const_name="perk_id_stationary_reloader",
        const_addr="DAT_004c2c10",
        name="Stationary Reloader",
        description="It's incredibly hard to reload your piece while moving around, you've noticed. In fact, realizing that, when you don't move a (leg) muscle you can reload the gun THREE TIMES FASTER!",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.MAN_BOMB,
        const_name="perk_id_man_bomb",
        const_addr="DAT_004c2c24",
        name="Man Bomb",
        description="You have the ability to go boom for you are the MAN BOMB. Going boom requires a lot of concentration and standing completely still for a few seconds.",
        flags=None,
        prereq=(),
        notes="Burst spawns projectile types `0x15/0x16`.",
    ),
    PerkMeta(
        perk_id=PerkId.FIRE_CAUGH,
        const_name="perk_id_fire_caugh",
        const_addr="DAT_004c2c2c",
        name="Fire Caugh",
        description="You have a fireball stuck in your throat. Repeatedly. Mind your manners.",
        flags=None,
        prereq=(),
        notes="Uses projectile type `0x2d` (see Fire Bullets in the atlas notes).",
    ),
    PerkMeta(
        perk_id=PerkId.LIVING_FORTRESS,
        const_name="perk_id_living_fortress",
        const_addr="DAT_004c2c28",
        name="Living Fortress",
        description="It comes a time in each man's life when you'd just rather not move anymore. Being living fortress not moving comes with extra benefits as well. You do the more damage the longer you stand still.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.TOUGH_RELOADER,
        const_name="perk_id_tough_reloader",
        const_addr="DAT_004c2c30",
        name="Tough Reloader",
        description="Damage received during reloading a weapon is halved.",
        flags=None,
        prereq=(),
        notes=None,
    ),
    PerkMeta(
        perk_id=PerkId.LIFELINE_50_50,
        const_name="perk_id_lifeline_50_50",
        const_addr="DAT_004c2be4",
        name="Lifeline 50-50",
        description="The computer removes half of the wrong monsters for you. You don't gain any experience.",
        flags=None,
        prereq=(),
        notes=None,
    ),
]

PERK_BY_ID = {int(entry.perk_id): entry for entry in PERK_TABLE}


def perk_label(perk_id: int) -> str:
    entry = PERK_BY_ID.get(perk_id)
    if entry is None:
        return "unknown"
    return entry.name
