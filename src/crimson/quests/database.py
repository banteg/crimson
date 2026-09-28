from __future__ import annotations

from ..perks import PerkId
from ..terrain_slots import terrain_slots_for_quest
from ..weapons import WeaponId
from .level import QuestLevel
from .tier1 import (
    quest_build_8_legged_terror,
    quest_build_alien_dens,
    quest_build_alien_squads,
    quest_build_frontline_assault,
    quest_build_land_hostile,
    quest_build_minor_alien_breach,
    quest_build_nesting_grounds,
    quest_build_spider_wave_syndrome,
    quest_build_target_practice,
    quest_build_the_random_factor,
)
from .tier2 import (
    quest_build_arachnoid_farm,
    quest_build_everred_pastures,
    quest_build_evil_zombies_at_large,
    quest_build_ghost_patrols,
    quest_build_land_of_lizards,
    quest_build_spider_spawns,
    quest_build_spideroids,
    quest_build_survival_of_the_fastest,
    quest_build_sweep_stakes,
    quest_build_two_fronts,
)
from .tier3 import (
    quest_build_deja_vu,
    quest_build_hidden_evil,
    quest_build_lizard_kings,
    quest_build_lizard_raze,
    quest_build_spiders_inc,
    quest_build_surrounded_by_reptiles,
    quest_build_the_blighting,
    quest_build_the_killing,
    quest_build_the_lizquidation,
    quest_build_zombie_masters,
)
from .tier4 import (
    quest_build_gauntlet,
    quest_build_lizard_zombie_pact,
    quest_build_major_alien_breach,
    quest_build_syntax_terror,
    quest_build_the_annihilation,
    quest_build_the_collaboration,
    quest_build_the_end_of_all,
    quest_build_the_massacre,
    quest_build_the_unblitzkrieg,
    quest_build_zombie_time,
)
from .tier5 import (
    quest_build_army_of_three,
    quest_build_cross_fire,
    quest_build_knee_deep_in_the_dead,
    quest_build_monster_blues,
    quest_build_nagolipoli,
    quest_build_the_beating,
    quest_build_the_fortress,
    quest_build_the_gang_wars,
    quest_build_the_gathering,
    quest_build_the_spanking_of_the_dead,
)
from .types import QuestBuilder, QuestDefinition

# `quest_database_init` (0x00439230) order: title, start weapon, time limit, builder, then the
# unlocked weapon and perk it assigns afterwards by slot.
_QUEST_DATABASE: tuple[tuple[str, WeaponId, int, QuestBuilder, WeaponId | None, PerkId | None], ...] = (
    ("Land Hostile", WeaponId.PISTOL, 120000, quest_build_land_hostile, WeaponId.ASSAULT_RIFLE, None),
    ("Minor Alien Breach", WeaponId.PISTOL, 120000, quest_build_minor_alien_breach, WeaponId.SHOTGUN, None),
    ("Target Practice", WeaponId.PISTOL, 65000, quest_build_target_practice, None, PerkId.URANIUM_FILLED_BULLETS),
    ("Frontline Assault", WeaponId.PISTOL, 300000, quest_build_frontline_assault, WeaponId.FLAMETHROWER, None),
    ("Alien Dens", WeaponId.PISTOL, 180000, quest_build_alien_dens, None, PerkId.DOCTOR),
    ("The Random Factor", WeaponId.PISTOL, 300000, quest_build_the_random_factor, WeaponId.SUBMACHINE_GUN, None),
    ("Spider Wave Syndrome", WeaponId.PISTOL, 240000, quest_build_spider_wave_syndrome, None, PerkId.MONSTER_VISION),
    ("Alien Squads", WeaponId.PISTOL, 180000, quest_build_alien_squads, WeaponId.GAUSS_GUN, None),
    ("Nesting Grounds", WeaponId.PISTOL, 240000, quest_build_nesting_grounds, None, PerkId.HOT_TEMPERED),
    ("8-legged Terror", WeaponId.PISTOL, 240000, quest_build_8_legged_terror, WeaponId.ROCKET_LAUNCHER, None),
    ("Everred Pastures", WeaponId.PISTOL, 300000, quest_build_everred_pastures, None, PerkId.BONUS_ECONOMIST),
    ("Spider Spawns", WeaponId.PISTOL, 300000, quest_build_spider_spawns, WeaponId.PLASMA_RIFLE, None),
    ("Arachnoid Farm", WeaponId.PISTOL, 240000, quest_build_arachnoid_farm, None, PerkId.THICK_SKINNED),
    ("Two Fronts", WeaponId.PISTOL, 240000, quest_build_two_fronts, WeaponId.ION_RIFLE, None),
    ("Sweep Stakes", WeaponId.GAUSS_GUN, 35000, quest_build_sweep_stakes, None, PerkId.BARREL_GREASER),
    ("Evil Zombies At Large", WeaponId.PISTOL, 180000, quest_build_evil_zombies_at_large, WeaponId.MEAN_MINIGUN, None),
    ("Survival Of The Fastest", WeaponId.SUBMACHINE_GUN, 120000, quest_build_survival_of_the_fastest, None, PerkId.AMMUNITION_WITHIN),
    ("Land Of Lizards", WeaponId.PISTOL, 180000, quest_build_land_of_lizards, WeaponId.SAWED_OFF_SHOTGUN, None),
    ("Ghost Patrols", WeaponId.PISTOL, 180000, quest_build_ghost_patrols, None, PerkId.VEINS_OF_POISON),
    ("Spideroids", WeaponId.PISTOL, 360000, quest_build_spideroids, WeaponId.PLASMA_MINIGUN, None),
    ("The Blighting", WeaponId.PISTOL, 300000, quest_build_the_blighting, None, PerkId.TOXIC_AVENGER),
    ("Lizard Kings", WeaponId.PISTOL, 180000, quest_build_lizard_kings, WeaponId.MULTI_PLASMA, None),
    ("The Killing", WeaponId.PISTOL, 300000, quest_build_the_killing, None, PerkId.REGENERATION),
    ("Hidden Evil", WeaponId.PISTOL, 300000, quest_build_hidden_evil, WeaponId.SEEKER_ROCKETS, None),
    ("Surrounded By Reptiles", WeaponId.PISTOL, 300000, quest_build_surrounded_by_reptiles, None, PerkId.PYROMANIAC),
    ("The Lizquidation", WeaponId.PISTOL, 300000, quest_build_the_lizquidation, WeaponId.BLOW_TORCH, None),
    ("Spiders Inc.", WeaponId.PLASMA_MINIGUN, 300000, quest_build_spiders_inc, None, PerkId.NINJA),
    ("Lizard Raze", WeaponId.PISTOL, 300000, quest_build_lizard_raze, WeaponId.ROCKET_MINIGUN, None),
    ("Deja vu", WeaponId.GAUSS_GUN, 120000, quest_build_deja_vu, None, PerkId.HIGHLANDER),
    ("Zombie Masters", WeaponId.PISTOL, 300000, quest_build_zombie_masters, WeaponId.JACKHAMMER, None),
    ("Major Alien Breach", WeaponId.ROCKET_MINIGUN, 300000, quest_build_major_alien_breach, None, PerkId.JINXED),
    ("Zombie Time", WeaponId.PISTOL, 300000, quest_build_zombie_time, WeaponId.PULSE_GUN, None),
    ("Lizard Zombie Pact", WeaponId.PISTOL, 300000, quest_build_lizard_zombie_pact, None, PerkId.PERK_MASTER),
    ("The Collaboration", WeaponId.PISTOL, 360000, quest_build_the_collaboration, WeaponId.PLASMA_SHOTGUN, None),
    ("The Massacre", WeaponId.PISTOL, 300000, quest_build_the_massacre, None, PerkId.REFLEX_BOOSTED),
    ("The Unblitzkrieg", WeaponId.PISTOL, 600000, quest_build_the_unblitzkrieg, WeaponId.MINI_ROCKET_SWARMERS, None),
    ("Gauntlet", WeaponId.PISTOL, 300000, quest_build_gauntlet, None, PerkId.GREATER_REGENERATION),
    ("Syntax Terror", WeaponId.PISTOL, 300000, quest_build_syntax_terror, WeaponId.ION_MINIGUN, None),
    ("The Annihilation", WeaponId.PISTOL, 300000, quest_build_the_annihilation, None, PerkId.BREATHING_ROOM),
    ("The End of All", WeaponId.PISTOL, 480000, quest_build_the_end_of_all, WeaponId.ION_CANNON, None),
    ("The Beating", WeaponId.PISTOL, 480000, quest_build_the_beating, WeaponId.ION_SHOTGUN, None),
    ("The Spanking Of The Dead", WeaponId.PISTOL, 480000, quest_build_the_spanking_of_the_dead, None, PerkId.DEATH_CLOCK),
    ("The Fortress", WeaponId.PISTOL, 480000, quest_build_the_fortress, None, PerkId.MY_FAVOURITE_WEAPON),
    ("The Gang Wars", WeaponId.PISTOL, 480000, quest_build_the_gang_wars, WeaponId.GAUSS_SHOTGUN, None),
    ("Knee-deep in the Dead", WeaponId.PISTOL, 480000, quest_build_knee_deep_in_the_dead, None, PerkId.BANDAGE),
    ("Cross Fire", WeaponId.PISTOL, 480000, quest_build_cross_fire, None, PerkId.ANGRY_RELOADER),
    ("Army of Three", WeaponId.PISTOL, 480000, quest_build_army_of_three, None, None),
    ("Monster Blues", WeaponId.PISTOL, 480000, quest_build_monster_blues, None, PerkId.ION_GUN_MASTER),
    ("Nagolipoli", WeaponId.PISTOL, 480000, quest_build_nagolipoli, None, PerkId.STATIONARY_RELOADER),
    ("The Gathering", WeaponId.PISTOL, 480000, quest_build_the_gathering, WeaponId.PLASMA_CANNON, None),
)

QUESTS: tuple[QuestDefinition, ...] = tuple(
    QuestDefinition(
        level=QuestLevel.from_global_index(index),
        title=title,
        start_weapon_id=start_weapon_id,
        time_limit_ms=time_limit_ms,
        builder=builder,
        unlock_weapon_id=unlock_weapon_id,
        unlock_perk_id=unlock_perk_id,
        terrain_slots=terrain_slots_for_quest(QuestLevel.from_global_index(index)),
    )
    for index, (title, start_weapon_id, time_limit_ms, builder, unlock_weapon_id, unlock_perk_id) in enumerate(
        _QUEST_DATABASE,
    )
)


def quest_by_level(level: QuestLevel) -> QuestDefinition:
    return QUESTS[level.global_index]
