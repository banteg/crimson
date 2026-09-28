from __future__ import annotations

from ..creatures.spawn import CreatureTypeId

CREATURE_ASSET: dict[CreatureTypeId, str] = {
    CreatureTypeId.ZOMBIE: "zombie",
    CreatureTypeId.LIZARD: "lizard",
    CreatureTypeId.ALIEN: "alien",
    CreatureTypeId.SPIDER_SP1: "spider_sp1",
    CreatureTypeId.SPIDER_SP2: "spider_sp2",
    CreatureTypeId.TROOPER: "trooper",
}
