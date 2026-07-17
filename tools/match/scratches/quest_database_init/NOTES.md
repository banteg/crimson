# quest_database_init

Native evidence at `0x00439230` shows a fully unrolled database initializer for
all 50 quest stages. Each entry calls `quest_meta_init_entry`, assigns its start
weapon, time limit, and builder, then advances the tier/index cursor through the
already matched `quest_database_advance_slot` helper.

The `Hidden Evil` entry additionally saves `quest_meta_cursor` in
`quest_monster_vision_meta`; `perks_generate_choices` later uses that pointer to
gate Monster Vision on quest progress.

The unlock tail is also unrolled. The native store order separates weapon and
perk unlocks for tiers 1-4, while tier 5 appears as paired stores, consistent
with that final tier having been appended to the database later.

The natural macro-expanded reconstruction is exact with MSVC 6: 1384/1384
instructions and 503/503 explained references.
