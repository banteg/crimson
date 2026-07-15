# `perks_init_database`

Native target: `crimsonland.exe` at `0x0042fd90` (3211 bytes).

Live Binary Ninja evidence recovers the complete 58-entry perk ID and display
metadata initializer, including the violence-disabled Quick Learner variant,
mode flags, prerequisite links, and final availability rebuild.

The recovered strings preserve native spelling and punctuation, including the
trailing space in the My Favourite Weapon description. Non-default flags are
set for Grim Deal, Alternate Weapon, Instant Winner, Fatal Lottery, Random
Weapon, Final Revenge, Highlander, and Breathing Room. Prerequisites link Toxic
Avenger, Ninja, Perk Master, and Greater Regeneration to their required perks.

Verified with MSVC 6.5 `/O2 /GB`: 588/588 instructions, 3211 bytes, and all
443 masked references audited.
