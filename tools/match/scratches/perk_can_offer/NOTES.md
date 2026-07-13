# perk_can_offer

The recovered predicate matches the shipped function exactly: 55/55
instructions and all 17 masked references. It preserves the Hardcore quest
2-10 poison-perk exclusion, the exact two-player and quest-mode metadata flag
gates, prerequisite handling through player 0's shared perk counts, and the
shareware-only exception tail.

The final full-version branch still returns false when an unmet prerequisite
reaches it, even for its four named exceptions. That redundant control flow is
natural VC6 output from the clean source and is retained rather than simplified
away in the matching reconstruction.

Comparing the exact predicate against the ports exposed a Zig-only parity bug:
Python already blocked Poison Bullets, Veins of Poison, and Plaguebearer on
Hardcore quest 2-10, while Zig skipped that gate. The runtime now applies the
same exact stage and mode boundary, with a regression test covering all three
perks and the adjacent minor-stage case.
