-- A run the verifier no longer accepts leaves the boards with the reason, and keeps its page (docs/rewrite/ranked-rules.md).
ALTER TABLE runs ADD COLUMN retired TEXT;

-- 0.14's verifier: a perk pick must come with the tick right after the menu opened (a tick without one is Cancel),
-- and experience past 2^24 counts exactly, as the original does. Every human run still verifies; these bot runs
-- picked from a menu left open, or passed 2^24 experience, and replay differently now.
UPDATE runs SET retired = 'A perk pick from a menu left open, which the rules no longer take' WHERE id IN (
  '04cb61aba7f7487629c996b9cad03eb8a8be7d2532b37b859348822a13deeaea',
  '4e4139a6f3cdbc13c7e63df06deed86de7b68f8fde2a36ea7e32a9398dd3031e',
  '54402dffd54627d5949acd726da7c4ac00022c2ae8ae4ba28e97f63bac373a48',
  '8867c4d878b9614c016be3672d34cee9ba34fa7497d6a62572af5760a0ba06d4',
  'cd6b3191afbe11a08287190e369f9b159b5db58dc5574df99d79e0755850e7cb',
  'f73a7b0ac23d5f4e325b57bcaad22b936c818d90c401295691dacd3396badce8'
);
UPDATE runs SET retired = 'Experience past 16,777,216, which now counts exactly as in the original' WHERE id IN (
  '5f05d70bcf860f5292c2de2706fafb2ca127c4571df5efc98b19957b79029c75',
  '6ec3a605be1c9709888bebf7ff14e2d2462c533813c350fe928bc8d20018f0a6',
  '7419132fe1671edb05098dd6b871b05e804ad9427b232f8377a047098f468507'
);
