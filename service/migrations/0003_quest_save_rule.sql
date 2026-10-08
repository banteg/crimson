-- Quest runs now play on the save that has just unlocked their quest (docs/rewrite/ranked-rules.md). The quest runs
-- ranked before, with every quest unlocked, leave the boards.
UPDATE runs SET hidden = 1 WHERE board IN ('quests', 'quests-hardcore');
