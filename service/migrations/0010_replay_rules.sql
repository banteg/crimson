-- Before the first rules-2 deployment every accepted run was rules 1.
-- New writes always supply rules explicitly. Preserve all scores, IDs and timestamps.
ALTER TABLE runs ADD COLUMN rules INTEGER NOT NULL DEFAULT 1 CHECK (rules IN (1, 2));
