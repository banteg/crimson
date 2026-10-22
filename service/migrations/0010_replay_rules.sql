-- Before the first rules-2 deployment every accepted run was rules 1.
-- New writes always supply rules explicitly. Preserve all scores, IDs and timestamps.
-- Supported versions are enforced by the verifier; future versions need no table rebuild.
ALTER TABLE runs ADD COLUMN rules INTEGER NOT NULL DEFAULT 1 CHECK (rules >= 1);
