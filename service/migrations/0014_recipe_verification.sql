-- The proof clears the portable definition. Recipe text becomes public only after the project's
-- Python compiler reproduces that definition with the submitted construction seed.
ALTER TABLE custom_quests ADD COLUMN source_state TEXT NOT NULL DEFAULT 'pending'
  CHECK (source_state IN ('pending', 'verified', 'rejected'));
ALTER TABLE custom_quests ADD COLUMN source_revision TEXT;
ALTER TABLE custom_quests ADD COLUMN source_compiler TEXT;
UPDATE custom_quests SET source_revision = lower(hex(randomblob(16))) WHERE source IS NOT NULL;
CREATE INDEX pending_quest_recipes ON custom_quests(created_at, id) WHERE source IS NOT NULL AND source_state = 'pending';

-- Older Workers can continue to insert or attach a recipe while the deployment rolls over.
CREATE TRIGGER new_quest_recipe AFTER INSERT ON custom_quests WHEN NEW.source IS NOT NULL BEGIN
  UPDATE custom_quests SET source_revision = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
CREATE TRIGGER changed_quest_recipe AFTER UPDATE OF source, seed ON custom_quests
WHEN NEW.source IS NOT OLD.source OR NEW.seed != OLD.seed BEGIN
  UPDATE custom_quests SET source_revision = lower(hex(randomblob(16))), source_state = 'pending', source_compiler = NULL WHERE id = NEW.id;
END;
