-- The program that recorded each run (replay format v30), so boards can show, filter or withdraw runs by client.
ALTER TABLE runs ADD COLUMN client TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN client_version TEXT NOT NULL DEFAULT '';
ALTER TABLE runs ADD COLUMN platform TEXT NOT NULL DEFAULT '';
