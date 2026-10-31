-- The original build whose rules a run plays, its replay's run.cl_build (src/crimson/cl_build.py ClBuild): 10993 for
-- 1.9.93, 10908 for 1.9.8. Each build ranks on boards of its own (docs/rewrite/ranked-rules.md). Every run accepted
-- before 1.9.8 runs ranked played 1.9.93; new writes supply the build from the verified replay.
ALTER TABLE runs ADD COLUMN cl_build INTEGER NOT NULL DEFAULT 10993 CHECK (cl_build IN (10908, 10993));
