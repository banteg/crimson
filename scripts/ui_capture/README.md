# UI capture

Drives the real game with scripted input at a fixed 60 Hz and saves screenshots of named frames, so a UI
change can be checked by pixel-diffing captures taken before and after it. Two runs of the same build are
pixel-identical, so every difference in a diff comes from the change.

`capture.py` replaces the `pyray` input and time functions (all game code reads them through
`grim.raylib_api`) with a scripted timeline, runs `run_game` in a hidden window at native size with a fixed seed,
a throwaway base dir and volume 0, and writes a PNG for each `("shot", name)` step. Scenarios in `scenarios/`
are lists of steps (`wait`, `key`, `hold`, `pad`, `move`, `click`, `rclick`, `fire`, `text`, `hook`, `shot`); `hook`
runs a function on the live `GameState`, which is how scenarios reach level-ups, deaths and quest completion
without playing. Menu clicks need about 150 frames after boot; panel layouts depend on the window width, so the
`small_*` scenarios carry their own coordinates.

Before/after check (run outside the sandbox; it opens windows):

```bash
git worktree add --detach /tmp/claude/ui-base HEAD
scripts/ui_capture/run_all.sh /tmp/claude/ui-base /tmp/claude/cap_before
scripts/ui_capture/run_all.sh . /tmp/claude/cap_after
for d in /tmp/claude/cap_before/*/; do
  uv run --with pillow --with numpy python scripts/ui_capture/diff.py "$d" /tmp/claude/cap_after/$(basename "$d") /tmp/claude/cap_diff/$(basename "$d")
done
```

`diff.py` prints the changed shots with their bounding boxes and writes before | after | highlight strips;
`sheet.py` tiles captures into a contact sheet and `crops.py` builds zoomed before/after crops. A full run is
about 900 shots and 1.2 GB; delete the capture directories afterwards.
