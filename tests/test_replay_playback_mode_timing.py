from __future__ import annotations

from pathlib import Path


def test_replay_playback_mode_tick_loop_decrements_accum(monkeypatch) -> None:
    # Regression test: a missing `dt_accum -= dt_frame` inside the playback loop
    # can cause the entire replay to run in a single frame (or an infinite loop).
    import crimson.modes.replay_playback_mode as replay_playback_mode
    from grim.config import CrimsonConfig
    from grim.console import ConsoleLog, ConsoleState
    from grim.view import ViewContext

    # Avoid touching real runtime dirs/logs/audio; this test only exercises timing logic.
    cfg = CrimsonConfig(path=Path("crimson.cfg"), data={})
    console = ConsoleState(base_dir=Path("."), log=ConsoleLog(base_dir=Path(".")))

    view = replay_playback_mode.ReplayPlaybackMode(
        ViewContext(assets_dir=Path("."), preserve_bugs=False),
        replay_path=Path("dummy.crdemo.gz"),
        config=cfg,
        console=console,
    )

    # Prevent key handlers from running.
    monkeypatch.setattr(replay_playback_mode.rl, "is_key_pressed", lambda _key: False)

    calls = 0

    def fake_tick_one() -> None:
        nonlocal calls
        calls += 1
        # If the loop does not decrement accumulated time, it would spin forever.
        if calls > 64:
            raise RuntimeError("playback tick loop did not consume accumulated dt")

    view._tick_one = fake_tick_one  # type: ignore[method-assign]
    view._finished = False
    view._paused = False
    view._tick_rate = 60
    view._dt_frame = 1.0 / 60.0
    view._dt_accum = 0.0

    view.update(0.05)

    # 0.05s at 60Hz should advance exactly 3 ticks (0.0166.. * 3 == 0.05).
    assert calls == 3

