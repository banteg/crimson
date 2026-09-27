from __future__ import annotations

from pathlib import Path

import msgspec
import pytest
import zstandard as zstd

from crimson.dbg.canonical_channels import GameFrameRngAdvanceOperation, PostludeOperation, PreludeOperation
from crimson.dbg.capture_replay import (
    CAPTURE_REPLAY_FORMAT_VERSION,
    CapturePlaybackDriver,
    CaptureReplay,
    CaptureReplayError,
    CaptureTick,
    dump_capture_replay,
    dump_capture_replay_file,
    load_capture_replay,
    load_capture_replay_file,
)
from crimson.dbg.frida_finalize import FRIDA_CAPTURE_FORMAT_VERSION
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.persistence.save_status import GameStatusData
from crimson.replay.driver.playback_driver import PlaybackWalkObserver, RngTraceDraw
from crimson.replay.driver.setup import ReplayRunnerError
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.commands import PerkMenuOpenCommand
from crimson.sim.hooks import TickResult
from crimson.sim.run_spec import RunSpec, RunStatus
from crimson.sim.world_reset import CreatureSlotResidue

CAPTURE_DT = float(f32(0.016))


def build_capture(
    *,
    ticks: int = 3,
    prelude: dict[int, list[PreludeOperation]] | None = None,
    postlude: dict[int, list[PostludeOperation]] | None = None,
) -> CaptureReplay:
    status = GameStatusData(quest_unlock_index=3, mode_play_survival=7, play_time_ms=1234)
    return CaptureReplay(
        format_version=CAPTURE_REPLAY_FORMAT_VERSION,
        capture_format_version=FRIDA_CAPTURE_FORMAT_VERSION,
        tick_rate=60,
        run=RunSpec(
            game_mode_id=GameMode.SURVIVAL,
            seed=0xBEEF,
            preserve_bugs=True,
            status=RunStatus.from_status_data(status),
        ),
        status=status,
        creature_pool=(CreatureSlotResidue(index=0, phase_seed=5), CreatureSlotResidue(index=1)),
        ticks=[
            CaptureTick(
                dt=CAPTURE_DT,
                inputs=[(0.0, 0.0, 512.0, 512.0, 0)],
                # Native captures start every prelude with the previous frame's end.
                prelude=(prelude or {}).get(index, [GameFrameRngAdvanceOperation(frames=1)]),
                postlude=(postlude or {}).get(index, []),
            )
            for index in range(ticks)
        ],
    )


class _RngRows(PlaybackWalkObserver):
    rows: dict[int, list[RngTraceDraw]]

    def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
        self.rows[int(tick_result.tick_index)] = list(draws)


def _tick_rng_rows(capture: CaptureReplay, *, perks_pending: int = 0) -> dict[int, list[RngTraceDraw]]:
    observer = _RngRows(rows={})
    driver = CapturePlaybackDriver(capture, trace_rng=True)
    driver.world.state.perk_selection.pending_count = perks_pending
    driver.run(observer=observer)
    return observer.rows


def test_capture_replay_roundtrips_through_file(tmp_path: Path) -> None:
    capture = build_capture(
        prelude={1: [GameFrameRngAdvanceOperation(frames=2)]},
        postlude={2: [PerkMenuOpenCommand(player_index=0)]},
    )
    path = tmp_path / "run.ccr"
    dump_capture_replay_file(path, capture)

    assert load_capture_replay_file(path) == capture


def test_capture_replay_rejects_noncanonical_payload() -> None:
    raw = msgspec.msgpack.decode(zstd.ZstdDecompressor().decompress(dump_capture_replay(build_capture())))
    raw["ticks"][0]["dt"] = 0
    payload = zstd.ZstdCompressor().compress(msgspec.msgpack.encode(raw))

    with pytest.raises(CaptureReplayError):
        load_capture_replay(payload)


@pytest.mark.parametrize(
    ("change", "error"),
    [
        (lambda capture: msgspec.structs.replace(capture, format_version=0), "format version"),
        (
            lambda capture: msgspec.structs.replace(capture, status=GameStatusData(quest_unlock_index=4)),
            "run.status must mirror status",
        ),
        (
            lambda capture: msgspec.structs.replace(capture, run=msgspec.structs.replace(capture.run, game_mode_id=GameMode.TYPO)),
            "not a capture mode",
        ),
        (lambda capture: msgspec.structs.replace(capture, creature_pool=(CreatureSlotResidue(index=1),)), "slot"),
        (
            lambda capture: msgspec.structs.replace(
                capture,
                ticks=[msgspec.structs.replace(capture.ticks[0], prelude=[GameFrameRngAdvanceOperation(frames=0)])],
            ),
            "frames must be positive",
        ),
        (
            lambda capture: msgspec.structs.replace(
                capture,
                ticks=[msgspec.structs.replace(capture.ticks[0], postlude=[PerkMenuOpenCommand(player_index=1)])],
            ),
            "player_index is out of range",
        ),
        (lambda capture: msgspec.structs.replace(capture, ticks=[]), "at least one tick"),
    ],
)
def test_capture_replay_rejects_invalid_contents(change, error: str) -> None:
    with pytest.raises(CaptureReplayError, match=error):
        dump_capture_replay(change(build_capture()))


def test_capture_playback_draws_extra_frame_rng_before_the_tick_trace() -> None:
    plain = _tick_rng_rows(build_capture(ticks=1))
    advanced = _tick_rng_rows(build_capture(ticks=1, prelude={0: [GameFrameRngAdvanceOperation(frames=3)]}))

    # The session owns the prelude's first frame; the other two draw before the tick.
    state = plain[0][0][0]
    for _ in range(2):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
    assert advanced[0][0][0] == state


def test_capture_playback_rejects_prelude_without_the_previous_frame_end() -> None:
    capture = build_capture(ticks=1, prelude={0: []})
    with pytest.raises(ReplayRunnerError, match="previous frame's end"):
        _tick_rng_rows(capture)


def test_capture_playback_opens_postlude_menu_inside_the_tick_trace() -> None:
    plain = _tick_rng_rows(build_capture(ticks=1), perks_pending=1)
    opened = _tick_rng_rows(
        build_capture(ticks=1, postlude={0: [PerkMenuOpenCommand(player_index=0)]}),
        perks_pending=1,
    )

    # The choices draw mid-tick, before the frame end that closes it.
    assert len(opened[0]) > len(plain[0])
    assert opened[0][: len(plain[0]) - 1] == plain[0][:-1]
    assert opened[0][-1][3] == plain[0][-1][3] == RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED
