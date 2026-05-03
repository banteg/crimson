from __future__ import annotations

import msgspec

from crimson.replay.driver.replay_benchmark import (
    ReplayBenchmarkProgress,
    _TqdmReplayBenchmarkProgress,
)


class _FakeBar(msgspec.Struct):
    total: int
    unit: str
    desc: str
    leave: bool
    updates: list[int] = msgspec.field(default_factory=list)
    postfixes: list[str] = msgspec.field(default_factory=list)
    closed: bool = False

    def update(self, value: int) -> None:
        self.updates.append(int(value))

    def set_postfix_str(self, value: str, refresh: bool = True) -> None:
        _ = refresh
        self.postfixes.append(str(value))

    def close(self) -> None:
        self.closed = True


class _FakeTqdmFactory(msgspec.Struct):
    bars: list[_FakeBar] = msgspec.field(default_factory=list)

    def __call__(self, *, total: int, unit: str, desc: str, leave: bool) -> _FakeBar:
        bar = _FakeBar(
            total=int(total),
            unit=str(unit),
            desc=str(desc),
            leave=bool(leave),
        )
        self.bars.append(bar)
        return bar


def test_replay_benchmark_progress_runtime_drives_run_and_tick_bars() -> None:
    run_bar = _FakeBar(total=2, unit="run", desc="headless benchmark", leave=False)
    tqdm_factory = _FakeTqdmFactory()
    progress = _TqdmReplayBenchmarkProgress(
        run_bar=run_bar,
        tqdm_factory=tqdm_factory,
    )

    tick_progress = progress.begin_ticks(tick_desc="headless ticks sample 1/2", tick_total=10)
    assert tick_progress is not None

    tick_progress.progress(3)
    tick_progress.progress(2)
    tick_progress.progress(7)
    tick_progress.complete()
    tick_progress.close()
    progress.complete_step(phase="measure", sample_index=1, sample_count=2)
    progress.close()

    assert len(tqdm_factory.bars) == 1
    tick_bar = tqdm_factory.bars[0]
    assert tick_bar.total == 10
    assert tick_bar.unit == "tick"
    assert tick_bar.desc == "headless ticks sample 1/2"
    assert tick_bar.updates == [3, 4, 3]
    assert tick_bar.closed is True

    assert run_bar.updates == [1]
    assert run_bar.postfixes == ["phase=measure sample=1/2"]
    assert run_bar.closed is True


def test_replay_benchmark_noop_progress_does_not_create_tick_observer() -> None:
    progress = ReplayBenchmarkProgress()

    assert progress.begin_ticks(tick_desc="headless ticks warmup", tick_total=10) is None
    progress.complete_step(phase="warmup")
    progress.close()
