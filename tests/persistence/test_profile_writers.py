from __future__ import annotations

import multiprocessing
import os
import stat
from pathlib import Path

import pytest

from crimson.leaderboard.identity import IDENTITY_FILE, Identity, IdentityError
from crimson.replay.library import reserve_replay_number


def _first_run(profile: Path, results: Path, barrier) -> None:
    barrier.wait(timeout=30)
    key = Identity.load_or_create(profile).public_key.hex()
    numbers = [reserve_replay_number(profile / "replays") for _ in range(10)]
    results.write_text(" ".join([key, *map(str, numbers)]))


def test_simultaneous_first_launches_share_a_key_and_reserve_distinct_runs(tmp_path: Path) -> None:
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(4)
    results = [tmp_path / f"writer-{index}" for index in range(4)]
    profile = tmp_path / "profile"
    children = [context.Process(target=_first_run, args=(profile, path, barrier)) for path in results]
    for child in children:
        child.start()
    for child in children:
        child.join(timeout=45)
        assert child.exitcode == 0
    allocations = [path.read_text().split() for path in results]
    assert {row[0] for row in allocations} == {Identity.load(profile / IDENTITY_FILE).public_key.hex()}
    assert sorted(int(number) for row in allocations for number in row[1:]) == list(range(1, 41))


@pytest.mark.parametrize("seed", [b"", bytes(31), bytes(33)])
def test_a_malformed_private_key_survives_failed_initialization(tmp_path: Path, seed: bytes) -> None:
    path = tmp_path / IDENTITY_FILE
    path.write_bytes(seed)
    with pytest.raises(IdentityError, match="expected 32"):
        Identity.load_or_create(tmp_path)
    assert path.read_bytes() == seed


@pytest.mark.skipif(os.name == "nt", reason="POSIX access mode")
def test_loading_an_old_key_repairs_file_permissions(tmp_path: Path) -> None:
    path = tmp_path / IDENTITY_FILE
    path.write_bytes(bytes(32))
    path.chmod(0o644)
    before = Identity.load(path)
    assert Identity.load_or_create(tmp_path).public_key == before.public_key
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("counter", [b"", b"1x", b"-1", b"2147483647"])
def test_an_invalid_or_exhausted_replay_counter_preserves_the_high_water_mark(tmp_path: Path, counter: bytes) -> None:
    path = tmp_path / ".last-number"
    path.write_bytes(counter)
    with pytest.raises(ValueError, match="Invalid replay counter|Replay numbers are exhausted"):
        reserve_replay_number(tmp_path)
    assert path.read_bytes() == counter
