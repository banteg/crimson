from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.net.deterministic_status import build_lan_deterministic_status, status_snapshot_from_status
from crimson.persistence.save_status import (
    QUEST_PLAY_COUNT,
    UNKNOWN_TAIL_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
)
from crimson.weapon_runtime.availability import weapon_pick_random_available
from crimson.weapons import WeaponId
from grim.rand import Crand


class _SeqRng(Crand):
    def __init__(self, seq: list[int]) -> None:
        super().__init__(0)
        self._seq = list(seq)
        self.calls = 0

    def rand(self, *, caller: int | None = None) -> int:
        _ = caller
        self.calls += 1
        if not self._seq:
            raise AssertionError("rng exhausted")
        return int(self._seq.pop(0))


def _make_status(*, pistol_used: bool) -> GameStatus:
    usage_counts = [0] * int(WEAPON_USAGE_COUNT)
    if pistol_used:
        usage_counts[1] = 1
    data = {
        "quest_unlock_index": 50,
        "quest_unlock_index_full": 50,
        "weapon_usage_counts": usage_counts,
        "quest_play_counts": [0] * int(QUEST_PLAY_COUNT),
        "mode_play_survival": 0,
        "mode_play_rush": 0,
        "mode_play_typo": 0,
        "mode_play_other": 0,
        "game_sequence_id": 0,
        "unknown_tail": b"\x00" * int(UNKNOWN_TAIL_SIZE),
    }
    return GameStatus(path=Path("game.cfg"), data=data, dirty=False)


def _make_state(*, status: GameStatus, rng: _SeqRng) -> GameplayState:
    state = GameplayState(rng=rng, game_mode=GameMode.SURVIVAL, demo_mode_active=False)
    state.status = status
    return state


def test_lan_deterministic_status_uses_host_save_snapshot() -> None:
    # Craft a sequence where the first pick is pistol (weapon_id=1). If pistol
    # usage count is non-zero, native logic has a 50% chance to reroll and will
    # consume extra RNG draws.
    seq = [0, 0, 1]  # base_rand=0 -> pistol; bit_rand=0 -> reroll; base_rand=1 -> weapon_id=2

    status_used = _make_status(pistol_used=True)
    status_fresh = _make_status(pistol_used=False)

    rng_a = _SeqRng(list(seq))
    rng_b = _SeqRng(list(seq))
    state_a = _make_state(status=status_used, rng=rng_a)
    state_b = _make_state(status=status_fresh, rng=rng_b)

    picked_a = weapon_pick_random_available(state_a)
    picked_b = weapon_pick_random_available(state_b)

    assert picked_a == WeaponId.ASSAULT_RIFLE
    assert picked_b == WeaponId.PISTOL
    assert rng_a.calls == 3
    assert rng_b.calls == 1

    host_snapshot = status_snapshot_from_status(status_used)
    lan_status_a = build_lan_deterministic_status(snapshot=host_snapshot)
    lan_status_b = build_lan_deterministic_status(snapshot=host_snapshot)

    # LAN sim status uses the host's save snapshot for all peers, so both runs
    # should take the same path and consume the same RNG regardless of local saves.
    rng_c = _SeqRng(list(seq))
    rng_d = _SeqRng(list(seq))
    state_c = _make_state(status=lan_status_a, rng=rng_c)
    state_d = _make_state(status=lan_status_b, rng=rng_d)

    assert weapon_pick_random_available(state_c) == WeaponId.ASSAULT_RIFLE
    assert weapon_pick_random_available(state_d) == WeaponId.ASSAULT_RIFLE
    assert rng_c.calls == 3
    assert rng_d.calls == 3
