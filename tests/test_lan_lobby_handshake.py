from __future__ import annotations

from crimson.net.lobby import HostLobby
from crimson.net.protocol import Hello, Ready, TICK_RATE, INPUT_DELAY_TICKS


def _hello(*, build_id: str = "b1", mode_id: int = 1, player_count: int = 2) -> Hello:
    return Hello(
        protocol_version=1,
        build_id=build_id,
        mode_id=mode_id,
        player_count=player_count,
        tick_rate=TICK_RATE,
        input_delay_ticks=INPUT_DELAY_TICKS,
        quest_level="",
        preserve_bugs=False,
        host=False,
    )


def test_host_lobby_assigns_slot_and_starts_when_ready() -> None:
    lobby = HostLobby(
        mode_id=1,
        player_count=2,
        build_id="b1",
        tick_rate=TICK_RATE,
        input_delay_ticks=INPUT_DELAY_TICKS,
    )

    addr = ("127.0.0.1", 32001)
    welcome = lobby.process_hello(addr, _hello())
    assert welcome.accepted is True
    assert welcome.slot_index == 1
    assert welcome.host_slot_index == 0

    # Same peer keeps same slot.
    welcome2 = lobby.process_hello(addr, _hello())
    assert welcome2.accepted is True
    assert welcome2.slot_index == 1

    state = lobby.lobby_state()
    assert state.slots[0].is_host is True
    assert state.slots[0].connected is True
    assert state.slots[1].connected is True

    lobby.process_ready(addr, Ready(slot_index=1, ready=True))
    assert lobby.all_ready() is True

    started = lobby.start_match(seed=1234)
    assert started.seed == 1234
    assert lobby.started is True


def test_host_lobby_rejects_build_mismatch() -> None:
    lobby = HostLobby(
        mode_id=1,
        player_count=2,
        build_id="b1",
        tick_rate=TICK_RATE,
        input_delay_ticks=INPUT_DELAY_TICKS,
    )

    welcome = lobby.process_hello(("127.0.0.1", 32001), _hello(build_id="other"))
    assert welcome.accepted is False
    assert welcome.reason == "build_mismatch"


def test_host_lobby_rejects_when_full() -> None:
    lobby = HostLobby(
        mode_id=1,
        player_count=2,
        build_id="b1",
        tick_rate=TICK_RATE,
        input_delay_ticks=INPUT_DELAY_TICKS,
    )

    first = lobby.process_hello(("127.0.0.1", 32001), _hello())
    second = lobby.process_hello(("127.0.0.1", 32002), _hello())

    assert first.accepted is True
    assert second.accepted is False
    assert second.reason == "lobby_full"
