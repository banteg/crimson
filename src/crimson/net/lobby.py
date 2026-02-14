from __future__ import annotations

from dataclasses import dataclass, field
import uuid

from .protocol import (
    Hello,
    LobbySlot,
    LobbyState,
    MatchStart,
    PROTOCOL_VERSION,
    Ready,
    Welcome,
)
from .transport import PeerAddr


@dataclass(slots=True)
class HostPeer:
    addr: PeerAddr
    slot_index: int
    ready: bool = False
    peer_name: str = ""


@dataclass(slots=True)
class HostLobby:
    mode_id: int
    player_count: int
    build_id: str
    tick_rate: int
    input_delay_ticks: int
    quest_level: str = ""
    preserve_bugs: bool = False
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started: bool = False
    host_ready: bool = True
    peers_by_addr: dict[PeerAddr, HostPeer] = field(default_factory=dict)

    def _next_free_slot(self) -> int | None:
        used = {0}
        used.update(int(peer.slot_index) for peer in self.peers_by_addr.values())
        for slot in range(1, int(self.player_count)):
            if slot not in used:
                return int(slot)
        return None

    def process_hello(self, addr: PeerAddr, hello: Hello) -> Welcome:
        if self.started:
            return Welcome(accepted=False, reason="match_already_started")
        if int(hello.protocol_version) != int(PROTOCOL_VERSION):
            return Welcome(accepted=False, reason="protocol_mismatch")
        if str(hello.build_id) != str(self.build_id):
            return Welcome(accepted=False, reason="build_mismatch")

        peer = self.peers_by_addr.get(addr)
        if peer is None:
            slot = self._next_free_slot()
            if slot is None:
                return Welcome(accepted=False, reason="lobby_full")
            peer = HostPeer(addr=addr, slot_index=int(slot), ready=False)
            self.peers_by_addr[addr] = peer

        return Welcome(
            accepted=True,
            reason="",
            session_id=str(self.session_id),
            protocol_version=int(PROTOCOL_VERSION),
            build_id=str(self.build_id),
            mode_id=int(self.mode_id),
            player_count=int(self.player_count),
            slot_index=int(peer.slot_index),
            host_slot_index=0,
            tick_rate=int(self.tick_rate),
            input_delay_ticks=int(self.input_delay_ticks),
            seed=0,
            quest_level=str(self.quest_level),
            preserve_bugs=bool(self.preserve_bugs),
            started=bool(self.started),
        )

    def process_ready(self, addr: PeerAddr, ready: Ready) -> None:
        peer = self.peers_by_addr.get(addr)
        if peer is None:
            return
        if int(ready.slot_index) != int(peer.slot_index):
            return
        peer.ready = bool(ready.ready)

    def all_connected(self) -> bool:
        if int(self.player_count) <= 1:
            return True
        return len(self.peers_by_addr) >= (int(self.player_count) - 1)

    def all_ready(self) -> bool:
        if not self.host_ready:
            return False
        if not self.all_connected():
            return False
        for peer in self.peers_by_addr.values():
            if not bool(peer.ready):
                return False
        return True

    def slot_for_addr(self, addr: PeerAddr) -> int | None:
        peer = self.peers_by_addr.get(addr)
        if peer is None:
            return None
        return int(peer.slot_index)

    def lobby_state(self) -> LobbyState:
        slots: list[LobbySlot] = []
        for slot in range(int(self.player_count)):
            if slot == 0:
                slots.append(
                    LobbySlot(
                        slot_index=0,
                        connected=True,
                        ready=bool(self.host_ready),
                        is_host=True,
                        peer_name="host",
                    )
                )
                continue
            peer = next((p for p in self.peers_by_addr.values() if int(p.slot_index) == slot), None)
            if peer is None:
                slots.append(
                    LobbySlot(
                        slot_index=int(slot),
                        connected=False,
                        ready=False,
                        is_host=False,
                        peer_name="",
                    )
                )
                continue
            slots.append(
                LobbySlot(
                    slot_index=int(slot),
                    connected=True,
                    ready=bool(peer.ready),
                    is_host=False,
                    peer_name=str(peer.peer_name),
                )
            )
        return LobbyState(
            session_id=str(self.session_id),
            mode_id=int(self.mode_id),
            player_count=int(self.player_count),
            slots=slots,
            all_ready=bool(self.all_ready()),
            started=bool(self.started),
            quest_level=str(self.quest_level),
        )

    def start_match(self, *, seed: int, start_tick: int = 0) -> MatchStart:
        self.started = True
        return MatchStart(
            session_id=str(self.session_id),
            mode_id=int(self.mode_id),
            player_count=int(self.player_count),
            seed=int(seed),
            start_tick=int(start_tick),
            quest_level=str(self.quest_level),
            preserve_bugs=bool(self.preserve_bugs),
        )


@dataclass(slots=True)
class ClientLobby:
    build_id: str
    hello: Hello
    welcome: Welcome | None = None
    lobby_state_latest: LobbyState | None = None
    match_start: MatchStart | None = None

    @property
    def slot_index(self) -> int:
        welcome = self.welcome
        if welcome is None:
            return -1
        return int(welcome.slot_index)

    @property
    def joined(self) -> bool:
        welcome = self.welcome
        return welcome is not None and bool(welcome.accepted)

    @property
    def started(self) -> bool:
        return self.match_start is not None

    def ingest_welcome(self, welcome: Welcome) -> None:
        self.welcome = welcome

    def ingest_lobby_state(self, state: LobbyState) -> None:
        self.lobby_state_latest = state

    def ingest_match_start(self, event: MatchStart) -> None:
        self.match_start = event
