from __future__ import annotations

from dataclasses import dataclass, field
import time

from .debug_log import lan_debug_log
from .lobby import ClientLobby, HostLobby
from .protocol import (
    INPUT_DELAY_TICKS,
    LINK_TIMEOUT_MS,
    PROTOCOL_VERSION,
    TICK_RATE,
    Disconnect,
    Hello,
    LobbyState,
    MatchStart,
    NetMessage,
    PauseState,
    Ready,
    Welcome,
    current_build_id,
)
from .reliable import ReliableLink
from .transport import PeerAddr, UdpTransport


def _now_ms() -> int:
    return int(time.monotonic() * 1000.0)


@dataclass(slots=True)
class LanRuntimeConfig:
    role: str
    mode_id: int
    player_count: int
    bind_host: str
    host_ip: str
    port: int
    quest_level: str = ""
    preserve_bugs: bool = False
    tick_rate: int = TICK_RATE
    input_delay_ticks: int = INPUT_DELAY_TICKS


@dataclass(slots=True)
class _HostPeerLink:
    addr: PeerAddr
    link: ReliableLink = field(default_factory=ReliableLink)
    last_seen_ms: int = 0


@dataclass(slots=True)
class LanRuntime:
    """Drive LAN lobby handshake and keep socket state alive across views."""

    cfg: LanRuntimeConfig
    build_id: str = field(default_factory=current_build_id)
    transport: UdpTransport = field(init=False)
    started: bool = field(init=False, default=False)
    error: str = field(init=False, default="")

    host_lobby: HostLobby | None = field(init=False, default=None)
    host_peers: dict[PeerAddr, _HostPeerLink] = field(init=False, default_factory=dict)
    host_seed: int = field(init=False, default=0)
    host_match_start: MatchStart | None = field(init=False, default=None)
    host_last_broadcast_ms: int = field(init=False, default=0)

    client_lobby: ClientLobby | None = field(init=False, default=None)
    client_link: ReliableLink | None = field(init=False, default=None)
    client_host_addr: PeerAddr | None = field(init=False, default=None)
    client_last_hello_ms: int = field(init=False, default=0)
    client_last_seen_ms: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        bind_port = int(self.cfg.port) if str(self.cfg.role) == "host" else 0
        self.transport = UdpTransport(bind_host=str(self.cfg.bind_host), bind_port=int(bind_port))

    def open(self) -> None:
        if self.host_lobby is not None or self.client_lobby is not None:
            return
        self.transport.open()
        lan_debug_log(
            "net_open",
            role=str(self.cfg.role),
            bind_host=str(self.cfg.bind_host),
            bind_port=int(self.transport.bound_port),
        )
        if str(self.cfg.role) == "host":
            self.host_lobby = HostLobby(
                mode_id=int(self.cfg.mode_id),
                player_count=int(self.cfg.player_count),
                build_id=str(self.build_id),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
                quest_level=str(self.cfg.quest_level),
                preserve_bugs=bool(self.cfg.preserve_bugs),
            )
            self.host_last_broadcast_ms = _now_ms()
        else:
            self.client_host_addr = (str(self.cfg.host_ip), int(self.cfg.port))
            self.client_link = ReliableLink()
            hello = Hello(
                protocol_version=int(PROTOCOL_VERSION),
                build_id=str(self.build_id),
                mode_id=int(self.cfg.mode_id),
                player_count=int(self.cfg.player_count),
                tick_rate=int(self.cfg.tick_rate),
                input_delay_ticks=int(self.cfg.input_delay_ticks),
                quest_level=str(self.cfg.quest_level),
                preserve_bugs=bool(self.cfg.preserve_bugs),
                host=False,
            )
            self.client_lobby = ClientLobby(build_id=str(self.build_id), hello=hello)
            self.client_last_hello_ms = 0
            self.client_last_seen_ms = _now_ms()

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.host_lobby = None
            self.host_peers.clear()
            self.host_seed = 0
            self.host_match_start = None
            self.host_last_broadcast_ms = 0
            self.client_lobby = None
            self.client_link = None
            self.client_host_addr = None
            self.client_last_hello_ms = 0
            self.client_last_seen_ms = 0
            self.started = False
            self.error = ""
            lan_debug_log("net_close", role=str(self.cfg.role))

    @property
    def bound_port(self) -> int:
        return int(self.transport.bound_port)

    def lobby_state(self) -> LobbyState | None:
        if str(self.cfg.role) == "host":
            lobby = self.host_lobby
            if lobby is None:
                return None
            return lobby.lobby_state()
        lobby = self.client_lobby
        if lobby is None:
            return None
        return lobby.lobby_state_latest

    def match_start(self) -> MatchStart | None:
        if str(self.cfg.role) == "host":
            return self.host_match_start
        lobby = self.client_lobby
        if lobby is None:
            return None
        return lobby.match_start

    @property
    def local_slot_index(self) -> int:
        if str(self.cfg.role) == "host":
            return 0
        lobby = self.client_lobby
        if lobby is None:
            return -1
        return int(lobby.slot_index)

    def update(self, *, now_ms: int | None = None) -> None:
        if now_ms is None:
            now_ms = _now_ms()
        if str(self.cfg.role) == "host":
            self._update_host(now_ms=int(now_ms))
        else:
            self._update_client(now_ms=int(now_ms))

    def _update_host(self, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return

        for addr, packet in self.transport.recv_packets():
            peer_link = self.host_peers.get(addr)
            if peer_link is None:
                peer_link = _HostPeerLink(addr=addr, last_seen_ms=int(now_ms))
                self.host_peers[addr] = peer_link
            peer_link.last_seen_ms = int(now_ms)

            messages, dup = peer_link.link.ingest_packet(packet)
            if dup:
                lan_debug_log("net_recv_dup", role="host", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_host_message(addr, message, now_ms=int(now_ms))

        # Drop timed-out peers.
        for addr, peer in list(self.host_peers.items()):
            if (int(now_ms) - int(peer.last_seen_ms)) < int(LINK_TIMEOUT_MS):
                continue
            self.host_peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            lan_debug_log("net_timeout", role="host", addr=f"{addr[0]}:{addr[1]}")

        # Broadcast lobby state periodically.
        if (not lobby.started) and (int(now_ms) - int(self.host_last_broadcast_ms)) >= 250:
            self.host_last_broadcast_ms = int(now_ms)
            self._host_broadcast_lobby_state(now_ms=int(now_ms))

        # Start automatically once ready.
        if (not lobby.started) and lobby.all_ready():
            self.host_seed = int((_now_ms() * 1103515245 + 12345) & 0xFFFFFFFF)
            event = lobby.start_match(seed=int(self.host_seed))
            self.started = True
            self.host_match_start = event
            lan_debug_log("net_match_start", role="host", seed=int(event.seed), player_count=int(event.player_count))
            self._host_broadcast(event, reliable=True, now_ms=int(now_ms))

        # Resend reliable packets.
        for addr, peer in self.host_peers.items():
            for resend in peer.link.poll_resends(now_ms=int(now_ms)):
                try:
                    self.transport.send_packet(addr, resend)
                except OSError:
                    continue

    def _handle_host_message(self, addr: PeerAddr, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_recv", role="host", kind=str(kind), addr=f"{addr[0]}:{addr[1]}")
        if isinstance(message, Hello):
            welcome = lobby.process_hello(addr, message)
            self._host_send(addr, welcome, reliable=True, now_ms=int(now_ms))
            # Publish lobby state update after accepting/rejecting.
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, Ready):
            lobby.process_ready(addr, message)
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
            return
        if isinstance(message, Disconnect):
            self.host_peers.pop(addr, None)
            lobby.peers_by_addr.pop(addr, None)
            self._host_broadcast_lobby_state(now_ms=int(now_ms))
            return

    def _host_send(self, addr: PeerAddr, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        peer = self.host_peers.get(addr)
        if peer is None:
            peer = _HostPeerLink(addr=addr)
            self.host_peers[addr] = peer
        packet = peer.link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(addr, packet)
        except OSError:
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_send", role="host", kind=str(kind), addr=f"{addr[0]}:{addr[1]}", reliable=bool(reliable))

    def _host_broadcast(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        for addr in list(self.host_peers):
            self._host_send(addr, message, reliable=bool(reliable), now_ms=int(now_ms))

    def _host_broadcast_lobby_state(self, *, now_ms: int) -> None:
        lobby = self.host_lobby
        if lobby is None:
            return
        state = lobby.lobby_state()
        self._host_broadcast(state, reliable=True, now_ms=int(now_ms))

    def _update_client(self, *, now_ms: int) -> None:
        lobby = self.client_lobby
        link = self.client_link
        host = self.client_host_addr
        if lobby is None or link is None or host is None:
            return

        # Send hello until welcome arrives.
        if lobby.welcome is None and (int(now_ms) - int(self.client_last_hello_ms)) >= 200:
            self.client_last_hello_ms = int(now_ms)
            self._client_send(lobby.hello, reliable=True, now_ms=int(now_ms))

        for addr, packet in self.transport.recv_packets():
            if addr != host:
                continue
            self.client_last_seen_ms = int(now_ms)
            messages, dup = link.ingest_packet(packet)
            if dup:
                lan_debug_log("net_recv_dup", role="join", addr=f"{addr[0]}:{addr[1]}", seq=int(packet.seq))
            for message in messages:
                self._handle_client_message(message, now_ms=int(now_ms))

        if (int(now_ms) - int(self.client_last_seen_ms)) >= int(LINK_TIMEOUT_MS):
            if not self.error:
                self.error = "timeout"
                lan_debug_log("net_timeout", role="join", addr=f"{host[0]}:{host[1]}")

        for resend in link.poll_resends(now_ms=int(now_ms)):
            try:
                self.transport.send_packet(host, resend)
            except OSError:
                continue

    def _handle_client_message(self, message: NetMessage, *, now_ms: int) -> None:
        lobby = self.client_lobby
        if lobby is None:
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_recv", role="join", kind=str(kind))
        if isinstance(message, Welcome):
            lobby.ingest_welcome(message)
            if not bool(message.accepted):
                self.error = str(message.reason or "rejected")
                return
            ready = Ready(slot_index=int(message.slot_index), ready=True)
            self._client_send(ready, reliable=True, now_ms=int(now_ms))
            return
        if isinstance(message, LobbyState):
            lobby.ingest_lobby_state(message)
            return
        if isinstance(message, MatchStart):
            lobby.ingest_match_start(message)
            self.started = True
            return
        if isinstance(message, PauseState):
            # Lobby doesn't model pause; keep for logging and future integration.
            return
        if isinstance(message, Disconnect):
            self.error = str(message.reason or "disconnect")
            return

    def _client_send(self, message: NetMessage, *, reliable: bool, now_ms: int) -> None:
        link = self.client_link
        host = self.client_host_addr
        if link is None or host is None:
            return
        packet = link.build_packet(message, reliable=bool(reliable), now_ms=int(now_ms))
        try:
            self.transport.send_packet(host, packet)
        except OSError:
            return
        kind = getattr(message, "kind", type(message).__name__)
        lan_debug_log("net_send", role="join", kind=str(kind), reliable=bool(reliable))


__all__ = ["LanRuntime", "LanRuntimeConfig"]
