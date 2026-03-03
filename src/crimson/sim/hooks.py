from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

import msgspec


class TickContext(msgspec.Struct, frozen=True):
    tick_index: int
    dt_seconds: float
    inputs_present: bool
    session_kind: str
    mode_id: str
    is_networked: bool
    is_replay: bool


class TickHashes(msgspec.Struct, frozen=True):
    command_hash: str
    state_hash: str | None = None


class TickResult(msgspec.Struct, frozen=True):
    tick_index: int
    command_hash: str
    dt_sim: float


class TickHook(Protocol):
    def on_tick_begin(self, ctx: TickContext) -> None: ...

    def on_tick_stall(self, ctx: TickContext) -> None: ...

    def on_pre_sim(self, ctx: TickContext) -> None: ...

    def on_world_step_done(self, ctx: TickContext, result: TickResult) -> None: ...

    def on_pre_hash(self, ctx: TickContext, result: TickResult) -> None: ...

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None: ...

    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None: ...

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None: ...


class NoopTickHook:
    def on_tick_begin(self, ctx: TickContext) -> None:
        _ = ctx

    def on_tick_stall(self, ctx: TickContext) -> None:
        _ = ctx

    def on_pre_sim(self, ctx: TickContext) -> None:
        _ = ctx

    def on_world_step_done(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx, result

    def on_pre_hash(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx, result

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None:
        _ = ctx, hashes

    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx, result

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None:
        _ = ctx, result


class TickHookBus:
    def __init__(self, hooks: Iterable[TickHook] | None = None) -> None:
        self._hooks: list[TickHook] = list(hooks or [])

    @property
    def hooks(self) -> tuple[TickHook, ...]:
        return tuple(self._hooks)

    def add_hook(self, hook: TickHook) -> None:
        self._hooks.append(hook)

    def on_tick_begin(self, ctx: TickContext) -> None:
        for hook in self._hooks:
            hook.on_tick_begin(ctx)

    def on_tick_stall(self, ctx: TickContext) -> None:
        for hook in self._hooks:
            hook.on_tick_stall(ctx)

    def on_pre_sim(self, ctx: TickContext) -> None:
        for hook in self._hooks:
            hook.on_pre_sim(ctx)

    def on_world_step_done(self, ctx: TickContext, result: TickResult) -> None:
        for hook in self._hooks:
            hook.on_world_step_done(ctx, result)

    def on_pre_hash(self, ctx: TickContext, result: TickResult) -> None:
        for hook in self._hooks:
            hook.on_pre_hash(ctx, result)

    def on_post_hash(self, ctx: TickContext, hashes: TickHashes) -> None:
        for hook in self._hooks:
            hook.on_post_hash(ctx, hashes)

    def on_post_presentation(self, ctx: TickContext, result: TickResult) -> None:
        for hook in self._hooks:
            hook.on_post_presentation(ctx, result)

    def on_tick_end(self, ctx: TickContext, result: TickResult) -> None:
        for hook in self._hooks:
            hook.on_tick_end(ctx, result)
