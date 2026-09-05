from __future__ import annotations

from collections.abc import Callable

import msgspec

from grim.app import RunViewHooks
from grim.view import View, ViewContext


class ViewInstance(msgspec.Struct, frozen=True):
    view: View
    hooks: RunViewHooks = msgspec.field(default_factory=RunViewHooks)


class ViewDefinition(msgspec.Struct, frozen=True):
    name: str
    title: str
    factory: Callable[[ViewContext], ViewInstance]


_VIEW_REGISTRY: dict[str, ViewDefinition] = {}


def register_view(
    name: str, title: str,
) -> Callable[[Callable[[ViewContext], ViewInstance]], Callable[[ViewContext], ViewInstance]]:
    def decorator(factory: Callable[[ViewContext], ViewInstance]) -> Callable[[ViewContext], ViewInstance]:
        if name in _VIEW_REGISTRY:
            raise ValueError(f"view already registered: {name}")
        _VIEW_REGISTRY[name] = ViewDefinition(name=name, title=title, factory=factory)
        return factory

    return decorator


def all_views() -> list[ViewDefinition]:
    return [_VIEW_REGISTRY[name] for name in sorted(_VIEW_REGISTRY.keys(), key=str.casefold)]


def view_by_name(name: str) -> ViewDefinition | None:
    return _VIEW_REGISTRY.get(name)
