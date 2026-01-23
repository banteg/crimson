from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from grim.view import View


@dataclass(frozen=True, slots=True)
class ViewDefinition:
    name: str
    title: str
    factory: Callable[..., View]


_VIEW_REGISTRY: dict[str, ViewDefinition] = {}


def register_view(name: str, title: str) -> Callable[[Callable[..., View]], Callable[..., View]]:
    def decorator(factory: Callable[..., View]) -> Callable[..., View]:
        if name in _VIEW_REGISTRY:
            raise ValueError(f"view already registered: {name}")
        _VIEW_REGISTRY[name] = ViewDefinition(name=name, title=title, factory=factory)
        return factory

    return decorator


def all_views() -> list[ViewDefinition]:
    return [_VIEW_REGISTRY[name] for name in sorted(_VIEW_REGISTRY.keys(), key=str.casefold)]


def view_by_name(name: str) -> ViewDefinition | None:
    return _VIEW_REGISTRY.get(name)
