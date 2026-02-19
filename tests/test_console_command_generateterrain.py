from __future__ import annotations

import crimson.game.loop_view as loop_view
from crimson.game.loop_view import GameLoopView
from crimson.game.runtime import _boot_command_handlers


def test_generateterrain_command_sets_regenerate_request(make_game_state) -> None:
    state = make_game_state()
    handlers = _boot_command_handlers(state)

    assert state.terrain_regenerate_requested is False
    handlers["generateterrain"]([])
    assert state.terrain_regenerate_requested is True


def test_game_loop_consumes_terrain_regenerate_request(monkeypatch, make_game_state) -> None:
    class _FakeView:
        called = 0

        def open(self) -> None:
            return

        def close(self) -> None:
            return

        def update(self, dt: float) -> None:
            _ = dt

        def draw(self) -> None:
            return

        def take_action(self) -> str | None:
            return None

        def regenerate_terrain_for_console(self) -> None:
            self.called += 1

    calls: list[bool] = []

    def _fake_ensure_menu_ground(*_args, regenerate: bool = False, **_kwargs):
        calls.append(bool(regenerate))
        return None

    monkeypatch.setattr(loop_view, "ensure_menu_ground", _fake_ensure_menu_ground)

    state = make_game_state()
    view = GameLoopView(state)
    fake = _FakeView()
    view._front_active = fake
    state.terrain_regenerate_requested = True

    view._handle_console_requests()

    assert state.terrain_regenerate_requested is False
    assert calls == [True]
    assert fake.called == 1
