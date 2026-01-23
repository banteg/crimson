from __future__ import annotations


class Crand:
    """MSVCRT-compatible `rand()` LCG used by the original game.

    Matches:
      seed = seed * 214013 + 2531011
      return (seed >> 16) & 0x7fff
    """

    __slots__ = ("_state",)

    def __init__(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    @property
    def state(self) -> int:
        return self._state

    def srand(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    def rand(self) -> int:
        self._state = (self._state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        return (self._state >> 16) & 0x7FFF

