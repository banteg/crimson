from __future__ import annotations

import os

CRT_RAND_MULT = 214013
CRT_RAND_INC = 2531011


class CrtRand:
    """MSVCRT-compatible `rand()` LCG used by the original game.

    Matches:
      seed = seed * 214013 + 2531011
      return (seed >> 16) & 0x7fff
    """

    __slots__ = ("_state",)

    def __init__(self, seed: int | None = None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(4), "little")
        self._state = seed & 0xFFFFFFFF

    @property
    def state(self) -> int:
        return self._state

    def srand(self, seed: int) -> None:
        self._state = seed & 0xFFFFFFFF

    def rand(self) -> int:
        self._state = (self._state * CRT_RAND_MULT + CRT_RAND_INC) & 0xFFFFFFFF
        return (self._state >> 16) & 0x7FFF


class Crand(CrtRand):
    """Backward-compatible name for the MSVCRT LCG."""
