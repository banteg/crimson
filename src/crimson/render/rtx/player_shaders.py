"""Opaque player cloth lighting: painted relief and a directional inner rim."""

from .bonus_shaders import BONUS_VERTEX
from .shaders import glsl

PLAYER_VERTEX = BONUS_VERTEX

PLAYER_FRAGMENT = glsl("player.frag")
