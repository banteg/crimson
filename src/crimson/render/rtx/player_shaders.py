"""Opaque player cloth lighting: painted relief and a directional inner rim."""

from .creature_shaders import CREATURE_VERTEX
from .shaders import glsl

PLAYER_VERTEX = CREATURE_VERTEX

PLAYER_FRAGMENT = glsl("player.frag")
