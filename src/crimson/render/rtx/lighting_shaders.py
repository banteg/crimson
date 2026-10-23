"""Shared finite-source visibility for ground and creature lighting."""

from .shaders import glsl

SOURCE_GEOMETRY_GLSL = glsl("source_geometry.glsl")
LIGHT_VISIBILITY_GLSL = glsl("light_visibility.glsl")
