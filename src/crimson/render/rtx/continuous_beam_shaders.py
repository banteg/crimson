"""Analytic continuous beam lighting for Python RTX."""

from .shaders import glsl

CONTINUOUS_BEAM_GLSL = glsl("continuous_beam.glsl")
