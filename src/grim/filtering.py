"""Shared GLSL for alpha-aware color reconstruction (also built into the SDL host), and linear light's decoding."""

from importlib.resources import files

FILTERING_GLSL = files("grim").joinpath("filtering.glsl").read_text()
LINEAR_LIGHT_GLSL = files("grim").joinpath("linear_light.glsl").read_text()
