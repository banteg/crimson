"""Shared GLSL for alpha-aware color reconstruction (also built into the SDL host)."""

from importlib.resources import files

FILTERING_GLSL = files("grim").joinpath("filtering.glsl").read_text()
