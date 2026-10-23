"""RTX GLSL the client builds in too (crimson-core/client/shaders.py), so both renderers run one source."""

from importlib.resources import files

RTX_SHADERS = files(__name__)
