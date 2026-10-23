"""Single-scattering display of a simulated planar density/temperature field."""

from .hdr import _HDR_TONEMAP_VS_330
from .shaders import glsl

SMOKE_VERTEX = _HDR_TONEMAP_VS_330
SMOKE_FRAGMENT = glsl("smoke.frag")
