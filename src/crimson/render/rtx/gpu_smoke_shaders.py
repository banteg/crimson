"""GL 3.3 fragment passes for a shared world-space smoke field."""

from .shaders import glsl

GPU_SMOKE_FRAGMENT = glsl("smoke_solver.frag")
GPU_SMOKE_SPLAT_FRAGMENT = glsl("smoke_splat.frag")
GPU_ATMOSPHERE_IMPULSE_FRAGMENT = glsl("smoke_impulse.frag")
