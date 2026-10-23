"""RTX GLSL the client builds in too (crimson-core/client/shaders.py), so both renderers run one source."""

import re
from importlib.resources import files

RTX_SHADERS = files(__name__)
_INCLUDES = (RTX_SHADERS, files("grim"))


def glsl(name: str) -> str:
    """A shader file with its `#include "name"` lines inlined, from this folder or grim's (filtering.glsl)."""

    def include(match: re.Match) -> str:
        return glsl(match[1])

    source = next(folder.joinpath(name) for folder in _INCLUDES if folder.joinpath(name).is_file())
    return re.sub(r'(?m)^#include "([^"]+)"[ \t]*$', include, source.read_text())
