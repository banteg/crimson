"""The GLSL the client shares with the Python port, as headers the renderer includes.

filtering.h is src/grim/filtering.glsl as one raw string. rtx_shaders.h defines RTX_SHADER_<NAME>_<STAGE> for each
file in src/crimson/render/rtx/shaders, without its #version line: the renderer prepends its own (330 core or 300 es).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RTX_SHADERS = ROOT / "src/crimson/render/rtx/shaders"


def write_shader_headers(out: Path) -> None:
    filtering = (ROOT / "src/grim/filtering.glsl").read_text()
    (out / "filtering.h").write_text('R"GLSL(' + filtering + ')GLSL"\n')
    lines = [f"// Generated from {RTX_SHADERS.relative_to(ROOT)} by crimson-core/client/shaders.py."]
    for path in sorted(p for p in RTX_SHADERS.iterdir() if p.suffix in (".frag", ".vert")):
        source = re.sub(r"(?m)^#version[^\n]*\n", "", path.read_text(), count=1)
        name = f"RTX_SHADER_{path.stem}_{path.suffix[1:]}".upper()
        lines.append(f'#define {name} R"GLSL({source})GLSL"')
    (out / "rtx_shaders.h").write_text("\n".join(lines) + "\n")
