"""Standalone macOS raylib EDR comparison using the Python port's window setup.

Run: uv run --no-sync python scripts/experiments/edr_compare.py
Two processes are needed because raylib owns one global window/context.
Both run the same shader. Only the window pixel format and Cocoa EDR opt-in differ.
The values shown are OpenGL output components, NOT calibrated nits or linear-light ratios.

Apple's OpenGL recipe: https://developer.apple.com/videos/play/wwdc2021/10161/
The production bridge temporarily supplies GLFW's missing float-buffer hint
and restores the Cocoa method immediately after InitWindow.
"""

from __future__ import annotations

import argparse
import ctypes as C
import json
import subprocess
import sys
import time
from pathlib import Path

WIDTH, HEIGHT = 620, 560
VALUES = (0.25, 0.5, 1.0, 1.25, 1.5, 2.0)

SHADER = """
#version 330
in vec2 fragTexCoord;
out vec4 finalColor;
uniform vec2 resolution;
uniform float phase;
float segment(vec2 p, vec2 a, vec2 b) {
    vec2 v = b-a;
    return length(p-a-v*clamp(dot(p-a,v)/dot(v,v), 0.0, 1.0));
}
void main() {
    vec2 p = vec2(gl_FragCoord.x/resolution.x,
                  1.0-gl_FragCoord.y/resolution.y)*vec2(620.0,560.0);
    vec3 c = vec3(0.035,0.045,0.065);
    if (p.y > 128.0 && p.y < 370.0) {
        // Ordinary floor and grid stay comfortably below reference white.
        float grid = float(mod(p.x, 30.0)<1.0 || mod(p.y,30.0)<1.0);
        c = vec3(0.075,0.095,0.12) + grid*0.025;
        vec2 a = vec2(75.0,285.0), b = vec2(380.0,205.0);
        float d = segment(p,a,b);
        c += vec3(0.02,0.25,0.45)*exp(-d*d/500.0);
        c += vec3(0.45,1.3,2.0)*exp(-d*d/9.0);
        // Hot impact with rings and flecks, identical in both windows.
        float r = length(p-b);
        c += vec3(1.8,1.5,0.75)*exp(-r*r/130.0);
        c += vec3(0.15,0.55,1.1)*exp(-pow((r-35.0)/1.5,2.0));
        for (int i=0; i<12; i++) {
            float angle = float(i)*2.39996;
            vec2 spark = b+vec2(cos(angle),sin(angle))*(48.0+float(i)*3.0);
            c += vec3(1.8,0.9,0.25)*exp(-dot(p-spark,p-spark)/3.0);
        }
        // A modest, synchronized animation; no full-screen flashes.
        vec2 moving = mix(a,b,fract(phase*0.22));
        c += vec3(0.8,1.3,1.8)*exp(-dot(p-moving,p-moving)/24.0);
        float orb = length(p-vec2(495.0,295.0));
        c += vec3(1.9,0.45,0.12)*exp(-orb*orb/140.0);
        c += vec3(0.3,0.08,0.01)*exp(-orb*orb/1200.0);
    }
    if (p.y >= 405.0 && p.y < 453.0 && p.x >= 28.0 && p.x < 592.0) {
        int i = int((p.x-28.0)/94.0);
        float levels[6] = float[6](0.25,0.5,1.0,1.25,1.5,2.0);
        if (mod(p.x-28.0,94.0)<82.0) c = vec3(levels[i]);
    }
    finalColor = vec4(c,1.0);
}
"""


class GLProbe:
    def __init__(self):
        self.lib = C.CDLL("/System/Library/Frameworks/OpenGL.framework/OpenGL")
        self.lib.glGetFramebufferAttachmentParameteriv.argtypes = [C.c_uint, C.c_uint, C.c_uint, C.POINTER(C.c_int)]
        self.lib.glReadPixels.argtypes = [C.c_int, C.c_int, C.c_int, C.c_int, C.c_uint, C.c_uint, C.c_void_p]
        self.lib.glClampColor.argtypes = [C.c_uint, C.c_uint]
        self.lib.glReadBuffer.argtypes = [C.c_uint]
        self.lib.glGetError.restype = C.c_uint
        self.lib.glUseProgram.argtypes = [C.c_uint]
        self.lib.glUniform2f.argtypes = [C.c_int, C.c_float, C.c_float]
        self.lib.glUniform1f.argtypes = [C.c_int, C.c_float]

    def attachment(self, key):
        value = C.c_int()
        self.lib.glGetFramebufferAttachmentParameteriv(0x8D40, 0x0402, key, C.byref(value))
        return value.value

    def samples(self, width, height):
        self.lib.glClampColor(0x891C, 0)  # GL_CLAMP_READ_COLOR, GL_FALSE
        self.lib.glReadBuffer(0x0405)  # GL_BACK, before swap
        samples = []
        for i in range(6):
            pixel = (C.c_float * 4)()
            x = int((28 + i * 94 + 41) * width / WIDTH)
            y = int((HEIGHT - 429) * height / HEIGHT)
            self.lib.glReadPixels(x, y, 1, 1, 0x1908, 0x1406, pixel)  # RGBA, FLOAT
            samples.append(round(float(pixel[0]), 4))
        error = self.lib.glGetError()
        if error:
            raise RuntimeError(f"OpenGL probe failed: {error:#x}")
        return samples


def run_window(mode, seconds):
    import pyray as rl
    from raylib import ffi

    from grim import edr

    edr.reset_edr_window()
    cocoa = edr._MacosEdr()
    rl.set_trace_log_level(rl.TraceLogLevel.LOG_WARNING)
    rl.set_config_flags(rl.ConfigFlags.FLAG_WINDOW_HIGHDPI)
    if mode == "edr":
        with edr.macos_float_backbuffer(enabled=True):
            rl.init_window(WIDTH, HEIGHT, "EDR comparison - extended range")
    else:
        rl.init_window(WIDTH, HEIGHT, "EDR comparison - SDR control")
    if not rl.is_window_ready():
        raise RuntimeError("Window creation failed")
    shader = None
    try:
        window = int(ffi.cast("uintptr_t", rl.get_window_handle()))
        view = cocoa.send(window, "contentView")
        selector = "setWantsExtendedDynamicRangeOpenGLSurface:"
        if not cocoa.supports(view, selector):
            raise RuntimeError("Window content view has no OpenGL EDR opt-in")
        edr.activate_macos_edr_window(mode == "edr")
        requested = bool(cocoa.send(view, "wantsExtendedDynamicRangeOpenGLSurface", C.c_bool))
        rl.set_window_position(30 if mode == "sdr" else 670, 140)
        rl.set_target_fps(30)
        probe = GLProbe()
        component_type = probe.attachment(0x8211)
        bits = [probe.attachment(key) for key in (0x8212, 0x8213, 0x8214, 0x8215)]
        floating = component_type == 0x1406
        if mode == "edr" and (not floating or min(bits) < 16 or not requested):
            raise RuntimeError(f"EDR window setup failed: type={component_type:#x}, bits={bits}, opt_in={requested}")
        shader = rl.load_shader_from_memory(ffi.NULL, SHADER)
        if shader.id == rl.rl_get_shader_id_default():
            raise RuntimeError("Demo shader compilation failed")
        resolution_loc = rl.get_shader_location(shader, "resolution")
        phase_loc = rl.get_shader_location(shader, "phase")
        started = time.monotonic()
        next_probe = 0.0
        samples = []
        current = potential = 1.0
        while not rl.window_should_close():
            elapsed = time.monotonic() - started
            if seconds and elapsed >= seconds:
                break
            if mode == "edr" and rl.is_key_pressed(rl.KeyboardKey.KEY_E):
                requested = not requested
            edr.activate_macos_edr_window(requested)
            screen = cocoa.send(window, "screen")
            current = cocoa.send(screen, "maximumExtendedDynamicRangeColorComponentValue", C.c_double)
            potential = cocoa.send(screen, "maximumPotentialExtendedDynamicRangeColorComponentValue", C.c_double)
            rw, rh = rl.get_render_width(), rl.get_render_height()
            rl.begin_drawing()
            rl.clear_background(rl.BLACK)
            rl.begin_shader_mode(shader)
            # Explicit GL calls avoid the installed binding's uniform upload issue.
            probe.lib.glUseProgram(shader.id)
            probe.lib.glUniform2f(resolution_loc, rw, rh)
            probe.lib.glUniform1f(phase_loc, time.monotonic() % 1000)
            rl.draw_rectangle(0, 0, WIDTH, HEIGHT, rl.WHITE)
            rl.end_shader_mode()
            title = "EXTENDED RANGE" if mode == "edr" else "SDR CONTROL"
            rl.draw_text(title, 28, 24, 28, rl.RAYWHITE)
            rl.draw_text("Same shader / same scene / same output values", 28, 62, 18, rl.LIGHTGRAY)
            fmt = "RGBA16F" if floating else "RGBA8"
            rl.draw_text(f"{fmt}   |   Cocoa EDR {'ON' if requested else 'OFF'}", 28, 94, 18, rl.LIGHTGRAY)
            rl.draw_text("OUTPUT COMPONENTS  (1.0 = ordinary white)", 28, 380, 18, rl.LIGHTGRAY)
            for i, value in enumerate(VALUES):
                rl.draw_text(f"{value:g}", 47 + i * 94, 463, 18, rl.LIGHTGRAY)
            rl.draw_text(
                f"Display headroom: {current:.2f}x now / {potential:.2f}x potential",
                28,
                500,
                17,
                rl.LIGHTGRAY,
            )
            hint = (
                "E: toggle Cocoa EDR on this same float surface"
                if mode == "edr"
                else "Below 1.0 should match the other window."
            )
            rl.draw_text(hint, 28, 528, 17, rl.LIGHTGRAY)
            if elapsed >= next_probe:
                rl.rl_draw_render_batch_active()
                samples = probe.samples(rw, rh)
                expected = list(VALUES) if floating else [min(v, 1) for v in VALUES]
                if any(abs(a - b) > 0.006 for a, b in zip(samples, expected, strict=True)):
                    raise RuntimeError(f"Backbuffer readback mismatch: {samples}, expected {expected}")
                print(
                    json.dumps(
                        {
                            "mode": mode,
                            "cocoa_edr": requested,
                            "bits": bits,
                            "float": floating,
                            "headroom": round(current, 3),
                            "potential": round(potential, 3),
                            "backbuffer_red": samples,
                        },
                    ),
                    flush=True,
                )
                next_probe = elapsed + 5
            rl.end_drawing()
    finally:
        if shader is not None:
            rl.unload_shader(shader)
        edr.reset_edr_window()
        rl.close_window()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", choices=("sdr", "edr"), help=argparse.SUPPRESS)
    parser.add_argument("--seconds", type=float, default=0, help="Auto-close after N seconds (default: stay open)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("This experiment requires macOS")
    if args.window:
        run_window(args.window, args.seconds)
        return
    children = []
    try:
        for mode in ("sdr", "edr"):
            children.append(
                subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), "--window", mode, "--seconds", str(args.seconds)],
                ),
            )
        while all(child.poll() is None for child in children):
            time.sleep(0.2)
        if any(child.poll() not in (None, 0) for child in children):
            raise SystemExit("Comparison failed; see the window diagnostic above")
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait()


if __name__ == "__main__":
    main()
