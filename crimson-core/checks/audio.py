"""Check audio timing against a chunked device, no device, a locked device and stalls.

Compile the actual client pump and game cooldown clock against small device and
state doubles. No audio device, game assets, SDL installation or WASM build needed.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]


def main():
    compiler = shutil.which("clang++")
    if not compiler:
        raise SystemExit("clang++ is required")
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder)
        source = (CORE / "client/audio.cpp").read_text()
        # Replace only the external API declarations; the pump is compiled unchanged.
        source = source.replace('#include "client.h"\n', "").replace("#include <SDL3/SDL.h>\n", "")
        (out / "audio-under-test.cpp").write_text(source)
        command = [compiler, "-std=c++17", "-ffp-contract=off", "-I" + str(out)]
        subprocess.run([*command, str(CORE / "checks/client_audio.cpp"), "-o", str(out / "client")], check=True)
        for quantum in (512, 2048, 4096):
            for scenario in range(7):
                for fps in (60, 30):
                    subprocess.run([str(out / "client"), str(quantum), str(scenario), str(fps)], check=True)
        (out / "crimsonland_audio.h").write_text(
            "#pragma once\nstruct Config { bool sound_disabled = false; };\n"
            "extern Config config_blob;\nextern float sfx_cooldown_table[128];\n",
        )
        (out / "crimsonland_gameplay.h").write_text(
            "#pragma once\nextern int game_state_id;\nconstexpr int GAME_STATE_GAMEPLAY = 9;\n",
        )
        subprocess.run(
            [
                *command,
                str(CORE / "checks/audio_timing.cpp"),
                str(CORE / "game/audio_timing.cpp"),
                "-o",
                str(out / "timing"),
            ],
            check=True,
        )
        subprocess.run([str(out / "timing")], check=True)


if __name__ == "__main__":
    main()
