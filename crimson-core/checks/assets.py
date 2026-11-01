"""Check native artwork hash detection and the shared SHA-256 against hashlib."""

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        payloads = {"old": b"old art" * 200, "current": b"current art" * 100,
                    "custom": b"paq\0x\0\x01\0\0\0a", "empty": b"", "abc": b"abc",
                    "55": b"a" * 55, "56": b"a" * 56, "64": bytes(range(64)), "65": bytes(range(65))}
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
        (root / "assets_version.h").write_text(
            f'constexpr const char *CRIMSON_PAQ_SHA256 = "{hashes["current"]}";\n'
            f'constexpr const char *MUSIC_PAQ_SHA256 = "{hashes["55"]}";\n'
            f'constexpr const char *SFX_PAQ_SHA256 = "{hashes["56"]}";\n'
            f'constexpr const char *LEGACY_MUSIC_SHA256 = "{hashes["abc"]}";\n'
            f'constexpr const char *PREVIOUS_CRIMSON_PAQ_SHA256[] = {{"{hashes["old"]}"}};\n',
        )
        driver = root / "check.cpp"
        driver.write_text('''
#include "assets.h"
#include "sha256.h"
#include <fstream>
#include <iterator>
#include <vector>
#include <stdio.h>
int main(int argc, char **argv) {
  for (int i = 1; i < argc; ++i) {
    std::ifstream file(argv[i], std::ios::binary);
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    unsigned char digest[32], empty = 0;
    sha256(bytes.empty() ? &empty : bytes.data(), bytes.size(), digest);
    printf("%d %d %d %d %d ", int(pack_state("crimson.paq", argv[i])), pack_is_current("crimson.paq", argv[i]),
           pack_is_current("music.paq", argv[i]), pack_is_current("sfx.paq", argv[i]),
           legacy_music_bytes(bytes.data(), bytes.size()));
    for (unsigned char b : digest) printf("%02x", b);
    puts("");
  }
}
''')
        compiler = shutil.which("clang++") or shutil.which("c++")
        if not compiler:
            raise SystemExit("A C++ compiler is required")
        binary = root / "check"
        subprocess.run([compiler, "-std=c++17", "-O2", "-I" + str(root), "-I" + str(CORE / "client"),
                        "-I" + str(CORE / "game"), str(driver), str(CORE / "client/assets.cpp"),
                        str(CORE / "game/sha256.cpp"), "-o", str(binary)], check=True)
        paths = []
        for name, data in payloads.items():
            path = root / name
            path.write_bytes(data)
            paths.append(str(path))
        result = subprocess.check_output([str(binary), *paths], text=True).splitlines()
        for name, line in zip(payloads, result, strict=True):
            state, current, music, sfx, legacy, digest = line.split()
            assert int(state) == (1 if name == "old" else 0 if name in ("current", "custom") else 2), name
            assert (current == "1") == (name == "current"), name
            assert (music == "1") == (name == "55") and (sfx == "1") == (name == "56")
            assert (legacy == "1") == (name == "abc")
            assert digest == hashes[name], name
        absent = subprocess.check_output([str(binary), str(root / "missing")], text=True)
        assert absent.startswith("2 0 ")
        print(json.dumps({"native_hash_cases": len(payloads), "missing_preserved": True}))


if __name__ == "__main__":
    main()
