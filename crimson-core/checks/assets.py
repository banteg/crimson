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
                    "custom": b"custom art", "empty": b"", "abc": b"abc",
                    "55": b"a" * 55, "56": b"a" * 56, "64": bytes(range(64)), "65": bytes(range(65))}
        hashes = {name: hashlib.sha256(data).hexdigest() for name, data in payloads.items()}
        (root / "assets_version.h").write_text(
            f'constexpr const char *CRIMSON_PAQ_SHA256 = "{hashes["current"]}";\n'
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
    printf("%d %d ", artwork_needs_update(argv[i]), artwork_is_current(argv[i]));
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
            old, current, digest = line.split()
            assert (old == "1") == (name == "old"), name
            assert (current == "1") == (name == "current"), name
            assert digest == hashes[name], name
        absent = subprocess.check_output([str(binary), str(root / "missing")], text=True)
        assert absent.startswith("0 0 ")
        print(json.dumps({"native_hash_cases": len(payloads), "missing_preserved": True}))


if __name__ == "__main__":
    main()
