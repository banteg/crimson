import os
from pathlib import Path
import sys


DEFAULT_WINDOWS_LOG_PATH = r"C:\games\crimsonland_1.9.93\windbg.log"


def is_wsl() -> bool:
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    proc_version = Path("/proc/version")
    return proc_version.exists() and "microsoft" in proc_version.read_text().lower()


def resolve_path(path: str) -> Path:
    if os.name == "nt":
        return Path(path)
    if is_wsl() and len(path) >= 3 and path[1:3] == ":\\":
        drive = path[0].lower()
        tail = path[3:].replace("\\", "/")
        return Path(f"/mnt/{drive}/{tail}")
    return Path(path)


def detect_log_path() -> Path:
    env_path = os.environ.get("CRIMSON_WINDBG_LOG")
    candidates = [path for path in [env_path, DEFAULT_WINDOWS_LOG_PATH, r"C:\Crimsonland\windbg.log"] if path]
    for path in candidates:
        resolved = resolve_path(path)
        if resolved.exists():
            return resolved
    return resolve_path(candidates[0])


def detect_state_path(log_path: Path) -> Path:
    env_state = os.environ.get("CRIMSON_WINDBG_STATE")
    if env_state:
        return resolve_path(env_state)
    return log_path.with_suffix(log_path.suffix + ".pos")


def read_pos(state_path: Path) -> int:
    if not state_path.exists():
        return 0
    try:
        return int(state_path.read_text().strip() or "0")
    except ValueError:
        return 0


def main() -> int:
    log_path = detect_log_path()
    state_path = detect_state_path(log_path)
    if not log_path.exists():
        print(f"log not found: {log_path}", file=sys.stderr)
        return 1

    pos = read_pos(state_path)
    size = log_path.stat().st_size
    if size < pos:
        pos = 0

    with log_path.open("rb") as log_file:
        log_file.seek(pos)
        data = log_file.read()
        new_pos = log_file.tell()

    encoding = "ascii"
    if pos == 0:
        if data.startswith(b"\xff\xfe"):
            data = data[2:]
            encoding = "utf-16-le"
        elif data.startswith(b"\xfe\xff"):
            data = data[2:]
            encoding = "utf-16-be"
        elif data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
            encoding = "utf-8"

    sys.stdout.write(data.decode(encoding, errors="replace"))
    state_path.write_text(str(new_pos))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
