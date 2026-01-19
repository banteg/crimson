from pathlib import Path
import sys


LOG_PATH = Path(r"C:\Crimsonland\windbg.log")
STATE_PATH = Path(r"C:\Crimsonland\windbg.log.pos")


def read_pos(state_path: Path) -> int:
    if not state_path.exists():
        return 0
    try:
        return int(state_path.read_text().strip() or "0")
    except ValueError:
        return 0


def main() -> int:
    if not LOG_PATH.exists():
        print(f"log not found: {LOG_PATH}", file=sys.stderr)
        return 1

    pos = read_pos(STATE_PATH)
    size = LOG_PATH.stat().st_size
    if size < pos:
        pos = 0

    with LOG_PATH.open("rb") as log_file:
        log_file.seek(pos)
        data = log_file.read()
        new_pos = log_file.tell()

    encoding = "utf-16-le"
    if pos == 0:
        if data.startswith(b"\xff\xfe"):
            data = data[2:]
        elif data.startswith(b"\xfe\xff"):
            data = data[2:]
            encoding = "utf-16-be"

    sys.stdout.write(data.decode(encoding, errors="replace"))
    STATE_PATH.write_text(str(new_pos))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
