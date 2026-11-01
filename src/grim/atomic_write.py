from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Replace a file only after its complete replacement has been flushed."""
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


@contextmanager
def locked_file(path: Path, *, append: bool = False) -> Generator[int]:
    """Hold the desktop clients' exclusive file lock until the descriptor closes.

    Replaced files use a separate, persistent lock file so waiters always lock the same inode.
    Scores append in place, so the append descriptor itself is locked.
    """
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags | (os.O_APPEND if append else 0), 0o644 if append else 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield fd
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
            yield fd
    finally:
        os.close(fd)
