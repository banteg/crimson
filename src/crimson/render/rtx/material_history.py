"""Bounded-RAM pending material bakes for late RTX activation (not replay snapshots)."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from tempfile import SpooledTemporaryFile

import msgspec

from ...sim.terrain_fx import TerrainFxBatch

MATERIAL_HISTORY_RAM_BYTES = 1 << 20


class MaterialHistory:
    """Keep at most 1 MiB of encoded bakes in RAM; larger backlogs spill to a temporary file.

    Applied batches are discarded once the GPU carries their state. No per-batch index or
    Python object graph accumulates during classic play. clear/close releases spilled files.
    """

    def __init__(self, *, ram_bytes: int = MATERIAL_HISTORY_RAM_BYTES) -> None:
        self._ram_bytes = ram_bytes
        self._file: SpooledTemporaryFile[bytes] | None = None
        self._count = 0
        self._encoder = msgspec.msgpack.Encoder()
        self._decoder = msgspec.msgpack.Decoder(TerrainFxBatch)

    def __len__(self) -> int:
        return self._count

    def append(self, batch: TerrainFxBatch) -> None:
        if self._file is None:
            # Persistent resource: clear() closes it after baking, reset, or renderer teardown.
            self._file = SpooledTemporaryFile(max_size=self._ram_bytes, mode="w+b")  # noqa: SIM115
        data = self._encoder.encode(batch)
        self._file.seek(0, 2)
        self._file.write(len(data).to_bytes(4, "little"))
        self._file.write(data)
        self._count += 1

    def extend(self, batches: Iterable[TerrainFxBatch]) -> None:
        for batch in batches:
            self.append(batch)

    def __iter__(self) -> Iterator[TerrainFxBatch]:
        if self._file is None:
            return
        self._file.seek(0)
        for _ in range(self._count):
            size = int.from_bytes(self._file.read(4), "little")
            yield self._decoder.decode(self._file.read(size))

    def chunks(self) -> Iterator[list[TerrainFxBatch]]:
        chunk: list[TerrainFxBatch] = []
        for batch in self:
            if chunk and (len(chunk) >= 128 or batch.elapsed_s - chunk[0].elapsed_s > 180):
                yield chunk
                chunk = []
            chunk.append(batch)
        if chunk:
            yield chunk

    def clear(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None
        self._count = 0
