"""Compare the early Career spawner, including slot reuse and nested rare rolls, to its original PE."""

import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def early_record(shared):
    # Project the client's 128-byte creature onto the 104-byte 1.0.2 ABI. Unused native bytes keep their sentinel.
    record = bytearray(b"\xa5" * 104)
    record[0] = shared[0]
    record[1] = shared[12]  # plague
    record[4:36] = shared[16:48]  # status timer, death, position, velocity, health, heading
    record[36:80] = shared[52:96]  # size through attack cooldown
    (reward,) = struct.unpack_from("<d", shared, 96)
    assert reward.is_integer(), reward
    struct.pack_into("<i", record, 80, int(reward))
    record[96:100] = shared[116:120]  # sprite type
    return record


def check_random_spawns(exe, edition, lines):
    early = edition == "1.0.2"
    entry, pool, stride, capacity, xp_addr, player, counter, rng = (
        (0x4062E0, 0x4252D0, 104, 128, 0x421EF8, 0x4287E8, 0x428868, 0x41DCC8)
        if early
        else (0x40B550, 0x4374F8, 128, 512, 0x430010, 0x44774C, 0x44780C, 0x42B634)
    )
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=rng)
    pos = pe.alloc_f32s(512, 384)
    hp, xy, infected = (28, 12, 1) if early else (40, 24, 12)
    cap = 60000 if early else 46200
    cases = [(seed, 5432, 0) for seed in (0, 45, 25, 214, 565, 53, 10047, 60423)]
    cases += [(0, score, 0) for score in (-2, 0, cap - 1, cap, cap + 1, 16777217)]
    cases += [(1, 100, layout) for layout in range(1, 7)]
    rows = [line.split()[1:] for line in lines if line.startswith("randomspawn ")]
    for (seed, xp, layout), row in zip(cases, rows, strict=True):
        seed_s, xp_s, layout_s, ok, count, state, peer_plague, record = row
        case = edition, seed, xp, layout
        assert (int(seed_s), int(xp_s), int(layout_s)) == case[1:], case
        occupied = (0, 1, 2, 2, capacity, 2, capacity)[layout]
        slot = 0 if occupied == capacity else occupied
        actor = 0 if early else seed % 2
        pe.write_u32(player, actor)
        actor_stride = 268 if early else 328
        pe.write_u32(xp_addr + (1 - actor) * actor_stride, (xp + 10) & 0xFFFFFFFF)
        pe.write_u32(xp_addr + actor * actor_stride, xp & 0xFFFFFFFF)
        pe.write_u32(counter, occupied)
        records = bytearray(stride * capacity)
        for i in range(occupied):
            records[i * stride] = 1
            struct.pack_into("<2f", records, i * stride + xy, 64, 64)
        peer = 0 if layout == 1 else stride
        if layout not in (0, 4):
            struct.pack_into("<2f", records, peer + xy, 512 + (45 if layout == 3 else 44), 384)
            records[peer + infected] = int(layout != 5)
        addr = slot * stride
        records[addr : addr + stride] = b"\xa5" * stride
        records[addr] = int(occupied == capacity)
        records[addr + infected] = int(layout == 5)
        struct.pack_into("<f", records, addr + hp, 25)
        struct.pack_into("<i" if early else "<d", records, addr + (80 if early else 96), 777)
        pe.write(pool, records)
        pe.rand_state = seed
        ret = pe.call(entry, pos).eax & 255
        assert (int(ok), int(count), int(state)) == (ret, pe.read_u32(counter), pe.rand_state), case
        assert int(peer_plague) == pe.read_u8(pool + peer + infected), case
        actual = bytes.fromhex(record)
        if early:
            actual = early_record(actual)
        expected = pe.read(pool + addr, stride)
        assert actual == expected, (
            case,
            [(i, a, b) for i, (a, b) in enumerate(zip(actual, expected, strict=True)) if a != b],
        )
    print(f"{edition}: {len(cases)} Career spawns matched original creature records, counter, return and RNG")
