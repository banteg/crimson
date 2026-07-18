pub const local_player_owner_id: i32 = -100;

pub const PlayerRef = struct {
    index: usize,
    local_host: bool = false,
};

pub const OwnerRef = union(enum) {
    none: void,
    player: PlayerRef,
    creature: usize,

    pub fn fromLocalPlayer(index: usize) OwnerRef {
        return .{ .player = .{ .index = index, .local_host = true } };
    }

    pub fn fromPlayer(index: usize) OwnerRef {
        return .{ .player = .{ .index = index, .local_host = false } };
    }

    pub fn fromCreature(index: usize) OwnerRef {
        return .{ .creature = index };
    }

    pub fn fromLegacy(owner_id: i32) OwnerRef {
        if (owner_id == local_player_owner_id) {
            return fromLocalPlayer(0);
        }
        if (owner_id < 0) {
            const idx: i32 = -1 - owner_id;
            if (idx >= 0) {
                return fromPlayer(@intCast(idx));
            }
            return .{ .none = {} };
        }
        return fromCreature(@intCast(owner_id));
    }

    pub fn toLegacy(owner: OwnerRef) i32 {
        return switch (owner) {
            .none => 0,
            .creature => |idx| @intCast(idx),
            .player => |ref| blk: {
                if (ref.local_host and ref.index == 0) break :blk local_player_owner_id;
                break :blk -1 - @as(i32, @intCast(ref.index));
            },
        };
    }

    pub fn isPlayer(owner: OwnerRef) bool {
        return switch (owner) {
            .player => true,
            else => false,
        };
    }

    pub fn usesNativePlayerProjectilePath(owner: OwnerRef) bool {
        const legacy_owner = toLegacy(owner);
        return legacy_owner == local_player_owner_id or
            (legacy_owner >= -3 and legacy_owner <= -1);
    }

    pub fn playerIndex(owner: OwnerRef) ?usize {
        return switch (owner) {
            .player => |ref| ref.index,
            else => null,
        };
    }

    pub fn playerIndexInBounds(owner: OwnerRef, player_count: usize) ?usize {
        const idx = playerIndex(owner) orelse return null;
        if (idx < player_count) return idx;
        return null;
    }

    pub fn creatureIndex(owner: OwnerRef) ?usize {
        return switch (owner) {
            .creature => |idx| idx,
            else => null,
        };
    }

    pub fn creatureIndexInBounds(owner: OwnerRef, creature_count: usize) ?usize {
        const idx = creatureIndex(owner) orelse return null;
        if (idx < creature_count) return idx;
        return null;
    }
};
