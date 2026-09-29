//! Native `owner_id` of projectiles, effects and a creature's last hit: a creature index (>= 0), a player as
//! `-1 - player_index`, or -100: the local player's shots with friendly fire off, which never hit players.

pub const owner_local_player: i32 = -100;

pub fn playerOwnerId(player_index: i32) i32 {
    return -1 - player_index;
}

/// The owner a player's shots carry: their own id only when they may hit other players.
pub fn playerProjectileOwnerId(friendly_fire: bool, player_index: i32) i32 {
    return if (friendly_fire) playerOwnerId(player_index) else owner_local_player;
}

/// Whether `projectile_spawn` counts the shot and applies Fire Bullets. Native lists -100, -1, -2 and -3, so a
/// fourth player's friendly-fire shots skip it; the rewrite takes any player.
pub fn projectileSpawnUsesPlayerPath(owner_id: i32, preserve_bugs: bool) bool {
    if (preserve_bugs) return owner_id == owner_local_player or (owner_id >= -3 and owner_id <= -1);
    return owner_id < 0;
}
