const game_ids = @import("../game_ids.zig");
const state_mod = @import("../runtime/state.zig");

pub const typo_weapon_id = game_ids.WeaponId.shotgun;

/// Native typo `player_fire_weapon` clears a living player's cooldown, spread
/// and reload and refills the clip each frame.
pub fn enforceTypoPlayerFrame(player: *state_mod.PlayerState) void {
    if (!(player.health > 0.0)) return;
    player.weapon.shot_cooldown = 0.0;
    player.spread_heat = 0.0;
    player.weapon.ammo = @floatFromInt(@max(0, player.weapon.clip_size));
    player.weapon.reload_active = false;
    player.weapon.reload_timer = 0.0;
    player.weapon.reload_timer_max = 0.0;
}
