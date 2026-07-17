const game_ids = @import("../game_ids.zig");
const player_runtime = @import("../runtime/player.zig");
const state_mod = @import("../runtime/state.zig");

pub const typo_weapon_id = game_ids.WeaponId.shotgun;

pub fn enforceTypoPlayerFrame(
    player: *state_mod.PlayerState,
    state: *state_mod.GameplayState,
) void {
    if (player.weapon.weapon_id != typo_weapon_id) {
        player_runtime.weaponAssignPlayerWithState(player, typo_weapon_id, state);
    }

    player.weapon.shot_cooldown = 0.0;
    player.spread_heat = 0.0;
    player.weapon.ammo = @floatFromInt(@max(0, player.weapon.clip_size));
    player.weapon.reload_active = false;
    player.weapon.reload_timer = 0.0;
    player.weapon.reload_timer_max = 0.0;
}
