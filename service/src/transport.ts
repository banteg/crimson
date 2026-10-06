// The crimson-core input stream for a replay, a port of crimson-core/checks/replay.py: a 65-word config, then per
// tick the player's four f32 axes, the flag word, the command count and each command as (kind, argument).

import { GameMode, type Replay } from "./replay";

export const CONFIG_BYTES = 65 * 4;
export const TICK_BYTES = 24;
const COMMAND_BYTES = 8;
export const MAX_TICK_COMMANDS = 16;

export class TransportError extends Error {}

export function encodeTransport(replay: Replay): Uint8Array {
  const run = replay.run;
  if (run.player_count !== 1 || ![GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS].includes(run.game_mode_id as 1 | 2 | 3))
    throw new TransportError("The core supports one player in Rush, Survival or Quests");
  const commandCount = replay.ticks.reduce((sum, tick) => sum + tick.commands.length, 0);
  const bytes = new Uint8Array(CONFIG_BYTES + replay.ticks.length * TICK_BYTES + commandCount * COMMAND_BYTES);
  const view = new DataView(bytes.buffer);
  const config = [
    run.seed,
    run.game_mode_id,
    run.quest_level?.major ?? 1,
    run.quest_level?.minor ?? 1,
    run.status.quest_unlock_index,
    run.status.quest_unlock_index_hardcore,
    run.detail_preset,
    run.violence_disabled,
    Number(run.friendly_fire),
    Number(run.hardcore),
    run.quest_fail_retry_count,
    Number(run.preserve_bugs),
    ...run.status.weapon_usage_counts,
  ];
  config.forEach((word, i) => view.setUint32(i * 4, word >>> 0, true));
  let at = CONFIG_BYTES;
  for (const tick of replay.ticks) {
    if (tick.commands.length > MAX_TICK_COMMANDS) throw new TransportError("Unsupported player or command count");
    const [mx, my, ax, ay, flags] = tick.inputs[0]!;
    [mx, my, ax, ay].forEach((axis, i) => view.setFloat32(at + i * 4, axis, true));
    view.setUint32(at + 16, flags, true);
    view.setUint32(at + 20, tick.commands.length, true);
    at += TICK_BYTES;
    for (const command of tick.commands) {
      if (command.player_index !== 0) throw new TransportError("Unsupported command player");
      if (command.type === "perk_pick") view.setInt32(at, 1, true), view.setInt32(at + 4, command.choice_index, true);
      else if (command.type === "perk_menu_open") view.setInt32(at, 2, true), view.setInt32(at + 4, 0, true);
      else throw new TransportError(`Unsupported command: ${command.type}`);
      at += COMMAND_BYTES;
    }
  }
  return bytes;
}
