// The crimson-core input stream for a replay, a port of crimson-core/checks/replay.py: a 68-word config, then per
// tick each player's four f32 axes and flag word (player one first), the command count and each command as (kind,
// argument). A perk command carries no player: the core knows whose perk menu is open.

import { type CustomQuest, GameMode, type Replay } from "./replay";

export const CONFIG_BYTES = 68 * 4;
// The config word holding the player count, which the stream gained after runs were first accepted.
const PLAYERS_WORD = 12;
export const QUEST_HEAD_BYTES = 10 * 4;
export const QUEST_SPAWN_BYTES = 24;
export const QUEST_BYTES = QUEST_HEAD_BYTES + 256 * QUEST_SPAWN_BYTES;
export const INPUT_BYTES = 20;
const COMMAND_BYTES = 8;
export const MAX_TICK_COMMANDS = 16;

export class TransportError extends Error {}

// A tick's inputs and command count, before its commands.
export const tickBytes = (players: number) => players * INPUT_BYTES + 4;

export function encodePortableQuest(quest: CustomQuest): Uint8Array {
  const bytes = new Uint8Array(QUEST_BYTES);
  const view = new DataView(bytes.buffer);
  let bonuses = 0;
  for (const id of quest.no_bonuses) bonuses |= 1 << id;
  let perksLo = 0, perksHi = 0;
  for (const id of quest.no_perks) {
    if (id < 32) perksLo |= 1 << id;
    else perksHi |= 1 << (id - 32);
  }
  let weaponsLo = 0, weaponsHi = 0;
  for (const id of quest.no_weapons) {
    if (id < 32) weaponsLo |= 1 << id;
    else weaponsHi |= 1 << (id - 32);
  }
  const head = [
    quest.start_weapon_id,
    quest.terrain_slots[0],
    quest.terrain_slots[1],
    quest.terrain_slots[2],
    quest.entries.length,
    bonuses >>> 0,
    perksLo >>> 0,
    perksHi >>> 0,
    weaponsLo >>> 0,
    weaponsHi >>> 0,
  ];
  head.forEach((word, i) => view.setUint32(i * 4, word >>> 0, true));
  quest.entries.forEach((e, i) => {
    const at = QUEST_HEAD_BYTES + i * QUEST_SPAWN_BYTES;
    view.setFloat32(at, e.pos.x, true);
    view.setFloat32(at + 4, e.pos.y, true);
    view.setFloat32(at + 8, e.heading, true);
    view.setInt32(at + 12, e.spawn_id, true);
    view.setInt32(at + 16, e.trigger_ms, true);
    view.setInt32(at + 20, e.count, true);
  });
  return bytes;
}

export function encodeTransport(replay: Replay): Uint8Array {
  const run = replay.run;
  const players = run.player_count;
  if ((players !== 1 && players !== 2) || ![GameMode.SURVIVAL, GameMode.RUSH, GameMode.QUESTS].includes(run.game_mode_id as 1 | 2 | 3))
    throw new TransportError("The core supports one or two players in Rush, Survival or Quests");
  const custom = run.custom_quest;
  const headBytes = CONFIG_BYTES + (custom ? QUEST_BYTES : 0);
  const ticks = replay.ticks;
  const commandCount = [...ticks.commands.values()].reduce((sum, commands) => sum + commands.length, 0);
  const bytes = new Uint8Array(headBytes + ticks.length * tickBytes(players) + commandCount * COMMAND_BYTES);
  const view = new DataView(bytes.buffer);
  const config = [
    run.seed,
    run.game_mode_id,
    custom ? 0 : (run.quest_level?.major ?? 1),
    custom ? 0 : (run.quest_level?.minor ?? 1),
    run.status.quest_unlock_index,
    run.status.quest_unlock_index_hardcore,
    run.detail_preset,
    run.violence_disabled,
    Number(run.friendly_fire),
    Number(run.hardcore),
    run.quest_fail_retry_count,
    Number(run.preserve_bugs),
    run.player_count,
    ...run.status.weapon_usage_counts,
    replay.rules,
    Number(legacyCoopReload(replay)),
  ];
  config.forEach((word, i) => view.setUint32(i * 4, word >>> 0, true));
  if (custom) bytes.set(encodePortableQuest(custom), CONFIG_BYTES);
  let at = headBytes;
  for (let tick = 0; tick < ticks.length; tick++) {
    const commands = ticks.commands.get(tick) ?? [];
    if (commands.length > MAX_TICK_COMMANDS) throw new TransportError("Unsupported player or command count");
    for (let player = 0; player < players; player++, at += INPUT_BYTES) {
      const [mx, my, ax, ay, flags] = ticks.input(tick, player);
      [mx, my, ax, ay].forEach((axis, i) => view.setFloat32(at + i * 4, axis, true));
      view.setUint32(at + 16, flags, true);
    }
    view.setUint32(at, commands.length, true);
    at += 4;
    for (const command of commands) {
      if (command.player_index >= players) throw new TransportError("Unsupported command player");
      if (command.type === "perk_pick") view.setInt32(at, 1, true), view.setInt32(at + 4, command.choice_index, true);
      else if (command.type === "perk_menu_open") view.setInt32(at, 2, true), view.setInt32(at + 4, 0, true);
      else throw new TransportError(`Unsupported command: ${command.type}`);
      at += COMMAND_BYTES;
    }
  }
  return bytes;
}

// The bytes a run's id hashes. Ids name stored replays, links and the duplicate check, so they stay put when the
// stream's layout changes: a one-player run hashes its stream as the service first encoded it, without the player
// count, which the stream gained later; a co-op run hashes its whole stream, the count included. (A ranked run's
// weapon usage words are zero, so the shifted one-player bytes never spell a co-op stream.)
export function runIdentity(transport: Uint8Array): Uint8Array {
  const rules = new DataView(transport.buffer, transport.byteOffset, transport.byteLength).getUint32(66 * 4, true);
  // Freeze the old identity independently of the appended internal config word.
  const legacy = new Uint8Array(transport.length - 8);
  legacy.set(transport.subarray(0, 66 * 4));
  legacy.set(transport.subarray(CONFIG_BYTES), 66 * 4);
  if (rules === 1) return legacyIdentity(legacy);
  if (rules !== 2) throw new TransportError(`Unsupported rules ${rules}`);
  const tag = new TextEncoder().encode("crimson:run:rules\0");
  const bytes = new Uint8Array(tag.length + 4 + legacy.length);
  bytes.set(tag);
  new DataView(bytes.buffer).setUint32(tag.length, rules, true);
  bytes.set(legacy, tag.length + 4);
  return bytes;
}

function legacyIdentity(transport: Uint8Array): Uint8Array {
  const at = PLAYERS_WORD * 4;
  if (new DataView(transport.buffer, transport.byteOffset + at, 4).getUint32(0, true) !== 1) return transport;
  const bytes = new Uint8Array(transport.length - 4);
  bytes.set(transport.subarray(0, at));
  bytes.set(transport.subarray(at + 4), at);
  return bytes;
}


export function legacyCoopReload(replay: Replay): boolean {
  if (replay.rules !== 1 || replay.run.player_count === 1 || replay.run.preserve_bugs) return false;
  // Service vectors from bde24bef7, after the co-op reload fix.
  if (replay.game_version === "0.18.0+build.64a9589f5fbefdc036f0559b") return false;
  const match = /^(\d+)\.(\d+)\.(\d+)(.*)$/.exec(replay.game_version);
  if (match) {
    const [major, minor, patch] = [Number(match[1]), Number(match[2]), Number(match[3])];
    if (major! > 0 || minor! >= 19) return false;
    if (minor! < 18 || (minor === 18 && patch === 0 && match[4] === "")) return true;
  }
  throw new TransportError("rules-1 co-op reload behavior requires known recording-build provenance");
}
