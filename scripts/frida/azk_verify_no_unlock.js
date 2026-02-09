"use strict";

// AZK runtime verification harness.
//
// Goal:
// 1) Force-enter AlienZooKeeper (state 0x1a) on attach.
// 2) Auto-solve quickly by applying valid swap+match steps via board memory.
// 3) Verify no external unlock/transition side-effects occur.
//
// Attach:
//   frida -n crimsonland.exe -l C:\share\frida\azk_verify_no_unlock.js
//
// Optional env:
//   CRIMSON_FRIDA_DIR=C:\share\frida
//   CRIMSON_AZK_MAX_STEPS=512
//   CRIMSON_AZK_BATCH_STEPS=24
//   CRIMSON_AZK_SETTLE_MS=2500
//   CRIMSON_AZK_WEAPON_SLOTS=96
//   CRIMSON_AZK_FORCE_CLEAR=1
//   CRIMSON_AZK_TIMER_RESET_MS=9600
//   CRIMSON_AZK_MOVE_DELAY_MS=40
//   CRIMSON_AZK_MEM_STORE_CAP=67108864
//   CRIMSON_AZK_MEM_DIFF_SAMPLES=32

const DEFAULT_LOG_DIR = "C:\\share\\frida";

function getEnv(name, fallback) {
  try {
    const value = Process.env[name];
    return value == null || value === "" ? fallback : value;
  } catch (_) {
    return fallback;
  }
}

function getIntEnv(name, fallback) {
  const raw = getEnv(name, null);
  if (raw == null) return fallback;
  const value = parseInt(String(raw).trim(), 0);
  return Number.isFinite(value) ? value : fallback;
}

function getBoolEnv(name, fallback) {
  const raw = getEnv(name, null);
  if (raw == null) return fallback;
  const value = String(raw).trim().toLowerCase();
  if (value === "1" || value === "true" || value === "yes" || value === "on") return true;
  if (value === "0" || value === "false" || value === "no" || value === "off") return false;
  return fallback;
}

function joinPath(base, leaf) {
  if (!base) return leaf;
  const sep = base.endsWith("\\") || base.endsWith("/") ? "" : "\\";
  return base + sep + leaf;
}

const LOG_DIR = getEnv("CRIMSON_FRIDA_DIR", DEFAULT_LOG_DIR);

const CONFIG = {
  outPath: joinPath(LOG_DIR, "azk_verify_no_unlock.jsonl"),
  targetState: 0x1a,
  maxSteps: Math.max(1, getIntEnv("CRIMSON_AZK_MAX_STEPS", 512)),
  batchSteps: Math.max(1, getIntEnv("CRIMSON_AZK_BATCH_STEPS", 24)),
  settleMs: Math.max(100, getIntEnv("CRIMSON_AZK_SETTLE_MS", 2500)),
  weaponSlots: Math.max(16, getIntEnv("CRIMSON_AZK_WEAPON_SLOTS", 96)),
  forceClear: getBoolEnv("CRIMSON_AZK_FORCE_CLEAR", true),
  timerResetMs: Math.max(0, getIntEnv("CRIMSON_AZK_TIMER_RESET_MS", 0x2580)),
  moveDelayMs: Math.max(0, getIntEnv("CRIMSON_AZK_MOVE_DELAY_MS", 40)),
  memStoreCapBytes: Math.max(1024 * 1024, getIntEnv("CRIMSON_AZK_MEM_STORE_CAP", 64 * 1024 * 1024)),
  memDiffSampleLimit: Math.max(1, getIntEnv("CRIMSON_AZK_MEM_DIFF_SAMPLES", 32)),
};

const LINK_BASE = ptr("0x00400000");
const MODULE_NAME = "crimsonland.exe";

const ADDR = {
  game_state_set: 0x004461c0,
  game_state_prev: 0x0048726c,
  game_state_id: 0x00487270,
  game_state_pending: 0x00487274,
  ui_transition_direction: 0x0048724c,

  credits_secret_unlock_flag: 0x004811c4,
  credits_secret_selected_index: 0x00472ef0,
  credits_secret_flags: 0x00481c10,
  credits_secret_board: 0x004819ec,
  credits_secret_timer_ms: 0x004824e4,
  credits_secret_anim_time_ms: 0x004824e8,
  credits_secret_score: 0x004824ec,

  quest_results_unlock_weapon_id: 0x00482700,
  quest_results_unlock_perk_id: 0x00482704,
  weapon_table: 0x004d7a2c,
};

const STRIDE = {
  boardCells: 36,
  boardSide: 6,
  weaponEntry: 0x7c,
  weaponUnlockedOffset: 0x40,
};

const TIMER_MATCH_BONUS_MS = 2000;
const CLEAR_SENTINEL = -3;
const U32_MASK = 0xffffffff;

// Known fast-changing globals/ranges during AZK and regular UI runtime.
const EXPECTED_VOLATILE_RANGES = [
  { start: 0x00480840, size: 0x80, name: "core_timing" },
  { start: 0x004819d0, size: 0x260, name: "azk_runtime_block" },
  { start: 0x004824e4, size: 0x10, name: "azk_timer_score_block" },
  { start: 0x0048718c, size: 0x100, name: "state_block" },
  { start: 0x00489de8, size: 0x80, name: "azk_layout_anim_block" },
];

let exeModule = null;
let baseExe = null;
let logFile = null;
let logWarned = false;
let gameStateSetFn = null;

const observedGameStateSet = [];
const selfStateSetWindow = {
  target: null,
  untilMs: 0,
};

const runState = {
  phase: "init",
  startedMs: 0,
  enterDeadlineMs: 0,
  settleDeadlineMs: 0,
  stepCount: 0,
  nextStepAtMs: 0,
  baseline: null,
  memBaseline: null,
  solveStatus: "not_started",
  stateSetCallsBeforeSolve: 0,
};

function nowMs() {
  return Date.now();
}

function nowIso() {
  return new Date().toISOString();
}

function toHexU32(value) {
  let v = (value >>> 0).toString(16);
  while (v.length < 8) v = "0" + v;
  return "0x" + v;
}

function ptrToU32(p) {
  return p.toUInt32() >>> 0;
}

function staticPtr(staticVa) {
  return baseExe.add(ptr(staticVa).sub(LINK_BASE));
}

function openLog() {
  if (logFile !== null) return;
  try {
    logFile = new File(CONFIG.outPath, "w");
  } catch (_) {
    logFile = null;
  }
}

function writeLog(event) {
  const payload = Object.assign(
    {
      ts_ms: nowMs(),
      ts_iso: nowIso(),
      script: "azk_verify_no_unlock",
    },
    event,
  );
  const line = JSON.stringify(payload);
  let wrote = false;
  try {
    openLog();
    if (logFile) {
      logFile.write(line + "\n");
      wrote = true;
    }
  } catch (_) {}
  if (!wrote && !logWarned) {
    logWarned = true;
    console.log("azk_verify_no_unlock: file logging unavailable, console only");
  }
  console.log(line);
}

function safeReadS32(p) {
  try {
    return p.readS32();
  } catch (_) {
    return null;
  }
}

function safeReadU8(p) {
  try {
    return p.readU8();
  } catch (_) {
    return null;
  }
}

function safeWriteS32(p, value) {
  try {
    p.writeS32(value | 0);
    return true;
  } catch (_) {
    return false;
  }
}

function safeReadBytes(p, size) {
  try {
    const raw = p.readByteArray(size);
    if (raw == null) return null;
    return new Uint8Array(raw);
  } catch (_) {
    return null;
  }
}

function enumerateWritableExeRanges() {
  let ranges = [];
  try {
    ranges = exeModule.enumerateRanges("rw-");
  } catch (_) {
    ranges = [];
  }
  const out = [];
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    const size = r.size >>> 0;
    if (size <= 0) continue;
    out.push({
      base: r.base,
      size,
      protection: r.protection || "rw-",
    });
  }
  out.sort((a, b) => {
    const aa = ptrToU32(a.base);
    const bb = ptrToU32(b.base);
    return aa - bb;
  });
  return out;
}

function rangeKey(basePtr, size) {
  return basePtr.toString() + ":" + (size >>> 0);
}

function isExpectedVolatileAddr(addrU32) {
  const a = addrU32 >>> 0;
  for (let i = 0; i < EXPECTED_VOLATILE_RANGES.length; i++) {
    const r = EXPECTED_VOLATILE_RANGES[i];
    const start = r.start >>> 0;
    const end = (start + r.size) >>> 0;
    if (a >= start && a < end) return true;
  }
  return false;
}

function expectedOverlapBytes(startU32, sizeU32) {
  const start = startU32 >>> 0;
  const end = (start + sizeU32) >>> 0;
  let total = 0;
  for (let i = 0; i < EXPECTED_VOLATILE_RANGES.length; i++) {
    const r = EXPECTED_VOLATILE_RANGES[i];
    const rs = r.start >>> 0;
    const re = (rs + r.size) >>> 0;
    const lo = Math.max(start, rs);
    const hi = Math.min(end, re);
    if (hi > lo) total += hi - lo;
  }
  return total >>> 0;
}

function captureWritableSnapshot(tag) {
  const ranges = enumerateWritableExeRanges();
  const info = [];
  const bytesByKey = Object.create(null);
  let totalBytes = 0;
  let totalStoredBytes = 0;
  for (let i = 0; i < ranges.length; i++) {
    const r = ranges[i];
    totalBytes += r.size;
    const bytes = safeReadBytes(r.base, r.size);
    const hash = bytes ? fnv1aBytes(bytes) : null;
    const key = rangeKey(r.base, r.size);
    if (bytes && totalStoredBytes + r.size <= CONFIG.memStoreCapBytes) {
      bytesByKey[key] = bytes;
      totalStoredBytes += r.size;
    }
    info.push({
      key,
      base: r.base.toString(),
      base_u32: toHexU32(ptrToU32(r.base)),
      size: r.size,
      protection: r.protection,
      hash,
      stored: !!bytesByKey[key],
      read_ok: bytes != null,
    });
  }
  return {
    tag,
    range_count: info.length,
    total_bytes: totalBytes >>> 0,
    stored_bytes: totalStoredBytes >>> 0,
    ranges: info,
    _bytesByKey: bytesByKey,
  };
}

function summarizeWritableSnapshot(snapshot) {
  return {
    tag: snapshot.tag,
    range_count: snapshot.range_count,
    total_bytes: snapshot.total_bytes,
    stored_bytes: snapshot.stored_bytes,
  };
}

function diffWritableSnapshots(before, after) {
  const byKeyAfter = Object.create(null);
  for (let i = 0; i < after.ranges.length; i++) {
    byKeyAfter[after.ranges[i].key] = after.ranges[i];
  }

  const changedRanges = [];
  let changedRangeCount = 0;
  let unexpectedRangeCount = 0;
  let changedBytesKnown = 0;
  let unexpectedBytesKnown = 0;
  let unknownChangedRanges = 0;

  for (let i = 0; i < before.ranges.length; i++) {
    const b = before.ranges[i];
    const a = byKeyAfter[b.key];
    if (!a) {
      changedRangeCount += 1;
      unknownChangedRanges += 1;
      changedRanges.push({
        key: b.key,
        base_u32: b.base_u32,
        size: b.size,
        kind: "missing_after",
      });
      continue;
    }
    if (b.hash === a.hash) continue;

    changedRangeCount += 1;

    const startU32 = ptrToU32(ptr(a.base));
    const expectedSpanBytes = expectedOverlapBytes(startU32, a.size);
    const beforeBytes = before._bytesByKey[b.key] || null;
    const afterBytes = after._bytesByKey[a.key] || null;

    const detail = {
      key: b.key,
      base_u32: b.base_u32,
      size: b.size,
      hash_before: b.hash,
      hash_after: a.hash,
      expected_span_bytes: expectedSpanBytes,
      changed_bytes: null,
      expected_changed_bytes: null,
      unexpected_changed_bytes: null,
      sample_changed_offsets: [],
      sample_unexpected_offsets: [],
      compared: false,
    };

    if (beforeBytes && afterBytes && beforeBytes.length === afterBytes.length) {
      let changed = 0;
      let expectedChanged = 0;
      const sampleChanged = [];
      const sampleUnexpected = [];
      for (let off = 0; off < beforeBytes.length; off++) {
        if (beforeBytes[off] === afterBytes[off]) continue;
        changed += 1;
        if (sampleChanged.length < CONFIG.memDiffSampleLimit) sampleChanged.push(off);
        const addr = (startU32 + off) & U32_MASK;
        if (isExpectedVolatileAddr(addr)) {
          expectedChanged += 1;
        } else if (sampleUnexpected.length < CONFIG.memDiffSampleLimit) {
          sampleUnexpected.push(off);
        }
      }
      const unexpectedChanged = changed - expectedChanged;
      detail.changed_bytes = changed;
      detail.expected_changed_bytes = expectedChanged;
      detail.unexpected_changed_bytes = unexpectedChanged;
      detail.sample_changed_offsets = sampleChanged;
      detail.sample_unexpected_offsets = sampleUnexpected;
      detail.compared = true;
      changedBytesKnown += changed;
      unexpectedBytesKnown += unexpectedChanged;
      if (unexpectedChanged > 0) unexpectedRangeCount += 1;
    } else {
      unknownChangedRanges += 1;
      if (expectedSpanBytes < a.size) {
        // Conservative: if range has non-volatile addresses and couldn't compare bytes,
        // treat as unexpected changed range.
        unexpectedRangeCount += 1;
      }
    }

    changedRanges.push(detail);
  }

  changedRanges.sort((lhs, rhs) => {
    const a = parseInt(lhs.base_u32, 16);
    const b = parseInt(rhs.base_u32, 16);
    return a - b;
  });

  return {
    before_summary: summarizeWritableSnapshot(before),
    after_summary: summarizeWritableSnapshot(after),
    changed_range_count: changedRangeCount,
    unexpected_range_count: unexpectedRangeCount,
    unknown_changed_range_count: unknownChangedRanges,
    changed_bytes_known: changedBytesKnown,
    unexpected_bytes_known: unexpectedBytesKnown,
    changed_ranges: changedRanges,
  };
}

function safeReadState() {
  return {
    state_prev: safeReadS32(staticPtr(ADDR.game_state_prev)),
    state_id: safeReadS32(staticPtr(ADDR.game_state_id)),
    state_pending: safeReadS32(staticPtr(ADDR.game_state_pending)),
    ui_transition_direction: safeReadS32(staticPtr(ADDR.ui_transition_direction)),
  };
}

function safeReadAzkGlobals() {
  return {
    unlock_flag: safeReadU8(staticPtr(ADDR.credits_secret_unlock_flag)),
    flags: safeReadU8(staticPtr(ADDR.credits_secret_flags)),
    selected_index: safeReadS32(staticPtr(ADDR.credits_secret_selected_index)),
    timer_ms: safeReadS32(staticPtr(ADDR.credits_secret_timer_ms)),
    anim_time_ms: safeReadS32(staticPtr(ADDR.credits_secret_anim_time_ms)),
    score: safeReadS32(staticPtr(ADDR.credits_secret_score)),
    quest_unlock_weapon_id: safeReadS32(staticPtr(ADDR.quest_results_unlock_weapon_id)),
    quest_unlock_perk_id: safeReadS32(staticPtr(ADDR.quest_results_unlock_perk_id)),
  };
}

function readBoard() {
  const board = new Array(STRIDE.boardCells);
  const base = staticPtr(ADDR.credits_secret_board);
  for (let i = 0; i < STRIDE.boardCells; i++) {
    const value = safeReadS32(base.add(i * 4));
    if (value == null) return null;
    board[i] = value;
  }
  return board;
}

function writeBoard(board) {
  if (!board || board.length !== STRIDE.boardCells) return false;
  const base = staticPtr(ADDR.credits_secret_board);
  for (let i = 0; i < STRIDE.boardCells; i++) {
    if (!safeWriteS32(base.add(i * 4), board[i])) return false;
  }
  return true;
}

function boardStats(board) {
  let active = 0;
  let empty = 0;
  let cleared = 0;
  let other = 0;
  for (let i = 0; i < board.length; i++) {
    const v = board[i];
    if (v >= 0) {
      active += 1;
    } else if (v === -1) {
      empty += 1;
    } else if (v === CLEAR_SENTINEL) {
      cleared += 1;
    } else {
      other += 1;
    }
  }
  return {
    active,
    empty,
    cleared,
    other,
  };
}

function fnv1aBytes(bytes) {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i] & 0xff;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return toHexU32(h);
}

function readWeaponUnlockSnapshot() {
  const statuses = [];
  const unlockedIds = [];
  const base = staticPtr(ADDR.weapon_table);
  let scanned = 0;
  for (let i = 0; i < CONFIG.weaponSlots; i++) {
    const unlocked = safeReadU8(base.add(i * STRIDE.weaponEntry + STRIDE.weaponUnlockedOffset));
    if (unlocked == null) break;
    statuses.push(unlocked);
    if (unlocked !== 0) unlockedIds.push(i);
    scanned += 1;
  }
  return {
    scanned_slots: scanned,
    unlocked_ids: unlockedIds,
    status_hash: fnv1aBytes(statuses),
  };
}

function findMatch(board) {
  const side = STRIDE.boardSide;
  for (let row = 0; row < side; row++) {
    const base = row * side;
    for (let col = 0; col < side - 2; col++) {
      const idx = base + col;
      const v = board[idx];
      if (v < 0) continue;
      if (board[idx + 1] === v && board[idx + 2] === v) {
        return { has: true, out_idx: idx, out_dir: 1 };
      }
    }
  }
  for (let col = 0; col < side; col++) {
    for (let row = 0; row < side - 2; row++) {
      const idx = row * side + col;
      const v = board[idx];
      if (v < 0) continue;
      if (board[idx + side] === v && board[idx + side * 2] === v) {
        return { has: true, out_idx: idx, out_dir: 0 };
      }
    }
  }
  return { has: false, out_idx: 0, out_dir: 0 };
}

function findWinningSwap(board) {
  for (let i = 0; i < board.length; i++) {
    if (board[i] < 0) continue;
    for (let j = i + 1; j < board.length; j++) {
      if (board[j] < 0) continue;
      const trial = board.slice();
      const t = trial[i];
      trial[i] = trial[j];
      trial[j] = t;
      const match = findMatch(trial);
      if (match.has) {
        return {
          i,
          j,
          out_idx: match.out_idx,
          out_dir: match.out_dir,
          board_after_swap: trial,
        };
      }
    }
  }
  return null;
}

function applyMatch(board, outIdx, outDir) {
  board[outIdx] = CLEAR_SENTINEL;
  if (outDir === 0) {
    if (outIdx + STRIDE.boardSide < board.length) board[outIdx + STRIDE.boardSide] = CLEAR_SENTINEL;
    if (outIdx + STRIDE.boardSide * 2 < board.length) board[outIdx + STRIDE.boardSide * 2] = CLEAR_SENTINEL;
  } else {
    if (outIdx + 1 < board.length) board[outIdx + 1] = CLEAR_SENTINEL;
    if (outIdx + 2 < board.length) board[outIdx + 2] = CLEAR_SENTINEL;
  }
}

function applySolverStep() {
  const timerPtr = staticPtr(ADDR.credits_secret_timer_ms);
  const scorePtr = staticPtr(ADDR.credits_secret_score);
  const selectedPtr = staticPtr(ADDR.credits_secret_selected_index);

  const timerBefore = safeReadS32(timerPtr);
  if (timerBefore == null) return { ok: false, reason: "timer_unreadable" };
  if (timerBefore <= 0) return { ok: false, reason: "timer_expired" };

  const board = readBoard();
  if (!board) return { ok: false, reason: "board_unreadable" };

  const swap = findWinningSwap(board);
  if (!swap) return { ok: false, reason: "no_winning_swap", stats: boardStats(board) };

  applyMatch(swap.board_after_swap, swap.out_idx, swap.out_dir);
  if (!writeBoard(swap.board_after_swap)) {
    return { ok: false, reason: "board_write_failed" };
  }

  const scoreBefore = safeReadS32(scorePtr);
  if (scoreBefore != null) safeWriteS32(scorePtr, scoreBefore + 1);
  safeWriteS32(timerPtr, timerBefore + TIMER_MATCH_BONUS_MS);
  safeWriteS32(selectedPtr, -1);

  const scoreAfter = safeReadS32(scorePtr);
  const timerAfter = safeReadS32(timerPtr);
  const statsAfter = boardStats(swap.board_after_swap);
  return {
    ok: true,
    i: swap.i,
    j: swap.j,
    out_idx: swap.out_idx,
    out_dir: swap.out_dir,
    score_after: scoreAfter,
    timer_after: timerAfter,
    stats_after: statsAfter,
  };
}

function forceClearBoard() {
  const board = readBoard();
  if (!board) return false;
  let changed = 0;
  for (let i = 0; i < board.length; i++) {
    if (board[i] >= 0 || board[i] === -1) {
      board[i] = CLEAR_SENTINEL;
      changed += 1;
    }
  }
  if (!writeBoard(board)) return false;
  safeWriteS32(staticPtr(ADDR.credits_secret_selected_index), -1);
  writeLog({
    event: "force_clear_board",
    changed_cells: changed,
    board_stats: boardStats(board),
  });
  return true;
}

function resolveAbi() {
  if (Process.platform !== "windows") return null;
  if (Process.arch === "x64") return "win64";
  if (Process.arch === "ia32") return "mscdecl";
  return null;
}

function resolveFunctions() {
  const gameStateSetPtr = staticPtr(ADDR.game_state_set);
  const abi = resolveAbi();
  gameStateSetFn = abi
    ? new NativeFunction(gameStateSetPtr, "void", ["int"], abi)
    : new NativeFunction(gameStateSetPtr, "void", ["int"]);
}

function attachHooks() {
  const gameStateSetPtr = staticPtr(ADDR.game_state_set);
  Interceptor.attach(gameStateSetPtr, {
    onEnter(args) {
      const target = args[0].toInt32();
      const ts = nowMs();
      const fromSelf = selfStateSetWindow.target === target && ts <= selfStateSetWindow.untilMs;
      observedGameStateSet.push({
        ts_ms: ts,
        target_state: target,
        from_self: fromSelf,
      });
      writeLog({
        event: "game_state_set",
        target_state: target,
        from_self: fromSelf,
      });
    },
  });
}

function requestStateSet(stateId) {
  selfStateSetWindow.target = stateId | 0;
  selfStateSetWindow.untilMs = nowMs() + 500;
  try {
    gameStateSetFn(stateId | 0);
    return true;
  } catch (e) {
    writeLog({
      event: "error",
      where: "request_state_set",
      state_id: stateId | 0,
      error: String(e),
    });
    return false;
  }
}

function captureSnapshot(tag) {
  const board = readBoard();
  return {
    tag,
    state: safeReadState(),
    azk: safeReadAzkGlobals(),
    board_stats: board ? boardStats(board) : null,
    weapon_unlock: readWeaponUnlockSnapshot(),
    state_set_count: observedGameStateSet.length,
  };
}

function finishWithVerdict() {
  const finalSnapshot = captureSnapshot("final");
  const memFinal = captureWritableSnapshot("mem_final");
  const memDiff = diffWritableSnapshots(runState.memBaseline, memFinal);
  const baseline = runState.baseline;
  const sideEffects = [];

  if (finalSnapshot.state.state_id !== CONFIG.targetState) {
    sideEffects.push("state_id_changed");
  }
  if (baseline.azk.unlock_flag !== finalSnapshot.azk.unlock_flag) {
    sideEffects.push("credits_secret_unlock_flag_changed");
  }
  if (baseline.weapon_unlock.status_hash !== finalSnapshot.weapon_unlock.status_hash) {
    sideEffects.push("weapon_unlock_table_changed");
  }
  if (
    baseline.azk.quest_unlock_weapon_id !== finalSnapshot.azk.quest_unlock_weapon_id ||
    baseline.azk.quest_unlock_perk_id !== finalSnapshot.azk.quest_unlock_perk_id
  ) {
    sideEffects.push("quest_result_unlock_ids_changed");
  }

  const externalStateSets = observedGameStateSet
    .slice(runState.stateSetCallsBeforeSolve)
    .filter((e) => !e.from_self && e.target_state !== CONFIG.targetState)
    .map((e) => e.target_state);

  if (externalStateSets.length > 0) {
    sideEffects.push("unexpected_game_state_set_calls");
  }
  if (memDiff.unexpected_range_count > 0) {
    sideEffects.push("unexpected_memory_diff");
  }

  writeLog({
    event: "verdict",
    solve_status: runState.solveStatus,
    steps: runState.stepCount,
    side_effects: sideEffects,
    no_external_effect: sideEffects.length === 0,
    external_state_targets: externalStateSets,
    memory_diff: memDiff,
    baseline,
    final: finalSnapshot,
  });
}

function startSolverPhase() {
  const timerPtr = staticPtr(ADDR.credits_secret_timer_ms);
  const timerBefore = safeReadS32(timerPtr);
  const timerResetOk = safeWriteS32(timerPtr, CONFIG.timerResetMs);
  const timerAfter = safeReadS32(timerPtr);
  writeLog({
    event: "timer_reset",
    before_ms: timerBefore,
    target_ms: CONFIG.timerResetMs,
    after_ms: timerAfter,
    ok: timerResetOk,
  });

  runState.baseline = captureSnapshot("baseline");
  runState.memBaseline = captureWritableSnapshot("mem_baseline");
  writeLog({
    event: "memory_snapshot_baseline",
    memory: summarizeWritableSnapshot(runState.memBaseline),
    expected_volatile_ranges: EXPECTED_VOLATILE_RANGES,
  });
  runState.stateSetCallsBeforeSolve = observedGameStateSet.length;
  writeLog({
    event: "solver_start",
    baseline: runState.baseline,
    config: CONFIG,
  });
  runState.nextStepAtMs = nowMs();
  runState.phase = "solve";
}

function tickSolve() {
  const state = safeReadState();
  if (state.state_id !== CONFIG.targetState) {
    runState.solveStatus = "left_azk_state";
    runState.phase = "settle";
    runState.settleDeadlineMs = nowMs() + CONFIG.settleMs;
    writeLog({
      event: "solver_stop",
      reason: runState.solveStatus,
      state,
    });
    return;
  }

  if (nowMs() < runState.nextStepAtMs) {
    runState.solveStatus = "continue";
    return;
  }

  for (let i = 0; i < CONFIG.batchSteps; i++) {
    if (runState.stepCount >= CONFIG.maxSteps) {
      runState.solveStatus = "max_steps";
      break;
    }
    const step = applySolverStep();
    if (!step.ok) {
      runState.solveStatus = step.reason;
      if (step.stats) {
        writeLog({
          event: "solver_stop",
          reason: step.reason,
          stats: step.stats,
          steps: runState.stepCount,
        });
      } else {
        writeLog({
          event: "solver_stop",
          reason: step.reason,
          steps: runState.stepCount,
        });
      }
      break;
    }
    runState.stepCount += 1;
    writeLog({
      event: "solver_step",
      step: runState.stepCount,
      swap_i: step.i,
      swap_j: step.j,
      out_idx: step.out_idx,
      out_dir: step.out_dir,
      score_after: step.score_after,
      timer_after: step.timer_after,
      stats_after: step.stats_after,
    });
    runState.nextStepAtMs = nowMs() + CONFIG.moveDelayMs;
    if (step.stats_after.active === 0) {
      runState.solveStatus = "cleared";
      break;
    }
    if (CONFIG.moveDelayMs > 0) {
      runState.solveStatus = "continue";
      break;
    }
  }

  if (runState.solveStatus !== "not_started" && runState.solveStatus !== "continue") {
    if (CONFIG.forceClear) {
      forceClearBoard();
    }
    runState.phase = "settle";
    runState.settleDeadlineMs = nowMs() + CONFIG.settleMs;
    writeLog({
      event: "settle_start",
      solve_status: runState.solveStatus,
      settle_ms: CONFIG.settleMs,
    });
    return;
  }

  if (runState.stepCount >= CONFIG.maxSteps) {
    runState.solveStatus = "max_steps";
    if (CONFIG.forceClear) {
      forceClearBoard();
    }
    runState.phase = "settle";
    runState.settleDeadlineMs = nowMs() + CONFIG.settleMs;
    writeLog({
      event: "settle_start",
      solve_status: runState.solveStatus,
      settle_ms: CONFIG.settleMs,
    });
  } else {
    runState.solveStatus = "continue";
  }
}

function tickSettle() {
  writeLog({
    event: "settle_tick",
    snapshot: captureSnapshot("settle"),
  });
  if (nowMs() < runState.settleDeadlineMs) return;
  finishWithVerdict();
  runState.phase = "done";
}

function mainTick() {
  if (runState.phase === "init") {
    runState.startedMs = nowMs();
    const state = safeReadState();
    writeLog({
      event: "start",
      module_base: baseExe.toString(),
      initial_state: state,
      initial_snapshot: captureSnapshot("initial"),
      config: CONFIG,
    });

    if (state.state_id !== CONFIG.targetState) {
      const ok = requestStateSet(CONFIG.targetState);
      writeLog({
        event: "request_enter_azk",
        requested_state: CONFIG.targetState,
        ok,
      });
      runState.phase = "enter";
      runState.enterDeadlineMs = nowMs() + 4000;
      return;
    }

    writeLog({
      event: "already_in_azk",
      state,
    });
    startSolverPhase();
    return;
  }

  if (runState.phase === "enter") {
    const state = safeReadState();
    if (state.state_id === CONFIG.targetState) {
      writeLog({
        event: "entered_azk",
        state,
      });
      startSolverPhase();
      return;
    }
    if (nowMs() > runState.enterDeadlineMs) {
      writeLog({
        event: "error",
        where: "enter_azk",
        reason: "timeout",
        state,
      });
      runState.phase = "done";
      return;
    }
    return;
  }

  if (runState.phase === "solve") {
    tickSolve();
    return;
  }

  if (runState.phase === "settle") {
    tickSettle();
    return;
  }
}

function start() {
  exeModule = Process.findModuleByName(MODULE_NAME);
  if (!exeModule) {
    console.log("azk_verify_no_unlock: missing module " + MODULE_NAME);
    return;
  }

  baseExe = exeModule.base;
  resolveFunctions();
  attachHooks();

  setInterval(mainTick, 100);
}

start();
