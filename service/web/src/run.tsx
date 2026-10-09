// A run's page: its stats, experience against the board's top run and the player's best, kill rate or damage, weapons,
// perks and timed bonuses, and where it was played, all from the timeline verification recorded (src/timeline.ts).
import { type Accessor, createMemo, createResource, createSignal, For, type JSX, Show } from "solid-js";
import { type Category, type RunDetailView, type SignalName, type Timeline } from "../../src/api-types";
import { get, moderate } from "./api";
import { GameButton } from "./button";
import { formatScore } from "./format";
import perkNames from "./perks.json";
import { playerLabel } from "./names";
import { PilotName, PlayerName } from "./players";
import { paintGround } from "./terrain/draw";
import { type Ground, runGround } from "./terrain/rules";
import weaponData from "./weapons.json";

const PERKS: Record<string, string> = perkNames;
const WEAPONS: Record<string, { name: string; icon_index: number }> = weaponData;

interface Sample {
  t: number;
  xp: number;
  level: number;
  health: number;
  kills: number;
  damage: number;
}

interface Mark {
  t: number;
  name: string;
}

// A timeline as the charts read it: samples by name, perks and weapons by name, and the run's terrain.
interface RunTimeline extends Omit<Timeline, "samples" | "weapons" | "perks"> {
  samples: Sample[];
  weapons: Mark[];
  perks: Mark[];
  terrain: Ground;
}

function prepare(timeline: Timeline, detail: RunDetailView): RunTimeline {
  return {
    ...timeline,
    samples: timeline.samples.map(([t, xp, level, health, kills, damage]) => ({ t, xp, level, health, kills, damage })),
    weapons: timeline.weapons.map(({ t, id }) => ({ t, name: WEAPONS[id]?.name ?? `weapon ${id}` })),
    perks: timeline.perks.map(({ t, id }) => ({ t, name: PERKS[id] ?? `perk ${id}` })),
    terrain: runGround(timeline.seed, detail),
  };
}

const iconOf = (name: string) => Object.values(WEAPONS).find((weapon) => weapon.name === name)?.icon_index ?? 0;

// The last element at or before `t`.
function at<T>(items: T[], t: number, time: (item: T) => number = (item) => (item as { t: number }).t): T {
  let [lo, hi] = [0, items.length - 1];
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (time(items[mid]!) <= t) lo = mid;
    else hi = mid - 1;
  }
  return items[lo]!;
}

const W = 840;
const LEFT = 170;
const RIGHT = 10;
const BLUE = "rgb(70,180,240)";
const RED = "rgb(250,70,60)";
const GREEN = "rgb(128,255,153)";
const GOLD = "rgb(240,200,90)";
const WINDOW_S = 15;
const LABEL_GAP = 24;
// ui_wicons: an 8x8 grid of 32px cells; each icon is two cells wide, at frame icon_index * 2.
const ICON_CELL = 32;

const clock = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}`;
const grouped = (n: number) => Math.round(n).toLocaleString("en-US");
const short = (n: number) => (n >= 1e6 ? `${+(n / 1e6).toFixed(1)}M` : n >= 1000 ? `${Math.round(n / 1000)}k` : String(Math.round(n)));

// A round gridline step at least `rough`: 1, 2 or 5 times a power of ten.
function roundStep(rough: number): number {
  const power = 10 ** Math.floor(Math.log10(Math.max(rough, 1)));
  return [1, 2, 5, 10].map((m) => m * power).find((step) => step >= rough)!;
}

interface Cursor {
  t: Accessor<number | null>;
  set: (t: number | null) => void;
}

// Another run drawn over this one's charts once it is ticked and its timeline has arrived.
interface Rival {
  label: string;
  run: Accessor<RunTimeline | undefined>;
  color: string;
  shown: Accessor<boolean>;
}

const drawn = (rivals: Rival[]) => rivals.filter((rival) => rival.shown() && rival.run()).map((rival) => ({ rival, run: rival.run()! }));

function axis(run: RunTimeline, left = LEFT) {
  const x = (t: number) => left + (t / run.duration_s) * (W - left - RIGHT);
  const track = (cursor: Cursor) => ({
    onMouseMove: (event: MouseEvent) => {
      const box = (event.currentTarget as SVGSVGElement).getBoundingClientRect();
      const px = ((event.clientX - box.left) / box.width) * W;
      cursor.set(Math.max(0, Math.min(run.duration_s, ((px - left) / (W - left - RIGHT)) * run.duration_s)));
    },
    onMouseLeave: () => cursor.set(null),
  });
  return { x, track };
}

function TimeAxis(props: { run: RunTimeline; y: number }) {
  const { x } = axis(props.run);
  // At most about ten labels, on round times.
  const step = [5, 10, 15, 30, 60, 120, 300, 600].find((step) => props.run.duration_s / step <= 10) ?? 1200;
  return (
    <For each={Array.from({ length: Math.floor(props.run.duration_s / step) + 1 }, (_, i) => i * step)}>
      {(t) => (
        <text x={x(t)} y={props.y} class="axis" text-anchor="middle">
          {clock(t)}
        </text>
      )}
    </For>
  );
}

function CursorLine(props: { run: RunTimeline; cursor: Cursor; top: number; bottom: number }) {
  const { x } = axis(props.run);
  return (
    <Show when={props.cursor.t() !== null}>
      <line x1={x(props.cursor.t()!)} x2={x(props.cursor.t()!)} y1={props.top} y2={props.bottom} class="cursor" />
    </Show>
  );
}

function WeaponIcon(props: { icon: number; x: number; y: number; width: number }) {
  const frame = props.icon * 2;
  return (
    <svg x={props.x} y={props.y} width={props.width} height={props.width / 2} viewBox={`${(frame % 8) * ICON_CELL} ${Math.floor(frame / 8) * ICON_CELL} ${ICON_CELL * 2} ${ICON_CELL}`}>
      <image href="/ui/weapons.png" width={ICON_CELL * 8} height={ICON_CELL * 8} />
    </svg>
  );
}

// The game's checkbox, as the quest menu's Hardcore box.
function Check(props: { label: string; checked: boolean; disabled?: string; onToggle: () => void }) {
  return (
    <button type="button" class="check" disabled={props.disabled !== undefined} title={props.disabled} onClick={() => props.onToggle()}>
      <img src={`/ui/check-${props.checked && !props.disabled ? "on" : "off"}.png`} alt="" />
      {props.label}
    </button>
  );
}

// Per-window rates: kills per minute, or damage per second.
function rates(run: RunTimeline, kind: "kills" | "damage") {
  const out: { t: number; value: number }[] = [];
  for (let t = 0; t < run.duration_s; t += WINDOW_S) {
    const end = Math.min(t + WINDOW_S, run.duration_s);
    const delta = at(run.samples, end)[kind] - at(run.samples, t)[kind];
    out.push({ t, value: kind === "kills" ? (delta * 60) / (end - t) : delta / (end - t) });
  }
  return out;
}

function Readout(props: { run: RunTimeline; cursor: Cursor; rivals: Rival[] }) {
  const time = () => props.cursor.t() ?? props.run.duration_s;
  const sample = () => at(props.run.samples, time());
  return (
    <p class="readout">
      <b>{clock(time())}</b> · {grouped(sample().xp)} xp · level {sample().level} · {Math.round(sample().health)} hp
      <For each={drawn(props.rivals)}>
        {({ rival, run: other }) => {
          const end = other.samples.at(-1)!;
          const delta = () => sample().xp - at(other.samples, time()).xp;
          return (
            <>
              {" · "}
              <span style={{ color: rival.color }}>
                {time() > end.t
                  ? `${rival.label} ended at ${clock(end.t)}`
                  : `${delta() >= 0 ? "+" : "-"}${grouped(Math.abs(delta()))} vs ${rival.label}`}
              </span>
            </>
          );
        }}
      </For>
    </p>
  );
}

function ExperienceChart(props: { run: RunTimeline; cursor: Cursor; rivals: Rival[] }) {
  const run = props.run;
  const { x, track } = axis(run);
  const top = 12;
  const plot = 190;
  // Level-ups as ticks on the time axis: their spacing shows the pace, round levels get a taller tick and a label.
  const ticks = plot + 12;
  const tickH = 10;
  const healthTop = ticks + tickH + 24;
  const healthH = 46;
  const milestone = roundStep((run.levels.at(-1)?.level ?? 0) / 10);
  // Labels are kept from the last level back, each at least LABEL_GAP left of the one after it.
  const labelled = () => {
    const kept: typeof run.levels = [];
    for (const level of [...run.levels].reverse()) {
      const after = kept.at(-1);
      if (!after || (level.level % milestone === 0 && x(after.t) - x(level.t) >= LABEL_GAP)) kept.push(level);
    }
    return kept;
  };
  // A longer rival only counts up to this run's end, which is where its line is cut.
  const peak = () => Math.max(run.samples.at(-1)!.xp, ...drawn(props.rivals).map((other) => at(other.run.samples, run.duration_s).xp));
  const step = () => roundStep(peak() / 4);
  const max = () => Math.ceil(peak() / step()) * step();
  const y = (xp: number) => plot - (xp / max()) * (plot - top);
  const line = (samples: { t: number; xp: number }[]) => samples.map((s) => `${x(s.t)},${y(s.xp)}`).join(" ");
  const health =
    `M${x(0)},${healthTop + healthH} ` +
    run.samples.map((s) => `L${x(s.t)},${healthTop + healthH - (s.health / 100) * healthH}`).join(" ") +
    ` L${x(run.duration_s)},${healthTop + healthH} Z`;
  return (
    <svg viewBox={`0 0 ${W} ${healthTop + healthH + 22}`} class="chart" {...track(props.cursor)}>
      <For each={Array.from({ length: max() / step() + 1 }, (_, i) => i * step())}>
        {(v) => (
          <>
            <line x1={LEFT} x2={W - RIGHT} y1={y(v)} y2={y(v)} class="grid" />
            <text x={LEFT - 8} y={y(v) + 4} class="axis" text-anchor="end">
              {short(v)}
            </text>
          </>
        )}
      </For>
      <For each={drawn(props.rivals)}>
        {(other) => <polyline points={line(other.run.samples.filter((s) => s.t <= run.duration_s))} class="rival" stroke={other.rival.color} />}
      </For>
      <polyline points={line(run.samples)} fill="none" stroke={BLUE} stroke-width="2" />
      <text x={LEFT - 8} y={ticks + tickH} class="axis" text-anchor="end">
        level
      </text>
      <For each={run.levels}>
        {(level) => (
          <line x1={x(level.t)} x2={x(level.t)} y1={level.level % milestone === 0 ? ticks - 3 : ticks} y2={ticks + tickH} stroke="#fff" stroke-opacity={level.level % milestone === 0 ? 1 : 0.55} />
        )}
      </For>
      <For each={labelled()}>
        {(level) => (
          <text x={x(level.t)} y={ticks + tickH + 14} class="axis small" text-anchor="middle">
            {level.level}
          </text>
        )}
      </For>
      <text x={LEFT - 8} y={healthTop + 18} class="axis" text-anchor="end">
        health
      </text>
      <path d={health} fill={RED} fill-opacity="0.35" stroke={RED} stroke-width="1" />
      <TimeAxis run={run} y={healthTop + healthH + 18} />
      <CursorLine run={run} cursor={props.cursor} top={top} bottom={healthTop + healthH} />
    </svg>
  );
}

function RateChart(props: { run: RunTimeline; cursor: Cursor; rivals: Rival[]; kind: "kills" | "damage" }) {
  const run = props.run;
  const { x, track } = axis(run);
  const top = 16;
  const bottom = 170;
  const own = createMemo(() => rates(run, props.kind));
  const others = createMemo(() => drawn(props.rivals).map((other) => ({ rival: other.rival, values: rates(other.run, props.kind).filter((v) => v.t < run.duration_s) })));
  // The scale fits the typical windows; a burst above it (a death explosion, a nuke) is clipped and labelled.
  const peak = () => {
    const values = [...own(), ...others().flatMap((o) => o.values)].map((v) => v.value).sort((a, b) => a - b);
    return Math.min(values.at(-1)!, values[Math.floor(values.length * 0.97)]! * 1.25);
  };
  const y = (value: number) => bottom - (Math.min(value, peak()) / peak()) * (bottom - top);
  return (
    <svg viewBox={`0 0 ${W} ${bottom + 22}`} class="chart" {...track(props.cursor)}>
      <For each={[0, 0.5, 1]}>
        {(f) => (
          <>
            <line x1={LEFT} x2={W - RIGHT} y1={y(peak() * f)} y2={y(peak() * f)} class="grid" />
            <text x={LEFT - 8} y={y(peak() * f) + 4} class="axis" text-anchor="end">
              {short(peak() * f)}
            </text>
          </>
        )}
      </For>
      <For each={own()}>
        {(v) => (
          <>
            <rect x={x(v.t)} y={y(v.value)} width={Math.max(1, x(Math.min(v.t + WINDOW_S, run.duration_s)) - x(v.t) - 1)} height={bottom - y(v.value)} fill={BLUE} fill-opacity="0.55" />
            <Show when={v.value > peak()}>
              <text x={x(v.t)} y={top + 10} class="axis" text-anchor="end">
                {short(v.value)}
              </text>
            </Show>
          </>
        )}
      </For>
      <For each={others()}>
        {(other) => (
          <polyline points={other.values.map((v) => `${x(Math.min(v.t + WINDOW_S / 2, run.duration_s))},${y(v.value)}`).join(" ")} class="rival" stroke={other.rival.color} />
        )}
      </For>
      <For each={run.nukes}>
        {(t) => (
          <path d={`M${x(t) - 5},${top - 12} l10,0 l-5,8 Z`} fill={RED}>
            <title>{clock(t)} Nuke</title>
          </path>
        )}
      </For>
      <TimeAxis run={run} y={bottom + 18} />
      <CursorLine run={run} cursor={props.cursor} top={top} bottom={bottom} />
    </svg>
  );
}

function WeaponsChart(props: { run: RunTimeline; cursor: Cursor; held: boolean }) {
  const run = props.run;
  const { x, track } = axis(run);
  const segments = run.weapons.map((w, i) => ({ ...w, end: run.weapons[i + 1]?.t ?? run.duration_s }));
  const names = [...new Set(run.weapons.map((w) => w.name))];
  const totals = names.map((name) => ({ name, seconds: segments.filter((s) => s.name === name).reduce((sum, s) => sum + s.end - s.t, 0) }));
  totals.sort((a, b) => b.seconds - a.seconds);
  const ROW = 30;
  const effects = Object.entries(run.effects);
  const effectsTop = names.length * ROW + 10;
  const EFFECT_ROW = 13;
  const height = () => (props.held ? names.length * ROW + 8 : effectsTop + effects.length * EFFECT_ROW + 26);
  const icon = (name: string, y: number) => (
    <>
      <WeaponIcon icon={iconOf(name)} x={0} y={y} width={52} />
      <text x={58} y={y + 17} class="axis small">
        {name}
      </text>
    </>
  );
  const label = (text: string, y: number, size = "axis") => (
    <text x={LEFT - 8} y={y} class={size} text-anchor="end">
      {text}
    </text>
  );
  return (
    <svg viewBox={`0 0 ${W} ${height()}`} class="chart" {...track(props.cursor)}>
      <Show
        when={!props.held}
        fallback={
          <For each={totals}>
            {(total, i) => {
              const width = (total.seconds / totals[0]!.seconds) * (W - LEFT - RIGHT - 110);
              return (
                <g>
                  {icon(total.name, i() * ROW + 2)}
                  <rect x={LEFT} y={i() * ROW + 6} width={width} height={18} fill={BLUE} fill-opacity="0.55" />
                  <text x={LEFT + width + 8} y={i() * ROW + 20} class="axis">
                    {clock(total.seconds)} · {Math.round((total.seconds / run.duration_s) * 100)}%
                  </text>
                </g>
              );
            }}
          </For>
        }
      >
        <For each={names}>
          {(name, i) => (
            <g>
              {icon(name, i() * ROW + 2)}
              <line x1={LEFT} x2={W - RIGHT} y1={i() * ROW + 15} y2={i() * ROW + 15} class="grid" />
              <For each={segments.filter((s) => s.name === name)}>
                {(s) => (
                  <rect x={x(s.t)} y={i() * ROW + 6} width={Math.max(2, x(s.end) - x(s.t))} height={18} fill={BLUE} fill-opacity="0.7">
                    <title>
                      {name}, {clock(s.t)}–{clock(s.end)}
                    </title>
                  </rect>
                )}
              </For>
            </g>
          )}
        </For>
        <For each={effects}>
          {([name, spans], i) => (
            <g>
              {label(name, effectsTop + i() * EFFECT_ROW + 9, "axis small")}
              <For each={spans}>
                {([start, end]) => (
                  <rect x={x(start)} y={effectsTop + i() * EFFECT_ROW} width={Math.max(1.5, x(end) - x(start))} height={EFFECT_ROW - 4} fill={GOLD} fill-opacity="0.7">
                    <title>
                      {name} {clock(start)}–{clock(end)}
                    </title>
                  </rect>
                )}
              </For>
            </g>
          )}
        </For>
        <TimeAxis run={run} y={height() - 6} />
        <CursorLine run={run} cursor={props.cursor} top={0} bottom={height() - 22} />
      </Show>
    </svg>
  );
}

function Perks(props: { run: RunTimeline }) {
  return (
    <Show when={props.run.perks.length} fallback={<p class="muted">No perks picked.</p>}>
      <details class="perk-list" open>
        <summary>Perks <span class="muted">· {props.run.perks.length} picked</span></summary>
        <ol>
          <For each={props.run.perks}>
            {(perk) => (
              <li>
                <span class="perk-pick">
                  <span>{perk.name}</span>
                  <span class="perk-time">{clock(perk.t)}</span>
                </span>
              </li>
            )}
          </For>
        </ol>
      </details>
    </Show>
  );
}

function Arena(props: { run: RunTimeline; cursor: Cursor; outcome: string }) {
  const run = props.run;
  const [ground] = createResource(() => paintGround(run.terrain));
  // Where the player spent the run: the 10 Hz positions binned into 32px cells.
  const CELL = 32;
  const bins = new Map<number, number>();
  for (const [, x, y] of run.path) {
    const key = Math.floor(y / CELL) * 64 + Math.floor(x / CELL);
    bins.set(key, (bins.get(key) ?? 0) + 1);
  }
  const most = Math.max(...bins.values());
  const TRAIL_S = 20;
  const now = () => props.cursor.t() ?? run.duration_s;
  const trail = () => run.path.filter(([t]) => t > now() - TRAIL_S && t <= now());
  const here = () => at(run.path, now(), (p) => p[0]);
  return (
    <div class="arena-row">
      <div class="arena" style={{ "background-image": ground() ? `url(${ground()})` : "none" }}>
        <svg viewBox="0 0 1024 1024">
          <filter id="heat-blur">
            <feGaussianBlur stdDeviation="14" />
          </filter>
          <g filter="url(#heat-blur)">
          <For each={[...bins]}>
            {([key, count]) => (
              <rect x={(key % 64) * CELL} y={Math.floor(key / 64) * CELL} width={CELL} height={CELL} fill={GOLD} fill-opacity={0.85 * Math.sqrt(count / most)} />
            )}
          </For>
          </g>
          <polyline points={trail().map(([, x, y]) => `${x},${y}`).join(" ")} fill="none" stroke="#fff" stroke-width="5" stroke-linejoin="round" stroke-opacity="0.9" />
          <Show
            when={props.cursor.t() !== null}
            fallback={
              <g role="img" aria-label={props.outcome === "quest_completed" ? "Quest completed" : props.outcome === "death" ? "Death" : "Run ended"}>
                <Show when={props.outcome === "quest_completed"} fallback={
                  <Show when={props.outcome === "death"} fallback={<circle cx={here()[1]} cy={here()[2]} r="18" fill="none" stroke={GOLD} stroke-width="6" />}>
                    <path d={`M${here()[1] - 18},${here()[2] - 18} l36,36 M${here()[1] + 18},${here()[2] - 18} l-36,36`} stroke={RED} stroke-width="8" />
                  </Show>
                }>
                  <path d={`M${here()[1] - 20},${here()[2]} l14,16 l28,-32`} fill="none" stroke={GREEN} stroke-width="8" stroke-linecap="round" stroke-linejoin="round" />
                </Show>
              </g>
            }
          >
            <circle cx={here()[1]} cy={here()[2]} r="14" fill="#fff" stroke="#000" stroke-width="4" />
          </Show>
        </svg>
      </div>
      <p class="muted arena-note">
        Gold is where the player spent the run. The white line is their last {TRAIL_S} seconds before the time under the cursor, or before
        the run ended. {props.outcome === "quest_completed" ? "The green check marks quest completion." : props.outcome === "death" ? "The red X marks death." : "The gold circle marks the end of the run."}
      </p>
    </div>
  );
}

function Stats(props: { run: RunTimeline; detail: RunDetailView }) {
  const run = props.run;
  const result = props.detail.result;
  const end = run.samples.at(-1)!;
  const tiles: [string, string][] = [
    [props.detail.board === "survival" ? "survived" : "quest time", clock(result.elapsed_ms / 1000)],
    ["experience", grouped(result.experience)],
    ["level", String(end.level)],
    ["kills", grouped(result.kills)],
    ["kills / min", grouped(result.kills / (run.duration_s / 60))],
    ["damage / s", grouped(end.damage / run.duration_s)],
    ["accuracy", result.shots_fired ? `${Math.round((result.shots_hit / result.shots_fired) * 100)}%` : "-"],
    ["perks", String(run.perks.length)],
  ];
  return (
    <div class="tiles">
      <For each={tiles}>
        {([label, value]) => (
          <div class="tile">
            <span class="muted">{label}</span>
            <b>{value}</b>
          </div>
        )}
      </For>
    </div>
  );
}

// Use the stored result, not rounded chart samples: player 0's whole HP earns 50 ms, each pending perk 1 s.
function QuestScore(props: { detail: RunDetailView }) {
  const result = props.detail.result;
  const lifeBonus = Math.trunc(result.health) * 50;
  const perkBonus = result.pending_perks * 1000;
  const adjustment = (bonus: number) => `${bonus > 0 ? "−" : bonus < 0 ? "+" : ""}${formatScore("quests", Math.abs(bonus))}`;
  return (
    <div class="quest-score">
      <dl>
        <dt>Quest time</dt><dd>{formatScore("quests", result.elapsed_ms)}</dd>
        <dt>Life bonus</dt><dd>{adjustment(lifeBonus)}</dd>
        <dt>Unpicked perks <span class="muted">({result.pending_perks})</span></dt><dd>{adjustment(perkBonus)}</dd>
      </dl>
      <Show when={result.elapsed_ms - lifeBonus - perkBonus === 0}>
        <p class="muted">An exactly zero final time is recorded as 0:00.001.</p>
      </Show>
    </div>
  );
}

function boardPath(detail: RunDetailView): string {
  return detail.board === "survival" ? "/boards/survival" : `/boards/${detail.board}/${detail.quest}`;
}

export const SIGNAL_LABELS: Record<SignalName, string> = {
  aim_on_creature: "Aim on a creature",
  exact_moves: "Exact pad moves",
  reversals_per_min: "Reversals a minute",
  aim_jump_p99: "Aim jump, p99",
  one_tick_fire: "One-tick fire",
};

const CATEGORY_SOURCES = {
  moderator: "a moderator set it",
  pilot: "the replay declares a pilot",
  account: "a moderator marked the account as a bot",
  default: "no pilot, and the account is not marked",
};

// A moderator's view of the run: why it is in its category, its input signals, and the category controls.
function RunModerationPanel(props: { detail: RunDetailView; reload: () => void }) {
  const moderation = props.detail.moderation!;
  const set = async (category: Category | null) => (await moderate(`/api/mod/runs/${props.detail.id}`, { category })) && props.reload();
  return (
    <>
      <h3>Moderation</h3>
      <p class="muted">
        A {props.detail.category} run: {CATEGORY_SOURCES[moderation.source]}.
      </p>
      <Show when={moderation.signals} fallback={<p class="muted">The run's signals could not be measured.</p>}>
        {(signals) => (
          <div class="tiles">
            <For each={Object.keys(SIGNAL_LABELS) as SignalName[]}>
              {(name) => (
                <div class="tile">
                  <span class="muted">{SIGNAL_LABELS[name]}</span>
                  <b classList={{ flag: moderation.flagged.includes(name) }}>{signals()[name]}</b>
                </div>
              )}
            </For>
          </div>
        )}
      </Show>
      <p class="buttons">
        <Show when={props.detail.category !== "bot"}>
          <GameButton label="Bot run" onClick={() => set("bot")} />
        </Show>
        <Show when={props.detail.category !== "human"}>
          <GameButton label="Human run" onClick={() => set("human")} />
        </Show>
        <Show when={moderation.override}>
          <GameButton label="Follow the account" onClick={() => set(null)} />
        </Show>
      </p>
    </>
  );
}

// The run's panels; the top run's and the player's best's timelines load when their boxes are ticked.
export function runPanels(detail: RunDetailView, reload: () => void): (() => JSX.Element)[] {
  const run = detail.timeline ? prepare(detail.timeline, detail) : null;
  const header = () => (
    <div class="run-overview">
      <div>
        <h2>
          {detail.title}
          <Show when={detail.rank}>{(rank) => <> · #{rank()}</>}</Show>
          <Show when={detail.category === "bot"}>
            <span class="tag">bot</span>
          </Show>
        </h2>
        <p class="run-player">
          <PlayerName player={detail.player} heading />
          <Show when={detail.name !== detail.player.name}>
            <span class="muted"> · played as {detail.name}</span>
          </Show>
        </p>
        <Show when={detail.pilot}>
          {(pilot) => (
            <p class="run-player muted">
              Played by <PilotName pilot={pilot()} />
            </p>
          )}
        </Show>
        <Show when={detail.result.outcome === "quest_completed"}><p class="score-label muted">Final time</p></Show>
        <p class="run-score">{formatScore(detail.board, detail.score)}</p>
        <Show when={detail.result.outcome === "quest_completed"}><QuestScore detail={detail} /></Show>
        <p class="muted">
          {new Date(detail.accepted_at).toISOString().slice(0, 10)} · {detail.recorder.client} {detail.recorder.version} · {detail.recorder.platform}
        </p>
        <Show when={detail.retired}>
          {(reason) => <p class="muted">Retired from the boards: {reason()}. The game no longer plays it as recorded.</p>}
        </Show>
        <p class="buttons">
          <Show when={!detail.retired}>
            <GameButton label="Watch" href={`/play/?watch=${detail.id}`} native />
          </Show>
          <GameButton label="Download replay" href={`/runs/${detail.id}.crd`} native />
          <GameButton label="Board" href={boardPath(detail)} />
        </p>
      </div>
      <Show when={run}>{(run) => <Stats run={run()} detail={detail} />}</Show>
    </div>
  );
  const moderation = detail.moderation ? [() => <RunModerationPanel detail={detail} reload={reload} />] : [];
  if (!run) return [header, () => <p class="muted">This run's timeline is not available.</p>, ...moderation];
  const [t, set] = createSignal<number | null>(null);
  const cursor: Cursor = { t, set };
  const [showTop, setShowTop] = createSignal(detail.top !== null);
  const [showBest, setShowBest] = createSignal(detail.best !== null);
  const rival = (id: string | undefined, shown: Accessor<boolean>) => {
    const [loaded] = createResource(() => (shown() && id) || false, (rid) => get<Timeline>(`/api/runs/${rid}/timeline`));
    return () => (loaded() ? prepare(loaded()!, detail) : undefined);
  };
  const rivals: Rival[] = [
    ...(detail.top ? [{ label: `#1 ${detail.top.name}`, run: rival(detail.top.id, showTop), color: GOLD, shown: showTop }] : []),
    ...(detail.best ? [{ label: "personal best", run: rival(detail.best.id, showBest), color: GREEN, shown: showBest }] : []),
  ];
  const [rate, setRate] = createSignal<"kills" | "damage">("kills");
  const [held, setHeld] = createSignal(false);
  const name = playerLabel(detail.player);
  return [
    header,
    ...moderation,
    () => (
      <>
        <div class="panel-head">
          <h3>Experience</h3>
          <span class="checks">
            <Check label="Top score" checked={showTop()} disabled={detail.top ? undefined : "this is the top score"} onToggle={() => setShowTop(!showTop())} />
            <Check label="Personal best" checked={showBest()} disabled={detail.best ? undefined : `this is ${name}'s best run`} onToggle={() => setShowBest(!showBest())} />
          </span>
        </div>
        <Readout run={run} cursor={cursor} rivals={rivals} />
        <ExperienceChart run={run} cursor={cursor} rivals={rivals} />
      </>
    ),
    () => (
      <>
        <div class="panel-head">
          <span class="head-title">
            <h3>{rate() === "kills" ? "Kills per minute" : "Damage per second"}</h3>
            <Show when={run.nukes.length}>
              <span class="legend">
                <svg width="10" height="8" viewBox="0 0 10 8" aria-hidden="true">
                  <path d="M0,0 l10,0 l-5,8 Z" fill={RED} />
                </svg>
                Nuke
              </span>
            </Show>
          </span>
          <span class="buttons">
            <GameButton label="Kills/min" on={rate() === "kills"} onClick={() => setRate("kills")} />
            <GameButton label="Damage/s" on={rate() === "damage"} onClick={() => setRate("damage")} />
          </span>
        </div>
        <RateChart run={run} cursor={cursor} rivals={rivals} kind={rate()} />
      </>
    ),
    () => (
      <>
        <div class="panel-head">
          <h3>Weapons and bonuses</h3>
          <span class="buttons">
            <GameButton label="Timeline" on={!held()} onClick={() => setHeld(false)} />
            <GameButton label="Time held" on={held()} onClick={() => setHeld(true)} />
          </span>
        </div>
        <WeaponsChart run={run} cursor={cursor} held={held()} />
        <Perks run={run} />
      </>
    ),
    () => (
      <>
        <h3>Arena</h3>
        <Arena run={run} cursor={cursor} outcome={detail.result.outcome} />
      </>
    ),
  ];
}
