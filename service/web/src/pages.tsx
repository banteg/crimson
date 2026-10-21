import { type Accessor, createSignal, For, type JSX, Show } from "solid-js";
import {
  type Board,
  BOARDS,
  type BoardView,
  type CustomQuest,
  type CustomQuestDetailView,
  type CustomQuestsListView,
  type FlagsView,
  type JoinView,
  type LoginView,
  type ModerationAction,
  type PlayAnalyticsView,
  type ProfileView,
  type QuestMenuView,
  type Role,
  type RunDetailView,
} from "../../src/api-types";
import { boardFor, boardPath, type QuestBoard, questPage, type QuestPage, questsPath, type SurvivalBoard, survivalPage } from "../../src/paths";
import { get, moderate, post } from "./api";
import { formatLongDuration, formatScore, quantity } from "./format";
import { GameButton } from "./button";
import { playerLabel, runLabel } from "./names";
import { gameplayPreference, setGameplayPreference } from "./analytics-preference";
import perkNames from "./perks.json";
import { PilotName, PlayerName, PROVIDER_LABELS, RunPlayers } from "./players";
import { runPanels, SIGNAL_LABELS } from "./run";
import { CoopAnalytics } from "./coop-analytics";
import { questTokens } from "./quest-source";
import weaponData from "./weapons.json";

// What a route shows once its data has arrived: the page title, the quest whose terrain the ground shows (null for
// the game's random terrain), and its panels, which slide in one after another.
export interface Screen {
  title: string | null;
  quest: string | null;
  panels: Panel[];
}

// A keyed panel stays on screen when the next screen has it in the same place, and adopts that panel's data, so its
// elements update in place: the quest menu holds still while its stage, hardcore box or quest changes.
export type Panel = (() => JSX.Element) & { key?: string; adopt?: (next: Panel) => void };

function keep<D>(key: string, data: D, view: (data: Accessor<D>) => JSX.Element): Panel {
  const [current, setCurrent] = createSignal(data);
  const panel = Object.assign(() => view(current), {
    key,
    data,
    adopt: (next: Panel) => setCurrent(() => (next as typeof panel).data),
  });
  return panel;
}

export interface Navigator {
  go(path: string, replace?: boolean): void;
  reload(): void;
}

const STAGES = ["I", "II", "III", "IV", "V"];
export const DOCS = "https://crimson.banteg.xyz/";
const RULES = `${DOCS}rewrite/ranked-rules/`;
const BUGS = `${DOCS}rewrite/original-bugs/`;
const BOTS = `${DOCS}rewrite/bots/`;


// The signed-in account and its role.
async function me(): Promise<{ account: number | null; role: Role }> {
  return (await get<{ account: number | null; role: Role }>("/api/me"))!;
}


const BOARD_NAMES: Record<Board, string> = {
  survival: "Survival",
  quests: "Quests",
  "quests-hardcore": "Quests, hardcore",
  "survival-coop": "Survival, co-op",
  "quests-coop": "Quests, co-op",
  "quests-hardcore-coop": "Quests, hardcore, co-op",
};
const WEAPONS: Record<string, { name: string; icon_index: number }> = weaponData;
const PERKS: Record<string, string> = perkNames;
const BONUS_NAMES: Record<number, string> = {
  2: "Energizer",
  3: "Weapon",
  4: "Weapon Power Up",
  5: "Nuke",
  6: "Double XP",
  7: "Shock Chain",
  8: "Fireblast",
  9: "Reflex Boost",
  10: "Shield",
  11: "Freeze",
  12: "MediKit",
  13: "Speed",
  14: "Fire Bullets",
};

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function Weapon(props: { id: number }) {
  const weapon = () => WEAPONS[props.id];
  return (
    <span class="weapon">
      <Show when={weapon() && weapon()!.icon_index < 32}>
        <span
          class="weapon-icon"
          aria-hidden="true"
          style={{ "background-position": `${-(weapon()!.icon_index % 4) * 32}px ${-Math.floor(weapon()!.icon_index / 4) * 16}px` }}
        />
      </Show>
      {weapon()?.name ?? "Unknown"}
    </span>
  );
}

// A run's replay: watched in the browser game, or downloaded. A retired run no longer plays as recorded, so it only
// downloads; a compact row keeps the Watch icon.
function ReplayLinks(props: { run: string; retired?: string | null; compact?: boolean }) {
  return (
    <span class="replay-links">
      <Show when={!props.retired}>
        <a class="watch" href={`/play/?watch=${props.run}`} data-native title="Watch the replay in the game">
          <svg viewBox="0 0 10 10" aria-hidden="true">
            <path d="M2 1l7 4-7 4z" fill="currentColor" />
          </svg>
          <Show when={!props.compact}>Watch</Show>
        </a>
      </Show>
      <Show when={!props.compact}>
        <a class="crd" href={`/runs/${props.run}.crd`} data-native title="Download the replay file">
          .crd
        </a>
      </Show>
    </span>
  );
}

// A board's rows; a compact table, for the home page, keeps the rank, player and score, and Watch. A bot board names
// each run's bot, as its replay declares it.
function BoardTable(props: { view: BoardView; compact?: boolean }) {
  const bots = () => props.view.category === "bot";
  const full = () => !props.compact;
  return (
    <Show when={props.view.rows.length} fallback={<p class="muted">No runs yet.</p>}>
      <div class="board-table">
        <table>
          <thead>
            <tr>
              <th class="n">#</th>
              <th>Player</th>
              <Show when={bots() && full()}>
                <th>Bot</th>
              </Show>
              <th class="n">Score</th>
              <Show when={full()} fallback={<th />}>
                <th>Run</th>
                <th class="n">Duration</th>
                <th title="Most used weapon by time equipped">Weapon</th>
                <th>Replay</th>
              </Show>
            </tr>
          </thead>
          <tbody>
            <For each={props.view.rows}>
              {(row) => (
                <tr>
                  <td class="n">{row.rank}</td>
                  <td>
                    <RunPlayers player={row.player} team={row.team} tag={false} />
                    <Show when={props.compact && row.pilot}>
                      {(pilot) => (
                        <span class="muted">
                          {" · "}
                          <PilotName pilot={pilot()} />
                        </span>
                      )}
                    </Show>
                  </td>
                  <Show when={bots() && full()}>
                    <td>
                      <Show when={row.pilot} fallback={<span class="muted" title="The replay names no bot">—</span>}>
                        {(pilot) => <PilotName pilot={pilot()} />}
                      </Show>
                    </td>
                  </Show>
                  <td class="n">
                    <a class="run" href={`/runs/${row.run}`}>
                      {formatScore(props.view.board, row.score)}
                    </a>
                    <span class="muted"> · R{row.rules}</span>
                  </td>
                  <Show when={full()}>
                    <td>
                      <a class="run-details" href={`/runs/${row.run}`}>Details →</a>
                    </td>
                    <td class="n">{formatDuration(row.elapsed_ms)}</td>
                    <td>
                      <Weapon id={row.most_used_weapon_id} />
                    </td>
                    <td>
                      <ReplayLinks run={row.run} />
                    </td>
                  </Show>
                  <Show when={!full()}>
                    <td>
                      <ReplayLinks run={row.run} compact />
                    </td>
                  </Show>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </Show>
  );
}

// How a bot gets onto the bot boards.
const BotInvite = () => (
  <p class="muted">
    Bots and tool-assisted runs, verified under the same <a href={RULES}>rules</a>. Built one? Set <code>CRIMSON_PILOT_NAME</code> when the
    Python port records, and its runs list here under its name. See <a href={BOTS}>bots</a>.
  </p>
);

// The game's quest screen: its layout and colors (quest_select_menu_update), red rows on hardcore. The hardcore box
// keeps to one player's or the co-op boards.
function QuestMenu(props: { view: QuestMenuView; current?: string }) {
  const hardcore = () => BOARDS[props.view.board].hardcore;
  const toggle = () =>
    questsPath(boardFor(true, !hardcore(), BOARDS[props.view.board].players > 1) as QuestMenuView["board"], props.current ?? props.view.stage);
  return (
    <div class="quest-menu" classList={{ "hardcore-on": hardcore() }}>
      <span class="label">Quest:</span>
      <nav class="stages">
        <For each={STAGES}>
          {(numeral, i) => (
            <a classList={{ on: i() + 1 === props.view.stage }} style={{ left: `${88 + i() * 36}px` }} href={questsPath(props.view.board, i() + 1)}>
              <img src={`/ui/stage${i() + 1}.png`} alt={numeral} />
            </a>
          )}
        </For>
      </nav>
      <a class="hardcore" href={toggle()}>
        <img src={`/ui/check-${hardcore() ? "on" : "off"}.png`} alt="" />
        Hardcore
      </a>
      <ol class="quests">
        <For each={props.view.quests}>
          {(quest) => (
            <li>
              <a classList={{ on: quest.quest === props.current }} href={questsPath(props.view.board, quest.quest)}>
                <span class="n">{quest.quest}</span>
                {quest.title}
              </a>
              <Show when={quest.players}>
                <span class="count">{quest.players}</span>
              </Show>
            </li>
          )}
        </For>
      </ol>
    </div>
  );
}

// The main menu's Play Game item (ui_element_render): the label over the plate, then again additively, at the hover's alpha.
function PlayGame() {
  return (
    <a class="menu-item" href="/play/" data-native aria-label="Play Game">
      <img src="/ui/play-game.png" alt="" />
      <img src="/ui/play-game.png" alt="" />
    </a>
  );
}

// A command to type, in the game console's colors; a click copies it.
function Command(props: { children: string }) {
  const [copied, setCopied] = createSignal(false);
  const copy = async () => {
    await navigator.clipboard.writeText(props.children);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };
  return (
    <code class="command" classList={{ copied: copied() }} title="Copy" onClick={copy}>
      {props.children}
    </code>
  );
}

async function runPage(id: string, nav: Navigator): Promise<Screen> {
  const detail = await get<RunDetailView>(`/api/runs/${id}`);
  if (!detail) return notFound();
  const quest = detail.custom_slots ? `slots:${detail.custom_slots.join(",")}` : detail.quest.includes(".") ? detail.quest : null;
  return { title: `${runLabel(detail)} · ${detail.title}`, quest, panels: runPanels(detail, nav.reload) };
}

function notFound(): Screen {
  return { title: "Not found", quest: null, panels: [() => <p>Nothing here.</p>] };
}

const NOTICES: Record<string, (provider: string) => string> = {
  linked: (p) => `Linked ${p}.`,
  cancelled: (p) => `${p} sign-in was cancelled.`,
  failed: (p) => `Linking ${p} failed or expired; try again.`,
  joined: () => "This game's key joined the account.",
  switched: () => "This browser signed in to this account in another tab. Check it's the one you meant before linking.",
  deleted: () => "Your account and its runs are deleted.",
};

function notice(url: URL): string | null {
  const kind = url.searchParams.get("notice");
  const make = kind ? NOTICES[kind] : undefined;
  return make ? make(PROVIDER_LABELS[url.searchParams.get("provider") ?? ""] ?? "") : null;
}

function withNotice(url: URL, screen: Screen): Screen {
  const text = notice(url);
  return text ? { ...screen, panels: [() => <p class="notice">{text}</p>, ...screen.panels] } : screen;
}

async function home(): Promise<Screen> {
  const [humans, bots] = await Promise.all([
    get<BoardView>("/api/survival?limit=10"),
    get<BoardView>("/api/survival?limit=10&category=bot"),
  ]);
  return {
    title: null,
    quest: null,
    panels: [
      () => (
        <>
          <p>
            Crimsonland, the 2003 top-down shooter, back in your browser. It's the original game rebuilt from its own code, so it plays
            exactly like you remember, now with modern gamepads and a leaderboard where every score is verified by replay.
          </p>
          <PlayGame />
        </>
      ),
      () => (
        <>
          <h2>Survival</h2>
          <div class="board-pair">
            <div>
              <h3>Humans</h3>
              <BoardTotals view={humans!} />
              <BoardTable view={humans!} compact />
            </div>
            <div>
              <h3>Bots</h3>
              <BoardTotals view={bots!} />
              <BoardTable view={bots!} compact />
            </div>
          </div>
          <p>
            <a href="/survival">Full boards</a> · <a href="/quests">Quests</a> · <a href="/custom">Custom quests</a>
          </p>
        </>
      ),
    ],
  };
}

// Every ranked run on a board together, under its heading; Survival counts the time survived, a quest the time played.
function BoardTotals(props: { view: BoardView }) {
  const totals = () => props.view.totals;
  return (
    <Show when={totals().runs}>
      <p class="board-totals muted">
        {quantity(totals().runs, "run")} · {quantity(totals().kills, "kill")} · {formatLongDuration(totals().elapsed_ms)}{" "}
        {BOARDS[props.view.board].quests ? "played" : "survived"}
      </p>
    </Show>
  );
}

// A board's human runs, then its bot runs.
function rulesQuery(): string {
  const rules = new URLSearchParams(window.location.search).get("rules");
  return rules === "1" || rules === "2" ? `&rules=${rules}` : "";
}

function RulesFilter() {
  return <nav aria-label="Replay rules">
    <a data-native href={window.location.pathname}>All rules</a>{" · "}
    <a data-native href={`${window.location.pathname}?rules=1`}>Rules 1</a>{" · "}
    <a data-native href={`${window.location.pathname}?rules=2`}>Rules 2</a>
  </nav>;
}

function boardPanels(humans: BoardView, bots: BoardView): Panel[] {
  return [
    () => (
      <>
        <h2>{humans.title}</h2>
        <RulesFilter />
        <BoardTotals view={humans} />
        <BoardTable view={humans} />
      </>
    ),
    () => (
      <>
        <h2>{bots.title} · bots</h2>
        <BoardTotals view={bots} />
        <BotInvite />
        <BoardTable view={bots} />
      </>
    ),
  ];
}

// The leaderboards' switch: Survival or the quests, one player's boards or a co-op pair's. Each switch keeps the
// other, and on the quests the stage or quest and the hardcore box too.
function BoardSwitch(props: { board: Board; at?: number | string }) {
  const quests = BOARDS[props.board].quests, coop = BOARDS[props.board].players > 1;
  const to = (inQuests: boolean, inCoop: boolean) =>
    inQuests
      ? questsPath(boardFor(true, BOARDS[props.board].hardcore, inCoop) as QuestBoard, quests ? (props.at ?? 1) : 1)
      : boardPath(boardFor(false, false, inCoop), "");
  return (
    <>
      <nav class="board-switch">
        <span class="buttons">
          <GameButton label="Survival" href={to(false, coop)} on={!quests} />
          <GameButton label="Quests" href={to(true, coop)} on={quests} />
        </span>
        <span class="buttons">
          <GameButton label="Solo" href={to(quests, false)} on={!coop} />
          <GameButton label="Co-op" href={to(quests, true)} on={coop} />
        </span>
      </nav>
      <Show when={coop}>
        <p class="muted">Two players online, ranked as a pair.</p>
      </Show>
    </>
  );
}

async function survival(board: SurvivalBoard): Promise<Screen> {
  const path = boardPath(board, "");
  const [humans, bots] = await Promise.all([get<BoardView>(`/api${path}?category=human${rulesQuery()}`), get<BoardView>(`/api${path}?category=bot${rulesQuery()}`)]);
  return { title: humans!.title, quest: null, panels: [() => <BoardSwitch board={board} />, ...boardPanels(humans!, bots!)] };
}

// A stage's quest menu, and with a quest, its boards.
async function quests(page: QuestPage): Promise<Screen> {
  const api = (at: number | string) => `/api${questsPath(page.board, at)}`;
  const [menu, humans, bots] = await Promise.all([
    get<QuestMenuView>(api(page.stage)),
    page.quest && get<BoardView>(`${api(page.quest)}?category=human${rulesQuery()}`),
    page.quest && get<BoardView>(`${api(page.quest)}?category=bot${rulesQuery()}`),
  ]);
  const menuPanel = keep("quest-menu", { menu: menu!, quest: page.quest ?? undefined }, (data) => <QuestMenu view={data().menu} current={data().quest} />);
  const coop = BOARDS[page.board].players > 1;
  const panel = [() => <BoardSwitch board={page.board} at={page.quest ?? page.stage} />, menuPanel];
  if (!humans || !bots) return { title: `Quests ${STAGES[page.stage - 1]}${coop ? " · co-op" : ""}`, quest: `${page.stage}.1`, panels: panel };
  return { title: humans.title, quest: page.quest, panels: [...panel, ...boardPanels(humans, bots)] };
}

function spawnColor(spawnId: number): string {
  if (spawnId >= 0x07 && spawnId <= 0x10 && spawnId !== 0x0e && spawnId !== 0x0f) return "#e8a838";
  if (spawnId >= 0x11 && spawnId <= 0x19) return "#c084fc";
  if (spawnId === 0x00 || spawnId >= 0x41) return "#a3e635";
  if (spawnId === 0x04 || spawnId === 0x1c || (spawnId >= 0x2e && spawnId <= 0x31)) return "#34d399";
  if (spawnId === 0x01 || spawnId === 0x03 || spawnId === 0x05 || spawnId === 0x1b || (spawnId >= 0x32 && spawnId <= 0x40 && spawnId !== 0x36)) return "#60a5fa";
  return "#f87171";
}

function QuestPreviewSvg(props: { quest: CustomQuest }) {
  const entries = () => props.quest.entries;
  const totalCopies = () => entries().reduce((sum, e) => sum + e.count, 0);
  const maxTriggerMs = () => Math.max(1000, ...entries().map((e) => e.trigger_ms));
  const toMap = (coord: number) => 32 + ((coord + 256) / 1536) * 256;
  const arenaStart = toMap(0);
  const arenaSize = toMap(1024) - arenaStart;
  return (
    <div class="quest-preview" style={{ display: "flex", gap: "20px", "flex-wrap": "wrap", "align-items": "center", margin: "12px 0" }}>
      <svg viewBox="0 0 320 320" width="240" height="240" style={{ background: "rgba(0,0,0,0.35)", "border-radius": "6px", border: "1px solid rgba(255,255,255,0.12)" }}>
        <rect x={arenaStart} y={arenaStart} width={arenaSize} height={arenaSize} fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.28)" stroke-width="1" />
        <line x1={toMap(512)} y1={arenaStart} x2={toMap(512)} y2={arenaStart + arenaSize} stroke="rgba(255,255,255,0.08)" stroke-dasharray="3 3" />
        <line x1={arenaStart} y1={toMap(512)} x2={arenaStart + arenaSize} y2={toMap(512)} stroke="rgba(255,255,255,0.08)" stroke-dasharray="3 3" />
        <circle cx={toMap(512)} cy={toMap(512)} r="3" fill="#fff" opacity="0.7" />
        <For each={entries()}>
          {(entry) => (
            <circle
              cx={Math.max(8, Math.min(312, toMap(entry.pos.x)))}
              cy={Math.max(8, Math.min(312, toMap(entry.pos.y)))}
              r={Math.min(9, 2.5 + Math.log2(entry.count + 1) * 1.4)}
              fill={spawnColor(entry.spawn_id)}
              opacity="0.78"
            />
          )}
        </For>
      </svg>
      <div style={{ flex: "1", "min-width": "240px" }}>
        <p class="muted" style={{ margin: "0 0 6px" }}>
          Entry budget: <b>{entries().length} / 256</b> entries · <b>{totalCopies().toLocaleString("en-US")}</b> template copies · horizon{" "}
          <b>{formatDuration(maxTriggerMs())}</b>
        </p>
        <svg viewBox="0 0 400 44" width="100%" height="44" style={{ background: "rgba(0,0,0,0.35)", "border-radius": "4px", border: "1px solid rgba(255,255,255,0.12)" }}>
          <For each={entries()}>
            {(entry) => {
              const x = 12 + (entry.trigger_ms / maxTriggerMs()) * 376;
              const h = Math.min(32, 6 + Math.log2(entry.count + 1) * 6);
              return <line x1={x} y1={38 - h} x2={x} y2={38} stroke={spawnColor(entry.spawn_id)} stroke-width="2" opacity="0.8" />;
            }}
          </For>
        </svg>
        <p class="muted" style={{ "font-size": "12px", margin: "4px 0 0" }}>
          <span style={{ color: "#f87171" }}>●</span> Aliens · <span style={{ color: "#60a5fa" }}>●</span> Spiders ·{" "}
          <span style={{ color: "#34d399" }}>●</span> Lizards · <span style={{ color: "#a3e635" }}>●</span> Zombies ·{" "}
          <span style={{ color: "#e8a838" }}>●</span> Nests · <span style={{ color: "#c084fc" }}>●</span> Formations
        </p>
      </div>
    </div>
  );
}

function QuestRestrictions(props: { quest: CustomQuest }) {
  const fixedWeapon = () => props.quest.no_weapons.length === 32 && props.quest.no_bonuses.includes(3);
  const bonuses = () => props.quest.no_bonuses.map((id) => BONUS_NAMES[id] ?? `Bonus ${id}`);
  const perks = () => props.quest.no_perks.map((id) => PERKS[id] ?? `Perk ${id}`);
  const weapons = () => (fixedWeapon() ? [] : props.quest.no_weapons.map((id) => WEAPONS[id]?.name ?? `Weapon ${id}`));
  return (
    <Show when={fixedWeapon() || bonuses().length || perks().length || weapons().length}>
      <p class="muted">
        <Show when={fixedWeapon()}>
          <b>Fixed weapon</b> (weapon drops &amp; weapon perks disabled)
          <Show when={bonuses().length > 1 || perks().length > 2}> · </Show>
        </Show>
        <Show when={bonuses().length}>
          No bonuses: {bonuses().join(", ")}
          <Show when={perks().length || weapons().length}> · </Show>
        </Show>
        <Show when={perks().length}>
          No perks: {perks().join(", ")}
          <Show when={weapons().length}> · </Show>
        </Show>
        <Show when={weapons().length}>No weapon drops: {weapons().join(", ")}</Show>
      </p>
    </Show>
  );
}

async function customQuests(): Promise<Screen> {
  const list = (await get<CustomQuestsListView>("/api/custom"))!;
  return {
    title: "Custom Quests",
    quest: null,
    panels: [
      () => (
        <>
          <h2>Custom Quests</h2>
          <p class="muted">
            Community encounters authored in the <code>.quest</code> language. Every published quest is backed by a verified completion replay.
            Describe an encounter to an LLM using <a href="/custom/llm.txt" data-native>/custom/llm.txt</a>, beat it with{" "}
            <Command>uvx crimsonland@latest quest play my.quest</Command>, and publish with <Command>uvx crimsonland@latest quest publish my.quest</Command>.
          </p>
          <Show when={list.quests.length} fallback={<p class="muted">No custom quests published yet.</p>}>
            <div class="board-table">
              <table>
                <thead>
                  <tr>
                    <th>Quest</th>
                    <th>Author</th>
                    <th>Weapon</th>
                    <th class="n">Entries</th>
                    <th class="n">Best</th>
                    <th class="n">Players</th>
                    <th>Play</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={list.quests}>
                    {(q) => (
                      <tr>
                        <td>
                          <a href={`/custom/${q.id}`}>{q.title}</a>
                        </td>
                        <td>
                          {q.creator ? <PlayerName player={q.creator} tag={false} /> : (q.author ?? "—")}
                        </td>
                        <td>
                          <Weapon id={q.start_weapon_id} />
                        </td>
                        <td class="n">{q.entry_count}</td>
                        <td class="n">{q.top_score !== null ? formatScore("quests", q.top_score) : "—"}</td>
                        <td class="n">{q.players}</td>
                        <td>
                          <a class="watch" href={`/play/?quest=${q.id}`} data-native>
                            Play →
                          </a>
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </>
      ),
    ],
  };
}

async function customQuestPage(id: string): Promise<Screen> {
  const [detail, bots] = await Promise.all([
    get<CustomQuestDetailView>(`/api/custom/${id}?category=human${rulesQuery()}`),
    get<CustomQuestDetailView>(`/api/custom/${id}?category=bot${rulesQuery()}`),
  ]);
  if (!detail || !bots) return notFound();
  const def = detail.definition;
  const slots = `slots:${def.terrain_slots.join(",")}`;
  return {
    title: detail.title,
    quest: slots,
    panels: [
      () => (
        <>
          <h2>{detail.title}</h2>
          <p class="muted">
            <Show when={detail.creator}>
              {(creator) => (
                <>
                  Published by <PlayerName player={creator()} tag={false} /> ·{" "}
                </>
              )}
            </Show>
            <Show when={detail.author && detail.author !== detail.creator?.name}>recipe by {detail.author} · </Show>
            {new Date(detail.created_at).toISOString().slice(0, 10)} · ID <code>{detail.id}</code>
          </p>
          <p>
            Starting weapon: <Weapon id={def.start_weapon_id} />
          </p>
          <QuestRestrictions quest={def} />
          <QuestPreviewSvg quest={def} />
          <p class="buttons">
            <GameButton label="Play in browser" href={`/play/?quest=${detail.id}`} native />
            <GameButton label="Watch proof clear" href={`/play/?watch=${detail.first_run_id}`} native />
            <GameButton label="All custom quests" href="/custom" />
          </p>
        </>
      ),
      ...boardPanels(detail.board, bots.board),
      ...(detail.source
        ? [
            () => (
              <>
                <h3>Recipe (.quest)</h3>
                <p class="muted">
                  Construction seed: <code>{detail.seed}</code> · <a href="/custom/llm.txt" data-native>LLM Remix Reference</a>
                </p>
                <pre class="quest-source" tabIndex={0} aria-label="Quest recipe source">
                  <code><For each={questTokens(detail.source!)}>{(token) => token.kind
                    ? <span class={`syntax-${token.kind}`}>{token.text}</span> : token.text}</For></code>
                </pre>
                <p>
                  Click to copy recipe: <Command>{detail.source!}</Command>
                </p>
              </>
            ),
          ]
        : []),
    ],
  };
}

function AccountControls(props: { profile: ProfileView; nav: Navigator }) {
  // Each change names this page's account, which the service refuses once the browser signed in to another one.
  const account = props.profile.player.id;
  const act = async (path: string, then: () => void) => {
    const result = await post(path, { account });
    if (result.ok) then();
    else {
      alert(result.reason);
      props.nav.reload();
    }
  };
  return (
    <>
      <h2>Your account</h2>
      <Show when={props.profile.account!.providers.length}>
        <p class="muted">
          Linking shows your handle in place of the name you typed and lets you add another computer's game to this account by signing in with the
          same login there. See <a href="/privacy">what linking stores</a>.
        </p>
        <p class="buttons">
          <For each={props.profile.account!.providers}>
            {(provider) => (
              <Show
                when={provider.linked}
                fallback={<GameButton label={`Link ${provider.label}`} href={`/auth/${provider.name}/start?account=${account}`} native />}
              >
                <GameButton label={`Unlink ${provider.label}`} onClick={() => act(`/api/account/unlink/${provider.name}`, props.nav.reload)} />
              </Show>
            )}
          </For>
        </p>
      </Show>
      <p>
        <GameButton label="Sign out" onClick={() => act("/api/logout", () => props.nav.go("/"))} />
      </p>
      <h3>Delete account</h3>
      <p class="muted">
        Removes your runs and their replay files, names, links, keys and sessions. A co-op run stays your partner's, showing you as a
        deleted player. The game keeps its key, so playing ranked again starts a new account.
      </p>
      <p>
        <GameButton
          label="Delete account"
          danger
          onClick={() => confirm("Delete this account and all its runs?") && act("/api/account/delete", () => props.nav.go("/?notice=deleted"))}
        />
      </p>
    </>
  );
}

// A moderator's view of an account: its role, its overlapping runs, and the bot mark.
function AccountModerationPanel(props: { profile: ProfileView; viewer: Role; nav: Navigator }) {
  const id = props.profile.player.id;
  const moderation = props.profile.moderation!;
  const act = async (path: string, body: Record<string, unknown>) => (await moderate(path, body)) && props.nav.reload();
  return (
    <>
      <h3>Moderation</h3>
      <p class="muted">
        Role: {moderation.role || "player"} · {moderation.overlapping_runs} runs accepted sooner after the previous one than their own game time
      </p>
      <p class="buttons">
        <Show
          when={props.profile.player.bot}
          fallback={<GameButton label="Mark as bot" onClick={() => act(`/api/mod/accounts/${id}`, { bot: true })} />}
        >
          <GameButton label="Unmark bot" onClick={() => act(`/api/mod/accounts/${id}`, { bot: false })} />
        </Show>
        <Show when={props.viewer === "admin" && moderation.role !== "admin"}>
          <Show
            when={moderation.role === "mod"}
            fallback={<GameButton label="Make moderator" onClick={() => act(`/api/mod/roles/${id}`, { role: "mod" })} />}
          >
            <GameButton label="Revoke moderator" onClick={() => act(`/api/mod/roles/${id}`, { role: "" })} />
          </Show>
        </Show>
      </p>
    </>
  );
}

async function profile(id: number, nav: Navigator): Promise<Screen> {
  const [view, viewer] = await Promise.all([get<ProfileView>(`/api/players/${id}`), me()]);
  if (!view) return notFound();
  // The typed names, where they say more than the shown one.
  const history = view.names.some((name) => name !== view.player.name);
  return {
    title: playerLabel(view.player),
    quest: null,
    panels: [
      () => (
        <>
          <h2 class="player">
            <PlayerName player={view.player} heading />
            <Show when={view.player.name !== null}>
              <span class="muted fingerprint"> {view.player.fingerprint}</span>
            </Show>
          </h2>
          <Show when={history}>
            <p class="muted">Names: {view.names.join(", ")}</p>
          </Show>
          <h3>Runs</h3>
          <Show when={view.runs.length} fallback={<p class="muted">No ranked runs yet.</p>}>
            <div class="board-table">
              <table>
                <thead>
                  <tr>
                    <th>Board</th>
                    <th class="n">Score</th>
                    <th>Run</th>
                    <th>Version</th>
                    <th>Accepted</th>
                    <th>Replay</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={view.runs}>
                    {(run) => (
                      <tr>
                        <td>
                          <a href={boardPath(run.board, run.quest)}>
                            {BOARD_NAMES[run.board]} {run.quest}
                          </a>
                          <Show when={run.team?.filter((seat) => seat.player?.id !== view.player.id)}>
                            {(partners) => (
                              <Show when={partners().length}>
                                <span class="muted">
                                  {" with "}
                                  <RunPlayers player={view.player} team={partners()} tag={false} />
                                </span>
                              </Show>
                            )}
                          </Show>
                          <Show when={run.category === "bot"}>
                            <span class="tag">bot</span>
                          </Show>
                          <Show when={run.retired}>
                            {(reason) => <span class="tag" title={reason()}>retired</span>}
                          </Show>
                        </td>
                        <td class="n">
                          <a class="run" href={`/runs/${run.id}`}>
                            {formatScore(run.board, run.score)}
                          </a>
                        </td>
                        <td>
                          <a class="run-details" href={`/runs/${run.id}`}>Details →</a>
                        </td>
                        <td>R{run.rules} · {run.game_version.split("+", 1)[0]}</td>
                        <td>{new Date(run.accepted_at).toISOString().slice(0, 10)}</td>
                        <td>
                          <ReplayLinks run={run.id} retired={run.retired} />
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </>
      ),
      ...(view.moderation ? [() => <AccountModerationPanel profile={view} viewer={viewer.role} nav={nav} />] : []),
      ...(view.account ? [() => <AccountControls profile={view} nav={nav} />] : []),
    ],
  };
}

// A log entry's account or run, linked to its page.
function LogSubject(props: { subject: string }) {
  const [kind, id] = props.subject.split(" ");
  const href = kind === "account" ? `/players/${id}` : kind === "run" ? `/runs/${id}` : null;
  return href ? <a href={href}>{kind === "run" ? `run ${id!.slice(0, 12)}` : props.subject}</a> : <>{props.subject}</>;
}

// The flagged human runs, the runs left to measure, and the moderation log.
async function moderation(nav: Navigator): Promise<Screen> {
  const response = await fetch("/api/mod/flags");
  if (!response.ok) return { title: "Moderation", quest: null, panels: [() => <p>Moderators only.</p>] };
  const flags = (await response.json()) as FlagsView;
  const { actions } = (await get<{ actions: ModerationAction[] }>("/api/mod/log"))!;
  const measure = async () => {
    const result = await post("/api/mod/measure");
    if (result.ok) nav.reload();
  };
  return {
    title: "Moderation",
    quest: null,
    panels: [
      () => (
        <>
          <h2>Flagged runs</h2>
          <p class="muted">
            Human runs whose input signals look like a bot's. A flag never moves a run: mark the account, or set the run's category on its page.
            See <a href={BOTS}>bots</a>.
          </p>
          <Show when={flags.unmeasured}>
            <p class="buttons">
              <span class="muted">{flags.unmeasured} runs not measured yet. </span>
              <GameButton label="Measure more" onClick={measure} />
            </p>
          </Show>
          <Show when={flags.runs.length} fallback={<p class="muted">No flagged runs.</p>}>
            <div class="board-table">
              <table>
                <thead>
                  <tr>
                    <th>Player</th>
                    <th>Board</th>
                    <th class="n">Score</th>
                    <th>Flags</th>
                    <th>Accepted</th>
                  </tr>
                </thead>
                <tbody>
                  <For each={flags.runs}>
                    {(run) => (
                      <tr>
                        <td>
                          <RunPlayers player={run.player} team={run.team} />
                        </td>
                        <td>
                          {BOARD_NAMES[run.board]} {run.quest}
                        </td>
                        <td class="n">
                          <a class="run" href={`/runs/${run.id}`}>
                            {formatScore(run.board, run.score)}
                          </a>
                        </td>
                        <td class="flag">{run.flagged.map((name) => SIGNAL_LABELS[name]).join(", ")}</td>
                        <td>{new Date(run.accepted_at).toISOString().slice(0, 10)}</td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        </>
      ),
      () => (
        <>
          <h3>Log</h3>
          <Show when={actions.length} fallback={<p class="muted">Nothing yet.</p>}>
            <table>
              <tbody>
                <For each={actions}>
                  {(action) => (
                    <tr>
                      <td class="muted">{new Date(action.at).toISOString().slice(0, 16).replace("T", " ")}</td>
                      <td>
                        <LogSubject subject={action.actor} />
                      </td>
                      <td>{action.action}</td>
                      <td>
                        <LogSubject subject={action.target} />
                      </td>
                      <td class="muted">{action.note}</td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        </>
      ),
    ],
  };
}

async function playAnalytics(): Promise<Screen> {
  const response = await fetch("/api/analytics");
  if (!response.ok) return { title: "Gameplay analytics", quest: null, panels: [() => <p>The admin only.</p>] };
  const { days, coop } = await response.json() as PlayAnalyticsView;
  const daily = days.filter((row) => row.mode === "all");
  const byMode = new Map<string, { mode: string; runs: number; seconds: number }>();
  for (const row of days) {
    if (row.mode === "all") continue;
    let total = byMode.get(row.mode);
    if (!total) byMode.set(row.mode, (total = { mode: row.mode, runs: 0, seconds: 0 }));
    total.runs += row.runs;
    total.seconds += row.active_seconds;
  }
  const modes = [...byMode.values()];
  return { title: "Gameplay analytics", quest: null, panels: [() => <>
    <h2>Gameplay analytics</h2>
    <p>Browser gameplay only, for the last 30 UTC days. Replay watching and embedded players are excluded; practice takeover counts as play.</p>
    <p class="muted">Unique browsers are counted separately each day, not across days. Clearing storage or using another browser can count again; a shared browser counts once. These unverified client reports are approximate.</p>
    <Show when={daily.length} fallback={<p>No gameplay counts yet.</p>}>
      <div class="board-table"><table><thead><tr>
        <th>UTC day</th><th class="n">Unique browsers</th><th class="n">Loaded</th><th class="n">Play sessions</th><th class="n">5+ minutes</th>
      </tr></thead><tbody><For each={daily}>{(row) => <tr>
        <td>{row.day}</td><td class="n">{row.unique_browsers}</td><td class="n">{row.ready}</td><td class="n">{row.sessions}</td><td class="n">{row.engaged}</td>
      </tr>}</For></tbody></table></div>
    </Show>
    <p class="muted">Loaded means the game reached its first frame. A session starts with live gameplay and reaches 5+ minutes after five accumulated active minutes in that page. Counts can be missing when storage, the network or privacy preferences prevent reporting.</p>
  </>, () => <>
    <h3>Play by mode</h3>
    <table><thead><tr><th>Mode</th><th class="n">Runs</th><th class="n">Active minutes</th></tr></thead>
      <tbody><For each={modes}>{(row) => <tr><td>{row.mode}</td><td class="n">{row.runs}</td><td class="n">{(row.seconds / 60).toFixed(1)}</td></tr>}</For></tbody>
    </table>
    <p class="muted">Visible, focused, unpaused wall time, sampled about once a second. Long stalls are capped. Anonymous totals are separate from unique-count tokens and are not retried.</p>
  </>, () => <CoopAnalytics rows={coop} />] };
}

function GameplayAnalyticsPreference() {
  const [preference, setPreference] = createSignal(gameplayPreference());
  const [failed, setFailed] = createSignal(false);
  return <>
    <label><input type="checkbox" checked={preference().enabled} disabled={preference().forced || !preference().available}
      onChange={(event) => {
        const saved = setGameplayPreference(event.currentTarget.checked);
        setFailed(!saved);
        setPreference(gameplayPreference());
      }} /> Send anonymous gameplay counts</label>
    <Show when={preference().forced}><p>Your browser's Do Not Track or Global Privacy Control preference disables gameplay counts.</p></Show>
    <Show when={!preference().available || failed()}><p>Browser storage is unavailable, so this preference could not be saved.</p></Show>
    <p>This choice applies to gameplay counters in this browser. It does not change Cloudflare Web Analytics. Turning it off stops future gameplay reports and removes an earlier day's token; today's stays only so turning it back on today does not count this browser again. Existing aggregate counts remain.</p>
  </>;
}

const SIGN_IN = () => (
  <p>
    Open your profile from the game: press <em>Profile</em> on Play Game.
  </p>
);

async function account(nav: Navigator): Promise<Screen> {
  const me = await get<{ account: number | null }>("/api/me");
  if (me?.account) {
    nav.go(`/players/${me.account}`, true);
    return { title: null, quest: null, panels: [] };
  }
  return { title: "Sign in from the game", quest: null, panels: [SIGN_IN] };
}

// A login link from the game's Profile button: the browser signs in as the link's account only once the player
// confirms here, so a link someone else sends cannot switch it to their account unseen.
async function login(token: string, nav: Navigator): Promise<Screen> {
  const view = await get<LoginView>(`/api/login/${token}`).catch(() => null);
  if (!view) return { title: "Sign in", quest: null, panels: [() => <p>This sign-in link has expired. Open your profile from the game again.</p>] };
  const signIn = async () => {
    const result = await post<{ account: number }>("/api/login", { token });
    if (result.ok) nav.go(`/players/${result.data.account}`, true);
    else alert(result.reason);
  };
  return {
    title: "Sign in",
    quest: null,
    panels: [
      () => (
        <>
          <h2>Sign in as this game's account?</h2>
          <p>
            <PlayerName player={view.account} /> <span class="muted">· {quantity(view.runs, "run")}</span>
          </p>
          <Show when={view.current}>
            {(current) => (
              <p>
                This browser is signed in as <PlayerName player={current()} />. Signing in switches it to the account above.
              </p>
            )}
          </Show>
          <p class="muted">Continue only if you just pressed Profile in your game. A sign-in link someone sent you signs you in to their account.</p>
          <p class="buttons">
            <GameButton label="Sign in" onClick={signIn} />
            <GameButton label="Cancel" href="/" />
          </p>
        </>
      ),
    ],
  };
}

async function join(token: string, nav: Navigator): Promise<Screen> {
  const response = await fetch(`/api/join/${token}`);
  if (!response.ok) return { title: "Join account", quest: null, panels: [response.status === 401 ? SIGN_IN : () => <p>That request expired; link again to join the accounts.</p>] };
  const view = (await response.json()) as JoinView;
  const confirmJoin = async () => {
    const result = await post<{ account: number }>("/api/join", { token, account: view.source.id });
    if (!result.ok) alert(result.reason);
    nav.go(result.ok ? `/players/${result.data.account}?notice=joined` : "/account");
  };
  return {
    title: "Join account",
    quest: null,
    panels: [
      () => (
        <>
          <h2>This {view.provider} login belongs to another account</h2>
          <p>
            <PlayerName player={view.destination} /> <span class="muted">· {view.destination.fingerprint} · {quantity(view.destination_runs, "run")}</span>
          </p>
          <p>
            This browser is signed in as <PlayerName player={view.source} />. Joining moves its{" "}
            {view.moving.keys === 1 ? "key" : `${view.moving.keys} keys`}, {quantity(view.moving.runs, "run")} and {quantity(view.moving.names, "name")} into the
            account above and removes it, and from then on that key signs in to the account above.
          </p>
          <p>
            Join only if you played as <PlayerName player={view.source} tag={false} /> yourself. If you don't recognise it, someone signed this browser in
            to their account: cancel and sign out.
          </p>
          <p class="buttons">
            <GameButton label={`Join ${playerLabel(view.destination)}`} onClick={confirmJoin} />
            <GameButton label="Cancel" href="/account" />
          </p>
        </>
      ),
    ],
  };
}

const ABOUT: Screen = {
  title: "About",
  quest: null,
  panels: [
    () => (
      <>
        <h2>About</h2>
        <p>
          Crimsonland was one of my favourite games as a kid. It came out in 2003, and over the years it got harder and harder to run, so I
          brought it back.
        </p>
        <p>
          I reverse engineered the original game back into C/C++ source that compiles to the same machine code as the original .exe. That
          source is what you <a href="/play/" data-native>play in your browser</a>. It plays exactly like you remember, the same weapons,
          perks and quests, because it <em>is</em> the same code. On top of that it supports modern gamepads and has an online
          leaderboard. Your saves are kept in your browser, and the original art and sound are used with permission from 10tons.
        </p>
      </>
    ),
    () => (
      <>
        <h3>The leaderboard</h3>
        <p>
          Tick <em>Ranked</em> in the Play Game menu and play Survival or a quest to the end. Enter your name on the high score screen, and
          the game uploads your run. If you're offline, it uploads the next time you connect.
        </p>
        <p>
          Survival is ranked by experience and quests by time, with a separate board for hardcore. Only your best run counts.
        </p>
        <p>
          Every score comes with a recording of the run. The server plays it back using the same game code and checks that the result
          matches. Anyone can download the replay and verify it themselves. Bots can produce valid replays too, so verification confirms
          the score, not whether a human played.
        </p>
        <p>
          Ranked runs on each board use the same starting conditions: one player, a standard progression profile, and documented fixes
          for <a href={BUGS}>bugs in the original game</a>.
        </p>
        <p>
          Bots are welcome too. Every board ranks them next to the humans: a program that plays declares itself in its replay and lists
          under the bot's name, and moderators move undeclared bots there. See <a href={BOTS}>bots</a>.
        </p>
      </>
    ),
    () => (
      <>
        <h3>Your name</h3>
        <p>
          You don't need to sign up. The game makes a keypair on first launch, and that keypair is your account. You show up under the name
          from your latest run, and your <em>Profile</em> in the Play Game menu lists every name you've used. Link GitHub, Discord or X to
          show your handle so other players can identify you by your linked accounts, and to keep your runs when you switch computers or
          clear your browser's site data.
        </p>
        <h3>Replays, other ports and docs</h3>
        <p>
          Every run on the boards can be downloaded as a replay. There's also a Python port and a native desktop build, both on{" "}
          <a href="https://github.com/banteg/crimson">GitHub</a>. The <a href={DOCS}>docs</a> describe how the game actually works, from the
          real numbers behind every perk and weapon rather than the in-game descriptions, to how the whole thing was rebuilt.
        </p>
      </>
    ),
  ],
};

const PRIVACY: Screen = {
  title: "Privacy",
  quest: null,
  panels: [
    () => (
      <>
        <h2>Privacy</h2>
        <p>crimson.land runs the online leaderboard of the Crimsonland port. This is everything it keeps.</p>
        <h3>What we store</h3>
        <ul>
          <li>
            <em>Your game's public key</em> and a four-character fingerprint of it. The game makes the key on its first launch; the private
            half never leaves your computer.
          </li>
          <li>
            <em>Each ranked run you upload:</em> the replay file, the name you typed for it, its result and score, the game version, the
            program that recorded it and the bot that played it if the replay names one, and when it was accepted. The service also measures
            a few input statistics from the replay, which only moderators see. Your profile shows the name of your latest run and lists every
            name you have used.
          </li>
          <li>
            <em>Linked accounts</em>, if you link one: the GitHub, Discord or X account's numeric ID, handle and avatar URL. We ask for the
            least access each offers (GitHub: none; Discord: identify; X: users.read and tweet.read), use the access token once to read
            your profile, and do not keep it.
          </li>
          <li>
            <em>Sessions:</em> opening your profile from the game signs you in with a random token in a cookie, which we keep only as a hash,
            for 30 days or until you sign out. Sign-in links and challenges expire after five minutes, and account-linking
            requests after ten.
          </li>
        </ul>
        <h3>What is public</h3>
        <p>
          Boards, profiles and replays: your names, key fingerprint, linked handles and avatars, run results, and the replay files, which
          anyone can download. A replay file carries the name you typed for its run, so a name a moderator hides still shows in the file.
        </p>
        <h3>Where it lives</h3>
        <p>
          Cloudflare hosts the site and stores the data (Workers, D1 for the database, R2 for replay files). Cloudflare handles the service's
          request logs, including IP addresses, and keeps them for up to seven days under{" "}
          <a href="https://www.cloudflare.com/privacypolicy/">its privacy policy</a>. We do not store IP addresses ourselves or use ads.
          Profile pages load linked avatars straight from GitHub, Discord or X.
        </p>
        <h3>How long, and deleting it</h3>
        <p>
          Everything above stays until you delete your account; expired sessions, links and challenges are removed. Your profile's{" "}
          <em>Delete account</em> button removes your runs and their replay files, names, links, keys and sessions at once. A co-op run
          stays your partner's and shows you as a deleted player: until its last such run is gone, your account remains as a bare record
          with no name, key or link, only a number that keeps your partner's teams apart and any moderation decision on it.{" "}
          <em>Unlink</em> removes a linked account. Signing in again from the game starts a new account. For anything else,{" "}
          <a href="https://github.com/banteg/crimson/issues">open an issue</a>.
        </p>
        <h3>Site analytics</h3>
        <p>
          We use <a href="https://developers.cloudflare.com/web-analytics/about/">Cloudflare Web Analytics</a> to measure visits, page
          views and page loading performance. Cloudflare's beacon does not use analytics cookies, browser storage or fingerprinting to identify visitors.
          Analytics are separate from your game key and leaderboard account, and are kept by Cloudflare for up to six months.
        </p>
        <h3>Gameplay counts</h3>
        <p>
          The browser game also counts loading, play sessions, sessions reaching five active minutes, runs and active time by mode.
          It sends these as anonymous daily totals, without your name, account, game key, replay, URL or IP address. The service does not store IP addresses for these counters.
          When a co-op session ends, it also sends how the connection went: whether it was direct, relayed through TURN (over UDP or
          TCP from your browser, or a relay whose protocol your browser cannot see, such as your partner's), through the room, or not
          yet known, the round trip's range, minutes played, whether the two games ran differently, and how often the game had to
          correct, or wait for the connection or a perk pick. That summary names no room or partner, and only daily totals of it are kept.
        </p>
        <p>
          To count a browser once per UTC day of actual play, it keeps a random daily token in first-party browser storage. The token changes on
          the next playing day and is sent separately from gameplay totals. We keep only the day and token for deduplication, with no activity history.
          An hourly cleanup removes tokens for days older than the current day and the two previous days; daily totals remain. Cloudflare D1 backups can retain deleted data for up to 30 days.
          Clearing browser storage or using another browser can count you again. Daily counts cannot identify returning players across days.
        </p>
        <GameplayAnalyticsPreference />
      </>
    ),
  ],
};

const TERMS: Screen = {
  title: "Terms",
  quest: null,
  panels: [
    () => (
      <>
        <h2>Terms</h2>
        <ul>
          <li>
            crimson.land is a free, unofficial fan leaderboard for an open-source port of Crimsonland. It is not affiliated with 10tons, who
            own Crimsonland and its assets; the port distributes the assets with their permission.
          </li>
          <li>
            Upload runs you played yourself, or runs your own program played. A run a program played, in whole or in part, belongs on the bot
            boards: declare it in the replay, or moderators move it there. Runs other people played, runs that exploit a flaw in the verifier,
            and names that impersonate someone are not allowed. The <a href={RULES}>ranked rules</a> say which runs rank, and{" "}
            <a href={BOTS}>bots</a> how bot runs are told apart.
          </li>
          <li>Uploading a run lets us store and show it and lets anyone download its replay.</li>
          <li>We may hide or remove runs, names and accounts, move runs and accounts to the bot boards, and ban keys, when these terms are broken.</li>
          <li>The service comes as is, without guarantees. It may change, go down or lose data.</li>
          <li>Changes to these terms appear on this page.</li>
        </ul>
      </>
    ),
  ],
};

// The screen for a URL, with its data loaded.
export async function resolve(url: URL, nav: Navigator): Promise<Screen> {
  const path = url.pathname.replace(/\/+$/, "") || "/";
  let match: RegExpExecArray | null;
  let page: QuestPage | null;
  let board: SurvivalBoard | null;
  let screen: Screen;
  if (path === "/") screen = await home();
  else if ((board = survivalPage(path))) screen = await survival(board);
  else if ((page = questPage(path))) screen = await quests(page);
  else if (path === "/custom") screen = await customQuests();
  else if ((match = /^\/custom\/([0-9a-f]{12})$/.exec(path))) screen = await customQuestPage(match[1]!);
  else if (path === "/mod") screen = await moderation(nav);
  else if (path === "/analytics") screen = await playAnalytics();
  else if ((match = /^\/players\/(\d+)$/.exec(path))) screen = await profile(Number(match[1]), nav);
  else if ((match = /^\/join\/([0-9a-f]{64})$/.exec(path))) screen = await join(match[1]!, nav);
  else if ((match = /^\/login\/([0-9a-f]{64})$/.exec(path))) screen = await login(match[1]!, nav);
  else if (path === "/account") screen = await account(nav);
  else if ((match = /^\/runs\/([0-9a-f]{64})$/.exec(path))) screen = await runPage(match[1]!, nav);
  else if (path === "/about") screen = ABOUT;
  else if (path === "/privacy") screen = PRIVACY;
  else if (path === "/terms") screen = TERMS;
  else screen = notFound();
  return withNotice(url, screen);
}
