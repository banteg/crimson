import { type Accessor, createSignal, For, type JSX, Show } from "solid-js";
import type { Board, BoardView, FlagsView, JoinView, ModerationAction, ProfileView, QuestMenuView, Role, RunDetailView } from "../../src/api-types";
import { get, moderate, post } from "./api";
import { formatScore } from "./format";
import { GameButton } from "./button";
import { playerLabel } from "./names";
import { PilotName, PlayerName, PROVIDER_LABELS } from "./players";
import { runPanels, SIGNAL_LABELS } from "./run";
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
const QUEST = /^[1-5]\.(?:[1-9]|10)$/;
const DOCS = "https://crimson.banteg.xyz/";
const RULES = `${DOCS}rewrite/ranked-rules/`;
const BUGS = `${DOCS}rewrite/original-bugs/`;
const BOTS = `${DOCS}rewrite/bots/`;


// The signed-in account and its role.
async function me(): Promise<{ account: number | null; role: Role }> {
  return (await get<{ account: number | null; role: Role }>("/api/me"))!;
}


const BOARD_NAMES: Record<Board, string> = { survival: "Survival", quests: "Quests", "quests-hardcore": "Quests, hardcore" };
const WEAPONS: Record<string, { name: string; icon_index: number }> = weaponData;

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
                    <PlayerName player={row.player} tag={false} />
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

// The game's quest screen: its layout and colors (quest_select_menu_update), red rows on hardcore.
function QuestMenu(props: { view: QuestMenuView; current?: string }) {
  const hardcore = () => props.view.board === "quests-hardcore";
  const menu = () => (hardcore() ? "quests-hardcore" : "quests");
  const toggle = () =>
    props.current
      ? `/boards/${hardcore() ? "quests" : "quests-hardcore"}/${props.current}`
      : `/${hardcore() ? "quests" : "quests-hardcore"}/${props.view.stage}`;
  return (
    <div class="quest-menu" classList={{ "hardcore-on": hardcore() }}>
      <span class="label">Quest:</span>
      <nav class="stages">
        <For each={STAGES}>
          {(numeral, i) => (
            <a classList={{ on: i() + 1 === props.view.stage }} style={{ left: `${88 + i() * 36}px` }} href={`/${menu()}/${i() + 1}`}>
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
              <a classList={{ on: quest.quest === props.current }} href={`/boards/${props.view.board}/${quest.quest}`}>
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
  return { title: `${playerLabel(detail.player)} · ${detail.title}`, quest: detail.quest || null, panels: runPanels(detail, nav.reload) };
}

function notFound(): Screen {
  return { title: "Not found", quest: null, panels: [() => <p>Nothing here.</p>] };
}

const NOTICES: Record<string, (provider: string) => string> = {
  linked: (p) => `Linked ${p}.`,
  cancelled: (p) => `${p} sign-in was cancelled.`,
  failed: (p) => `Linking ${p} failed or expired; try again.`,
  joined: () => "This game's key joined the account.",
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
    get<BoardView>("/api/boards/survival?limit=10"),
    get<BoardView>("/api/boards/survival?limit=10&category=bot"),
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
              <BoardTable view={humans!} compact />
            </div>
            <div>
              <h3>Bots</h3>
              <BoardTable view={bots!} compact />
            </div>
          </div>
          <p>
            <a href="/boards/survival">Full boards</a> · <a href="/quests/1">Quests</a>
          </p>
        </>
      ),
    ],
  };
}

// A board's human runs, then its bot runs.
function boardPanels(humans: BoardView, bots: BoardView): Panel[] {
  return [
    () => (
      <>
        <h2>{humans.title}</h2>
        <BoardTable view={humans} />
      </>
    ),
    () => (
      <>
        <h2>{bots.title} · bots</h2>
        <BotInvite />
        <BoardTable view={bots} />
      </>
    ),
  ];
}

async function board(boardName: Board, quest: string): Promise<Screen> {
  const path = boardName === "survival" ? "/api/boards/survival" : `/api/boards/${boardName}/${quest}`;
  const [humans, bots] = await Promise.all([get<BoardView>(path), get<BoardView>(`${path}?category=bot`)]);
  if (boardName === "survival") return { title: "Survival", quest: null, panels: boardPanels(humans!, bots!) };
  const menu = (await get<QuestMenuView>(`/api/quests/${boardName}/${Number(quest.split(".")[0])}`))!;
  return {
    title: humans!.title,
    quest,
    panels: [keep("quest-menu", { menu, quest }, (data) => <QuestMenu view={data().menu} current={data().quest} />), ...boardPanels(humans!, bots!)],
  };
}

async function quests(boardName: "quests" | "quests-hardcore", stage: number): Promise<Screen> {
  const menu = (await get<QuestMenuView>(`/api/quests/${boardName}/${stage}`))!;
  return { title: `Quests ${STAGES[stage - 1]}`, quest: `${stage}.1`, panels: [keep("quest-menu", { menu, quest: undefined }, (data) => <QuestMenu view={data().menu} current={data().quest} />)] };
}

function AccountControls(props: { profile: ProfileView; nav: Navigator }) {
  const act = async (path: string, then: () => void) => {
    const result = await post(path);
    if (result.ok) then();
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
                fallback={<GameButton label={`Link ${provider.label}`} href={`/auth/${provider.name}/start`} native />}
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
        Removes your runs and their replay files, names, links, keys and sessions. The game keeps its key, so playing ranked again starts a
        new account.
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
                          <a href={`/boards/${run.board}${run.quest ? `/${run.quest}` : ""}`}>
                            {BOARD_NAMES[run.board]} {run.quest}
                          </a>
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
                        <td>{run.game_version}</td>
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
                          <PlayerName player={run.player} />
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

const SIGN_IN = () => (
  <p>
    Open your profile from the game: tick <em>Ranked</em> on Play Game and press <em>Profile</em>.
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

async function join(token: string, nav: Navigator): Promise<Screen> {
  const response = await fetch(`/api/join/${token}`);
  if (!response.ok) return { title: "Join account", quest: null, panels: [response.status === 401 ? SIGN_IN : () => <p>That request expired; link again to join the accounts.</p>] };
  const view = (await response.json()) as JoinView;
  const confirmJoin = async () => {
    const result = await post<{ account: number }>("/api/join", { token });
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
            <PlayerName player={view.destination} /> <span class="muted">· {view.destination.fingerprint} · {view.destination_runs} runs</span>
          </p>
          <p>
            Joining moves this game's {view.moving.keys === 1 ? "key" : `${view.moving.keys} keys`}, {view.moving.runs} runs and {view.moving.names} names into that
            account, and removes this one. Do it only if both are yours.
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
            for 30 days or until you sign out. Sign-in links expire after a minute, sign-in challenges after five minutes, and account-linking
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
          <a href="https://www.cloudflare.com/privacypolicy/">its privacy policy</a>. We do not store IP addresses ourselves, and we do not
          use analytics or ads. Profile pages load linked avatars straight from GitHub, Discord or X.
        </p>
        <h3>How long, and deleting it</h3>
        <p>
          Everything above stays until you delete your account; expired sessions, links and challenges are removed. Your profile's{" "}
          <em>Delete account</em> button removes your runs and their replay files, names, links, keys and sessions at once, and{" "}
          <em>Unlink</em> removes a linked account. Signing in again from the game starts a new account. For anything else,{" "}
          <a href="https://github.com/banteg/crimson/issues">open an issue</a>.
        </p>
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
  let screen: Screen;
  if (path === "/") screen = await home();
  else if (path === "/boards/survival") screen = await board("survival", "");
  else if ((match = /^\/boards\/(quests|quests-hardcore)\/([^/]+)$/.exec(path)) && QUEST.test(match[2]!)) screen = await board(match[1] as Board, match[2]!);
  else if ((match = /^\/(quests|quests-hardcore)\/([1-5])$/.exec(path))) screen = await quests(match[1] as "quests" | "quests-hardcore", Number(match[2]));
  else if (path === "/quests") screen = await quests("quests", 1);
  else if (path === "/mod") screen = await moderation(nav);
  else if ((match = /^\/players\/(\d+)$/.exec(path))) screen = await profile(Number(match[1]), nav);
  else if ((match = /^\/join\/([0-9a-f]{64})$/.exec(path))) screen = await join(match[1]!, nav);
  else if (path === "/account") screen = await account(nav);
  else if ((match = /^\/runs\/([0-9a-f]{64})$/.exec(path))) screen = await runPage(match[1]!, nav);
  else if (path === "/about") screen = ABOUT;
  else if (path === "/privacy") screen = PRIVACY;
  else if (path === "/terms") screen = TERMS;
  else screen = notFound();
  return withNotice(url, screen);
}
