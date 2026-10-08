import { type Accessor, createSignal, For, type JSX, Show } from "solid-js";
import type { Board, BoardView, JoinView, ProfileView, QuestMenuView, RunDetailView } from "../../src/api-types";
import { get, post } from "./api";
import { formatScore } from "./format";
import { GameButton } from "./button";
import { PlayerName, PROVIDER_LABELS } from "./players";
import { runPanels } from "./run";
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
const RULES = "https://crimson.banteg.xyz/rewrite/ranked-rules/";

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

function BoardTable(props: { view: BoardView }) {
  return (
    <Show when={props.view.rows.length} fallback={<p class="muted">No runs yet.</p>}>
      <div class="board-table">
        <table>
          <thead>
            <tr>
              <th class="n">#</th>
              <th>Player</th>
              <th class="n">Score</th>
              <th>Run</th>
              <th class="n">Duration</th>
              <th title="Most used weapon by time equipped">Weapon</th>
              <th>Replay</th>
            </tr>
          </thead>
          <tbody>
            <For each={props.view.rows}>
              {(row) => (
                <tr>
                  <td class="n">{row.rank}</td>
                  <td>
                    <PlayerName player={row.player} />
                  </td>
                  <td class="n">
                    <a class="run" href={`/runs/${row.run}`}>
                      {formatScore(props.view.board, row.score)}
                    </a>
                  </td>
                  <td>
                    <a class="run-details" href={`/runs/${row.run}`}>Details →</a>
                  </td>
                  <td class="n">{formatDuration(row.elapsed_ms)}</td>
                  <td>
                    <Weapon id={row.most_used_weapon_id} />
                  </td>
                  <td>
                    <a href={`/runs/${row.run}.crd`} data-native>
                      .crd
                    </a>
                  </td>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </div>
    </Show>
  );
}

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

async function runPage(id: string): Promise<Screen> {
  const detail = await get<RunDetailView>(`/api/runs/${id}`);
  if (!detail) return notFound();
  return { title: `${detail.name} · ${detail.title}`, quest: detail.quest || null, panels: runPanels(detail) };
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
  const [survival, quests] = await Promise.all([get<BoardView>("/api/boards/survival?limit=25"), get<QuestMenuView>("/api/quests/quests/1")]);
  return {
    title: null,
    quest: null,
    panels: [
      () => (
        <>
          <h2>Survival</h2>
          <BoardTable view={survival!} />
          <p>
            <a href="/boards/survival">Full board</a>
          </p>
        </>
      ),
      () => <QuestMenu view={quests!} />,
    ],
  };
}

async function board(boardName: Board, quest: string): Promise<Screen> {
  if (boardName === "survival") {
    const view = (await get<BoardView>("/api/boards/survival"))!;
    return {
      title: "Survival",
      quest: null,
      panels: [
        () => (
          <>
            <h2>Survival</h2>
            <BoardTable view={view} />
          </>
        ),
      ],
    };
  }
  const stage = Number(quest.split(".")[0]);
  const [view, menu] = await Promise.all([
    get<BoardView>(`/api/boards/${boardName}/${quest}`),
    get<QuestMenuView>(`/api/quests/${boardName}/${stage}`),
  ]);
  return {
    title: view!.title,
    quest,
    panels: [
      keep("quest-menu", { menu: menu!, quest }, (data) => <QuestMenu view={data().menu} current={data().quest} />),
      () => (
        <>
          <h2>{view!.title}</h2>
          <BoardTable view={view!} />
        </>
      ),
    ],
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
          Linking shows your handle next to your name and lets you add another computer's game to this account by signing in with the
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

async function profile(id: number, nav: Navigator): Promise<Screen> {
  const view = await get<ProfileView>(`/api/players/${id}`);
  if (!view) return notFound();
  const history = view.names.length > 1 || view.player.name === null;
  return {
    title: view.player.name ?? view.player.fingerprint,
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
          <Show when={history && view.names.length}>
            <p class="muted">Names: {view.names.join(", ")}</p>
          </Show>
          <h3>Runs</h3>
          <Show when={view.runs.length} fallback={<p class="muted">No ranked runs yet.</p>}>
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
                        <a href={`/runs/${run.id}.crd`} data-native>
                          .crd
                        </a>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
          </Show>
        </>
      ),
      ...(view.account ? [() => <AccountControls profile={view} nav={nav} />] : []),
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
            <GameButton label={`Join ${view.destination.name ?? view.destination.fingerprint}`} onClick={confirmJoin} />
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
          crimson.land is the home of <a href="https://github.com/banteg/crimson">Crimsonland, rebuilt</a>: the 2003 game, playable in your
          browser, and the online leaderboard of its reimplementation. Every score here is a replay of the whole run, which the server plays
          back from start to finish before the score counts.
        </p>
        <h3>Play</h3>
        <p>
          <a href="/play/" data-native>Play in your browser</a>, nothing to install: the original game, compiled from source recovered
          from its executable, with your saves kept in the browser. It plays with a keyboard and mouse or a gamepad.
        </p>
        <p>
          To play for the leaderboard, install <a href="https://docs.astral.sh/uv/getting-started/installation/">uv</a>, then run{" "}
          <Command>uvx crimsonland@latest</Command>: the reimplementation for Windows, macOS and Linux, which records ranked runs. Both
          download the original art and sound on first launch, distributed with permission from 10tons.
        </p>
      </>
    ),
    () => (
      <>
        <h3>Play for the leaderboard</h3>
        <ul>
          <li>
            In the installed game, tick <em>Ranked</em> in the Play Game menu, then play Survival or a quest. Ranked runs play the same for everyone, whatever your own save
            holds: one player, with the original's bugs fixed.
          </li>
          <li>
            Finish the run: die in Survival or complete the quest. The name you type into the high-score entry is the name the run shows
            under.
          </li>
          <li>
            The game uploads the run by itself. Playing offline is fine; runs wait on your computer and upload once the site can be reached.
          </li>
        </ul>
        <p>
          Survival ranks experience, higher first. Each quest ranks its final time, lower first, with hardcore on its own board. A board
          shows each player's best run. The <a href={RULES}>ranked rules</a> have the details.
        </p>
      </>
    ),
    () => (
      <>
        <h3>Your name and profile</h3>
        <p>
          The game makes you an identity on first launch, so there is no sign-up. Your name is the one on your latest run, and your
          profile lists every name you have used. The <em>Profile</em> button in the Play Game menu opens it, signed in.
        </p>
        <p>
          From your profile you can link a GitHub, Discord or X account. Linked players show their handle, so nobody can pass as them, and
          signing in with the same link from another computer joins its runs to your account.
        </p>
        <h3>Replays</h3>
        <p>
          Every run on a board can be downloaded as a <em>.crd</em> file. <Command>uvx crimsonland replay play</Command> followed by the
          file's path watches it, and <Command>uvx crimsonland replay verify</Command> checks it.
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
            <em>Each ranked run you upload:</em> the replay file, the name you typed for it, its result and score, the game version and the
            program that recorded it, and when it was accepted. Your profile shows the name of your latest run and lists every name you have
            used.
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
        <p>Boards, profiles and replays: your names, key fingerprint, linked handles and avatars, run results, and the replay files, which anyone can download.</p>
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
            Upload runs you played yourself. Runs played by tools or other people, runs that exploit a flaw in the verifier, and names that
            impersonate someone are not allowed. The <a href={RULES}>ranked rules</a> say which runs rank.
          </li>
          <li>Uploading a run lets us store and show it and lets anyone download its replay.</li>
          <li>We may hide or remove runs, names and accounts, and ban keys, when these terms are broken.</li>
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
  else if ((match = /^\/players\/(\d+)$/.exec(path))) screen = await profile(Number(match[1]), nav);
  else if ((match = /^\/join\/([0-9a-f]{64})$/.exec(path))) screen = await join(match[1]!, nav);
  else if (path === "/account") screen = await account(nav);
  else if ((match = /^\/runs\/([0-9a-f]{64})$/.exec(path))) screen = await runPage(match[1]!);
  else if (path === "/about") screen = ABOUT;
  else if (path === "/privacy") screen = PRIVACY;
  else if (path === "/terms") screen = TERMS;
  else screen = notFound();
  return withNotice(url, screen);
}
