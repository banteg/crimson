// The site's pages: boards, profiles, and the privacy and terms pages.

import { siDiscord, siGithub, siX } from "simple-icons";
import type { Env } from "./http";
import questTitles from "./quests.json";
import { configuredProviders, PROVIDERS, type ProviderName } from "./oauth";
import { type Board, LOWER_IS_BETTER } from "./ranked";

export function escape(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

// The game's menus: its own sign, panel frame, quest label, stage icons and checkboxes (scripts/assets.py exports
// them from crimson.paq) over its terrain, with the menu's label blue and quest-row colors.
const STYLE = `
@font-face{font-family:"Crimson Small";src:url(/ui/small.woff2) format("woff2");font-display:swap}
:root{--text:#e6e6e6;--label:#b3b3b3;--dim:#7d7d7d;--heading:#2089c6;--row:rgba(70,180,240,.6);--row-on:rgb(70,180,240);
  --row-hardcore:rgba(250,70,60,.6);--row-hardcore-on:rgb(250,70,60)}
body{margin:0;color:var(--text);background:#0b0a07;
  font:16px/20px "Crimson Small",Arial,sans-serif;-webkit-font-smoothing:none;-moz-osx-font-smoothing:unset}
/* The game's 1024-wide screen: the generated ground (terrain.js), the sign hanging from its right edge, panels
   whose wires run to its left edge. */
.screen{position:relative;max-width:1024px;min-height:100vh;margin:0 auto;overflow:hidden;
  background:rgb(63,56,25) center top/1024px 1024px no-repeat fixed}
header{text-align:right;padding-top:10px}header img{width:512px;max-width:100%;height:auto;display:inline-block;vertical-align:top}
main{padding:6px 40px 4px 178px}
@media (max-width:900px){main{padding:6px 12px 4px}}
h2,h3,.quest-menu .label{margin:2px 0 10px;color:var(--label);font:bold 20px/32px "Courier New",Courier,monospace;text-transform:uppercase}
td.n,.count,.score{font:bold 14px/20px "Courier New",Courier,monospace;white-space:nowrap}
a{color:var(--row-on)}a:hover{color:#8fd3ff}
.panel{position:relative;z-index:0;margin:0 0 20px;padding:4px 14px 6px;border:solid transparent;border-width:18px 19px 19px 14px;
  border-image:url(/ui/panel.png) 18 19 19 14 fill stretch}
@media (min-width:901px){.panel::before{content:"";position:absolute;z-index:-1;left:-192px;top:-2px;width:192px;height:50px;
  background:url(/ui/wires.png) no-repeat}}
table{width:100%;border-collapse:collapse}td,th{padding:2px 6px;text-align:left}tr+tr td{border-top:1px solid #151515}
th{color:var(--dim);font-weight:400}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.muted{color:var(--dim)}
img.avatar{width:18px;height:18px;border-radius:50%;vertical-align:middle;margin-right:6px}img.avatar.heading{width:36px;height:36px}
a.name{color:#fff;text-decoration:none}a.name:hover{color:var(--row-on)}
.links{margin-left:4px}.links .muted{margin-right:6px;font-weight:400}
a.provider{color:var(--dim);margin-right:6px;text-decoration:none;white-space:nowrap}a.provider:hover{color:var(--text)}
svg.icon{width:13px;height:13px;fill:currentColor;vertical-align:-1px}h2 svg.icon{width:17px;height:17px}
h2 a.name,h2 .links,.fingerprint{text-transform:none}h2 .avatar+a.name{font-weight:400}
.fingerprint{font-size:16px}
button{background:#1b1b1b;color:var(--label);border:1px solid #484848;border-radius:3px;padding:1px 12px;cursor:pointer;font:inherit}
button:hover{color:#fff;border-color:#777}button.danger{border-color:#6a2a2a;color:#e88}form.inline{display:inline}
/* quest_select_menu_update's layout from its QUEST label, whose 64px art becomes "QUEST:" in 20px Courier (72px):
   stage icons 16px past it and 3px down, 36px apart, 32px or
   25.6px from their top-left corner; the list origin 32px right and 50px down, its rows 10px lower for the
   hardcore box, in 20px rows; the hardcore box 132px right of the list origin and 12px above it. The label and idle icons are tinted 0.7. */
.quest-menu{position:relative;width:296px;height:264px;margin:4px 0 0 4px}.panel:has(>.quest-menu){width:fit-content}
.quest-menu>.label{position:absolute;left:0;top:0;margin:0}
.stages a{position:absolute;top:3px;width:26px;height:26px}.stages img{width:100%;height:100%;filter:brightness(.7);opacity:.7}
.stages a:hover img{filter:none;opacity:.8}.stages a.on{width:32px;height:32px}.stages a.on img{filter:none;opacity:1}
.hardcore{position:absolute;left:164px;top:38px;color:var(--label);text-decoration:none;white-space:nowrap}.hardcore:hover{color:#fff}
.hardcore img{width:16px;height:16px;vertical-align:-3px;margin-right:6px}
ol.quests{position:absolute;left:32px;top:60px;list-style:none;margin:0;padding:0}ol.quests li{height:20px;white-space:nowrap}
ol.quests .count{font-size:13px}
ol.quests a{color:var(--row);text-decoration:none;border-bottom:1px solid}ol.quests a:hover,ol.quests a.on{color:var(--row-on)}
.hardcore-on ol.quests a{color:var(--row-hardcore)}.hardcore-on ol.quests a:hover,.hardcore-on ol.quests a.on{color:var(--row-hardcore-on)}
ol.quests .n{display:inline-block;width:34px}ol.quests .count{margin-left:10px;color:var(--dim)}
footer{padding:0 0 20px;text-align:center;color:var(--label);text-shadow:0 1px 2px #000}footer a{color:var(--text)}`;

// `quest` picks the quest whose terrain the ground shows; other pages roll the game's random terrain.
export function page(title: string, panels: string | string[], status = 200, headers: HeadersInit = {}, quest = ""): Response {
  const body = (Array.isArray(panels) ? panels : [panels]).map((panel) => `<section class="panel">${panel}</section>`).join("");
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)} · crimson.land</title><style>${STYLE}</style><script type="module" src="/terrain.js"></script></head>
<body><div class="screen"${quest ? ` data-quest="${quest}"` : ""}>
<header><a href="/"><img src="/ui/sign.png" width="512" height="128" alt="Crimsonland"></a></header><main>${body}</main>
<footer><a href="/">Boards</a> · <a href="/quests/1">Quests</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="https://github.com/banteg/crimson">Source</a></footer>
</div></body></html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", ...headers } });
}

interface Link {
  provider: ProviderName;
  subject: string;
  handle: string;
  avatar_url: string | null;
}
interface Player {
  id: number;
  name: string;
  name_hidden: number;
  fingerprint: string;
  links: Link[];
  clash: boolean;
}

// How the boards show players (docs/rewrite/leaderboard-identity.md, "Names"): the latest run's name; a linked
// account adds its handles; an unlinked one adds its key fingerprint when another account shows the same name.
async function players(env: Env, ids: number[]): Promise<Map<number, Player>> {
  const found = new Map<number, Player>();
  if (!ids.length) return found;
  const marks = ids.map(() => "?").join(",");
  const { results: accounts } = await env.DB.prepare(
    `SELECT a.id, a.name, a.name_hidden,
       (SELECT fingerprint FROM keys WHERE account_id = a.id ORDER BY added_at LIMIT 1) AS fingerprint,
       (SELECT count(*) FROM accounts b WHERE lower(b.name) = lower(a.name) AND b.id != a.id AND b.name != '') AS clashes
     FROM accounts a WHERE a.id IN (${marks})`,
  )
    .bind(...ids)
    .all<{ id: number; name: string; name_hidden: number; fingerprint: string; clashes: number }>();
  const { results: links } = await env.DB.prepare(`SELECT account_id, provider, subject, handle, avatar_url FROM links WHERE account_id IN (${marks})`)
    .bind(...ids)
    .all<Link & { account_id: number }>();
  for (const account of accounts)
    found.set(account.id, {
      ...account,
      links: links.filter((link) => link.account_id === account.id),
      clash: account.clashes > 0,
    });
  return found;
}

// Linked accounts in this order: the avatar comes from the first that has one.
const LINK_ORDER: ProviderName[] = ["x", "discord", "github"];
const ICONS: Record<ProviderName, { title: string; path: string }> = { github: siGithub, discord: siDiscord, x: siX };

function icon(provider: ProviderName): string {
  return `<svg class="icon" viewBox="0 0 24 24" role="img" aria-label="${ICONS[provider].title}"><path d="${ICONS[provider].path}"/></svg>`;
}

function providerProfile(link: Link): string {
  switch (link.provider) {
    case "github":
      return `https://github.com/${encodeURIComponent(link.handle)}`;
    case "x":
      return `https://x.com/${encodeURIComponent(link.handle)}`;
    case "discord":
      return `https://discord.com/users/${encodeURIComponent(link.subject)}`;
  }
}

// A player as boards and profiles show them: the avatar of their first linked account, the latest run's name, and
// each linked account's icon. Handles shared by every link collapse into one, shown only where it differs from the
// name; an unlinked account adds its key fingerprint when another account shows the same name.
function playerName(player: Player, size: "row" | "heading" = "row"): string {
  const links = [...player.links].sort((a, b) => LINK_ORDER.indexOf(a.provider) - LINK_ORDER.indexOf(b.provider));
  const named = Boolean(player.name) && !player.name_hidden;
  const label = named ? escape(player.name) : `<span class="muted">${player.fingerprint}</span>`;
  const avatar = links.find((link) => link.avatar_url)?.avatar_url;
  const shown = `${avatar ? `<img class="avatar ${size}" src="${escape(avatar)}" alt="">` : ""}<a class="name" href="/players/${player.id}">${label}</a>`;
  if (!links.length) return player.clash && named ? `${shown} <span class="muted">· ${player.fingerprint}</span>` : shown;
  const handles = new Set(links.map((link) => link.handle.toLowerCase()));
  const iconLink = (link: Link, text = "") =>
    `<a class="provider" href="${escape(providerProfile(link))}" title="${PROVIDERS[link.provider].label} ${escape(link.handle)}">${icon(link.provider)}${text}</a>`;
  if (handles.size === 1) {
    const handle = links[0]!.handle;
    const differs = !named || handle.toLowerCase() !== player.name.toLowerCase();
    return `${shown} <span class="links">${differs ? `<span class="muted">${escape(handle)}</span>` : ""}${links.map((link) => iconLink(link)).join("")}</span>`;
  }
  return `${shown} <span class="links">${links.map((link) => iconLink(link, ` ${escape(link.handle)}`)).join("")}</span>`;
}

const BOARD_TITLES: Record<Board, string> = { survival: "Survival", quests: "Quests", "quests-hardcore": "Quests, hardcore" };

function formatScore(board: Board, score: number): string {
  if (board === "survival") return `${score.toLocaleString("en-US")} xp`;
  const sign = score < 0 ? "-" : "";
  const ms = Math.abs(score);
  return `${sign}${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, "0")}.${String(ms % 1000).padStart(3, "0")}`;
}

// Each account's best run on a board; equal scores keep the earlier accepted run ahead.
async function boardRows(env: Env, board: Board, quest: string, limit: number) {
  const order = LOWER_IS_BETTER[board] ? "ASC" : "DESC";
  const { results } = await env.DB.prepare(
    `SELECT r.id, r.account_id, r.score, r.accepted_at FROM runs r JOIN accounts a ON a.id = r.account_id
     WHERE r.board = ? AND r.quest = ? AND r.hidden = 0 AND a.banned = 0
       AND r.id = (SELECT id FROM runs b WHERE b.account_id = r.account_id AND b.board = r.board AND b.quest = r.quest AND b.hidden = 0
                   ORDER BY b.score ${order}, b.accepted_at LIMIT 1)
     ORDER BY r.score ${order}, r.accepted_at LIMIT ?`,
  )
    .bind(board, quest, limit)
    .all<{ id: string; account_id: number; score: number; accepted_at: number }>();
  return results;
}

async function boardTable(env: Env, board: Board, quest: string, limit: number): Promise<string> {
  const rows = await boardRows(env, board, quest, limit);
  if (!rows.length) return `<p class="muted">No runs yet.</p>`;
  const who = await players(env, rows.map((row) => row.account_id));
  return `<table><tr><th class="n">#</th><th>Player</th><th class="n">Score</th><th>Replay</th></tr>${rows
    .map(
      (row, i) =>
        `<tr><td class="n">${i + 1}</td><td>${playerName(who.get(row.account_id)!)}</td><td class="n">${formatScore(board, row.score)}</td>` +
        `<td><a href="/runs/${row.id}.crd">.crd</a></td></tr>`,
    )
    .join("")}</table>`;
}

const STAGES = ["I", "II", "III", "IV", "V"];
const QUEST_TITLES: Record<string, string> = questTitles;

// The quest boards' menu, as the game's quest screen: stage tabs, the hardcore box and the stage's ten quests.
async function questMenu(env: Env, stage: number, hardcore: boolean, current = ""): Promise<string> {
  const board: Board = hardcore ? "quests-hardcore" : "quests";
  const { results } = await env.DB.prepare(
    "SELECT quest, count(DISTINCT account_id) AS players FROM runs WHERE board = ? AND quest LIKE ? AND hidden = 0 GROUP BY quest",
  )
    .bind(board, `${stage}.%`)
    .all<{ quest: string; players: number }>();
  const players = new Map(results.map((row) => [row.quest, row.players]));
  const menu = hardcore ? "quests-hardcore" : "quests";
  const toggle = current ? `/boards/${hardcore ? "quests" : "quests-hardcore"}/${current}` : `/${hardcore ? "quests" : "quests-hardcore"}/${stage}`;
  const tabs = STAGES.map(
    (numeral, i) =>
      `<a class="${i + 1 === stage ? "on" : ""}" style="left:${88 + i * 36}px" href="/${menu}/${i + 1}"><img src="/ui/stage${i + 1}.png" alt="${numeral}"></a>`,
  ).join("");
  const rows = Array.from({ length: 10 }, (_, i) => {
    const quest = `${stage}.${i + 1}`;
    const count = players.get(quest);
    return `<li><a class="${quest === current ? "on" : ""}" href="/boards/${board}/${quest}"><span class="n">${quest}</span>${escape(QUEST_TITLES[quest]!)}</a>${
      count ? `<span class="count">${count}</span>` : ""
    }</li>`;
  }).join("");
  return `<div class="quest-menu${hardcore ? " hardcore-on" : ""}"><span class="label">Quest:</span>
<nav class="stages">${tabs}</nav><a class="hardcore" href="${toggle}"><img src="/ui/check-${hardcore ? "on" : "off"}.png" alt="">Hardcore</a>
<ol class="quests">${rows}</ol></div>`;
}

export async function homePage(env: Env): Promise<Response> {
  return page("Boards", [
    `<p class="muted">Verified runs of the Crimsonland port: every score is a replay the server re-simulates. <a href="https://crimson.banteg.xyz/rewrite/ranked-rules/">Ranked rules</a>.</p>
<h2>Survival</h2>${await boardTable(env, "survival", "", 25)}<p><a href="/boards/survival">Full board</a></p>`,
    await questMenu(env, 1, false),
  ]);
}

export async function questsPage(env: Env, stage: number, hardcore: boolean): Promise<Response> {
  return page(`Quests ${STAGES[stage - 1]}`, await questMenu(env, stage, hardcore), 200, {}, `${stage}.1`);
}

export async function boardPage(env: Env, board: Board, quest: string): Promise<Response> {
  if (board === "survival") return page("Survival", `<h2>Survival</h2>${await boardTable(env, board, quest, 100)}`);
  const title = `${quest} ${QUEST_TITLES[quest]}`;
  return page(
    `${title}${board === "quests-hardcore" ? " (hardcore)" : ""}`,
    [
      await questMenu(env, Number(quest.split(".")[0]), board === "quests-hardcore", quest),
      `<h2>${escape(title)}${board === "quests-hardcore" ? " · hardcore" : ""}</h2>${await boardTable(env, board, quest, 100)}`,
    ],
    200,
    {},
    quest,
  );
}

export async function profilePage(env: Env, accountId: number, viewer: number | null, notice = ""): Promise<Response> {
  const player = (await players(env, [accountId])).get(accountId);
  if (!player) return page("Not found", "<p>No such player.</p>", 404);
  const { results: names } = await env.DB.prepare("SELECT name FROM names WHERE account_id = ? ORDER BY last_at DESC").bind(accountId).all<{ name: string }>();
  const { results: runs } = await env.DB.prepare(
    "SELECT id, board, quest, score, game_version, accepted_at FROM runs WHERE account_id = ? AND hidden = 0 ORDER BY accepted_at DESC LIMIT 100",
  )
    .bind(accountId)
    .all<{ id: string; board: Board; quest: string; score: number; game_version: string; accepted_at: number }>();
  const history = names.length > 1 || player.name_hidden ? `<p class="muted">Names: ${names.map((n) => escape(n.name)).join(", ")}</p>` : "";
  const table = runs.length
    ? `<table><tr><th>Board</th><th class="n">Score</th><th>Version</th><th>Accepted</th><th>Replay</th></tr>${runs
        .map(
          (run) =>
            `<tr><td><a href="/boards/${run.board}${run.quest ? `/${run.quest}` : ""}">${BOARD_TITLES[run.board]} ${run.quest}</a></td><td class="n">${formatScore(run.board, run.score)}</td><td>${escape(run.game_version)}</td>` +
            `<td>${new Date(run.accepted_at).toISOString().slice(0, 10)}</td><td><a href="/runs/${run.id}.crd">.crd</a></td></tr>`,
        )
        .join("")}</table>`
    : `<p class="muted">No ranked runs yet.</p>`;
  const header = `${notice ? `<p>${escape(notice)}</p>` : ""}<h2>${playerName(player, "heading")}${
    player.name && !player.name_hidden ? ` <span class="muted fingerprint">${player.fingerprint}</span>` : ""
  }</h2>${history}`;
  return page(player.name || player.fingerprint, [
    `${header}<h3>Runs</h3>${table}`,
    ...(viewer === accountId ? [accountControls(env, player)] : []),
  ]);
}

function accountControls(env: Env, player: Player): string {
  const linked = new Set(player.links.map((link) => link.provider));
  const providers = configuredProviders(env);
  const rows = providers
    .map((provider) =>
      linked.has(provider.name)
        ? `<li>${provider.label}: linked · <form class="inline" method="post" action="/account/unlink/${provider.name}"><button>Unlink</button></form></li>`
        : `<li><a href="/auth/${provider.name}/start">Link ${provider.label}</a></li>`,
    )
    .join("");
  return `<h2>Your account</h2>
${providers.length ? `<p class="muted">Linking shows your handle next to your name and lets you add another computer's game to this account by signing in with the same login there. See <a href="/privacy">what linking stores</a>.</p><ul>${rows}</ul>` : ""}
<form class="inline" method="post" action="/logout"><button>Sign out</button></form>
<h2>Delete account</h2><p class="muted">Removes your runs and their replay files, names, links, keys and sessions. The game keeps its key, so playing ranked again starts a new account.</p>
<form method="post" action="/account/delete" onsubmit="return confirm('Delete this account and all its runs?')"><button class="danger">Delete account</button></form>`;
}

export function privacyPage(): Response {
  return page(
    "Privacy",
    `<h2>Privacy</h2>
<p>crimson.land runs the online leaderboard of the Crimsonland port. This is everything it keeps.</p>
<h3>What we store</h3>
<ul>
<li><b>Your game's public key</b> and a four-character fingerprint of it. The game makes the key on its first launch; the private half never leaves your computer.</li>
<li><b>Each ranked run you upload:</b> the replay file, the name you typed for it, its result and score, the game version, and when it was accepted. Your profile shows the name of your latest run and lists every name you have used.</li>
<li><b>Linked accounts</b>, if you link one: the GitHub, Discord or X account's numeric ID, handle and avatar URL. We ask for the least access each offers (GitHub: none; Discord: <code>identify</code>; X: <code>users.read tweet.read</code>), use the access token once to read your profile, and do not keep it.</li>
<li><b>Sessions:</b> opening your profile from the game signs you in with a random token in a cookie, which we keep only as a hash, for 30 days or until you sign out. Sign-in links expire after a minute, sign-in challenges after five minutes, and account-linking requests after ten.</li>
</ul>
<h3>What is public</h3>
<p>Boards, profiles and replays: your names, key fingerprint, linked handles and avatars, run results, and the replay files, which anyone can download.</p>
<h3>Where it lives</h3>
<p>Cloudflare hosts the site and stores the data (Workers, D1 for the database, R2 for replay files). Cloudflare handles the service's request logs, including IP addresses, and keeps them for up to seven days under <a href="https://www.cloudflare.com/privacypolicy/">its privacy policy</a>. We do not store IP addresses ourselves, and we do not use analytics or ads. Profile pages load linked avatars straight from GitHub, Discord or X.</p>
<h3>How long, and deleting it</h3>
<p>Everything above stays until you delete your account; expired sessions, links and challenges are removed. Your profile's <b>Delete account</b> button removes your runs and their replay files, names, links, keys and sessions at once, and <b>Unlink</b> removes a linked account. Signing in again from the game starts a new account. For anything else, <a href="https://github.com/banteg/crimson/issues">open an issue</a>.</p>`,
  );
}

export function termsPage(): Response {
  return page(
    "Terms",
    `<h2>Terms</h2>
<ul>
<li>crimson.land is a free, unofficial fan leaderboard for an open-source port of Crimsonland. It is not affiliated with 10tons, who own Crimsonland and its assets; the port distributes the assets with their permission.</li>
<li>Upload runs you played yourself. Runs played by tools or other people, runs that exploit a flaw in the verifier, and names that impersonate someone are not allowed. The <a href="https://crimson.banteg.xyz/rewrite/ranked-rules/">ranked rules</a> say which runs rank.</li>
<li>Uploading a run lets us store and show it and lets anyone download its replay.</li>
<li>We may hide or remove runs, names and accounts, and ban keys, when these terms are broken.</li>
<li>The service comes as is, without guarantees. It may change, go down or lose data.</li>
<li>Changes to these terms appear on this page.</li>
</ul>`,
  );
}

// Confirming that this game's key joins the account a linked login belongs to.
export async function mergePage(env: Env, token: string, from: number, into: number, providerLabel: string): Promise<Response> {
  const who = await players(env, [from, into]);
  const destination = who.get(into)!;
  const count = async (sql: string, id: number) => (await env.DB.prepare(sql).bind(id).first<{ n: number }>())!.n;
  const [keys, runs, names] = await Promise.all([
    count("SELECT count(*) AS n FROM keys WHERE account_id = ?", from),
    count("SELECT count(*) AS n FROM runs WHERE account_id = ?", from),
    count("SELECT count(*) AS n FROM names WHERE account_id = ?", from),
  ]);
  const destinationRuns = await count("SELECT count(*) AS n FROM runs WHERE account_id = ?", into);
  return page(
    "Join account",
    `<h2>This ${escape(providerLabel)} login belongs to another account</h2>
<p>${playerName(destination)} <span class="muted">· ${destination.fingerprint} · ${destinationRuns} runs</span></p>
<p>Joining moves this game's ${keys === 1 ? "key" : `${keys} keys`}, ${runs} runs and ${names} names into that account, and removes
this one. Do it only if both are yours.</p>
<form method="post" action="/account/merge"><input type="hidden" name="token" value="${token}">
<button>Join ${escape(destination.name || destination.fingerprint)}</button> <a href="/players/${from}">Cancel</a></form>`,
  );
}
