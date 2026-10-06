// The site's pages: boards, profiles, and the privacy and terms pages.

import type { Env } from "./http";
import { configuredProviders, PROVIDERS, type ProviderName } from "./oauth";
import { type Board, LOWER_IS_BETTER } from "./ranked";

export function escape(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`);
}

const STYLE = `
body{margin:0;background:#0b0b0d;color:#ddd;font:15px/1.5 system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:24px 16px}
a{color:#e8a33d}h1,h2{color:#fff;font-weight:600}h1 a{color:#c33;text-decoration:none}
table{width:100%;border-collapse:collapse}td,th{padding:4px 6px;text-align:left;border-bottom:1px solid #222}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.muted{color:#888}.badge{font-size:12px;border:1px solid #444;border-radius:4px;padding:0 4px;margin-left:4px}
img.avatar{width:20px;height:20px;border-radius:50%;vertical-align:middle;margin-right:4px}
button{background:#222;color:#ddd;border:1px solid #444;border-radius:4px;padding:4px 10px;cursor:pointer}
button.danger{border-color:#833;color:#f99}form.inline{display:inline}
footer{margin-top:48px;padding-top:12px;border-top:1px solid #222;font-size:13px}`;

export function page(title: string, body: string, status = 200, headers: HeadersInit = {}): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escape(title)} · crimson.land</title><style>${STYLE}</style></head><body><main>
<h1><a href="/">crimson.land</a></h1>${body}
<footer class="muted"><a href="/">Boards</a> · <a href="/privacy">Privacy</a> · <a href="/terms">Terms</a> · <a href="https://github.com/banteg/crimson">Source</a></footer>
</main></body></html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", ...headers } });
}

interface Link {
  provider: ProviderName;
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
  const { results: links } = await env.DB.prepare(`SELECT account_id, provider, handle, avatar_url FROM links WHERE account_id IN (${marks})`)
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

function playerName(player: Player, withLink = true): string {
  const name = player.name && !player.name_hidden ? escape(player.name) : `<span class="muted">${player.fingerprint}</span>`;
  const shown = `<a href="/players/${player.id}">${name}</a>`;
  if (player.links.length && withLink)
    return shown + player.links.map((link) => `<span class="badge">${PROVIDERS[link.provider].label} ${escape(link.handle)}</span>`).join("");
  return player.clash && !player.links.length && !player.name_hidden ? `${shown} <span class="muted">· ${player.fingerprint}</span>` : shown;
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

export async function homePage(env: Env): Promise<Response> {
  const { results: quests } = await env.DB.prepare(
    "SELECT board, quest, count(DISTINCT account_id) AS players FROM runs WHERE board != 'survival' AND hidden = 0 GROUP BY board, quest ORDER BY board, quest",
  ).all<{ board: Board; quest: string; players: number }>();
  const questLinks = quests.length
    ? `<ul>${quests.map((q) => `<li><a href="/boards/${q.board}/${q.quest}">${BOARD_TITLES[q.board]} ${q.quest}</a> <span class="muted">${q.players} players</span></li>`).join("")}</ul>`
    : `<p class="muted">No quest runs yet.</p>`;
  return page(
    "Boards",
    `<p class="muted">Verified runs of the Crimsonland port: every score is a replay the server re-simulates. <a href="https://crimson.banteg.xyz/rewrite/ranked-rules/">Ranked rules</a>.</p>
<h2>Survival</h2>${await boardTable(env, "survival", "", 25)}<p><a href="/boards/survival">Full board</a></p><h2>Quests</h2>${questLinks}`,
  );
}

export async function boardPage(env: Env, board: Board, quest: string): Promise<Response> {
  const title = `${BOARD_TITLES[board]}${quest ? ` ${quest}` : ""}`;
  return page(title, `<h2>${escape(title)}</h2>${await boardTable(env, board, quest, 100)}`);
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
  const links = player.links.length
    ? `<p>${player.links.map((link) => `${link.avatar_url ? `<img class="avatar" src="${escape(link.avatar_url)}" alt="">` : ""}${PROVIDERS[link.provider].label} <b>${escape(link.handle)}</b>`).join(" · ")}</p>`
    : "";
  const history = names.length > 1 || player.name_hidden ? `<p class="muted">Names: ${names.map((n) => escape(n.name)).join(", ")}</p>` : "";
  const table = runs.length
    ? `<table><tr><th>Board</th><th class="n">Score</th><th>Version</th><th>Accepted</th><th>Replay</th></tr>${runs
        .map(
          (run) =>
            `<tr><td>${BOARD_TITLES[run.board]} ${run.quest}</td><td class="n">${formatScore(run.board, run.score)}</td><td>${escape(run.game_version)}</td>` +
            `<td>${new Date(run.accepted_at).toISOString().slice(0, 10)}</td><td><a href="/runs/${run.id}.crd">.crd</a></td></tr>`,
        )
        .join("")}</table>`
    : `<p class="muted">No ranked runs yet.</p>`;
  const own = viewer === accountId ? accountControls(env, player) : "";
  return page(
    player.name || player.fingerprint,
    `${notice ? `<p>${escape(notice)}</p>` : ""}<h2>${playerName(player, false)}${player.name && !player.name_hidden ? ` <span class="muted">· ${player.fingerprint}</span>` : ""}</h2>${links}${history}<h2>Runs</h2>${table}${own}`,
  );
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
