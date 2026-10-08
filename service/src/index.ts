import { confirmMerge, deleteAccount, linkIdentity, pendingJoin, unlink } from "./accounts";
import { getLogin, postChallenge, postLogin, SESSION_COOKIE, secure, sessionAccount, sessionToken, tokenHash } from "./auth";
import { CARD_HEIGHT, CARD_WIDTH, runCard } from "./card";
import { type Env, json, refuse } from "./http";
import { playerLabel } from "../web/src/names";
import { authorizeUrl, completeLink, PROVIDERS, provider } from "./oauth";
import type { Board } from "./ranked";
import { postRun, timelineFor } from "./runs";
import { boardTitle, boardView, gameScores, joinView, players, profileView, questMenuView, runDescription, runDetailView, runSummary, visibleRun } from "./views";

// Links, OAuth callbacks and the session cookie follow the request's origin, so the site answers only over
// HTTPS, and browsers are told to stay there. Plain-HTTP localhost stays for wrangler dev.
const HSTS = "max-age=31536000; includeSubDomains";
const QUEST = /^[1-5]\.(?:[1-9]|10)$/;
// The game's files the playable game loads, from the version the bucket keeps them under; the page keeps them in the
// player's browser after the first visit (crimson-core/client/web/shell.html).
const GAME_FILES = new Set(["crimson.paq", "sfx.paq", "music.paq"]);
const GAME_VERSION = "v1.9.93";
// The game's high score tables hold 100 records (TABLE_MAX).
const SCORES_LIMIT = 100;
// How long the edge keeps a run's card: link previews fetch it once, and a rank or a moderator's change shows soon.
const CARD_MAX_AGE_S = 600;
const REPLAY_MAX_AGE_S = 300;

const signedOut = (request: Request) => `${SESSION_COOKIE}=; Path=/; HttpOnly;${secure(request)} SameSite=Lax; Max-Age=0`;

function redirect(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, { status: 303, headers: { Location: location, ...headers } });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol === "http:" && url.hostname !== "localhost") {
      url.protocol = "https:";
      // 308 keeps the method and body, so a POST is repeated over HTTPS rather than turned into a GET.
      return Response.redirect(url.toString(), request.method === "GET" || request.method === "HEAD" ? 301 : 308);
    }
    const response = await handle(request, env, url);
    if (url.protocol !== "https:") return response;
    const secured = new Response(response.body, response);
    secured.headers.set("Strict-Transport-Security", HSTS);
    return secured;
  },
} satisfies ExportedHandler<Env>;

async function handle(request: Request, env: Env, url: URL): Promise<Response> {
  const route = `${request.method} ${url.pathname}`;
  let match: RegExpExecArray | null;

  // The game's API.
  switch (route) {
    case "POST /api/runs":
      return postRun(request, env);
    case "POST /api/auth/challenge":
      return postChallenge(request, env);
    case "POST /api/auth/login":
      return postLogin(request, env);
    case "POST /api/scores": {
      // The high score screen's Update scores: a board's best runs as high score records, {board, quest}.
      const body = (await request.json().catch(() => ({}))) as { board?: unknown; quest?: unknown };
      const quest = String(body.quest ?? "");
      if (body.board === "survival" && quest === "") return json({ scores: await gameScores(env, "survival", "", SCORES_LIMIT) });
      if ((body.board === "quests" || body.board === "quests-hardcore") && QUEST.test(quest))
        return json({ scores: await gameScores(env, body.board, quest, SCORES_LIMIT) });
      return refuse(400, "no such board");
    }
  }

  // The site's read API.
  if (route === "GET /api/boards/survival") {
    const limit = Math.min(100, Number(url.searchParams.get("limit")) || 100);
    return json(await boardView(env, "survival", "", limit));
  }
  if ((match = /^GET \/api\/boards\/(quests|quests-hardcore)\/([^/]+)$/.exec(route)) && QUEST.test(match[2]!))
    return json(await boardView(env, match[1] as Board, match[2]!, 100));
  if ((match = /^GET \/api\/quests\/(quests|quests-hardcore)\/([1-5])$/.exec(route)))
    return json(await questMenuView(env, match[1] as "quests" | "quests-hardcore", Number(match[2])));
  if ((match = /^GET \/api\/players\/(\d+)$/.exec(route))) {
    const profile = await profileView(env, Number(match[1]), await sessionAccount(request, env));
    return profile ? json(profile) : refuse(404, "no such player");
  }
  if ((match = /^GET \/api\/runs\/([0-9a-f]{64})$/.exec(route))) {
    const run = await runDetailView(env, match[1]!);
    return run ? json(run) : refuse(404, "no such run");
  }
  if ((match = /^GET \/api\/runs\/([0-9a-f]{64})\/timeline$/.exec(route))) {
    const timeline = (await visibleRun(env, match[1]!)) && (await timelineFor(env, match[1]!));
    return timeline ? json(timeline) : refuse(404, "no such run");
  }
  if (route === "GET /api/me") return json({ account: await sessionAccount(request, env) });

  // The playable game: its page, built from crimson-core/client into dist/play/, and the game's files.
  // The redirect keeps the query, which can name where the page loads the game files from.
  if (route === "GET /play") return Response.redirect(new URL(`/play/${url.search}`, url).toString(), 301);
  if (route === "GET /play/") {
    // Staged by `npm run play`; a build without it has no game page.
    const page = await env.ASSETS.fetch(request);
    if (!page.ok) return page;
    return withPreview(page, url, { title: "Play", description: "Crimsonland in the browser: the original game, recovered from its executable.", image: null });
  }
  if ((match = /^(GET|HEAD) \/play\/game\/(.+)$/.exec(route))) {
    const key = `${GAME_VERSION}/${match[2]}`;
    const head = match[1] === "HEAD";
    const file = GAME_FILES.has(match[2]!) && (await (head ? env.GAME_FILES.head(key) : env.GAME_FILES.get(key)));
    if (!file) return new Response(null, { status: 404 });
    return new Response(head ? null : (file as R2ObjectBody).body, {
      headers: {
        "content-type": "application/octet-stream",
        "content-length": String(file.size),
        etag: file.httpEtag,
        "cache-control": "public, max-age=86400",
      },
    });
  }

  // Pages the server answers itself: the game's login link and replay files.
  if ((match = /^GET \/login\/([0-9a-f]{64})$/.exec(route))) return getLogin(request, env, match[1]!);
  if ((match = /^GET \/runs\/([0-9a-f]{64})\.crd$/.exec(route))) {
    const file = (await visibleRun(env, match[1]!)) && (await env.REPLAYS.get(`runs/${match[1]}.crd`));
    if (!file) return new Response("No such replay.", { status: 404 });
    // A run's replay never changes; the short life lets hiding, bans and deletions take effect.
    return new Response(file.body, {
      headers: {
        "content-type": "application/octet-stream",
        "content-disposition": `attachment; filename="${match[1]!.slice(0, 12)}.crd"`,
        "cache-control": `public, max-age=${REPLAY_MAX_AGE_S}, must-revalidate`,
      },
    });
  }

  if ((match = /^GET \/runs\/([0-9a-f]{64})\.png$/.exec(route))) {
    const cached = await caches.default.match(request);
    if (cached) return cached;
    const card = await runCard(env, url.origin, match[1]!);
    if (!card) return new Response("No such run.", { status: 404 });
    const response = new Response(card, { headers: { "content-type": "image/png", "cache-control": `public, max-age=${CARD_MAX_AGE_S}, must-revalidate` } });
    await caches.default.put(request, response.clone());
    return response;
  }

  // Linking: the provider's sign-in and its callback, which hand back to the site's pages.
  const accountId = await sessionAccount(request, env);
  const token = sessionToken(request);
  if ((match = /^GET \/auth\/([a-z]+)\/(start|callback)$/.exec(route))) {
    const chosen = provider(env, match[1]!);
    if (!chosen || accountId === null || token === null) return redirect("/account");
    if (match[2] === "start") return redirect(await authorizeUrl(env, url.origin, chosen, token));
    const notice = (kind: string) => redirect(`/players/${accountId}?notice=${kind}&provider=${chosen.name}`);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return notice("cancelled");
    const identity = await completeLink(env, url.origin, chosen, token, state, code);
    if (!identity) return notice("failed");
    const linked = await linkIdentity(env, accountId, token, chosen.name, identity);
    return linked.outcome === "confirm" ? redirect(`/join/${linked.token}`) : notice("linked");
  }

  // The signed-in account's API, for the site's own pages only.
  if (url.pathname.startsWith("/api/account/") || url.pathname.startsWith("/api/join") || url.pathname === "/api/logout") {
    if (request.method === "POST" && request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    if (accountId === null || token === null) return refuse(401, "sign in from the game");
    const expired = () => refuse(410, "this request expired; link again to join the accounts");
    if ((match = /^GET \/api\/join\/([0-9a-f]{64})$/.exec(route))) {
      const pending = await pendingJoin(env, accountId, token, match[1]!);
      if (!pending) return expired();
      const label = PROVIDERS[pending.provider as keyof typeof PROVIDERS].label;
      return json(await joinView(env, accountId, pending.into, label));
    }
    if (route === "POST /api/join") {
      const body = (await request.json().catch(() => ({}))) as { token?: unknown };
      const into = await confirmMerge(env, accountId, token, String(body.token ?? ""));
      return into === null ? expired() : json({ account: into });
    }
    if ((match = /^POST \/api\/account\/unlink\/([a-z]+)$/.exec(route))) {
      const chosen = provider(env, match[1]!);
      if (chosen) await unlink(env, accountId, chosen.name);
      return json({ account: accountId });
    }
    if (route === "POST /api/account/delete") {
      await deleteAccount(env, accountId);
      return json({ account: null }, 200, { "Set-Cookie": signedOut(request) });
    }
    if (route === "POST /api/logout") {
      await env.DB.prepare("DELETE FROM sessions WHERE account_id = ? AND token_hash = ?").bind(accountId, await tokenHash(token)).run();
      return json({ account: null }, 200, { "Set-Cookie": signedOut(request) });
    }
  }
  if (url.pathname.startsWith("/api/")) return refuse(404, "no such endpoint");

  // The site: its files, else its page with the route's title and preview tags.
  // Quest routes end in ".1" and such, so only real file extensions count as files.
  if (/\.(?:js|css|png|jpg|svg|ico|woff2|txt|map|webmanifest|wasm)$/i.test(url.pathname)) return env.ASSETS.fetch(request);
  return shell(env, url);
}

// What a shared link previews: the route's title, and for a run, what happened and its card.
interface Preview {
  title: string | null;
  description: string;
  image: { url: string; width: number; height: number } | null;
}

const SITE_DESCRIPTION = "Play Crimsonland in your browser, and verified leaderboards where every score is a replay the server re-simulates.";
// The preview of a page with no image of its own: a moment of the Survival board's top run (public/og.jpg).
const SITE_IMAGE = { path: "/og.jpg", width: CARD_WIDTH, height: CARD_HEIGHT };

async function routePreview(env: Env, url: URL): Promise<Preview> {
  const path = url.pathname;
  const titled = (title: string | null): Preview => ({ title, description: SITE_DESCRIPTION, image: null });
  let match: RegExpExecArray | null;
  if (path === "/boards/survival") return titled(boardTitle("survival", ""));
  if ((match = /^\/boards\/(quests|quests-hardcore)\/([^/]+)$/.exec(path)) && QUEST.test(match[2]!)) return titled(boardTitle(match[1] as Board, match[2]!));
  if ((match = /^\/(quests|quests-hardcore)\/([1-5])$/.exec(path))) return titled(`Quests ${["I", "II", "III", "IV", "V"][Number(match[2]) - 1]}`);
  if ((match = /^\/players\/(\d+)$/.exec(path))) {
    const player = (await players(env, [Number(match[1])])).get(Number(match[1]));
    return titled(player ? playerLabel(player) : null);
  }
  if ((match = /^\/runs\/([0-9a-f]{64})$/.exec(path))) {
    const run = await runSummary(env, match[1]!);
    if (!run) return titled(null);
    return {
      title: `${playerLabel(run.player)} · ${run.title}`,
      description: runDescription(run),
      image: { url: `${url.origin}/runs/${run.id}.png`, width: CARD_WIDTH, height: CARD_HEIGHT },
    };
  }
  return titled(({ "/about": "About", "/privacy": "Privacy", "/terms": "Terms" } as Record<string, string>)[path] ?? null);
}

// The site's one page, titled for the route so shared links preview what they point at.
async function shell(env: Env, url: URL): Promise<Response> {
  return withPreview(await env.ASSETS.fetch(new Request(new URL("/", url))), url, await routePreview(env, url));
}

// A page with its title and the tags shared links preview.
function withPreview(page: Response, url: URL, preview: Preview): Response {
  const full = preview.title ? `${preview.title} · crimson.land` : "crimson.land";
  const image = preview.image ?? { ...SITE_IMAGE, url: `${url.origin}${SITE_IMAGE.path}` };
  const escape = (text: string) => text.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`);
  const meta = (attribute: string, entries: [string, string | number][]) =>
    entries.map(([key, value]) => `<meta ${attribute}="${key}" content="${escape(String(value))}">`);
  const tags = [
    ...meta("name", [["description", preview.description]]),
    ...meta("property", [
      ["og:title", full],
      ["og:description", preview.description],
      ["og:url", url.toString()],
      ["og:image", image.url],
      ["og:image:width", image.width],
      ["og:image:height", image.height],
    ]),
    // X shows a large image only when asked to.
    ...meta("name", [["twitter:card", "summary_large_image"]]),
  ];
  return new HTMLRewriter()
    .on("title", { element: (element) => void element.setInnerContent(full) })
    .on("head", { element: (element) => void element.append(tags.join(""), { html: true }) })
    .transform(new Response(page.body, { headers: { "content-type": "text/html; charset=utf-8" } }));
}
