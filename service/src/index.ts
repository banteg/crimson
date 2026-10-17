import { confirmMerge, deleteAccount, linkIdentity, pendingJoin, unlink } from "./accounts";
import { analyticsView, postAnalytics, pruneAnalytics } from "./analytics";
import { loginLink, postChallenge, postLogin, postLoginLink, SESSION_COOKIE, secure, sessionAccount, sessionToken, tokenHash } from "./auth";
import { CARD_HEIGHT, CARD_WIDTH, runCard } from "./card";
import { coopRoute } from "./coop";
import { type Env, json, refuse } from "./http";
import { playerLabel, runLabel } from "../web/src/names";
import { authorizeUrl, completeLink, PROVIDERS, provider } from "./oauth";
import { CUSTOM_QUEST_ID, QUEST, type QuestBoard, questPage, questsPath, survivalPage } from "./paths";
import { groundFor, postRun, timelineFor } from "./runs";
import {
  boardTitle,
  boardView,
  customQuestDetailView,
  customQuestPortableBytes,
  customQuestsListView,
  gameScores,
  joinView,
  loginView,
  players,
  profileView,
  questMenuView,
  replaysView,
  runDescription,
  runDetailView,
  runSummary,
  visibleRun,
} from "./views";
import { VIEW_H, VIEW_W } from "./verify";
import { type Board, BOARDS, CATEGORIES, type Category } from "./api-types";
import { flagsView, isModerator, markAccount, measureRuns, moderationLog, roleOf, setRole, setRunCategory } from "./moderation";

// Links, OAuth callbacks and the session cookie follow the request's origin, so the site answers only over
// HTTPS, and browsers are told to stay there. Plain-HTTP localhost stays for wrangler dev.
const HSTS = "max-age=31536000; includeSubDomains";
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

const categoryOf = (value: unknown): Category | null => (CATEGORIES.includes(value as Category) ? (value as Category) : null);

function redirect(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, { status: 303, headers: { Location: location, ...headers } });
}

export default {
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await pruneAnalytics(env);
  },
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol === "http:" && url.hostname !== "localhost") {
      url.protocol = "https:";
      // 308 keeps the method and body, so a POST is repeated over HTTPS rather than turned into a GET.
      return Response.redirect(url.toString(), request.method === "GET" || request.method === "HEAD" ? 301 : 308);
    }
    const response = await handle(request, env, url);
    // A WebSocket handshake's 101 passes as it is: a Response cannot be rebuilt with that status.
    if (url.protocol !== "https:" || response.webSocket) return response;
    const secured = new Response(response.body, response);
    secured.headers.set("Strict-Transport-Security", HSTS);
    return secured;
  },
} satisfies ExportedHandler<Env>;

export { CoopRoom } from "./coop";

async function handle(request: Request, env: Env, url: URL): Promise<Response> {
  const route = `${request.method} ${url.pathname}`;
  let match: RegExpExecArray | null;

  // Ingestion runs before any cookie, key or account lookup.
  if (route === "POST /api/analytics" || route === "POST /api/analytics/unique")
    return postAnalytics(request, env, url.pathname.endsWith("/unique"));
  // Co-op rooms (docs/rewrite/network-coop.md §6.1) also need no account.
  if (url.pathname.startsWith("/api/coop/")) return coopRoute(request, env, url);

  // The game's API.
  switch (route) {
    case "POST /api/runs":
      return postRun(request, env);
    case "POST /api/custom":
      return postRun(request, env, { requireCustomQuest: true });
    case "POST /api/auth/challenge":
      return postChallenge(request, env);
    case "POST /api/auth/login":
      return postLogin(request, env);
    case "POST /api/scores": {
      // The high score screen's Update scores: a board's best runs as high score records, {board, quest, category}.
      const body = (await request.json().catch(() => ({}))) as { board?: unknown; quest?: unknown; category?: unknown };
      const quest = String(body.quest ?? "");
      const category = categoryOf(body.category ?? "human");
      if (category === null) return refuse(400, "no such category");
      const board = Object.hasOwn(BOARDS, String(body.board)) ? (body.board as Board) : null;
      // A custom quest's board is one player's.
      const known = board && (BOARDS[board].quests ? QUEST.test(quest) || (board === "quests" && CUSTOM_QUEST_ID.test(quest)) : quest === "");
      if (!known) return refuse(400, "no such board");
      return json({ scores: await gameScores(env, board, quest, category, SCORES_LIMIT) });
    }
  }

  // The site's read API. Boards and the quest menu take ?category=bot; they show human runs without it.
  const category = categoryOf(url.searchParams.get("category") ?? "human");
  if (url.pathname.startsWith("/api/") && category === null) return refuse(400, "no such category");
  // Each page's data is at /api plus its path (paths.ts).
  const page = request.method === "GET" && url.pathname.startsWith("/api/") ? url.pathname.slice("/api".length) : null;
  const survival = page === null ? null : survivalPage(page);
  if (survival) {
    const limit = Math.min(100, Number(url.searchParams.get("limit")) || 100);
    return json(await boardView(env, survival, "", category!, limit));
  }
  const quests = page === null ? null : questPage(page);
  if (quests)
    return json(quests.quest ? await boardView(env, quests.board, quests.quest, category!, 100) : await questMenuView(env, quests.board, quests.stage, category!));
  if (page === "/custom") return json(await customQuestsListView(env, category!));
  if (page === "/replays") return json(await replaysView(env));
  if (page !== null && (match = /^\/custom\/([^/]+)$/.exec(page)) && CUSTOM_QUEST_ID.test(match[1]!)) {
    const quest = await customQuestDetailView(env, match[1]!, category!);
    return quest ? json(quest) : refuse(404, "no such quest");
  }
  const viewer = await sessionAccount(request, env);
  const role = await roleOf(env, viewer);
  if (route === "GET /api/analytics") {
    if (role !== "admin") return refuse(403, "the admin only");
    return json(await analyticsView(env), 200, { "cache-control": "no-store" });
  }
  if ((match = /^GET \/api\/players\/(\d+)$/.exec(route))) {
    const profile = await profileView(env, Number(match[1]), viewer, isModerator(role));
    return profile ? json(profile) : refuse(404, "no such player");
  }
  if ((match = /^GET \/api\/runs\/([0-9a-f]{64})$/.exec(route))) {
    const run = await runDetailView(env, match[1]!, isModerator(role));
    return run ? json(run) : refuse(404, "no such run");
  }
  if ((match = /^GET \/api\/runs\/([0-9a-f]{64})\/timeline$/.exec(route))) {
    const timeline = (await visibleRun(env, match[1]!)) && (await timelineFor(env, match[1]!));
    return timeline ? json(timeline) : refuse(404, "no such run");
  }
  if (route === "GET /api/me") return json({ account: viewer, role });

  // Moderation (docs/rewrite/bots.md), for signed-in moderators on the site's own pages.
  if (url.pathname.startsWith("/api/mod/")) {
    if (request.method === "POST" && request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    if (viewer === null || !isModerator(role)) return refuse(403, "moderators only");
    if (route === "GET /api/mod/flags") return json(await flagsView(env));
    if (route === "GET /api/mod/log") return json({ actions: await moderationLog(env) });
    if (route === "POST /api/mod/measure") return json({ unmeasured: await measureRuns(env) });
    const body = (await request.json().catch(() => ({}))) as { bot?: unknown; category?: unknown; role?: unknown; note?: unknown };
    const note = String(body.note ?? "").slice(0, 500);
    const done = (changed: boolean) => (changed ? json({ ok: true }) : refuse(404, "no such account or run"));
    if ((match = /^POST \/api\/mod\/accounts\/(\d+)$/.exec(route)) && typeof body.bot === "boolean")
      return done(await markAccount(env, viewer, Number(match[1]), body.bot, note));
    if ((match = /^POST \/api\/mod\/runs\/([0-9a-f]{64})$/.exec(route)) && (body.category === null || categoryOf(body.category)))
      return done(await setRunCategory(env, viewer, match[1]!, body.category === null ? null : categoryOf(body.category), note));
    if ((match = /^POST \/api\/mod\/roles\/(\d+)$/.exec(route)) && (body.role === "" || body.role === "mod")) {
      if (role !== "admin") return refuse(403, "the admin only");
      return done(await setRole(env, viewer, Number(match[1]), body.role, note));
    }
    return refuse(400, "no such moderation request");
  }

  // The playable game: its page, built from crimson-core/client into dist/play/, and the game's files.
  // The redirect keeps the query, which can name where the page loads the game files from.
  if (route === "GET /play") return Response.redirect(new URL(`/play/${url.search}`, url).toString(), 301);
  if (route === "GET /play/") {
    // Staged by `npm run play`; a build without it has no game page.
    const page = await env.ASSETS.fetch(request);
    if (!page.ok) return page;
    return withPreview(page, url, {
      title: "Play",
      description: "Crimsonland in the browser: the original game, recovered from its executable.",
      image: null,
      player: { url: url.toString(), width: VIEW_W, height: VIEW_H },
    });
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

  // Pages the server answers itself: replay files.
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
  if ((match = /^GET \/custom\/([0-9a-f]{12})\.bin$/.exec(route))) {
    const bytes = await customQuestPortableBytes(env, match[1]!);
    if (!bytes) return new Response("No such quest.", { status: 404 });
    return new Response(bytes, {
      headers: {
        "content-type": "application/octet-stream",
        "cache-control": `public, max-age=${REPLAY_MAX_AGE_S}, must-revalidate`,
      },
    });
  }

  if ((match = /^GET \/runs\/([0-9a-f]{64})\.ground\.jpg$/.exec(route))) {
    const ground = (await visibleRun(env, match[1]!)) && (await groundFor(env, url.origin, match[1]!));
    if (!ground) return new Response("No such run.", { status: 404 });
    // As a replay: it never changes, and the short life lets hiding, bans and deletions take effect.
    return new Response(ground, { headers: { "content-type": "image/jpeg", "cache-control": `public, max-age=${REPLAY_MAX_AGE_S}, must-revalidate` } });
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
  const accountId = viewer;
  const token = sessionToken(request);
  if ((match = /^GET \/auth\/([a-z]+)\/(start|callback)$/.exec(route))) {
    const chosen = provider(env, match[1]!);
    if (!chosen || accountId === null || token === null) return redirect("/account");
    // The profile's link names the account it showed; a tab left open while the browser signed in to another account
    // must not link a login to that one.
    if (match[2] === "start")
      return url.searchParams.get("account") === String(accountId)
        ? redirect(await authorizeUrl(env, url.origin, chosen, token))
        : redirect(`/players/${accountId}?notice=switched`);
    const notice = (kind: string) => redirect(`/players/${accountId}?notice=${kind}&provider=${chosen.name}`);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return notice("cancelled");
    const identity = await completeLink(env, url.origin, chosen, token, state, code);
    if (!identity) return notice("failed");
    const linked = await linkIdentity(env, accountId, token, chosen.name, identity);
    return linked.outcome === "confirm" ? redirect(`/join/${linked.token}`) : notice("linked");
  }

  // A login link's confirmation page asks who it signs in as; confirming it, from the site's own page, signs in.
  if ((match = /^GET \/api\/login\/([0-9a-f]{64})$/.exec(route))) {
    const account = await loginLink(env, match[1]!);
    return account === null ? refuse(410, "this sign-in link has expired; open your profile from the game again") : json(await loginView(env, account, viewer));
  }
  if (route === "POST /api/login") {
    if (request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    return postLoginLink(request, env);
  }

  // The signed-in account's API, for the site's own pages only.
  if (url.pathname.startsWith("/api/account/") || url.pathname.startsWith("/api/join") || url.pathname === "/api/logout") {
    if (request.method === "POST" && request.headers.get("origin") !== url.origin) return refuse(403, "cross-site request refused");
    if (accountId === null || token === null) return refuse(401, "sign in from the game");
    const body = request.method === "POST" ? ((await request.json().catch(() => ({}))) as { token?: unknown; account?: unknown }) : {};
    // Each change names the account its page showed: a tab left open while the browser signed in to another account
    // must not act on that one.
    if (request.method === "POST" && route !== "POST /api/logout" && body.account !== accountId)
      return refuse(409, "this browser is signed in to another account now; reload the page");
    const expired = () => refuse(410, "this request expired; link again to join the accounts");
    if ((match = /^GET \/api\/join\/([0-9a-f]{64})$/.exec(route))) {
      const pending = await pendingJoin(env, accountId, token, match[1]!);
      if (!pending) return expired();
      const label = PROVIDERS[pending.provider as keyof typeof PROVIDERS].label;
      return json(await joinView(env, accountId, pending.into, label));
    }
    if (route === "POST /api/join") {
      const into = await confirmMerge(env, accountId, token, String(body.token ?? ""));
      return into === null ? expired() : json({ account: into });
    }
    if ((match = /^POST \/api\/account\/unlink\/([a-z]+)$/.exec(route))) {
      const chosen = provider(env, match[1]!);
      if (chosen) await unlink(env, accountId, chosen.name);
      return json({ account: accountId });
    }
    if (route === "POST /api/account/delete") {
      if (!(await deleteAccount(env, accountId))) return refuse(403, "the admin's account cannot be deleted");
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
  const moved = movedPath(url.pathname);
  if (moved) return Response.redirect(new URL(`${moved}${url.search}`, url).toString(), 301);
  return shell(env, url);
}

// Where shared links to the boards' old paths moved.
function movedPath(path: string): string | null {
  if (path === "/boards/survival") return "/survival";
  let match = /^\/boards\/(quests|quests-hardcore)\/([^/]+)$/.exec(path);
  if (match && QUEST.test(match[2]!)) return questsPath(match[1] as QuestBoard, match[2]!);
  match = /^\/quests-hardcore\/([1-5])$/.exec(path);
  return match ? questsPath("quests-hardcore", match[1]!) : null;
}

// What a shared link previews: the route's title, and for a run, what happened, its card and its replay to watch.
interface Preview {
  title: string | null;
  description: string;
  image: { url: string; width: number; height: number } | null;
  player: { url: string; width: number; height: number } | null;
}

const SITE_DESCRIPTION = "Play Crimsonland in your browser, and verified leaderboards where every score is a replay the server re-simulates.";
// The preview of a page with no image of its own: a moment of the Survival board's top run (public/og.jpg).
const SITE_IMAGE = { path: "/og.jpg", width: 1200, height: 630 };

async function routePreview(env: Env, url: URL): Promise<Preview> {
  const path = url.pathname;
  const titled = (title: string | null): Preview => ({ title, description: SITE_DESCRIPTION, image: null, player: null });
  let match: RegExpExecArray | null;
  const survival = survivalPage(path);
  if (survival) return titled(boardTitle(survival, ""));
  const quests = questPage(path);
  if (quests)
    return titled(
      quests.quest
        ? boardTitle(quests.board, quests.quest)
        : `Quests ${["I", "II", "III", "IV", "V"][quests.stage - 1]}${BOARDS[quests.board].players > 1 ? " · co-op" : ""}`,
    );
  if (path === "/custom") return titled("Custom Quests");
  if ((match = /^\/custom\/([0-9a-f]{12})$/.exec(path))) {
    const quest = await customQuestDetailView(env, match[1]!, "human");
    if (!quest) return titled(null);
    const byline = quest.author ? ` by ${quest.author}` : "";
    return {
      title: `${quest.title}${byline}`,
      description: `Play "${quest.title}"${byline} in the browser (${quest.definition.entries.length} spawn entries) and compete on its verified leaderboard.`,
      image: { url: `${url.origin}/runs/${quest.first_run_id}.png`, width: CARD_WIDTH, height: CARD_HEIGHT },
      player: { url: `${url.origin}/play/?quest=${quest.id}`, width: VIEW_W, height: VIEW_H },
    };
  }
  if ((match = /^\/players\/(\d+)$/.exec(path))) {
    const player = (await players(env, [Number(match[1])])).get(Number(match[1]));
    return titled(player ? playerLabel(player) : null);
  }
  if ((match = /^\/runs\/([0-9a-f]{64})$/.exec(path))) {
    const run = await runSummary(env, match[1]!);
    if (!run) return titled(null);
    return {
      title: `${runLabel(run)} · ${run.title}`,
      description: runDescription(run),
      image: { url: `${url.origin}/runs/${run.id}.png`, width: CARD_WIDTH, height: CARD_HEIGHT },
      player: { url: `${url.origin}/play/?watch=${run.id}`, width: VIEW_W, height: VIEW_H },
    };
  }
  return titled(({ "/about": "About", "/privacy": "Privacy", "/terms": "Terms", "/analytics": "Gameplay analytics" } as Record<string, string>)[path] ?? null);
}

// The site's one page, titled for the route so shared links preview what they point at.
// The site's pages never show inside another site's: only the game (/play/) does, as a post's player card.
async function shell(env: Env, url: URL): Promise<Response> {
  const page = withPreview(await env.ASSETS.fetch(new Request(new URL("/", url))), url, await routePreview(env, url));
  page.headers.set("Content-Security-Policy", "frame-ancestors 'none'");
  return page;
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
    // X shows a large image only when asked to. A page with a player plays it inside the post, the image standing in
    // until it is opened; X's player card asks for its title and image under its own names.
    ...meta("name", preview.player
      ? [
          ["twitter:card", "player"],
          ["twitter:title", full],
          ["twitter:description", preview.description],
          ["twitter:image", image.url],
          ["twitter:player", preview.player.url],
          ["twitter:player:width", preview.player.width],
          ["twitter:player:height", preview.player.height],
        ]
      : [["twitter:card", "summary_large_image"]]),
  ];
  return new HTMLRewriter()
    .on("title", { element: (element) => void element.setInnerContent(full) })
    .on("head", { element: (element) => void element.append(tags.join(""), { html: true }) })
    .transform(new Response(page.body, { headers: { "content-type": "text/html; charset=utf-8" } }));
}
