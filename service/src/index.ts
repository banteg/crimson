import { confirmMerge, deleteAccount, linkIdentity, pendingJoin, unlink } from "./accounts";
import { getLogin, postChallenge, postLogin, SESSION_COOKIE, secure, sessionAccount, sessionToken, tokenHash } from "./auth";
import { type Env, json, refuse } from "./http";
import { authorizeUrl, completeLink, PROVIDERS, provider } from "./oauth";
import type { Board } from "./ranked";
import { postRun } from "./runs";
import { boardTitle, boardView, gameScores, joinView, players, profileView, questMenuView } from "./views";

// Links, OAuth callbacks and the session cookie follow the request's origin, so the site answers only over
// HTTPS, and browsers are told to stay there. Plain-HTTP localhost stays for wrangler dev.
const HSTS = "max-age=31536000; includeSubDomains";
const QUEST = /^[1-5]\.(?:[1-9]|10)$/;
// The game's high score tables hold 100 records (TABLE_MAX).
const SCORES_LIMIT = 100;

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
  if (route === "GET /api/me") return json({ account: await sessionAccount(request, env) });

  // Pages the server answers itself: the game's login link and replay files.
  if ((match = /^GET \/login\/([0-9a-f]{64})$/.exec(route))) return getLogin(request, env, match[1]!);
  if ((match = /^GET \/runs\/([0-9a-f]{64})\.crd$/.exec(route))) {
    const run = await env.DB.prepare("SELECT 1 FROM runs WHERE id = ? AND hidden = 0").bind(match[1]).first();
    const file = run && (await env.REPLAYS.get(`runs/${match[1]}.crd`));
    if (!file) return new Response("No such replay.", { status: 404 });
    return new Response(file.body, {
      headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${match[1]!.slice(0, 12)}.crd"` },
    });
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
  if (/\.(?:js|css|png|svg|ico|woff2|txt|map|webmanifest)$/i.test(url.pathname)) return env.ASSETS.fetch(request);
  return shell(env, url);
}

async function routeTitle(env: Env, path: string): Promise<string | null> {
  let match: RegExpExecArray | null;
  if (path === "/boards/survival") return boardTitle("survival", "");
  if ((match = /^\/boards\/(quests|quests-hardcore)\/([^/]+)$/.exec(path)) && QUEST.test(match[2]!)) return boardTitle(match[1] as Board, match[2]!);
  if ((match = /^\/(quests|quests-hardcore)\/([1-5])$/.exec(path))) return `Quests ${["I", "II", "III", "IV", "V"][Number(match[2]) - 1]}`;
  if ((match = /^\/players\/(\d+)$/.exec(path))) {
    const player = (await players(env, [Number(match[1])])).get(Number(match[1]));
    return player ? (player.name ?? player.fingerprint) : null;
  }
  return ({ "/about": "About", "/privacy": "Privacy", "/terms": "Terms" } as Record<string, string>)[path] ?? null;
}

// The site's one page, titled for the route so shared links preview what they point at.
async function shell(env: Env, url: URL): Promise<Response> {
  const page = await env.ASSETS.fetch(new Request(new URL("/", url)));
  const title = await routeTitle(env, url.pathname);
  const full = title ? `${title} · crimson.land` : "crimson.land";
  const description = "Verified leaderboards for the Crimsonland port: every score is a replay the server re-simulates.";
  const escape = (text: string) => text.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`);
  const tags = [
    `<meta name="description" content="${escape(description)}">`,
    ...[
      ["og:title", full],
      ["og:description", description],
      ["og:image", `${url.origin}/ui/sign.png`],
      ["og:url", url.toString()],
    ].map(([key, value]) => `<meta property="${key}" content="${escape(value!)}">`),
  ];
  return new HTMLRewriter()
    .on("title", { element: (element) => void element.setInnerContent(full) })
    .on("head", { element: (element) => void element.append(tags.join(""), { html: true }) })
    .transform(new Response(page.body, { headers: { "content-type": "text/html; charset=utf-8" } }));
}
