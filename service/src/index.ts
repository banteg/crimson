import { confirmMerge, deleteAccount, linkIdentity, unlink } from "./accounts";
import { getLogin, postChallenge, postLogin, SESSION_COOKIE, sessionAccount, sessionToken, tokenHash } from "./auth";
import { type Env, refuse } from "./http";
import { authorizeUrl, completeLink, provider } from "./oauth";
import type { Board } from "./ranked";
import { postRun } from "./runs";
import { boardPage, homePage, mergePage, page, privacyPage, profilePage, termsPage } from "./site";

const BOARDS = new Set<Board>(["survival", "quests", "quests-hardcore"]);
const signedOutCookie = `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

function redirect(location: string, headers: HeadersInit = {}): Response {
  return new Response(null, { status: 303, headers: { Location: location, ...headers } });
}

const needSession = () =>
  page("Sign in from the game", "<p>Open your profile from the game: tick <b>Ranked</b> on Play Game and press <b>Profile</b>.</p>", 401);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;
    switch (route) {
      case "POST /api/runs":
        return postRun(request, env);
      case "POST /api/auth/challenge":
        return postChallenge(request, env);
      case "POST /api/auth/login":
        return postLogin(request, env);
      case "GET /":
        return homePage(env);
      case "GET /privacy":
        return privacyPage();
      case "GET /terms":
        return termsPage();
    }
    if (url.pathname.startsWith("/api/")) return refuse(404, "no such endpoint");

    let match: RegExpExecArray | null;
    if ((match = /^GET \/login\/([0-9a-f]{64})$/.exec(route))) return getLogin(request, env, match[1]!);
    if ((match = /^GET \/boards\/(survival)$|^GET \/boards\/(quests|quests-hardcore)\/([1-5]\.(?:[1-9]|10))$/.exec(route)))
      return boardPage(env, (match[1] ?? match[2]) as Board, match[3] ?? "");
    if ((match = /^GET \/players\/(\d+)$/.exec(route))) return profilePage(env, Number(match[1]), await sessionAccount(request, env));
    if ((match = /^GET \/runs\/([0-9a-f]{64})\.crd$/.exec(route))) {
      const run = await env.DB.prepare("SELECT 1 FROM runs WHERE id = ? AND hidden = 0").bind(match[1]).first();
      const file = run && (await env.REPLAYS.get(`runs/${match[1]}.crd`));
      if (!file) return page("Not found", "<p>No such replay.</p>", 404);
      return new Response(file.body, {
        headers: { "content-type": "application/octet-stream", "content-disposition": `attachment; filename="${match[1]!.slice(0, 12)}.crd"` },
      });
    }

    // Everything below acts for the signed-in account.
    const accountId = await sessionAccount(request, env);
    const token = sessionToken(request);
    if (request.method === "POST" && request.headers.get("origin") !== url.origin) return new Response("Cross-site request refused", { status: 403 });
    if (route === "GET /account") return accountId === null ? needSession() : redirect(`/players/${accountId}`);
    if (accountId === null || token === null) return route.startsWith("GET /auth/") || request.method === "POST" ? needSession() : page("Not found", "<p>Nothing here.</p>", 404);

    if ((match = /^GET \/auth\/([a-z]+)\/start$/.exec(route))) {
      const chosen = provider(env, match[1]!);
      return chosen ? redirect(await authorizeUrl(env, url.origin, chosen, token)) : page("Not found", "<p>That provider is not available.</p>", 404);
    }
    if ((match = /^GET \/auth\/([a-z]+)\/callback$/.exec(route))) {
      const chosen = provider(env, match[1]!);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      if (!chosen) return page("Not found", "<p>That provider is not available.</p>", 404);
      if (!code || !state) return profilePage(env, accountId, accountId, `${chosen.label} sign-in was cancelled.`);
      const identity = await completeLink(env, url.origin, chosen, token, state, code);
      if (!identity) return profilePage(env, accountId, accountId, `Linking ${chosen.label} failed or expired; try again.`);
      const linked = await linkIdentity(env, accountId, token, chosen.name, identity);
      if (linked.outcome === "confirm") return mergePage(env, linked.token, accountId, linked.into, chosen.label);
      return profilePage(env, accountId, accountId, `Linked ${chosen.label}.`);
    }
    if (route === "POST /account/merge") {
      const form = await request.formData();
      const into = await confirmMerge(env, accountId, token, String(form.get("token") ?? ""));
      if (into === null) return profilePage(env, accountId, accountId, "That request expired; link again to join the accounts.");
      return profilePage(env, into, into, "This game's key joined the account.");
    }
    if ((match = /^POST \/account\/unlink\/([a-z]+)$/.exec(route))) {
      const chosen = provider(env, match[1]!);
      if (chosen) await unlink(env, accountId, chosen.name);
      return redirect(`/players/${accountId}`);
    }
    if (route === "POST /account/delete") {
      await deleteAccount(env, accountId);
      return page("Deleted", "<p>Your account and its runs are deleted.</p>", 200, { "Set-Cookie": signedOutCookie });
    }
    if (route === "POST /logout") {
      await env.DB.prepare("DELETE FROM sessions WHERE account_id = ? AND token_hash = ?").bind(accountId, await tokenHash(token)).run();
      return redirect("/", { "Set-Cookie": signedOutCookie });
    }
    return page("Not found", "<p>Nothing here.</p>", 404);
  },
} satisfies ExportedHandler<Env>;

