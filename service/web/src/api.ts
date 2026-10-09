// The Worker's JSON API (src/index.ts).

export async function get<T>(path: string): Promise<T | null> {
  const response = await fetch(path, { headers: { accept: "application/json" } });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

export async function post<T>(path: string, body: unknown = {}): Promise<{ ok: true; data: T } | { ok: false; reason: string }> {
  const response = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  return response.ok ? { ok: true, data: data as T } : { ok: false, reason: (data as { reason?: string }).reason ?? `HTTP ${response.status}` };
}

// A moderation request (docs/rewrite/bots.md), with the note the moderator types for the log; false when they cancel
// or the service refuses it.
export async function moderate(path: string, body: Record<string, unknown>): Promise<boolean> {
  const note = prompt("Note for the moderation log", "");
  if (note === null) return false;
  const result = await post(path, { ...body, note });
  if (!result.ok) alert(result.reason);
  return result.ok;
}
