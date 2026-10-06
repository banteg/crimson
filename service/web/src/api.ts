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
