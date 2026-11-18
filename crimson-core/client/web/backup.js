// The player's files, independently of downloaded assets and caches. The browser
// writes the same score store, numbered recordings and identity.key as desktop.
const PROFILE_ROOTS = ["game.cfg", "crimson.cfg", "registry.cfg", "render_mode.txt", "reduce_camera_shake.txt", "scores.jsonl"];
const PROFILE_DIRS = ["scores5", "replays", "leaderboard/outbox", "leaderboard/rejected"];
const PROFILE_LIMIT = 512 * 1024 * 1024;
const PROFILE_MANIFEST_LIMIT = 16 * 1024 * 1024;
const PROFILE_MAGIC = "Crimsonland profile backup 1\n";
function profileName(name) {
  // Keep control bytes out of both file names and the minified HTML shell.
  for (const ch of name) if (ch.charCodeAt(0) < 32) return false;
  return PROFILE_ROOTS.includes(name)
    || /^replays\/(?:\.last-number|[0-9]+-[a-z]+\.crd)$/.test(name)
    || /^leaderboard\/(?:outbox|rejected)\/[0-9a-f]{64}\.json$/.test(name)
    || /^scores5\/(?:imported\/)?(?:[^/\\]{1,200}\.hi[^/\\]{0,48})$/.test(name);
}

function profileNames(fs) {
  const names = PROFILE_ROOTS.filter(name => {
    const path = "/game/" + name;
    return fs.analyzePath(path).exists && fs.isFile(fs.lstat(path).mode);
  });
  for (const dir of [...PROFILE_DIRS, "scores5/imported"]) {
    if (!fs.analyzePath("/game/" + dir).exists) continue;
    for (const file of fs.readdir("/game/" + dir)) {
      const name = dir + "/" + file;
      if (profileName(name) && fs.isFile(fs.lstat("/game/" + name).mode)) names.push(name);
    }
  }
  return names.sort();
}

// A short JSON manifest with the lengths and checksums, followed by the original
// bytes. There is no decompression of untrusted data or filesystem path expansion.
async function profileBackup(fs) {
  const files = [], chunks = [];
  let size = 0;
  for (const name of profileNames(fs)) {
    const path = "/game/" + name;
    size += fs.stat(path).size;
    if (size > PROFILE_LIMIT) throw Error("Profile exceeds the 512 MiB backup limit.");
    const bytes = fs.readFile(path);
    files.push([name, bytes.length]);
    chunks.push(bytes);
  }
  // Snapshot every file in one turn before the asynchronous hash yields to an upload.
  for (const [i, bytes] of chunks.entries()) files[i].push(await artHash(bytes));
  const manifest = new TextEncoder().encode(JSON.stringify(files));
  if (manifest.length > PROFILE_MANIFEST_LIMIT) throw Error("Profile exceeds the 16 MiB backup manifest limit.");
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, manifest.length, true);
  const blob = new Blob([PROFILE_MAGIC, length, manifest, ...chunks], { type: "application/octet-stream" });
  if (blob.size > PROFILE_LIMIT) throw Error("Profile exceeds the 512 MiB backup limit.");
  return blob;
}

async function readProfile(blob) {
  const header = PROFILE_MAGIC.length + 4;
  if (blob.size > PROFILE_LIMIT || blob.size < header) throw Error("Invalid backup size.");
  const prefix = await blob.slice(0, header).arrayBuffer();
  if (new TextDecoder().decode(prefix.slice(0, -4)) !== PROFILE_MAGIC) throw Error("Choose a Crimsonland profile backup.");
  const length = new DataView(prefix).getUint32(header - 4, true);
  let at = header + length;
  if (at > blob.size || length > PROFILE_MANIFEST_LIMIT) throw Error("Invalid backup manifest.");
  const list = JSON.parse(await blob.slice(header, at).text());
  if (!Array.isArray(list)) throw Error("Invalid backup manifest.");
  const files = new Map();
  for (const item of list) {
    if (!Array.isArray(item) || item.length !== 3) throw Error("Invalid backup entry.");
    const [name, size, hash] = item;
    if (typeof name !== "string" || !profileName(name) || files.has(name)
        || !Number.isSafeInteger(size) || size < 0 || at + size > blob.size)
      throw Error("Invalid or duplicate profile file.");
    const bytes = new Uint8Array(await blob.slice(at, at + size).arrayBuffer());
    if (await artHash(bytes) !== hash) throw Error("Damaged backup file: " + name);
    files.set(name, bytes);
    at += size;
  }
  if (at !== blob.size) throw Error("Unexpected trailing data in backup.");
  return files;
}

// The owner calls this with the game stopped and IDBFS sync paused. Commit all
// replacements to IDBFS's store in one transaction, then reload from it. Failed
// imports leave both the live MEMFS and the previous durable profile intact.
async function commitProfile(idbfs, files, removed) {
  const db = await new Promise((resolve, reject) => idbfs.getDB("/game", (error, result) => error ? reject(error) : resolve(result)));
  await new Promise((resolve, reject) => {
    const tx = db.transaction(idbfs.DB_STORE_NAME, "readwrite");
    tx.oncomplete = resolve;
    tx.onabort = () => reject(tx.error ?? Error("Restore was interrupted."));
    const store = tx.objectStore(idbfs.DB_STORE_NAME);
    const timestamp = new Date(), dirs = new Set();
    try {
      for (const name of removed) store.delete("/game/" + name);
      for (const [name, contents] of files) {
        const parts = name.split("/");
        let parent = "/game";
        for (const part of parts.slice(0, -1)) {
          parent += "/" + part;
          if (!dirs.has(parent)) store.put({ timestamp, mode: 0o40755 }, parent);
          dirs.add(parent);
        }
        store.put({ timestamp, mode: name === "identity.key" ? 0o100600 : 0o100644, contents }, "/game/" + name);
      }
    } catch (error) {
      tx.abort();
      reject(error);
    }
  });
}
