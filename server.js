//Ansadkl
require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const bigInt = require("big-integer");
const { TelegramClient, Api } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { CustomFile } = require("telegram/client/uploads");

const {
  API_ID, API_HASH, BOT_TOKEN, CHANNEL_ID,
  PORT = 3000, ADMIN_PASSWORD = "", BASE_URL = "",
} = process.env;

for (const [k, v] of Object.entries({ API_ID, API_HASH, BOT_TOKEN, CHANNEL_ID })) {
  if (!v) { console.error(`Missing ${k} in .env`); process.exit(1); }
}

const MAX_FILE = 4 * 1024 * 1024 * 1024;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const TMP_DIR = path.join(DATA_DIR, "tmp");
fs.mkdirSync(TMP_DIR, { recursive: true });
for (const f of fs.readdirSync(TMP_DIR)) fs.unlink(path.join(TMP_DIR, f), () => {});

const db = new Database(path.join(DATA_DIR, "teledrive.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  mime TEXT NOT NULL,
  tg_message_id INTEGER NOT NULL,
  tg_file_id TEXT,
  downloads INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  trashed_at INTEGER,
  password_hash TEXT,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_files_trashed ON files(trashed_at);
`);
const byHash = db.prepare("SELECT * FROM files WHERE hash = ?");

let client, channel, channelTitle = "";
async function initTelegram() {
  const sessionFile = path.join(DATA_DIR, "session.txt");
  const saved = fs.existsSync(sessionFile) ? fs.readFileSync(sessionFile, "utf8") : "";
  client = new TelegramClient(new StringSession(saved), Number(API_ID), API_HASH, { connectionRetries: 10 });
  await client.start({ botAuthToken: BOT_TOKEN });
  fs.writeFileSync(sessionFile, client.session.save());
  const ref = String(CHANNEL_ID).trim().replace(/^https?:\/\/t\.me\//i, "").replace(/^@/, "").replace(/\/.*$/, "");
  if (ref.startsWith("+") || ref.startsWith("joinchat")) {
    throw new Error("Private invite links can't be used. Set CHANNEL_ID to the channel's numeric ID or its public username.");
  }
  channel = /^-?\d+$/.test(ref)
    ? await client.getEntity(new Api.PeerChannel({ channelId: bigInt(ref.replace(/^-100/, "")) }))
    : await client.getEntity(ref);
  channelTitle = channel.title || "Telegram channel";
  console.log(`Telegram connected. Storage channel: ${channelTitle}`);
}

const mediaCache = new Map();
async function getMessage(id) {
  const c = mediaCache.get(id);
  if (c && Date.now() - c.t < 15 * 60e3) return c.m;
  const [m] = await client.getMessages(channel, { ids: [id] });
  if (!m || !m.media) throw new Error("File no longer exists in the Telegram channel");
  mediaCache.set(id, { m, t: Date.now() });
  if (mediaCache.size > 500) mediaCache.delete(mediaCache.keys().next().value);
  return m;
}

const h = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const safeEq = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};
const SECRET = h(BOT_TOKEN + ADMIN_PASSWORD);
const sign = (v) => crypto.createHmac("sha256", SECRET).update(v).digest("base64url");
const getCookies = (req) =>
  Object.fromEntries(
    (req.headers.cookie || "").split(";").map((c) => c.trim().split("=")).filter((p) => p[0])
      .map(([k, ...v]) => [k, decodeURIComponent(v.join("="))])
  );
const setCookie = (req, res, name, value, maxAge) =>
  res.append("Set-Cookie", `${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${req.secure ? "; Secure" : ""}`);
const hashPw = (pw) => { const s = crypto.randomBytes(16).toString("hex"); return s + ":" + crypto.scryptSync(pw, s, 32).toString("hex"); };
const checkPw = (pw, st) => { const [s, hh] = st.split(":"); return safeEq(crypto.scryptSync(String(pw), s, 32).toString("hex"), hh); };
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const baseUrl = (req) => (BASE_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
const fmtSize = (n) => { const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };

const attempts = new Map();
const limited = (ip, k) => { const a = attempts.get(ip + k); return a && a.n >= 10 && Date.now() - a.t < 6e5; };
const hit = (ip, k) => { const key = ip + k, a = attempts.get(key); (!a || Date.now() - a.t >= 6e5) ? attempts.set(key, { n: 1, t: Date.now() }) : a.n++; };

const serialize = (r, req) => ({
  id: r.id, hash: r.hash, name: r.name, size: r.size, mime: r.mime, downloads: r.downloads,
  createdAt: r.created_at, trashedAt: r.trashed_at, protected: !!r.password_hash, expiresAt: r.expires_at,
  link: `${baseUrl(req)}/dl/${r.hash}`,
});

const INLINE_OK = /^(video|audio)\/|^image\/(png|jpe?g|gif|webp|avif|bmp|tiff?|svg\+xml|heic|heif|x-icon)|^(application\/(pdf|zip|x-rar-compressed|x-tar|x-gzip|x-7z-compressed)|text\/plain)$/;

async function streamFile(req, res, row, forceDownload) {
  const size = row.size;
  const isPublic = !row.password_hash;
  const etag = `"${row.hash}-${size}"`;

  if (isPublic && !forceDownload && req.headers["if-none-match"] === etag && !req.headers.range) {
    return res.status(304).set({ ETag: etag, "Cache-Control": "public, max-age=86400" }).end();
  }

  let start = 0, end = size - 1, status = 200;
  const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || "");
  if (m) {
    if (m[1] === "" && m[2] !== "") start = Math.max(0, size - parseInt(m[2], 10));
    else { start = parseInt(m[1] || "0", 10); if (m[2] !== "") end = Math.min(end, parseInt(m[2], 10)); }
    if (start > end || start >= size) return res.status(416).set("Content-Range", `bytes */${size}`).end();
    status = 206;
  }

  let msg;
  try { msg = await getMessage(row.tg_message_id); }
  catch (e) { return res.status(502).json({ error: e.message }); }

  const inline = !forceDownload && INLINE_OK.test(row.mime);
  const ascii = row.name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  res.status(status).set({
    "Content-Type": inline ? row.mime : "application/octet-stream",
    "Accept-Ranges": "bytes",
    "Content-Length": end - start + 1,
    "Content-Disposition": `${inline ? "inline" : "attachment"}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(row.name)}`,
    "Cache-Control": isPublic ? "public, max-age=86400" : "private, no-store",
    ...(isPublic ? { ETag: etag } : {}),
  });
  if (row.mime !== "application/pdf") res.set("Content-Security-Policy", "sandbox");
  if (status === 206) res.set("Content-Range", `bytes ${start}-${end}/${size}`);
  if (req.method === "HEAD") return res.end();
  if (start === 0) db.prepare("UPDATE files SET downloads = downloads + 1 WHERE id = ?").run(row.id);

  const REQ = 1024 * 1024;
  const alignedStart = Math.floor(start / REQ) * REQ;
  let skip = start - alignedStart, remaining = end - start + 1, closed = false;
  res.on("close", () => (closed = true));
  try {
    const iter = client.iterDownload({ file: msg.media, offset: bigInt(alignedStart), requestSize: REQ, chunkSize: REQ });
    for await (const chunk of iter) {
      if (closed) break;
      let buf = Buffer.from(chunk);
      if (skip) { buf = buf.subarray(skip); skip = 0; }
      if (buf.length > remaining) buf = buf.subarray(0, remaining);
      remaining -= buf.length;
      if (!res.write(buf)) await new Promise((r) => { res.once("drain", r); res.once("close", r); });
      if (remaining <= 0) break;
    }
  } catch (e) { console.error("stream error:", e.message); mediaCache.delete(row.tg_message_id); }
  res.end();
}

const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,Range",
    "Access-Control-Expose-Headers": "Content-Range,Content-Length,Accept-Ranges",
  });
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.static(path.join(__dirname, "public")));

const requireAuth = (req, res, next) => next();

app.get("/api/me", (req, res) => res.json({ ok: true }));

app.get("/api/stats", (req, res) => {
  const a = db.prepare("SELECT COUNT(*) c, COALESCE(SUM(size),0) s, COALESCE(SUM(downloads),0) d FROM files WHERE trashed_at IS NULL").get();
  const t = db.prepare("SELECT COUNT(*) c, COALESCE(SUM(size),0) s FROM files WHERE trashed_at IS NOT NULL").get();
  res.json({ files: a.c, bytes: a.s, downloads: a.d, trashFiles: t.c, trashBytes: t.s, channel: channelTitle, maxFile: MAX_FILE });
});

const uploads = new Map();
const publicUpload = (u) => ({ id: u.id, status: u.status, received: u.received, tgProgress: u.tgProgress, error: u.error, file: u.file });

app.post("/api/upload/init", express.json(), (req, res) => {
  const name = path.basename(String(req.body?.name || "").trim()).slice(0, 255);
  const size = Number(req.body?.size);
  if (!name) return res.status(400).json({ error: "Missing file name" });
  if (!Number.isFinite(size) || size < 1) return res.status(400).json({ error: "Empty files can't be uploaded" });
  if (size > MAX_FILE) return res.status(400).json({ error: "File exceeds Telegram's size limit" });
  
  let mime = String(req.body?.mime || "").trim();
  const ext = path.extname(name).toLowerCase();
  
  if (!mime || mime === "application/octet-stream") {
    const mimeMap = {
      
      ".png": "image/png",
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".jpe": "image/jpeg",
      ".jfif": "image/jpeg",
      ".gif": "image/gif",
      ".webp": "image/webp",
      ".avif": "image/avif",
      ".bmp": "image/bmp",
      ".dib": "image/bmp",
      ".svg": "image/svg+xml",
      ".tif": "image/tiff",
      ".tiff": "image/tiff",
      ".ico": "image/x-icon",
      ".heic": "image/heic",
      ".heif": "image/heif",
      
      // Audio
      ".mp3": "audio/mpeg",
      ".wav": "audio/wav",
      ".wave": "audio/wave",
      ".flac": "audio/flac",
      ".ogg": "audio/ogg",
      ".oga": "audio/ogg",
      ".aac": "audio/aac",
      ".m4a": "audio/mp4",
      ".wma": "audio/x-ms-wma",

      // Video
      ".mkv": "video/x-matroska",
      ".mp4": "video/mp4",
      ".m4v": "video/mp4",
      ".webm": "video/webm",
      ".mov": "video/quicktime",
      ".avi": "video/x-msvideo",
      ".wmv": "video/x-ms-wmv",
      ".flv": "video/x-flv",
      ".3gp": "video/3gpp",

      // Archives & Documents
      ".pdf": "application/pdf",
      ".zip": "application/zip",
      ".rar": "application/x-rar-compressed",
      ".7z": "application/x-7z-compressed",
      ".tar": "application/x-tar",
      ".gz": "application/x-gzip",
      ".txt": "text/plain",
      ".json": "application/json"
    };
    mime = mimeMap[ext] || "application/octet-stream";
  }

  const id = crypto.randomUUID();
  const file = path.join(TMP_DIR, id + ".part");
  fs.writeFileSync(file, "");
  uploads.set(id, { id, name, size, mime, path: file, next: 0, received: 0, status: "uploading", tgProgress: 0, created: Date.now() });
  res.json({ id });
});

app.put("/api/upload/:id/chunk", express.raw({ type: "application/octet-stream", limit: "17mb" }), async (req, res) => {
  const u = uploads.get(req.params.id);
  if (!u || u.status !== "uploading") return res.status(404).json({ error: "Upload not found" });
  const index = Number(req.query.index);
  if (index < u.next) return res.json({ ok: true, next: u.next });
  if (index > u.next) return res.status(409).json({ error: "Out of order", next: u.next });
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: "Empty chunk" });
  if (u.received + req.body.length > u.size) return res.status(400).json({ error: "Too much data" });
  try {
    await fs.promises.appendFile(u.path, req.body);
    u.received += req.body.length; u.next++;
    res.json({ ok: true, next: u.next });
  } catch (e) { res.status(500).json({ error: "Disk write failed" }); }
});

app.post("/api/upload/:id/complete", (req, res) => {
  const u = uploads.get(req.params.id);
  if (!u) return res.status(404).json({ error: "Upload not found" });
  if (u.received !== u.size) return res.status(400).json({ error: "Upload incomplete" });
  u.status = "processing";
  res.status(202).json({ ok: true });
  forwardToTelegram(u, req);
});

async function forwardToTelegram(u, req) {
  try {
    const hash = crypto.randomBytes(9).toString("base64url");
    const created = Date.now();
    const caption = "XD1 " + JSON.stringify({ h: hash, n: u.name, s: u.size, m: u.mime, t: created });
    const msg = await client.sendFile(channel, {
      file: new CustomFile(u.name, u.size, u.path),
      forceDocument: true,
      caption,
      workers: 3,
      progressCallback: (p) => { u.tgProgress = Number(p) || 0; },
    });
    const doc = msg.document || msg.media?.document;
    const info = db.prepare(
      "INSERT INTO files (hash,name,size,mime,tg_message_id,tg_file_id,created_at) VALUES (?,?,?,?,?,?,?)"
    ).run(hash, u.name, u.size, u.mime, msg.id, doc ? String(doc.id) : null, created);
    u.file = serialize(db.prepare("SELECT * FROM files WHERE id = ?").get(info.lastInsertRowid), req);
    u.status = "done";
  } catch (e) {
    console.error("telegram upload failed:", e.message);
    u.status = "error"; u.error = e.message.includes("FLOOD") ? "Telegram is rate-limiting uploads. Wait a bit and retry." : e.message;
  } finally { fs.unlink(u.path, () => {}); }
}

app.get("/api/upload/:id", (req, res) => {
  const u = uploads.get(req.params.id);
  u ? res.json(publicUpload(u)) : res.status(404).json({ error: "Upload not found" });
});
app.delete("/api/upload/:id", (req, res) => {
  const u = uploads.get(req.params.id);
  if (u) { fs.unlink(u.path, () => {}); uploads.delete(u.id); }
  res.json({ ok: true });
});

/* ------------------------------ File API ------------------------------ */
app.get("/api/files", (req, res) => {
  const trash = req.query.view === "trash";
  const q = `%${String(req.query.q || "").replace(/[%_]/g, "\\$&")}%`;
  const order = { name: "name COLLATE NOCASE ASC", size: "size DESC", downloads: "downloads DESC" }[req.query.sort] || "created_at DESC";
  const rows = db.prepare(
    `SELECT * FROM files WHERE trashed_at IS ${trash ? "NOT" : ""} NULL AND name LIKE ? ESCAPE '\\' ORDER BY ${order}`
  ).all(q);
  res.json(rows.map((r) => serialize(r, req)));
});

const withRow = (fn) => (req, res) => {
  const row = db.prepare("SELECT * FROM files WHERE id = ?").get(req.params.id);
  return row ? fn(req, res, row) : res.status(404).json({ error: "File not found" });
};

app.get("/api/files/:id/stream", withRow((req, res, row) => streamFile(req, res, row, req.query.download === "1")));
app.patch("/api/files/:id", express.json(), withRow((req, res, row) => {
  const name = path.basename(String(req.body?.name || "").trim()).slice(0, 255);
  if (!name) return res.status(400).json({ error: "Name can't be empty" });
  db.prepare("UPDATE files SET name = ? WHERE id = ?").run(name, row.id);
  res.json(serialize({ ...row, name }, req));
}));
app.post("/api/files/:id/trash", withRow((req, res, row) => {
  db.prepare("UPDATE files SET trashed_at = ? WHERE id = ?").run(Date.now(), row.id); res.json({ ok: true });
}));
app.post("/api/files/:id/restore", withRow((req, res, row) => {
  db.prepare("UPDATE files SET trashed_at = NULL WHERE id = ?").run(row.id); res.json({ ok: true });
}));
async function destroy(row) {
  try { await client.deleteMessages(channel, [row.tg_message_id], { revoke: true }); } catch (e) { console.error("delete message:", e.message); }
  mediaCache.delete(row.tg_message_id);
  db.prepare("DELETE FROM files WHERE id = ?").run(row.id);
}
app.delete("/api/files/:id", withRow(async (req, res, row) => { await destroy(row); res.json({ ok: true }); }));
app.post("/api/trash/empty", async (req, res) => {
  for (const r of db.prepare("SELECT * FROM files WHERE trashed_at IS NOT NULL").all()) await destroy(r);
  res.json({ ok: true });
});

app.post("/api/files/:id/share", express.json(), withRow((req, res, row) => {
  const { password, keepPassword, expiresInHours } = req.body || {};
  let pw = row.password_hash;
  if (!keepPassword) pw = password ? hashPw(String(password)) : null;
  let exp = row.expires_at;
  if (expiresInHours !== "keep") exp = Number(expiresInHours) > 0 ? Date.now() + Number(expiresInHours) * 36e5 : null;
  db.prepare("UPDATE files SET password_hash = ?, expires_at = ? WHERE id = ?").run(pw, exp, row.id);
  res.json(serialize({ ...row, password_hash: pw, expires_at: exp }, req));
}));


let recovering = false;
async function recover() {
  if (recovering) return 0;
  recovering = true;
  let added = 0, emptyBatches = 0;
  try {
    for (let from = 1; emptyBatches < 10; from += 100) {
      const ids = Array.from({ length: 100 }, (_, i) => from + i);
      let msgs = [];
      try { msgs = await client.getMessages(channel, { ids }); } catch (e) { console.error("recover:", e.message); break; }
      let any = false;
      for (const m of msgs) {
        if (!m || !m.media) continue;
        any = true;
        const cap = m.message || "";
        if (!cap.startsWith("XD1 ")) continue;
        try {
          const j = JSON.parse(cap.slice(4));
          if (!j.h || byHash.get(j.h)) continue;
          db.prepare("INSERT INTO files (hash,name,size,mime,tg_message_id,created_at) VALUES (?,?,?,?,?,?)")
            .run(j.h, j.n, j.s, j.m || "application/octet-stream", m.id, j.t || Date.now());
          added++;
        } catch {}
      }
      emptyBatches = any ? 0 : emptyBatches + 1;
    }
  } finally { recovering = false; }
  return added;
}
app.post("/api/recover", async (req, res) => res.json({ ok: true, restored: await recover() }));


const unlockCookie = (row) => sign(`dl:${row.hash}:${row.password_hash.slice(0, 16)}`);
function shareState(row, req) {
  if (!row || row.trashed_at) return "gone";
  if (row.expires_at && row.expires_at < Date.now()) return "expired";
  if (row.password_hash) {
    const c = getCookies(req)["dl_" + row.hash];
    if (!c || !safeEq(c, unlockCookie(row))) return "locked";
  }
  return "ok";
}

const shell = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>
  :root{--bg:#0f0a1f;--panel:#1a1230;--line:#2e2350;--text:#efe8ff;--dim:#a698c6;--accent:#8b5cf6;--err:#f43f5e}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg);color:var(--text);font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  main{width:100%;max-width:640px;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}
  .bar{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--line);color:var(--dim);font-size:12px}
  .method{background:rgba(139,92,246,.18);color:var(--accent);padding:2px 8px;border-radius:4px;font-weight:600}
  .content{padding:18px}
  h1{margin:0 0 4px;font-size:16px;font-weight:600;word-break:break-all}
  .dim{color:var(--dim)}
  input{width:100%;margin-top:16px;padding:11px 12px;background:#0f0a1f;border:1px solid var(--line);border-radius:6px;color:var(--text);font:inherit;outline:none}
  input:focus{border-color:var(--accent)}
  .btn{display:block;width:100%;margin-top:16px;padding:11px;background:var(--accent);color:#fff;border:0;border-radius:6px;font:inherit;font-weight:700;text-align:center;text-decoration:none;cursor:pointer}
  .btn:hover{filter:brightness(1.1)}
  .err{color:var(--err);margin:8px 0 0;font-size:13px}
  .hidden{display:none}
</style></head>
<body><main>${body}</main></body></html>`;
const bar = (status, p) => `<div class="bar"><span class="method">GET</span><span>${esc(p)}</span><span style="margin-left:auto">${status}</span></div>`;

app.get("/dl/:hash", (req, res) => {
  const row = byHash.get(req.params.hash);
  const state = shareState(row, req);
  const p = `/dl/${req.params.hash}`;
  if (state === "gone") return res.status(404).send(shell("Not found", `${bar("404 Not Found", p)}<div class="content"><h1>File not available</h1><p class="dim">The link is wrong or the file was deleted.</p></div>`));
  if (state === "expired") return res.status(410).send(shell("Link expired", `${bar("410 Gone", p)}<div class="content"><h1>Link expired</h1><p class="dim">Ask the owner to share a new one.</p></div>`));
  if (state === "locked") {
    return res.send(shell(row.name, `${bar("401 Unauthorized", p)}<div class="content"><h1>${esc(row.name)}</h1><p class="dim">${fmtSize(row.size)} &middot; password required</p>
<form id="f"><input id="pw" type="password" autofocus required placeholder="password">
<p id="err" class="err hidden"></p><button class="btn">Unlock</button></form></div>
<script>f.onsubmit=async e=>{e.preventDefault();const r=await fetch(location.pathname+'/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw.value})});if(r.ok)location.reload();else{const d=await r.json();err.textContent=d.error;err.classList.remove('hidden')}}</script>`));
  }
  streamFile(req, res, row, req.query.download === "1");
});

app.post("/dl/:hash/unlock", express.json(), (req, res) => {
  const row = byHash.get(req.params.hash);
  if (!row || !row.password_hash) return res.status(404).json({ error: "Not found" });
  if (limited(req.ip, "unlock")) return res.status(429).json({ error: "Too many attempts. Try again later." });
  if (!checkPw(req.body?.password || "", row.password_hash)) { hit(req.ip, "unlock"); return res.status(401).json({ error: "Incorrect password" }); }
  setCookie(req, res, "dl_" + row.hash, unlockCookie(row), 6 * 3600);
  res.json({ ok: true });
});

app.get("/dl/:hash/raw", (req, res) => {
  const row = byHash.get(req.params.hash);
  const state = shareState(row, req);
  if (state !== "ok") return res.status(state === "locked" ? 401 : state === "expired" ? 410 : 404).json({ error: state });
  streamFile(req, res, row, req.query.download === "1");
});


setInterval(() => {
  for (const u of uploads.values())
    if (u.status !== "processing" && Date.now() - u.created > 2 * 36e5) { fs.unlink(u.path, () => {}); uploads.delete(u.id); }
  for (const r of db.prepare("SELECT * FROM files WHERE trashed_at IS NOT NULL AND trashed_at < ?").all(Date.now() - 30 * 864e5)) destroy(r);
}, 36e5).unref();

(async () => {
  await initTelegram();
  const srv = app.listen(PORT, () => console.log(`Ansadkl Drive running on http://localhost:${PORT}`));
  srv.requestTimeout = 0;
  if (!db.prepare("SELECT 1 FROM files LIMIT 1").get()) recover().then((n) => n && console.log(`Restored ${n} files from Telegram`));
})().catch((e) => { console.error("Startup failed:", e); process.exit(1); });
