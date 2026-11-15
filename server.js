"use strict";
// Zero-dependency web server: run with `node server.js` (no npm install needed).
// The crypto is 100% the lab's Keychain (password-manager.js); this file only does HTTP + storage.
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { Keychain } = require("./password-manager");
const { encodeBuffer } = require("./lib");

const PORT = process.env.PORT || 3000, DB = path.join(__dirname, "data", "db.json");
const IDLE_MS = 5 * 60 * 1000;                       // auto-lock after 5 idle minutes
const db = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, "utf8")) : { users: {} };
fs.mkdirSync(path.dirname(DB), { recursive: true });   // create data/ on first run
const save = () => fs.writeFileSync(DB, JSON.stringify(db));
const sessions = new Map(), fails = new Map();       // token -> {kc,user,last,pw?}; user -> {n,until}

// The Keychain hides domain names (they are HMAC tags), so it cannot list them.
// We keep an index INSIDE the keychain: every record goes through set(), so it is
// encrypted, swap-protected and covered by the SHA-256 checksum. User names are
// prefixed with "site:" so they can never collide with the "meta:" index records.
const S = n => "site:" + n, U = n => "user:" + n, I = i => "meta:idx:" + i;
async function count(kc) { return parseInt(await kc.get("meta:count") || "0", 10); }
async function list(kc) {
  const out = [], n = await count(kc);
  for (let i = 0; i < n; i++) { const s = await kc.get(I(i)); out.push({ site: s, username: await kc.get(U(s)) || "" }); }
  return out.sort((a, b) => a.site.localeCompare(b.site));
}
async function putSite(kc, site, username, password) {
  if (await kc.get(S(site)) === null) { const n = await count(kc); await kc.set(I(n), site); await kc.set("meta:count", String(n + 1)); }
  await kc.set(S(site), password); await kc.set(U(site), username);
}
async function delSite(kc, site) {
  if (!await kc.remove(S(site))) return false;
  await kc.remove(U(site));
  const n = await count(kc); let at = -1;
  for (let i = 0; i < n; i++) if (await kc.get(I(i)) === site) at = i;
  if (at >= 0) { await kc.set(I(at), await kc.get(I(n - 1))); await kc.remove(I(n - 1)); await kc.set("meta:count", String(n - 1)); }
  return true;
}
async function persist(sess) {                        // dump -> DB; checksum goes back to the user's device
  const [repr, checksum] = await sess.kc.dump(), u = db.users[sess.user];
  u.prev = u.repr; u.repr = repr; save(); return checksum;
}

const ok = (res, o, code = 200, h = {}) => { res.writeHead(code, { "Content-Type": "application/json", ...h }); res.end(JSON.stringify(o)); };
const body = req => new Promise(r => { let b = ""; req.on("data", c => { b += c; if (b.length > 1e5) req.destroy(); }); req.on("end", () => { try { r(JSON.parse(b || "{}")); } catch { r({}); } }); });
const cookie = t => `sid=${t}; HttpOnly; SameSite=Strict; Path=/`;
function auth(req) {
  const t = (/sid=([a-f0-9]+)/.exec(req.headers.cookie || "") || [])[1], s = sessions.get(t);
  if (!s || Date.now() - s.last > IDLE_MS) { sessions.delete(t); return null; }
  s.last = Date.now(); s.token = t; return s;
}
async function startSession(res, user, kc, password, checksum, extra = {}) {
  const t = crypto.randomBytes(32).toString("hex"); sessions.set(t, { kc, user, last: Date.now(), pw: undefined });
  ok(res, { user, checksum, ...extra }, 200, { "Set-Cookie": cookie(t) });
}

const routes = {
  async "POST /api/register"(req, res, b) {
    const user = String(b.username || "").trim().toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/.test(user)) return ok(res, { error: "Username must be 3-32 letters, numbers, . _ -" }, 400);
    if (String(b.password || "").length < 8) return ok(res, { error: "Master password must be at least 8 characters" }, 400);
    if (db.users[user]) return ok(res, { error: "That username is taken" }, 409);
    const kc = await Keychain.init(b.password); db.users[user] = {};
    let checksum; try { checksum = await persist({ kc, user }); } catch (e) { delete db.users[user]; throw e; }   // no half-created accounts
    await startSession(res, user, kc, b.password, checksum);
  },
  async "POST /api/login"(req, res, b) {
    const user = String(b.username || "").trim().toLowerCase(), f = fails.get(user) || { n: 0, until: 0 };
    if (Date.now() < f.until) return ok(res, { error: "Too many attempts. Try again in " + Math.ceil((f.until - Date.now()) / 1000) + "s" }, 429);
    const u = db.users[user];
    try {
      if (!u) throw "Invalid master password or corrupted keychain";
      const kc = await Keychain.load(String(b.password || ""), u.repr, b.checksum || undefined);
      fails.delete(user);
      await startSession(res, user, kc, null, b.checksum || null, { verified: !!b.checksum });
    } catch (e) {
      const tamper = String(e).startsWith("Tampering");
      if (!tamper) { f.n++; if (f.n >= 5) { f.until = Date.now() + 30000; f.n = 0; } fails.set(user, f); }
      ok(res, { error: String(e), tamper }, 401);
    }
  },
  async "POST /api/checksum"(req, res, b, s) { ok(res, { checksum: (await s.kc.dump())[1] }); },
  async "POST /api/logout"(req, res) { const s = auth(req); if (s) sessions.delete(s.token); ok(res, { ok: true }); },
  async "GET /api/list"(req, res, b, s) { ok(res, { user: s.user, items: await list(s.kc) }); },
  async "POST /api/get"(req, res, b, s) { const p = await s.kc.get(S(b.site)); p === null ? ok(res, { error: "Not found" }, 404) : ok(res, { password: p }); },
  async "POST /api/set"(req, res, b, s) {
    const site = String(b.site || "").trim(), pw = String(b.password || ""), un = String(b.username || "");
    if (!site || site.length > 64 || un.length > 64 || !pw || pw.length > 64) return ok(res, { error: "Site, username and password must each be 1-64 characters" }, 400);
    await putSite(s.kc, site, un, pw); ok(res, { checksum: await persist(s) });
  },
  async "POST /api/remove"(req, res, b, s) { const r = await delSite(s.kc, b.site); ok(res, { removed: r, checksum: await persist(s) }); },

  // ---- Security Lab: runs the lab's attacks against the real stored data ----
  async "POST /api/lab/raw"(req, res, b, s) {
    const repr = db.users[s.user].repr, kvs = JSON.parse(repr).kvs;
    const lens = [...new Set(Object.values(kvs).map(r => Buffer.from(r.ct, "base64").length))];
    ok(res, { repr, records: Object.keys(kvs).length, ciphertextLengths: lens });
  },
  async "POST /api/lab/swap"(req, res, b, s) {      // swap two ciphertexts, NO trusted checksum supplied
    const { hmacKey } = s.kc.secrets, tag = async n => encodeBuffer(await crypto.webcrypto.subtle.sign("HMAC", hmacKey, Buffer.from(S(n))));
    const t = JSON.parse(db.users[s.user].repr), [x, y] = [await tag(b.site1), await tag(b.site2)];
    if (!t.kvs[x] || !t.kvs[y] || x === y) return ok(res, { error: "Pick two different saved sites" }, 400);
    [t.kvs[x], t.kvs[y]] = [t.kvs[y], t.kvs[x]];
    try { const kc = await Keychain.load(String(b.password || ""), JSON.stringify(t)); await kc.get(S(b.site1)); ok(res, { detected: false, message: "Swap NOT detected" }); }
    catch (e) { ok(res, { detected: true, message: String(e) }); }
  },
  async "POST /api/lab/rollback"(req, res, b, s) {  // load the previous version against the current trusted checksum
    const u = db.users[s.user]; if (!u.prev) return ok(res, { error: "Save a change first so an older version exists" }, 400);
    const [, current] = await s.kc.dump();
    try { await Keychain.load(String(b.password || ""), u.prev, current); ok(res, { detected: false, message: "Rollback NOT detected" }); }
    catch (e) { ok(res, { detected: true, message: String(e) }); }
  },
};

http.createServer(async (req, res) => {
  try {
    const url = req.url.split("?")[0], key = req.method + " " + url, h = routes[key];
    if (h) {
      const open = key.endsWith("/login") || key.endsWith("/register") || key.endsWith("/logout");
      const s = open ? null : auth(req);
      if (!open && !s) return ok(res, { error: "Session expired. Please sign in again." }, 401);
      return await h(req, res, await body(req), s);
    }
    if (req.method === "GET" && url === "/") { res.writeHead(200, { "Content-Type": "text/html", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'" }); return res.end(fs.readFileSync(path.join(__dirname, "public", "index.html"))); }
    ok(res, { error: "Not found" }, 404);
  } catch (e) { console.error(e); ok(res, { error: "Server error" }, 500); }
}).listen(PORT, () => console.log("Password manager running at http://localhost:" + PORT));