/**
 * PETRO.POVAR — сервер сайта (Cloudflare Worker + база D1).
 * Привязка базы: переменная DB.  Таблицы создаются сами при первом запросе.
 * Пароль админки задаётся при первом входе в admin.html (в коде его нет).
 */
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated INTEGER)",
  "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, kind TEXT, status TEXT DEFAULT 'new', name TEXT, phone TEXT, data TEXT, total INTEGER DEFAULT 0, ip TEXT)",
  "CREATE INDEX IF NOT EXISTS orders_created ON orders(created)",
  "CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, mime TEXT, data TEXT, size INTEGER, created INTEGER)",
];
let schemaReady = false;
const STATUSES = ["new", "confirmed", "done", "cancelled"];
const enc = new TextEncoder();

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const cors = corsHeaders(req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      if (!env.DB) return json({ error: "Не подключена база: добавьте привязку D1 с именем DB" }, 500, cors);
      await ensureSchema(env);
      const p = url.pathname.replace(/\/+$/, "") || "/";
      const m = req.method;

      if (p === "/") return json({ ok: true, name: "petropovar-api" }, 200, cors);
      if (p === "/api/content" && m === "GET") {
        const row = await env.DB.prepare("SELECT v, updated FROM kv WHERE k='content'").first();
        return json({ content: row ? JSON.parse(row.v) : null, updated: row ? row.updated : 0 }, 200, { ...cors, "Cache-Control": "no-store" });
      }
      if (p === "/api/busy" && m === "GET") return busyList(env, cors);
      if (p.startsWith("/img/") && m === "GET") return serveImage(env, p.slice(5), cors);
      if (p === "/api/order" && m === "POST") return createOrder(req, env, ctx, cors);

      // ---- admin ----
      if (p === "/api/admin/status" && m === "GET") {
        return json({ hasPassword: !!(await kvGet(env, "auth")) }, 200, cors);
      }
      if (p === "/api/admin/setup" && m === "POST") {
        if (await kvGet(env, "auth")) return json({ error: "Пароль уже создан. Войдите с ним." }, 409, cors);
        const { password } = await body(req);
        if (!password || String(password).length < 6) return json({ error: "Пароль — минимум 6 символов" }, 400, cors);
        await setPassword(env, String(password));
        return json({ token: await makeToken(env) }, 200, cors);
      }
      if (p === "/api/admin/login" && m === "POST") {
        const ip = req.headers.get("cf-connecting-ip") || "x";
        const lk = "fail:" + (await sha(ip)).slice(0, 16);
        const fails = JSON.parse((await kvGet(env, lk)) || "[]").filter((t) => t > Date.now() - 15 * 60e3);
        if (fails.length >= 8) return json({ error: "Слишком много попыток. Подождите 15 минут." }, 429, cors);
        const { password } = await body(req);
        if (await checkPassword(env, String(password || ""))) {
          await env.DB.prepare("DELETE FROM kv WHERE k=?").bind(lk).run();
          return json({ token: await makeToken(env) }, 200, cors);
        }
        fails.push(Date.now());
        await kvSet(env, lk, JSON.stringify(fails));
        return json({ error: "Неверный пароль" }, 401, cors);
      }

      if (p.startsWith("/api/admin/")) {
        if (!(await authed(req, env))) return json({ error: "Войдите заново" }, 401, cors);
        if (p === "/api/admin/orders" && m === "GET") {
          const st = url.searchParams.get("status");
          const lim = Math.min(500, +url.searchParams.get("limit") || 200);
          const q = st && STATUSES.includes(st)
            ? env.DB.prepare("SELECT id,created,kind,status,name,phone,data,total FROM orders WHERE status=? ORDER BY id DESC LIMIT ?").bind(st, lim)
            : env.DB.prepare("SELECT id,created,kind,status,name,phone,data,total FROM orders ORDER BY id DESC LIMIT ?").bind(lim);
          const { results } = await q.all();
          const counts = await env.DB.prepare("SELECT status, COUNT(*) n FROM orders GROUP BY status").all();
          return json({ orders: results.map((r) => ({ ...r, data: safeParse(r.data) })), counts: Object.fromEntries(counts.results.map((r) => [r.status, r.n])) }, 200, cors);
        }
        const om = p.match(/^\/api\/admin\/orders\/(\d+)$/);
        if (om && m === "PATCH") {
          const { status } = await body(req);
          if (!STATUSES.includes(status)) return json({ error: "Неизвестный статус" }, 400, cors);
          await env.DB.prepare("UPDATE orders SET status=? WHERE id=?").bind(status, +om[1]).run();
          return json({ ok: true }, 200, cors);
        }
        if (om && m === "DELETE") {
          await env.DB.prepare("DELETE FROM orders WHERE id=?").bind(+om[1]).run();
          return json({ ok: true }, 200, cors);
        }
        if (p === "/api/admin/content" && m === "PUT") {
          const text = await req.text();
          if (text.length > 900000) return json({ error: "Слишком много данных" }, 413, cors);
          const c = safeParse(text);
          if (!c || typeof c !== "object" || !Array.isArray(c.dishes) || !c.settings) return json({ error: "Неверный формат меню" }, 400, cors);
          const now = Date.now();
          await env.DB.prepare("INSERT INTO kv(k,v,updated) VALUES('content',?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated").bind(JSON.stringify(c), now).run();
          return json({ ok: true, updated: now }, 200, cors);
        }
        if (p === "/api/admin/image" && m === "POST") {
          const { data, mime } = await body(req);
          if (!/^image\/(webp|jpeg|png)$/.test(mime || "")) return json({ error: "Нужна картинка JPG, PNG или WebP" }, 400, cors);
          if (!data || data.length > 1900000) return json({ error: "Фото слишком большое" }, 413, cors);
          const id = crypto.randomUUID().replace(/-/g, "").slice(0, 20);
          await env.DB.prepare("INSERT INTO images(id,mime,data,size,created) VALUES(?,?,?,?,?)").bind(id, mime, data, Math.round(data.length * 0.75), Date.now()).run();
          return json({ url: url.origin + "/img/" + id }, 200, cors);
        }
        if (p === "/api/admin/notify" && m === "GET") {
          const n = safeParse(await kvGet(env, "notify")) || {};
          const envTok = String(env.TG_TOKEN || "").trim();
          return json({ tgChats: String(env.TG_CHAT || n.tgChats || ""), hasToken: !!(envTok || n.tgToken), fromSecret: !!envTok }, 200, cors);
        }
        if (p === "/api/admin/notify" && m === "PUT") {
          const b = await body(req);
          const n = safeParse(await kvGet(env, "notify")) || {};
          if (typeof b.tgToken === "string" && b.tgToken.trim()) n.tgToken = b.tgToken.trim();
          if (b.clearToken) delete n.tgToken;
          if (typeof b.tgChats === "string") n.tgChats = b.tgChats.replace(/[^\d,\-\s]/g, "").trim();
          await kvSet(env, "notify", JSON.stringify(n));
          return json({ ok: true }, 200, cors);
        }
        if (p === "/api/admin/notify/test" && m === "POST") {
          const r = await telegram(env, "✅ Проверка: уведомления с сайта PETRO.POVAR работают.");
          return json(r, r.ok ? 200 : 400, cors);
        }
        if (p === "/api/admin/password" && m === "POST") {
          const { old, password } = await body(req);
          if (!(await checkPassword(env, String(old || "")))) return json({ error: "Старый пароль не подходит" }, 400, cors);
          if (!password || String(password).length < 6) return json({ error: "Новый пароль — минимум 6 символов" }, 400, cors);
          await setPassword(env, String(password));
          return json({ token: await makeToken(env) }, 200, cors);
        }
      }
      return json({ error: "Не найдено" }, 404, cors);
    } catch (e) {
      return json({ error: "Ошибка сервера: " + (e && e.message || e) }, 500, cors);
    }
  },
};

/* ---------- orders ---------- */
async function createOrder(req, env, ctx, cors) {
  const o = await body(req);
  if (o.website) return json({ id: 0 }, 200, cors); // бот
  const kind = o.kind === "request" ? "request" : "order";
  const name = clip(o.name, 80), phone = String(o.phone || "").replace(/\D/g, "");
  if (!name) return json({ error: "Укажите имя" }, 400, cors);
  if (phone.length < 10 || phone.length > 12) return json({ error: "Проверьте номер телефона" }, 400, cors);
  const ip = req.headers.get("cf-connecting-ip") || "";
  const ipH = ip ? (await sha(ip)).slice(0, 16) : "";
  if (ipH) {
    const r = await env.DB.prepare("SELECT COUNT(*) n FROM orders WHERE ip=? AND created>?").bind(ipH, Date.now() - 10 * 60e3).first();
    if (r && r.n >= 6) return json({ error: "Слишком много заявок подряд. Напишите шефу в WhatsApp." }, 429, cors);
  }
  const data = {
    format: clip(o.format, 40), occasion: clip(o.occasion, 60), date: clip(o.date, 10), time: clip(o.time, 5),
    address: clip(o.address, 200), guests: clip(o.guests, 6), comment: clip(o.comment, 1000), items: [],
  };
  let total = 0;
  if (kind === "order") {
    const row = await env.DB.prepare("SELECT v FROM kv WHERE k='content'").first();
    const content = row ? safeParse(row.v) : null;
    const map = {};
    if (content) [...(content.dishes || []), ...(content.sets || [])].forEach((d) => (map[d.id] = d));
    for (const it of (Array.isArray(o.items) ? o.items : []).slice(0, 80)) {
      const qty = Math.max(1, Math.min(99, parseInt(it.qty) || 1));
      const ref = map[it.id];
      const price = ref ? +ref.price || 0 : Math.max(0, parseInt(it.price) || 0);
      const nm = ref ? ref.name : clip(it.name, 100);
      data.items.push({ id: clip(it.id, 20), name: nm, price, qty });
      total += price * qty;
    }
    if (!data.items.length) return json({ error: "Заказ пустой" }, 400, cors);
  }
  if (data.date && data.time && (await activeSlots(env)).indexOf(data.date + " " + data.time) >= 0)
    return json({ error: "Это время уже занято — выберите другое" }, 409, cors);
  const res = await env.DB.prepare("INSERT INTO orders(created,kind,status,name,phone,data,total,ip) VALUES(?,?,?,?,?,?,?,?)")
    .bind(Date.now(), kind, "new", name, phone, JSON.stringify(data), total, ipH).run();
  const id = res.meta.last_row_id;
  ctx.waitUntil(telegram(env, orderMessage(id, kind, name, phone, data, total)).catch(() => {}));
  return json({ id }, 200, cors);
}
async function activeSlots(env) {
  const { results } = await env.DB.prepare("SELECT data FROM orders WHERE status IN ('new','confirmed') ORDER BY id DESC LIMIT 500").all();
  const out = [];
  for (const r of results) {
    const d = safeParse(r.data) || {};
    if (d.date && d.time) out.push(d.date + " " + d.time);
  }
  return out;
}
async function busyList(env, cors) {
  const since = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
  const busy = (await activeSlots(env)).filter((s) => s.slice(0, 10) >= since);
  return json({ busy }, 200, { ...cors, "Cache-Control": "no-store" });
}
function money(n) { return String(Math.round(n || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, " ") + " ₸"; }
function ru(d) { const p = String(d || "").split("-"); return p.length === 3 ? `${p[2]}.${p[1]}.${p[0]}` : d; }
function orderMessage(id, kind, name, phone, d, total) {
  const L = [];
  if (kind === "order") {
    L.push(`🛒 Новый заказ №${id}`, "");
    d.items.forEach((i) => L.push(`• ${i.name} × ${i.qty} — ${money(i.price * i.qty)}`));
    L.push("", `💰 Итого: ${money(total)}`);
    if (d.format) L.push(`📦 ${d.format}`);
  } else {
    L.push(`🎉 Новая заявка №${id}`, "");
    if (d.occasion) L.push(`Повод: ${d.occasion}`);
  }
  if (d.date) L.push(`📅 ${ru(d.date)}${d.time ? ", " + d.time : ""}`);
  if (d.address) L.push(`📍 ${d.address}`);
  if (d.guests) L.push(`👥 Гостей: ${d.guests}`);
  L.push(`👤 ${name}`, `📞 +${phone}`, `WhatsApp: https://wa.me/${phone}`);
  if (d.comment) L.push(`💬 ${d.comment}`);
  return L.join("\n");
}
async function telegram(env, text) {
  const n = safeParse(await kvGet(env, "notify")) || {};
  const tok = String(env.TG_TOKEN || "").trim() || String(n.tgToken || "").trim();
  if (!tok) return { ok: false, error: "Не задан токен бота: добавьте секрет TG_TOKEN в Cloudflare" };
  let chats = String(env.TG_CHAT || n.tgChats || "").split(/[,\s]+/).filter(Boolean);
  if (!chats.length) chats = await discoverChats(env, tok, n);
  if (!chats.length) return { ok: false, error: "Откройте бота в Telegram и нажмите «Старт», затем повторите" };
  let ok = 0, last = "";
  for (const chat of chats) {
    const r = await fetch(`https://api.telegram.org/bot${tok}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text, disable_web_page_preview: true }),
    });
    const j = await r.json().catch(() => ({}));
    if (j.ok) ok++; else last = j.description || ("HTTP " + r.status);
  }
  return ok ? { ok: true, sent: ok, chats: chats.length } : { ok: false, error: "Telegram: " + last };
}
async function discoverChats(env, tok, n) {
  try {
    const j = await fetch(`https://api.telegram.org/bot${tok}/getUpdates`).then((r) => r.json());
    if (!j.ok) return [];
    const ids = [];
    (j.result || []).forEach((u) => {
      const msg = u.message || u.edited_message || u.channel_post || u.my_chat_member || {};
      const c = msg.chat;
      if (c && c.id && ids.indexOf(String(c.id)) < 0) ids.push(String(c.id));
    });
    if (ids.length) { n.tgChats = ids.join(","); await kvSet(env, "notify", JSON.stringify(n)); }
    return ids;
  } catch { return []; }
}

/* ---------- images ---------- */
async function serveImage(env, id, cors) {
  if (!/^[a-z0-9]{8,32}$/.test(id)) return new Response("Not found", { status: 404, headers: cors });
  const r = await env.DB.prepare("SELECT mime, data FROM images WHERE id=?").bind(id).first();
  if (!r) return new Response("Not found", { status: 404, headers: cors });
  const bin = atob(r.data), u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return new Response(u, { headers: { ...cors, "Content-Type": r.mime, "Cache-Control": "public, max-age=31536000, immutable" } });
}

/* ---------- auth ---------- */
async function setPassword(env, pw) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await pbkdf2(pw, salt);
  const secret = b64(crypto.getRandomValues(new Uint8Array(32)));
  await kvSet(env, "auth", JSON.stringify({ salt, hash, secret }));
}
async function checkPassword(env, pw) {
  const a = safeParse(await kvGet(env, "auth"));
  if (!a || !pw) return false;
  return timingEq(await pbkdf2(pw, a.salt), a.hash);
}
async function pbkdf2(pw, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 10000 }, key, 256);
  return b64(new Uint8Array(bits));
}
async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg))));
}
async function makeToken(env) {
  const a = safeParse(await kvGet(env, "auth"));
  const exp = Date.now() + 45 * 24 * 3600e3;
  return exp + "." + (await hmac(a.secret, String(exp)));
}
async function authed(req, env) {
  const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || +exp < Date.now()) return false;
  const a = safeParse(await kvGet(env, "auth"));
  if (!a) return false;
  return timingEq(await hmac(a.secret, exp), sig);
}
function timingEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }

/* ---------- helpers ---------- */
async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch(SCHEMA.map((s) => env.DB.prepare(s)));
  schemaReady = true;
}
async function kvGet(env, k) { const r = await env.DB.prepare("SELECT v FROM kv WHERE k=?").bind(k).first(); return r ? r.v : null; }
async function kvSet(env, k, v) { await env.DB.prepare("INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated").bind(k, v, Date.now()).run(); }
async function body(req) { try { return await req.json(); } catch { return {}; } }
async function sha(s) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)))); }
function b64(u) { let s = ""; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function clip(v, n) { return String(v == null ? "" : v).trim().slice(0, n); }
function safeParse(s) { try { return typeof s === "string" ? JSON.parse(s) : s; } catch { return null; } }
function corsHeaders(req) {
  return {
    "Access-Control-Allow-Origin": req.headers.get("origin") || "*",
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), { status, headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });
}
