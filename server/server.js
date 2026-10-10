// VoidLauncher server: профили (ник + пароль), уникальные ID (новым выдаётся случайный 8-значный; админ может поставить любой от 1 до 99999999), значки (текст или картинка), баны и админ-панель (/admin).
// Без внешних зависимостей. Нужен Node.js 22.5+ (встроенный node:sqlite).
//   запуск:  ADMIN_PASSWORD='длинный-пароль' node server/server.js
//   переменные: PORT (3000), HOST (0.0.0.0), DB_PATH (./data/void.db), TRUST_PROXY=1 (за nginx/Caddy), ADMIN_PASSWORD (≥10 символов; без него админ-панель выключена)
'use strict';
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path'), { promisify } = require('util');
const { DatabaseSync } = require('node:sqlite');
const scrypt = promisify(crypto.scrypt);

const ID_MIN = 1, ID_MAX = 99999999, ID_RANDOM_MIN = 10000000; // допустимы ID из 1–8 цифр; случайные всегда 8-значные
const TOKEN_RE = /^[0-9a-f]{64}$/;          // секрет установки: 32 случайных байта в hex, генерируется клиентом
const NICK_RE = /^[A-Za-z0-9_]{3,16}$/;     // как ник в Minecraft
const PASS_MIN = 6, PASS_MAX = 64;
const ADMIN_PASS_MIN = 10, ADMIN_SESSION_MS = 8 * 3600e3, MAX_BADGES = 100;
const HW_RE = /^[0-9a-f]{64}$/, NONCE_RE = /^[0-9a-f]{16,64}$/, MAX_DEVICES = 20;
const IMG_MAX_BYTES = 32768, IMG_MAX_SIDE = 256, IMG_RE = /^data:image\/png;base64,[A-Za-z0-9+\/]+={0,2}$/, REASON_MAX = 200;
const FAIL_WINDOW = 15 * 60 * 1000;         // окно подсчёта неудачных входов
const sha = t => crypto.createHash('sha256').update(t).digest('hex');
const shaBuf = t => crypto.createHash('sha256').update(String(t)).digest();
const defaultRng = () => crypto.randomInt(ID_RANDOM_MIN, ID_MAX + 1);
const fail = (code, status) => Object.assign(new Error(code), { code, status });
const hashPass = async (pw, salt) => (await scrypt(String(pw).normalize('NFKC'), salt, 64, { N: 16384, r: 8, p: 1 })).toString('hex');
const DUMMY_SALT = crypto.randomBytes(16).toString('hex'); // чтобы вход по несуществующему нику занимал столько же времени
const validPass = p => typeof p === 'string' && p.length >= PASS_MIN && p.length <= PASS_MAX;
const validId = n => Number.isInteger(n) && n >= ID_MIN && n <= ID_MAX;
const CTRL_RE = /[\u0000-\u001f\u007f]/;
const sleep = ms => new Promise(r => setTimeout(r, ms));

const USERS_DDL = `id INTEGER PRIMARY KEY CHECK(id BETWEEN ${ID_MIN} AND ${ID_MAX}),
      token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
      nick TEXT, nick_lc TEXT, pass_salt TEXT, pass_hash TEXT,
      banned INTEGER NOT NULL DEFAULT 0, ban_reason TEXT`;

function createApp({ dbPath = path.join(__dirname, 'data', 'void.db'), rng = defaultRng, trustProxy = false, regLimit = 20, loginLimit = 8, adminPassword = process.env.ADMIN_PASSWORD, adminLimit = 5, adminDelay = 300, signKey = process.env.BAN_SIGN_KEY, requireHw = process.env.REQUIRE_HWID === '1' } = {}) {
  let signKeyObj = null; // ключ подписи ответов (Ed25519, PKCS8 DER в base64); без него ответы не подписываются
  if (signKey) { try { signKeyObj = crypto.createPrivateKey({ key: Buffer.from(signKey, 'base64'), format: 'der', type: 'pkcs8' }); } catch { throw new Error('BAN_SIGN_KEY: неверный ключ (создайте новый: node genkey.js)'); } }
  if (dbPath !== ':memory:') fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
    CREATE TABLE IF NOT EXISTS users(${USERS_DDL}) STRICT;
    CREATE TABLE IF NOT EXISTS sessions(
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS badges(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL, icon TEXT NOT NULL, color TEXT NOT NULL,
      created_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE IF NOT EXISTS user_badges(
      user_id INTEGER NOT NULL,
      badge_id INTEGER NOT NULL REFERENCES badges(id) ON DELETE CASCADE,
      granted_at INTEGER NOT NULL,
      PRIMARY KEY(user_id, badge_id)
    ) STRICT;
    CREATE TABLE IF NOT EXISTS user_hw(user_id INTEGER NOT NULL, hw TEXT NOT NULL, last_seen INTEGER NOT NULL, PRIMARY KEY(user_id, hw)) STRICT;
    CREATE TABLE IF NOT EXISTS banned_hw(hw TEXT NOT NULL, user_id INTEGER NOT NULL, reason TEXT, created_at INTEGER NOT NULL, PRIMARY KEY(hw, user_id)) STRICT;`);
  // миграция старых баз (где были только ID): добавляем ник и пароль
  const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  for (const c of ['nick', 'nick_lc', 'pass_salt', 'pass_hash', 'ban_reason']) if (!cols.includes(c)) db.exec(`ALTER TABLE users ADD COLUMN ${c} TEXT`);
  if (!cols.includes('banned')) db.exec('ALTER TABLE users ADD COLUMN banned INTEGER NOT NULL DEFAULT 0');
  if (!db.prepare('PRAGMA table_info(badges)').all().some(c => c.name === 'image')) db.exec('ALTER TABLE badges ADD COLUMN image TEXT');
  // старые базы запрещали ID короче 8 цифр (CHECK в схеме): пересоздаём таблицу users без этого ограничения
  if (db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get().sql.includes('10000000')) {
    const names = 'id, token_hash, created_at, nick, nick_lc, pass_salt, pass_hash, banned, ban_reason';
    db.exec('PRAGMA foreign_keys=OFF'); // sessions ссылается на users: на время пересоздания проверку отключаем
    try {
      db.exec('BEGIN');
      db.exec(`CREATE TABLE users_new(${USERS_DDL}) STRICT; INSERT INTO users_new(${names}) SELECT ${names} FROM users; DROP TABLE users; ALTER TABLE users_new RENAME TO users;`);
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; } finally { db.exec('PRAGMA foreign_keys=ON'); }
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS users_nick_lc ON users(nick_lc)');

  const byUserToken = db.prepare('SELECT id, nick, created_at, banned, ban_reason FROM users WHERE token_hash=?');
  const bySession = db.prepare('SELECT u.id, u.nick, u.created_at, u.banned, u.ban_reason FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?');
  const byNick = db.prepare('SELECT id, nick, created_at, pass_salt, pass_hash, banned, ban_reason FROM users WHERE nick_lc=?');
  const byId = db.prepare('SELECT id, nick, created_at, banned, ban_reason FROM users WHERE id=?');
  const ins = db.prepare('INSERT INTO users(id, token_hash, created_at, nick, nick_lc, pass_salt, pass_hash) VALUES(?,?,?,?,?,?,?)');
  const claim = db.prepare('UPDATE users SET nick=?, nick_lc=?, pass_salt=?, pass_hash=? WHERE id=? AND nick IS NULL');
  const addSession = db.prepare('INSERT OR IGNORE INTO sessions(token_hash, user_id, created_at) VALUES(?,?,?)');
  const count = db.prepare('SELECT COUNT(*) n FROM users');
  const badgesOfStmt = db.prepare('SELECT b.id, b.title, b.icon, b.color, b.image FROM user_badges ub JOIN badges b ON b.id=ub.badge_id WHERE ub.user_id=? ORDER BY ub.granted_at, b.id');
  const badgesOf = id => badgesOfStmt.all(id).map(b => ({ id: b.id, title: b.title, icon: b.icon, color: b.color, image: b.image || null }));
  const find = h => byUserToken.get(h) || bySession.get(h);
  const noBan = u => { if (u && u.banned) throw Object.assign(fail('banned', 403), { reason: u.ban_reason || '', uid: u.id }); return u; }; // забаненный не может ни войти, ни зарегистрироваться
  const pub = u => ({ id: u.id, nick: u.nick || null, createdAt: u.created_at, badges: badgesOf(u.id) });
  const verify = async (u, pw) => {
    if (!u || !u.pass_hash || !u.pass_salt || typeof pw !== 'string') return false;
    const a = Buffer.from(await hashPass(pw, u.pass_salt), 'hex'), b = Buffer.from(u.pass_hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  };

  // создаёт пользователя с новым ID. Идемпотентно по токену; коллизии ID ловит PRIMARY KEY, без гонок.
  function createUser(h, extra) {
    const have = noBan(find(h)); if (have) return { ...pub(have), created: false };
    if (count.get().n >= ID_MAX - ID_MIN + 1) throw fail('full', 503);
    for (let i = 0; i < 1000; i++) {
      const id = rng(), now = Date.now();
      try {
        ins.run(id, h, now, extra ? extra.nick : null, extra ? extra.lc : null, extra ? extra.salt : null, extra ? extra.hash : null);
        return { id, nick: extra ? extra.nick : null, createdAt: now, badges: [], created: true };
      } catch (e) {
        if (!/UNIQUE|constraint/i.test(e.message)) throw e;
        if (/nick_lc/.test(e.message)) throw fail('nick_taken', 409);
        const again = noBan(find(h)); if (again) return { ...pub(again), created: false }; // параллельный запрос с тем же токеном
      } // занятый ID → пробуем следующий
    }
    throw fail('full', 503);
  }
  // анонимный ID без профиля (для старых версий лаунчера)
  const register = token => createUser(sha(token), null);

  async function signup(token, nick, password) {
    if (!NICK_RE.test(nick)) throw fail('bad_nick', 400);
    if (!validPass(password)) throw fail('bad_password', 400);
    const h = sha(token), lc = nick.toLowerCase(), have = noBan(find(h));
    if (have && have.nick) { // повтор после обрыва связи: тот же ник и пароль → тот же результат
      const u = byNick.get(lc);
      if (u && u.id === have.id && await verify(u, password)) return { ...pub(u), created: false };
      throw fail('token_used', 409);
    }
    if (byNick.get(lc)) throw fail('nick_taken', 409);
    const salt = crypto.randomBytes(16).toString('hex'), hash = await hashPass(password, salt);
    if (have) { // старый анонимный ID: привязываем к нему ник и пароль, ID сохраняется
      try { claim.run(nick, lc, salt, hash, have.id); } catch (e) { if (/UNIQUE|constraint/i.test(e.message)) throw fail('nick_taken', 409); throw e; }
      return { ...pub(byId.get(have.id)), created: false };
    }
    return createUser(h, { nick, lc, salt, hash });
  }

  const fails = new Map(); // неудачные входы: по IP и по нику, чтобы пароль нельзя было подобрать перебором
  const recent = k => { const now = Date.now(), a = (fails.get(k) || []).filter(t => now - t < FAIL_WINDOW); a.length ? fails.set(k, a) : fails.delete(k); return a; };
  const blocked = (ip, lc) => recent('ip:' + ip).length >= loginLimit * 4 || recent('n:' + lc).length >= loginLimit;
  const addFail = k => { const a = recent(k); a.push(Date.now()); fails.set(k, a); };

  async function login(token, nick, password, ip = '?') {
    const lc = String(nick).toLowerCase();
    if (!NICK_RE.test(String(nick)) || typeof password !== 'string' || !password || password.length > PASS_MAX) throw fail('bad_credentials', 401);
    if (blocked(ip, lc)) throw fail('rate_limited', 429);
    const u = byNick.get(lc), ok = u ? await verify(u, password) : (await hashPass(password, DUMMY_SALT), false);
    if (!ok) { addFail('ip:' + ip); addFail('n:' + lc); throw fail('bad_credentials', 401); }
    fails.delete('n:' + lc);
    noBan(u); // сообщаем о бане только после верного пароля
    const h = sha(token), have = find(h);
    if (have && have.id !== u.id) throw fail('token_used', 409);
    if (!have) addSession.run(h, u.id, Date.now());
    return pub(u);
  }

  // ---- значки и смена ID (используются админ-панелью) ----
  // картинка значка: только PNG в виде data-URL, до 32 КБ и до 256×256 (админка сама уменьшает до 64×64)
  const checkImage = v => {
    if (v == null || v === '') return null;
    if (typeof v !== 'string' || v.length > 48000 || !IMG_RE.test(v)) throw fail('bad_image', 400);
    const b = Buffer.from(v.slice(22), 'base64');
    if (b.length < 33 || b.length > IMG_MAX_BYTES || b.readUInt32BE(0) !== 0x89504e47 || b.readUInt32BE(4) !== 0x0d0a1a0a || b.toString('latin1', 12, 16) !== 'IHDR') throw fail('bad_image', 400);
    const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
    if (!w || !h || w > IMG_MAX_SIDE || h > IMG_MAX_SIDE) throw fail('bad_image', 400);
    return v;
  };
  const checkBadge = j => {
    const title = String(j.title == null ? '' : j.title).trim(), color = String(j.color == null ? '' : j.color).trim();
    const image = checkImage(j.image);
    let icon = String(j.icon == null ? '' : j.icon).trim(); if (!icon && image) icon = '★'; // запасной текст для старых версий лаунчера
    if (!title || title.length > 24 || CTRL_RE.test(title)) throw fail('bad_title', 400);
    if (!icon || [...icon].length > 8 || CTRL_RE.test(icon)) throw fail('bad_icon', 400);
    if (!/^#[0-9a-fA-F]{6}$/.test(color)) throw fail('bad_color', 400);
    return { title, icon, color: color.toLowerCase(), image };
  };
  const insBadge = db.prepare('INSERT INTO badges(title, icon, color, created_at, image) VALUES(?,?,?,?,?)');
  const badgeById = db.prepare('SELECT id, title, icon, color, image FROM badges WHERE id=?');
  const delBadgeLinks = db.prepare('DELETE FROM user_badges WHERE badge_id=?'), delBadge = db.prepare('DELETE FROM badges WHERE id=?');
  const grantStmt = db.prepare('INSERT OR IGNORE INTO user_badges(user_id, badge_id, granted_at) VALUES(?,?,?)'), revokeStmt = db.prepare('DELETE FROM user_badges WHERE user_id=? AND badge_id=?');
  const listBadgesStmt = db.prepare('SELECT b.id, b.title, b.icon, b.color, b.image, b.created_at, (SELECT COUNT(*) FROM user_badges WHERE badge_id=b.id) AS users FROM badges b ORDER BY b.id');
  const needUser = id => { if (!validId(id) || !byId.get(id)) throw fail('not_found', 404); };
  const needBadge = id => { if (!Number.isInteger(id) || !badgeById.get(id)) throw fail('badge_not_found', 404); };
  function createBadge(j) {
    if (db.prepare('SELECT COUNT(*) n FROM badges').get().n >= MAX_BADGES) throw fail('too_many_badges', 409);
    const b = checkBadge(j), r = insBadge.run(b.title, b.icon, b.color, Date.now(), b.image); return { id: Number(r.lastInsertRowid), ...b };
  }
  function deleteBadge(id) { needBadge(id); db.exec('BEGIN'); try { delBadgeLinks.run(id); delBadge.run(id); db.exec('COMMIT'); } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; } }
  function grant(userId, badgeId) { needUser(userId); needBadge(badgeId); grantStmt.run(userId, badgeId, Date.now()); return badgesOf(userId); }
  function revoke(userId, badgeId) { needUser(userId); revokeStmt.run(userId, badgeId); return badgesOf(userId); }

  // ---- баны ----
  const banStmt = db.prepare('UPDATE users SET banned=1, ban_reason=? WHERE id=?'), unbanStmt = db.prepare('UPDATE users SET banned=0, ban_reason=NULL WHERE id=?');
  // привязка к устройству: лаунчер присылает хеш ID машины (hw). Бан запоминает все устройства игрока,
  // поэтому после переустановки лаунчера и новой регистрации бан остаётся.
  const hwHash = h => sha('hw:' + h); // в базе только повторный хеш
  const hwArg = j => {
    if (j.hw == null || j.hw === '') { if (requireHw) throw fail('hw_required', 400); return null; }
    if (typeof j.hw !== 'string' || !HW_RE.test(j.hw)) throw fail('bad_hw', 400);
    return hwHash(j.hw);
  };
  const banByHw = db.prepare('SELECT reason FROM banned_hw WHERE hw=? LIMIT 1'), hwCount = db.prepare('SELECT COUNT(*) n FROM user_hw WHERE user_id=?');
  const touchStmt = db.prepare('INSERT INTO user_hw(user_id, hw, last_seen) VALUES(?,?,?) ON CONFLICT(user_id, hw) DO UPDATE SET last_seen=excluded.last_seen');
  const touchOld = db.prepare('UPDATE user_hw SET last_seen=? WHERE user_id=? AND hw=?'), banHwStmt = db.prepare('INSERT OR REPLACE INTO banned_hw(hw, user_id, reason, created_at) VALUES(?,?,?,?)');
  const devBan = hw => { if (!hw) return; const r = banByHw.get(hw); if (r) throw Object.assign(fail('banned', 403), { reason: r.reason || '' }); };
  function touchHw(u, hw) { // u: { id, banned?, ban_reason? }
    if (!hw) return;
    if (hwCount.get(u.id).n < MAX_DEVICES) touchStmt.run(u.id, hw, Date.now()); else touchOld.run(Date.now(), u.id, hw);
    if (u.banned) banHwStmt.run(hw, u.id, u.ban_reason || null, Date.now()); // забаненный зашёл с нового устройства: бан распространяется и на него
  }
  function ban(userId, reason) {
    needUser(userId); reason = String(reason == null ? '' : reason).trim();
    if (reason.length > REASON_MAX || CTRL_RE.test(reason)) throw fail('bad_reason', 400);
    db.exec('BEGIN');
    try {
      banStmt.run(reason || null, userId);
      db.prepare('INSERT OR REPLACE INTO banned_hw(hw, user_id, reason, created_at) SELECT hw, user_id, ?, ? FROM user_hw WHERE user_id=?').run(reason || null, Date.now(), userId);
      db.exec('COMMIT');
    } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; }
    return { banned: true, banReason: reason || null, devices: hwCount.get(userId).n };
  }
  function unban(userId) { needUser(userId); db.exec('BEGIN'); try { unbanStmt.run(userId); db.prepare('DELETE FROM banned_hw WHERE user_id=?').run(userId); db.exec('COMMIT'); } catch (e) { try { db.exec('ROLLBACK'); } catch {} throw e; } return { banned: false, banReason: null }; }
  // подпись успешного ответа: лаунчер проверяет её открытым ключом, поэтому подменой сервера или файла настроек «не забанен» не подделать
  const signed = (o, j) => {
    if (!signKeyObj || typeof j.nonce !== 'string' || !NONCE_RE.test(j.nonce)) return o;
    const ts = Date.now(); return { ...o, ts, sig: crypto.sign(null, Buffer.from(`void1|${o.id}|${j.nonce}|${ts}|0`), signKeyObj).toString('base64') };
  };

  // смена ID: newId не задан → случайный свободный. Токены и значки переезжают вместе с пользователем.
  function changeId(oldId, newId) {
    needUser(oldId);
    if (newId == null || newId === '') {
      newId = 0; for (let i = 0; i < 1000 && !newId; i++) { const c = rng(); if (!byId.get(c)) newId = c; }
      if (!newId) throw fail('full', 503);
    } else {
      newId = Number(newId); if (!validId(newId)) throw fail('bad_id', 400);
      if (newId === oldId) throw fail('same_id', 400);
      if (byId.get(newId)) throw fail('id_taken', 409);
    }
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec('PRAGMA defer_foreign_keys=ON'); // sessions ссылается на users(id): проверка после обновления всех таблиц
      db.prepare('UPDATE users SET id=? WHERE id=?').run(newId, oldId);
      db.prepare('UPDATE sessions SET user_id=? WHERE user_id=?').run(newId, oldId);
      db.prepare('UPDATE user_badges SET user_id=? WHERE user_id=?').run(newId, oldId);
      db.prepare('UPDATE user_hw SET user_id=? WHERE user_id=?').run(newId, oldId);
      db.prepare('UPDATE banned_hw SET user_id=? WHERE user_id=?').run(newId, oldId);
      db.exec('COMMIT');
    } catch (e) {
      try { db.exec('ROLLBACK'); } catch {}
      if (/UNIQUE|constraint/i.test(e.message)) throw fail('id_taken', 409);
      throw e;
    }
    return { id: newId };
  }
  const likeEsc = q => q.replace(/[\\%_]/g, '\\$&');
  const USERS_WHERE = `WHERE ?='' OR CAST(id AS TEXT) LIKE ?||'%' ESCAPE '\\' OR nick_lc LIKE '%'||?||'%' ESCAPE '\\'`;
  const usersStmt = db.prepare(`SELECT id, nick, created_at, banned, ban_reason FROM users ${USERS_WHERE} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`);
  const usersCount = db.prepare(`SELECT COUNT(*) n FROM users ${USERS_WHERE}`);
  function listUsers(q, limit, offset) {
    q = likeEsc(String(q || '').trim().toLowerCase().slice(0, 32)); limit = Math.min(100, Math.max(1, limit | 0 || 50)); offset = Math.max(0, offset | 0);
    return { total: usersCount.get(q, q, q).n, users: usersStmt.all(q, q, q, limit, offset).map(u => ({ ...pub(u), banned: !!u.banned, banReason: u.ban_reason || null })) };
  }

  // ---- админ-панель: пароль из ADMIN_PASSWORD, сессия в HttpOnly-cookie ----
  const adminOn = typeof adminPassword === 'string' && adminPassword.length >= ADMIN_PASS_MIN;
  const adminHtml = (() => { try { return fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8'); } catch { return null; } })();
  const adminHash = adminOn ? shaBuf(adminPassword) : null, adminSessions = new Map(); // токен → срок жизни
  const adminLog = (...a) => console.log('[admin]', new Date().toISOString(), ...a);
  const cookieOf = (req, name) => { for (const p of String(req.headers.cookie || '').split(';')) { const s = p.trim(); if (s.startsWith(name + '=')) return s.slice(name.length + 1); } return ''; };
  const isAdmin = req => { const t = cookieOf(req, 'void_admin'), exp = t && adminSessions.get(t); if (exp && exp > Date.now()) return t; if (exp) adminSessions.delete(t); return null; };
  const isHttps = req => req.socket.encrypted || (trustProxy && String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() === 'https');
  const cookie = (req, v, maxAge) => `void_admin=${v}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=${maxAge}${isHttps(req) ? '; Secure' : ''}`;
  const sameOrigin = req => { const o = req.headers.origin; if (!o) return true; try { return new URL(o).host === req.headers.host; } catch { return false; } };
  const idArg = v => (typeof v === 'number' ? v : typeof v === 'string' && /^[1-9]\d{0,15}$/.test(v) ? Number(v) : NaN);

  async function adminApi(req, res, url, ip) {
    if (!adminOn) throw fail('admin_disabled', 503);
    const route = url.pathname.slice('/admin/api/'.length), post = req.method === 'POST';
    if (post && (req.headers['x-admin'] !== '1' || !sameOrigin(req))) throw fail('forbidden', 403); // защита от CSRF: чужой сайт не сможет прислать такой запрос
    if (post && route === 'login') {
      if (recent('adm:' + ip).length >= adminLimit) throw fail('rate_limited', 429);
      const j = await json(req), ok = typeof j.password === 'string' && j.password.length <= 256 && crypto.timingSafeEqual(shaBuf(j.password), adminHash);
      if (!ok) { addFail('adm:' + ip); adminLog('неудачный вход', ip); await sleep(adminDelay); throw fail('bad_password', 401); }
      fails.delete('adm:' + ip);
      const t = crypto.randomBytes(32).toString('hex'); adminSessions.set(t, Date.now() + ADMIN_SESSION_MS); adminLog('вход', ip);
      return send(res, 200, { ok: true }, { 'set-cookie': cookie(req, t, ADMIN_SESSION_MS / 1000) });
    }
    const tok = isAdmin(req); if (!tok) throw fail('unauthorized', 401);
    if (post && route === 'logout') { adminSessions.delete(tok); return send(res, 200, { ok: true }, { 'set-cookie': cookie(req, '', 0) }); }
    if (req.method === 'GET' && route === 'session') return send(res, 200, { ok: true });
    if (req.method === 'GET' && route === 'users') return send(res, 200, listUsers(url.searchParams.get('q'), +url.searchParams.get('limit'), +url.searchParams.get('offset')));
    if (req.method === 'GET' && route === 'badges') return send(res, 200, { badges: listBadgesStmt.all().map(b => ({ id: b.id, title: b.title, icon: b.icon, color: b.color, image: b.image || null, users: b.users })) });
    if (post) {
      const j = await json(req, route === 'badges' ? 70000 : 2048); // для значка с картинкой тело больше
      if (route === 'badges') { const b = createBadge(j); adminLog('значок создан', b.id, b.title); return send(res, 201, b); }
      if (route === 'badges/delete') { deleteBadge(idArg(j.id)); adminLog('значок удалён', j.id); return send(res, 200, { ok: true }); }
      if (route === 'grant') { const b = grant(idArg(j.userId), idArg(j.badgeId)); adminLog('значок выдан', j.badgeId, '→', j.userId); return send(res, 200, { badges: b }); }
      if (route === 'revoke') { const b = revoke(idArg(j.userId), idArg(j.badgeId)); adminLog('значок отозван', j.badgeId, '←', j.userId); return send(res, 200, { badges: b }); }
      if (route === 'ban') { const r = ban(idArg(j.userId), j.reason); adminLog('бан', j.userId, r.banReason || '', 'устройств:', r.devices); return send(res, 200, r); }
      if (route === 'unban') { const r = unban(idArg(j.userId)); adminLog('разбан', j.userId); return send(res, 200, r); }
      if (route === 'change-id') { const r = changeId(idArg(j.userId), j.newId == null || j.newId === '' ? null : idArg(j.newId)); adminLog('ID сменён', j.userId, '→', r.id); return send(res, 200, r); }
    }
    throw fail('not_found', 404);
  }

  const hits = new Map(); // лимит регистраций: regLimit в час с одного IP
  const limited = ip => { const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 36e5); a.push(now); hits.set(ip, a); return a.length > regLimit; };
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, a] of hits) if (!a.some(t => now - t < 36e5)) hits.delete(k);
    for (const k of [...fails.keys()]) recent(k);
    for (const [k, exp] of adminSessions) if (exp <= now) adminSessions.delete(k);
  }, 6e5); timer.unref();

  const send = (res, code, o, extra) => { const b = JSON.stringify(o); res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(b), ...extra }); res.end(b); };
  const body = (req, max) => new Promise((ok, no) => { let s = '', n = 0; req.on('data', c => { n += c.length; if (n > max) { no(fail('too_big', 413)); req.destroy(); } else s += c; }); req.on('end', () => ok(s)); req.on('error', no); });
  const json = async (req, max = 2048) => { let s; try { s = await body(req, max); } catch (e) { throw e.status ? e : fail('bad_json', 400); } let j; try { j = JSON.parse(s); } catch { throw fail('bad_json', 400); } if (!j || typeof j !== 'object') throw fail('bad_json', 400); return j; };
  const tokenOf = j => { if (typeof j.token !== 'string' || !TOKEN_RE.test(j.token)) throw fail('bad_token', 400); return j.token; };
  const page = (res, code, html) => { res.writeHead(code, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" }); res.end(html); };

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x'), ip = (trustProxy && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';
      if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, { ok: true });
      if (url.pathname === '/admin' || url.pathname === '/admin/') {
        if (req.method !== 'GET') throw fail('not_found', 404);
        if (!adminOn || !adminHtml) return page(res, 503, '<!doctype html><meta charset="utf-8"><title>VoidLauncher</title><body style="font:16px system-ui;background:#0b0f0d;color:#e6f2ec;padding:40px"><h2>Админ-панель выключена</h2><p>Задайте переменную окружения <code>ADMIN_PASSWORD</code> (не короче ' + ADMIN_PASS_MIN + ' символов) и перезапустите сервер.</p>');
        return page(res, 200, adminHtml);
      }
      if (url.pathname.startsWith('/admin/api/')) return await adminApi(req, res, url, ip);
      if (req.method === 'POST' && url.pathname === '/api/register') {
        if (limited(ip)) throw fail('rate_limited', 429);
        const j = await json(req), hw = req.hw = hwArg(j); devBan(hw);
        const r = register(tokenOf(j)); touchHw({ id: r.id }, hw); return send(res, r.created ? 201 : 200, { id: r.id });
      }
      if (req.method === 'POST' && url.pathname === '/api/signup') {
        if (limited(ip)) throw fail('rate_limited', 429);
        const j = await json(req), hw = req.hw = hwArg(j); devBan(hw);
        const r = await signup(tokenOf(j), String(j.nick || '').trim(), j.password); touchHw({ id: r.id }, hw);
        return send(res, r.created ? 201 : 200, signed({ id: r.id, nick: r.nick, createdAt: r.createdAt, badges: r.badges }, j));
      }
      if (req.method === 'POST' && url.pathname === '/api/login') {
        const j = await json(req), hw = req.hw = hwArg(j), r = await login(tokenOf(j), String(j.nick || '').trim(), j.password, ip);
        devBan(hw); touchHw({ id: r.id }, hw); return send(res, 200, signed(r, j));
      }
      if (req.method === 'POST' && url.pathname === '/api/me') { // токен в теле, а не в URL — не попадает в логи прокси
        const j = await json(req), hw = req.hw = hwArg(j), u = noBan(find(sha(tokenOf(j))));
        if (!u) return send(res, 404, { error: 'not_found' });
        devBan(hw); touchHw(u, hw); return send(res, 200, signed(pub(u), j));
      }
      const m = url.pathname.match(/^\/api\/users\/([1-9]\d{0,7})$/);
      if (req.method === 'GET' && m) { const u = byId.get(+m[1]); return u ? send(res, 200, { id: u.id, createdAt: u.created_at }) : send(res, 404, { error: 'not_found' }); }
      send(res, 404, { error: 'not_found' });
    } catch (e) {
      if (e.code === 'banned' && e.uid && req.hw) { try { touchHw({ id: e.uid, banned: 1, ban_reason: e.reason }, req.hw); } catch {} } // запоминаем устройство забаненного
      if (e.status) return send(res, e.status, e.reason !== undefined ? { error: e.code, reason: e.reason } : { error: e.code });
      console.error(e); send(res, 500, { error: 'server' });
    }
  });
  return { server, db, register, signup, login, createBadge, deleteBadge, grant, revoke, ban, unban, changeId, listUsers, adminEnabled: adminOn && !!adminHtml, close: () => { clearInterval(timer); server.close(); db.close(); } };
}

module.exports = { createApp, ID_MIN, ID_MAX, ID_RANDOM_MIN, TOKEN_RE, NICK_RE };

if (require.main === module) {
  (async () => {
    const dbPath = process.env.DB_PATH || path.join(__dirname, 'data', 'void.db');
    const bk = require('./ghbackup').fromEnv(dbPath); // бэкап в GitHub включается, если заданы GH_BACKUP_TOKEN и GH_BACKUP_REPO
    if (bk) { try { await bk.restoreIfMissing(); } catch (e) { console.error('[backup] не удалось восстановить базу:', e.message); } }
    const app = createApp({ dbPath, trustProxy: process.env.TRUST_PROXY === '1' });
    const port = +process.env.PORT || 3000, host = process.env.HOST || '0.0.0.0';
    app.server.listen(port, host, () => {
      console.log(`VoidLauncher server: http://${host}:${port}`);
      console.log(app.adminEnabled ? `Админ-панель: http://${host}:${port}/admin` : `Админ-панель ВЫКЛЮЧЕНА: задайте ADMIN_PASSWORD (не короче ${ADMIN_PASS_MIN} символов).`);
      if (bk) bk.start(app.db);
    });
    for (const s of ['SIGINT', 'SIGTERM']) process.on(s, async () => { if (bk) await bk.stop(); app.close(); process.exit(0); });
  })();
}
