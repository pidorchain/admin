const test = require('node:test'), assert = require('node:assert');
const crypto = require('crypto');
const { createApp, ID_MIN, ID_MAX } = require('./server.js');
const tok = () => crypto.randomBytes(32).toString('hex');

test('ID: 8 цифр, идемпотентность по токену', () => {
  const a = createApp({ dbPath: ':memory:' }); const t = tok();
  const r1 = a.register(t), r2 = a.register(t);
  assert.ok(r1.id >= ID_MIN && r1.id <= ID_MAX && String(r1.id).length === 8);
  assert.equal(r1.id, r2.id); assert.equal(r1.created, true); assert.equal(r2.created, false);
  a.close();
});
test('ID: коллизия → выбирается другой', () => {
  const seq = [12345678, 12345678, 12345678, 87654321]; const a = createApp({ dbPath: ':memory:', rng: () => seq.shift() });
  assert.equal(a.register(tok()).id, 12345678); assert.equal(a.register(tok()).id, 87654321); a.close();
});
test('ID: 2000 пользователей — все разные', () => {
  const a = createApp({ dbPath: ':memory:' }), s = new Set(); for (let i = 0; i < 2000; i++) s.add(a.register(tok()).id);
  assert.equal(s.size, 2000); a.close();
});
test('HTTP: register / users / валидация', async () => {
  const a = createApp({ dbPath: ':memory:' }); await new Promise(r => a.server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + a.server.address().port, t = tok();
  const post = b => fetch(base + '/api/register', { method: 'POST', body: JSON.stringify(b) });
  const r1 = await post({ token: t }); assert.equal(r1.status, 201); const { id } = await r1.json();
  const r2 = await post({ token: t }); assert.equal(r2.status, 200); assert.equal((await r2.json()).id, id);
  assert.equal((await post({ token: 'abc' })).status, 400);
  assert.equal((await fetch(base + '/api/users/' + id)).status, 200);
  assert.equal((await fetch(base + '/api/users/11111111')).status, 404);
  a.close();
});

// ---- профили: ник + пароль ----
const expectErr = async (p, code) => { try { await p; assert.fail('ожидалась ошибка ' + code); } catch (e) { assert.equal(e.code, code); } };

test('профиль: регистрация даёт ID и ник, повтор идемпотентен', async () => {
  const a = createApp({ dbPath: ':memory:' }), t = tok();
  const r1 = await a.signup(t, 'Steve_01', 'secret123'), r2 = await a.signup(t, 'steve_01', 'secret123');
  assert.equal(r1.created, true); assert.equal(r2.created, false);
  assert.ok(String(r1.id).length === 8 && r1.id === r2.id && r1.nick === 'Steve_01');
  a.close();
});
test('профиль: ник уникален без учёта регистра, валидация', async () => {
  const a = createApp({ dbPath: ':memory:' });
  await a.signup(tok(), 'Alex', 'secret123');
  await expectErr(a.signup(tok(), 'ALEX', 'other-pass'), 'nick_taken');
  await expectErr(a.signup(tok(), 'ab', 'secret123'), 'bad_nick');
  await expectErr(a.signup(tok(), 'bad nick', 'secret123'), 'bad_nick');
  await expectErr(a.signup(tok(), 'Bob', '12345'), 'bad_password');
  await expectErr(a.signup(tok(), 'Bob', 'x'.repeat(65)), 'bad_password');
  a.close();
});
test('профиль: вход с другого устройства возвращает тот же ID', async () => {
  const a = createApp({ dbPath: ':memory:' }), t1 = tok(), t2 = tok();
  const r = await a.signup(t1, 'Notch', 'secret123');
  const l = await a.login(t2, 'notch', 'secret123'); assert.equal(l.id, r.id); assert.equal(l.nick, 'Notch');
  assert.equal((await a.login(t2, 'Notch', 'secret123')).id, r.id); // повторный вход с тем же токеном
  await expectErr(a.login(tok(), 'Notch', 'wrong-pass'), 'bad_credentials');
  await expectErr(a.login(tok(), 'Nobody', 'secret123'), 'bad_credentials');
  await expectErr(a.login(tok(), 'Notch', ''), 'bad_credentials'); // пустой пароль
  a.close();
});
test('профиль: старый анонимный ID сохраняется при привязке ника', async () => {
  const a = createApp({ dbPath: ':memory:' }), t = tok(), old = a.register(t);
  const r = await a.signup(t, 'Legacy', 'secret123'); assert.equal(r.id, old.id); assert.equal(r.nick, 'Legacy');
  a.close();
});
test('профиль: токен, уже занятый другим ником, не перепривязать', async () => {
  const a = createApp({ dbPath: ':memory:' }), t = tok();
  await a.signup(t, 'First', 'secret123');
  await expectErr(a.signup(t, 'Second', 'secret123'), 'token_used');
  await expectErr(a.signup(t, 'First', 'wrong-pass'), 'token_used');
  a.close();
});
test('профиль: перебор пароля блокируется', async () => {
  const a = createApp({ dbPath: ':memory:', loginLimit: 3 });
  await a.signup(tok(), 'Victim', 'secret123');
  for (let i = 0; i < 3; i++) await expectErr(a.login(tok(), 'Victim', 'guess' + i, '1.2.3.4'), 'bad_credentials');
  await expectErr(a.login(tok(), 'Victim', 'secret123', '1.2.3.4'), 'rate_limited'); // даже верный пароль не пускает, пока не пройдёт окно
  a.close();
});
test('профиль: пароль хранится только в виде scrypt-хеша', async () => {
  const a = createApp({ dbPath: ':memory:' }); await a.signup(tok(), 'Hashed', 'secret123');
  const row = a.db.prepare('SELECT pass_salt, pass_hash FROM users WHERE nick_lc=?').get('hashed');
  assert.ok(/^[0-9a-f]{32}$/.test(row.pass_salt) && /^[0-9a-f]{128}$/.test(row.pass_hash)); assert.ok(!row.pass_hash.includes('secret123'));
  a.close();
});
test('HTTP: signup / login / me', async () => {
  const a = createApp({ dbPath: ':memory:' }); await new Promise(r => a.server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + a.server.address().port, t1 = tok(), t2 = tok();
  const post = (p, b) => fetch(base + p, { method: 'POST', body: JSON.stringify(b) });
  const s = await post('/api/signup', { token: t1, nick: 'Http_User', password: 'secret123' }); assert.equal(s.status, 201);
  const sj = await s.json(); assert.equal(sj.nick, 'Http_User'); assert.ok(sj.createdAt > 0);
  assert.equal((await post('/api/signup', { token: tok(), nick: 'http_user', password: 'secret123' })).status, 409);
  assert.equal((await post('/api/signup', { token: tok(), nick: 'X', password: 'secret123' })).status, 400);
  assert.equal((await post('/api/signup', { token: 'bad', nick: 'Fine', password: 'secret123' })).status, 400);
  const l = await post('/api/login', { token: t2, nick: 'Http_User', password: 'secret123' }); assert.equal(l.status, 200); assert.equal((await l.json()).id, sj.id);
  assert.equal((await post('/api/login', { token: t2, nick: 'Http_User', password: 'nope-nope' })).status, 401);
  const me = await post('/api/me', { token: t2 }); assert.equal(me.status, 200); assert.equal((await me.json()).nick, 'Http_User');
  assert.equal((await post('/api/me', { token: tok() })).status, 404);
  assert.equal((await fetch(base + '/api/signup', { method: 'POST', body: 'nope' })).status, 400);
  a.close();
});
test('миграция: старая база с ID получает колонки ника и пароля', async () => {
  const os = require('os'), p = require('path').join(os.tmpdir(), 'void-mig-' + Date.now() + '.db'), { DatabaseSync } = require('node:sqlite');
  const old = new DatabaseSync(p); old.exec('CREATE TABLE users(id INTEGER PRIMARY KEY CHECK(id BETWEEN 10000000 AND 99999999), token_hash TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL) STRICT;');
  const t = tok(); old.prepare('INSERT INTO users VALUES(?,?,?)').run(12345678, require('crypto').createHash('sha256').update(t).digest('hex'), 1); old.close();
  const a = createApp({ dbPath: p }); const r = await a.signup(t, 'Migrated', 'secret123'); assert.equal(r.id, 12345678); a.close();
  for (const f of [p, p + '-wal', p + '-shm']) require('fs').rmSync(f, { force: true });
});

// ---- админ-панель ----
const ADMIN = 'very-long-admin-pass';
async function adminEnv(opts = {}) {
  const a = createApp({ dbPath: ':memory:', adminPassword: ADMIN, adminDelay: 0, ...opts }); await new Promise(r => a.server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + a.server.address().port; let cookie = '';
  const call = async (p, body, h = {}) => {
    const r = await fetch(base + p, body === undefined ? { headers: { cookie, ...h } } : { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', 'x-admin': '1', cookie, ...h } });
    const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    let j = null; try { j = await r.json(); } catch {} return { status: r.status, j, r };
  };
  const pub = (p, b) => fetch(base + p, { method: 'POST', body: JSON.stringify(b) }).then(async r => ({ status: r.status, j: await r.json() }));
  return { a, base, call, pub, login: () => call('/admin/api/login', { password: ADMIN }), clearCookie: () => { cookie = ''; } };
}

test('админка: без ADMIN_PASSWORD (или короткого) она выключена', async () => {
  for (const pw of [undefined, '', 'short']) {
    const a = createApp({ dbPath: ':memory:', adminPassword: pw }); await new Promise(r => a.server.listen(0, '127.0.0.1', r));
    const base = 'http://127.0.0.1:' + a.server.address().port;
    assert.equal((await fetch(base + '/admin')).status, 503);
    const r = await fetch(base + '/admin/api/login', { method: 'POST', body: '{"password":"short"}', headers: { 'x-admin': '1' } }); assert.equal(r.status, 503);
    a.close();
  }
});
test('админка: страница отдаётся с защитными заголовками, данные — только после входа', async () => {
  const e = await adminEnv();
  const p = await e.call('/admin'); assert.equal(p.status, 200);
  assert.match(p.r.headers.get('content-security-policy'), /default-src 'none'/); assert.equal(p.r.headers.get('x-frame-options'), 'DENY');
  for (const path of ['/admin/api/users', '/admin/api/badges', '/admin/api/session']) assert.equal((await e.call(path)).status, 401);
  assert.equal((await e.call('/admin/api/grant', { userId: 1, badgeId: 1 })).status, 401);
  e.a.close();
});
test('админка: неверный пароль → 401, верный → cookie HttpOnly/SameSite=Strict', async () => {
  const e = await adminEnv();
  assert.equal((await e.call('/admin/api/login', { password: 'wrong-wrong-wrong' })).status, 401);
  assert.equal((await e.call('/admin/api/login', {})).status, 401);
  const ok = await e.login(); assert.equal(ok.status, 200);
  const sc = ok.r.headers.get('set-cookie'); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.match(sc, /Path=\/admin/); assert.ok(!/Secure/.test(sc));
  assert.equal((await e.call('/admin/api/session')).status, 200);
  assert.equal((await e.call('/admin/api/logout', {})).status, 200); e.clearCookie();
  assert.equal((await e.call('/admin/api/session')).status, 401);
  e.a.close();
});
test('админка: Secure-cookie за HTTPS-прокси', async () => {
  const e = await adminEnv({ trustProxy: true });
  const r = await e.call('/admin/api/login', { password: ADMIN }, { 'x-forwarded-proto': 'https' }); assert.match(r.r.headers.get('set-cookie'), /; Secure/);
  e.a.close();
});
test('админка: защита от CSRF (нужен заголовок и тот же Origin)', async () => {
  const e = await adminEnv();
  const raw = (h, body) => fetch(e.base + '/admin/api/badges', { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', ...h } });
  const good = { title: 'VIP', icon: '★', color: '#ffcc00' };
  const login = await fetch(e.base + '/admin/api/login', { method: 'POST', body: JSON.stringify({ password: ADMIN }), headers: { 'x-admin': '1' } });
  const cookie = login.headers.get('set-cookie').split(';')[0];
  assert.equal((await raw({ cookie }, good)).status, 403);                                                        // нет заголовка x-admin
  assert.equal((await raw({ cookie, 'x-admin': '1', origin: 'https://evil.example' }, good)).status, 403);        // чужой Origin
  assert.equal((await raw({ 'x-admin': '1' }, good)).status, 401);                                                // заголовок есть, но нет сессии
  assert.equal((await raw({ cookie, 'x-admin': '1', origin: e.base }, good)).status, 201);                       // всё верно
  assert.equal((await fetch(e.base + '/admin/api/login', { method: 'POST', body: JSON.stringify({ password: ADMIN }) })).status, 403); // вход тоже без заголовка нельзя
  e.a.close();
});
test('админка: перебор пароля блокируется', async () => {
  const e = await adminEnv({ adminLimit: 3 });
  for (let i = 0; i < 3; i++) assert.equal((await e.call('/admin/api/login', { password: 'nope-nope-nope' + i })).status, 401);
  assert.equal((await e.login()).status, 429); // даже верный пароль не пускает, пока не пройдёт окно
  e.a.close();
});
test('админка: значки — создание, валидация, выдача, отзыв, удаление; игрок видит их в /api/me', async () => {
  const e = await adminEnv(); await e.login();
  const t = tok(), u = await e.a.signup(t, 'Badger', 'secret123');
  for (const bad of [{ title: '', icon: '★', color: '#ffffff' }, { title: 'x'.repeat(25), icon: '★', color: '#ffffff' }, { title: 'A', icon: '', color: '#ffffff' }, { title: 'A', icon: '123456789', color: '#ffffff' }, { title: 'A', icon: '★', color: 'red' }, { title: 'A\n', icon: '★\u0007', color: '#fff' }])
    assert.equal((await e.call('/admin/api/badges', bad)).status, 400);
  const b1 = (await e.call('/admin/api/badges', { title: ' Админ ', icon: '👑', color: '#FFCC00' })).j; assert.equal(b1.title, 'Админ'); assert.equal(b1.color, '#ffcc00');
  const b2 = (await e.call('/admin/api/badges', { title: 'Тестер', icon: '🧪', color: '#3dffa0' })).j;
  assert.equal((await e.call('/admin/api/grant', { userId: u.id, badgeId: b1.id })).j.badges.length, 1);
  assert.equal((await e.call('/admin/api/grant', { userId: u.id, badgeId: b1.id })).j.badges.length, 1); // повторная выдача не дублирует
  await e.call('/admin/api/grant', { userId: u.id, badgeId: b2.id });
  assert.equal((await e.call('/admin/api/grant', { userId: 11111111, badgeId: b1.id })).status, 404);
  assert.equal((await e.call('/admin/api/grant', { userId: u.id, badgeId: 999 })).status, 404);
  const me = await e.pub('/api/me', { token: t }); assert.deepEqual(me.j.badges.map(b => b.title), ['Админ', 'Тестер']); assert.equal(me.j.badges[0].icon, '👑');
  assert.equal((await e.call('/admin/api/revoke', { userId: u.id, badgeId: b1.id })).j.badges.length, 1);
  const list = (await e.call('/admin/api/badges')).j.badges; assert.equal(list.find(b => b.id === b2.id).users, 1);
  assert.equal((await e.call('/admin/api/badges/delete', { id: b2.id })).status, 200);
  assert.equal((await e.pub('/api/me', { token: t })).j.badges.length, 0); // удалённый значок пропал и у игрока
  assert.equal((await e.call('/admin/api/badges/delete', { id: b2.id })).status, 404);
  e.a.close();
});
test('админка: смена ID — токен и значки переезжают, старый ID свободен', async () => {
  const e = await adminEnv(); await e.login();
  const t1 = tok(), t2 = tok(), u = await e.a.signup(t1, 'Mover', 'secret123');
  await e.pub('/api/login', { token: t2, nick: 'Mover', password: 'secret123' }); // вторая сессия (другое устройство)
  const b = (await e.call('/admin/api/badges', { title: 'VIP', icon: '★', color: '#ffcc00' })).j; await e.call('/admin/api/grant', { userId: u.id, badgeId: b.id });
  const r = await e.call('/admin/api/change-id', { userId: u.id, newId: 77777777 }); assert.equal(r.status, 200); assert.equal(r.j.id, 77777777);
  for (const t of [t1, t2]) { const me = await e.pub('/api/me', { token: t }); assert.equal(me.j.id, 77777777); assert.equal(me.j.nick, 'Mover'); assert.equal(me.j.badges.length, 1); }
  assert.equal((await fetch(e.base + '/api/users/' + u.id)).status, 404); assert.equal((await fetch(e.base + '/api/users/77777777')).status, 200);
  assert.equal((await e.pub('/api/login', { token: tok(), nick: 'Mover', password: 'secret123' })).j.id, 77777777); // вход по паролю тоже даёт новый ID
  const other = await e.a.signup(tok(), 'Other', 'secret123');
  assert.equal((await e.call('/admin/api/change-id', { userId: other.id, newId: 77777777 })).j.error, 'id_taken');
  assert.equal((await e.call('/admin/api/change-id', { userId: other.id, newId: 12 })).j.error, 'bad_id');
  assert.equal((await e.call('/admin/api/change-id', { userId: other.id, newId: '01234567' })).j.error, 'bad_id');
  assert.equal((await e.call('/admin/api/change-id', { userId: other.id, newId: other.id })).j.error, 'same_id');
  assert.equal((await e.call('/admin/api/change-id', { userId: 12345678, newId: 22222222 })).status, 404);
  const rnd = await e.call('/admin/api/change-id', { userId: other.id }); assert.equal(rnd.status, 200); assert.ok(rnd.j.id >= ID_MIN && rnd.j.id <= ID_MAX && rnd.j.id !== other.id);
  assert.equal((await e.call('/admin/api/change-id', { userId: rnd.j.id, newId: other.id })).status, 200); // освободившийся ID можно занять снова
  e.a.close();
});
test('админка: список и поиск пользователей', async () => {
  const e = await adminEnv(); await e.login();
  const names = ['Alpha', 'Beta_1', 'Gamma']; const us = []; for (const n of names) us.push(await e.a.signup(tok(), n, 'secret123'));
  let r = (await e.call('/admin/api/users')).j; assert.equal(r.total, 3); assert.equal(r.users.length, 3); assert.ok(Array.isArray(r.users[0].badges));
  r = (await e.call('/admin/api/users?q=bet')).j; assert.deepEqual(r.users.map(u => u.nick), ['Beta_1']);
  r = (await e.call('/admin/api/users?q=' + String(us[2].id).slice(0, 4))).j; assert.ok(r.users.some(u => u.nick === 'Gamma'));
  assert.equal((await e.call('/admin/api/users?q=%25')).j.total, 0); // % и _ — не маски
  assert.equal((await e.call('/admin/api/users?q=_')).j.total, 1 /* только Beta_1 содержит «_» */);
  assert.equal((await e.call('/admin/api/users?limit=2&offset=2')).j.users.length, 1);
  e.a.close();
});
