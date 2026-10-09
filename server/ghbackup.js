// Бэкап базы SQLite в приватный репозиторий GitHub. Без зависимостей (Node 22: fetch).
// При старте, если файла базы нет (Render Free стёр диск), скачивает последнюю копию.
// Дальше раз в N минут делает снимок (VACUUM INTO) и коммитит его, только если база изменилась.
// Переменные: GH_BACKUP_TOKEN, GH_BACKUP_REPO (владелец/репозиторий), GH_BACKUP_PATH (void.db),
//             GH_BACKUP_BRANCH (main), GH_BACKUP_INTERVAL_MIN (10)
'use strict';
const fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');

function create({ token, repo, file = 'void.db', branch = 'main', intervalMin = 10, dbPath, fetchFn = fetch, log = console }) {
  const api = `https://api.github.com/repos/${repo}/contents/${file.split('/').map(encodeURIComponent).join('/')}`;
  const headers = (accept = 'application/vnd.github+json') => ({ authorization: `Bearer ${token}`, accept, 'x-github-api-version': '2022-11-28', 'user-agent': 'void-server-backup' });
  let lastHash = null, timer = null, db = null, busy = Promise.resolve();

  async function remoteSha() {
    const r = await fetchFn(`${api}?ref=${encodeURIComponent(branch)}`, { headers: headers() });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error('github ' + r.status);
    return (await r.json()).sha;
  }

  async function restoreIfMissing() {
    if (fs.existsSync(dbPath)) return false;
    const r = await fetchFn(`${api}?ref=${encodeURIComponent(branch)}`, { headers: headers('application/vnd.github.raw+json') });
    if (r.status === 404) { log.log('[backup] копии в GitHub ещё нет, начинаем с чистой базы'); return false; }
    if (!r.ok) throw new Error('github ' + r.status);
    const buf = Buffer.from(await r.arrayBuffer());
    if (buf.length < 100 || buf.subarray(0, 15).toString() !== 'SQLite format 3') throw new Error('в репозитории лежит не база SQLite');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    fs.writeFileSync(dbPath, buf);
    lastHash = crypto.createHash('sha256').update(buf).digest('hex');
    log.log(`[backup] база восстановлена из GitHub (${buf.length} байт)`);
    return true;
  }

  async function backupOnce() {
    if (!db) return false;
    const tmp = path.join(os.tmpdir(), `void-backup-${process.pid}.db`);
    try { fs.unlinkSync(tmp); } catch {}
    db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);
    const buf = fs.readFileSync(tmp); fs.unlinkSync(tmp);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    if (hash === lastHash) return false;
    for (let attempt = 0; attempt < 3; attempt++) {
      const body = { message: `backup ${new Date().toISOString()}`, content: buf.toString('base64'), branch };
      const sha = await remoteSha(); if (sha) body.sha = sha;
      const r = await fetchFn(api, { method: 'PUT', headers: { ...headers(), 'content-type': 'application/json' }, body: JSON.stringify(body) });
      if (r.ok) { lastHash = hash; log.log(`[backup] копия отправлена в GitHub (${buf.length} байт)`); return true; }
      if (r.status !== 409 && r.status !== 422) throw new Error('github ' + r.status);
    }
    throw new Error('github: конфликт версий');
  }

  // операции идут строго по очереди; ошибка не роняет сервер
  const run = () => (busy = busy.then(backupOnce).catch(e => { log.error('[backup] ошибка:', e.message); return false; }));

  return {
    restoreIfMissing,
    start(database) { db = database; run(); timer = setInterval(run, intervalMin * 60e3); timer.unref(); },
    now: run,
    async stop() { clearInterval(timer); await run(); },
  };
}

function fromEnv(dbPath, env = process.env) {
  if (!env.GH_BACKUP_TOKEN || !env.GH_BACKUP_REPO) return null;
  return create({ token: env.GH_BACKUP_TOKEN, repo: env.GH_BACKUP_REPO, file: env.GH_BACKUP_PATH || 'void.db',
    branch: env.GH_BACKUP_BRANCH || 'main', intervalMin: Math.max(1, +env.GH_BACKUP_INTERVAL_MIN || 10), dbPath });
}

module.exports = { create, fromEnv };
