// Sala de Video — API de base de datos (Cloudflare Pages Functions + D1)
// Requiere en Cloudflare: enlace D1 llamado "DB" y variable secreta "COACH_KEY".

let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS plays (
      video TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
      updated_at INTEGER NOT NULL, PRIMARY KEY (video, id))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS videos (
      id TEXT PRIMARY KEY, title TEXT, updated_at INTEGER NOT NULL)`),
  ]);
  ready = true;
}

const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
const VID = /^[\w-]{11}$/;
const PID = /^[\w-]{1,40}$/;

function isCoach(request, env) {
  const given = request.headers.get('x-coach-key') || '';
  const secret = env.COACH_KEY || '';
  if (!secret || given.length !== secret.length) return false;
  let diff = 0;
  for (let i = 0; i < secret.length; i++) diff |= secret.charCodeAt(i) ^ given.charCodeAt(i);
  return diff === 0;
}

export async function onRequest({ request, env, params }) {
  const path = [].concat(params.path || []).join('/');
  const url = new URL(request.url);
  const method = request.method;

  if (path === 'health') return json({ ok: true, db: !!env.DB, key: !!env.COACH_KEY });
  if (!env.DB) return json({ error: 'no_db' }, 503);

  try {
    await init(env.DB);
    const db = env.DB;

    if (path === 'check') {
      return isCoach(request, env) ? json({ ok: true }) : json({ error: 'bad_key' }, 401);
    }

    if (path === 'videos') {
      if (method === 'GET') {
        const r = await db.prepare('SELECT id, title, updated_at FROM videos ORDER BY updated_at DESC LIMIT 200').all();
        return json({ videos: r.results || [] });
      }
      if (method === 'POST') {
        if (!isCoach(request, env)) return json({ error: 'bad_key' }, 401);
        const b = await request.json();
        if (!VID.test(b.id || '')) return json({ error: 'bad_video' }, 400);
        await db.prepare(`INSERT INTO videos (id, title, updated_at) VALUES (?1, ?2, ?3)
          ON CONFLICT(id) DO UPDATE SET title = excluded.title, updated_at = excluded.updated_at`)
          .bind(b.id, String(b.title || b.id).slice(0, 200), Date.now()).run();
        return json({ ok: true });
      }
    }

    if (path === 'plays') {
      if (method === 'GET') {
        const v = url.searchParams.get('v') || '';
        if (!VID.test(v)) return json({ error: 'bad_video' }, 400);
        const r = await db.prepare('SELECT id, data FROM plays WHERE video = ?1').bind(v).all();
        const plays = (r.results || []).map(row => {
          try { return { ...JSON.parse(row.data), id: row.id }; } catch (e) { return null; }
        }).filter(Boolean);
        return json({ plays });
      }
      if (method === 'POST') {
        if (!isCoach(request, env)) return json({ error: 'bad_key' }, 401);
        const b = await request.json();
        if (!VID.test(b.video || '') || !PID.test(b.id || '')) return json({ error: 'bad_request' }, 400);
        const data = JSON.stringify(b.data || {});
        if (data.length > 500000) return json({ error: 'too_large' }, 413);
        const now = Date.now();
        await db.batch([
          db.prepare(`INSERT INTO plays (video, id, data, updated_at) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(video, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
            .bind(b.video, b.id, data, now),
          db.prepare(`INSERT INTO videos (id, title, updated_at) VALUES (?1, ?1, ?2)
            ON CONFLICT(id) DO UPDATE SET updated_at = excluded.updated_at`).bind(b.video, now),
        ]);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        if (!isCoach(request, env)) return json({ error: 'bad_key' }, 401);
        const v = url.searchParams.get('v') || '', id = url.searchParams.get('id') || '';
        if (!VID.test(v) || !PID.test(id)) return json({ error: 'bad_request' }, 400);
        await db.prepare('DELETE FROM plays WHERE video = ?1 AND id = ?2').bind(v, id).run();
        return json({ ok: true });
      }
    }

    return json({ error: 'not_found' }, 404);
  } catch (e) {
    return json({ error: 'server_error', message: String(e && e.message || e) }, 500);
  }
}
