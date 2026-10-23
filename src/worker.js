// Sideline — Worker: sirve el sitio (carpeta public) y la API /api/* con D1.
// Requiere: base D1 enlazada como "DB" (wrangler.jsonc) y secreto "COACH_KEY"
// (clave de administrador: panel /admin y solicitudes del cuestionario).
//
// Cuentas: cada equipo tiene coaches (editan) y jugadores (solo ven).
// Contraseñas con PBKDF2-SHA256; sesión en cookie HttpOnly.

let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch([
    // datos anteriores (una sola sala), se conservan para migrarlos a un equipo
    db.prepare(`CREATE TABLE IF NOT EXISTS plays (video TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (video, id))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS videos (id TEXT PRIMARY KEY, title TEXT, updated_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, data TEXT NOT NULL)`),
    // equipos y cuentas
    db.prepare(`CREATE TABLE IF NOT EXISTS teams (id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, team_id TEXT NOT NULL, username TEXT NOT NULL UNIQUE, name TEXT NOT NULL, role TEXT NOT NULL, pass TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 1, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL)`),
    db.prepare(`CREATE TABLE IF NOT EXISTS login_fail (username TEXT PRIMARY KEY, count INTEGER NOT NULL, until INTEGER NOT NULL)`),
    // datos por equipo
    db.prepare(`CREATE TABLE IF NOT EXISTS tplays (team_id TEXT NOT NULL, video TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, video, id))`),
    db.prepare(`CREATE TABLE IF NOT EXISTS tvideos (team_id TEXT NOT NULL, id TEXT NOT NULL, title TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY (team_id, id))`),
  ]);
  ready = true;
}

const json = (obj, status = 200, headers = {}) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});
const VID = /^[\w-]{11}$/;
const PID = /^[\w-]{1,40}$/;
const USERNAME = /^[a-z0-9._-]{3,32}$/;
const SESSION_DAYS = 30;
const enc = new TextEncoder();

// ---------- helpers ----------
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/../g).map(h => parseInt(h, 16)));
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
function tempPassword() {
  const a = 'abcdefghjkmnpqrstuvwxyz23456789';
  const r = crypto.getRandomValues(new Uint8Array(8));
  const c = [...r].map(x => a[x % a.length]).join('');
  return c.slice(0, 4) + '-' + c.slice(4);
}
async function hashPass(pw, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, key, 256);
  return `pbkdf2$100000$${hex(salt)}$${hex(bits)}`;
}
async function checkPass(pw, stored) {
  const [, , salt, want] = String(stored).split('$');
  if (!salt || !want) return false;
  const got = (await hashPass(pw, salt)).split('$')[3];
  let d = 0; for (let i = 0; i < want.length; i++) d |= want.charCodeAt(i) ^ (got.charCodeAt(i) || 0);
  return d === 0 && got.length === want.length;
}
function isAdmin(request, env) {
  const given = request.headers.get('x-coach-key') || '';
  const secret = env.COACH_KEY || '';
  if (!secret || given.length !== secret.length) return false;
  let diff = 0;
  for (let i = 0; i < secret.length; i++) diff |= secret.charCodeAt(i) ^ given.charCodeAt(i);
  return diff === 0;
}
function cookieToken(request) {
  const m = (request.headers.get('cookie') || '').match(/(?:^|;\s*)sl_session=([a-f0-9]{64})/);
  return m ? m[1] : '';
}
const setCookie = (token, maxAge) => `sl_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const publicUser = u => ({ id: u.id, username: u.username, name: u.name, role: u.role, must_change: !!u.must_change, active: !!u.active });

async function currentUser(request, db) {
  const t = cookieToken(request);
  if (!t) return null;
  const row = await db.prepare(`SELECT u.*, t.name AS team_name, t.active AS team_active FROM sessions s
      JOIN users u ON u.id = s.user_id JOIN teams t ON t.id = u.team_id
      WHERE s.token_hash = ?1 AND s.expires_at > ?2`).bind(await sha256(t), Date.now()).first();
  if (!row || !row.active || !row.team_active) return null;
  return row;
}
const me = u => ({ user: publicUser(u), team: { id: u.team_id, name: u.team_name } });

async function createUser(db, teamId, { name, username, role }) {
  name = str(name, 80); username = str(username, 32).toLowerCase(); role = role === 'coach' ? 'coach' : 'player';
  if (!name) return { error: 'Escribe el nombre.' };
  if (!USERNAME.test(username)) return { error: 'El usuario debe tener de 3 a 32 letras minúsculas, números, punto, guion o guion bajo, sin espacios.' };
  const exists = await db.prepare('SELECT 1 FROM users WHERE username = ?1').bind(username).first();
  if (exists) return { error: `El usuario "${username}" ya existe. Elige otro.` };
  const temp = tempPassword();
  const id = randHex(8);
  await db.prepare('INSERT INTO users (id, team_id, username, name, role, pass, must_change, active, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7)')
    .bind(id, teamId, username, name, role, await hashPass(temp), Date.now()).run();
  return { user: { id, username, name, role, must_change: true, active: true }, temp_password: temp };
}
async function resetUser(db, id, teamId) {
  const temp = tempPassword();
  const q = teamId
    ? db.prepare('UPDATE users SET pass = ?1, must_change = 1 WHERE id = ?2 AND team_id = ?3').bind(await hashPass(temp), id, teamId)
    : db.prepare('UPDATE users SET pass = ?1, must_change = 1 WHERE id = ?2').bind(await hashPass(temp), id);
  const r = await q.run();
  if (!r.meta || !r.meta.changes) return null;
  await db.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(id).run();
  return temp;
}

async function handleApi(request, env, path) {
  const url = new URL(request.url);
  const method = request.method;

  if (path === 'health') return json({ ok: true, db: !!env.DB, key: !!env.COACH_KEY, accounts: true });
  if (!env.DB) return json({ error: 'no_db' }, 503);

  try {
    await init(env.DB);
    const db = env.DB;
    const body = async () => { try { return await request.json(); } catch (e) { return {}; } };

    // ---------- sesión ----------
    if (path === 'login' && method === 'POST') {
      const b = await body();
      const username = str(b.username, 32).toLowerCase(), password = String(b.password || '');
      const now = Date.now();
      const fail = await db.prepare('SELECT count, until FROM login_fail WHERE username = ?1').bind(username).first();
      if (fail && fail.until > now) return json({ error: 'locked', message: 'Demasiados intentos. Espera 15 minutos o pide a tu coach que restablezca tu contraseña.' }, 429);
      const u = await db.prepare(`SELECT u.*, t.name AS team_name, t.active AS team_active FROM users u JOIN teams t ON t.id = u.team_id WHERE u.username = ?1`).bind(username).first();
      const ok = u && u.active && u.team_active && await checkPass(password, u.pass);
      if (!ok) {
        const count = (fail && fail.until <= now && fail.count >= 5 ? 0 : (fail ? fail.count : 0)) + 1;
        const until = count >= 5 ? now + 15 * 60000 : 0;
        await db.prepare('INSERT INTO login_fail (username, count, until) VALUES (?1, ?2, ?3) ON CONFLICT(username) DO UPDATE SET count = excluded.count, until = excluded.until').bind(username, count, until).run();
        return json({ error: 'bad_login', message: 'Usuario o contraseña incorrectos.' }, 401);
      }
      await db.prepare('DELETE FROM login_fail WHERE username = ?1').bind(username).run();
      const token = randHex(32);
      await db.batch([
        db.prepare('DELETE FROM sessions WHERE expires_at < ?1').bind(now),
        db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)').bind(await sha256(token), u.id, now + SESSION_DAYS * 864e5),
      ]);
      return json(me(u), 200, { 'set-cookie': setCookie(token, SESSION_DAYS * 86400) });
    }
    if (path === 'logout' && method === 'POST') {
      const t = cookieToken(request);
      if (t) await db.prepare('DELETE FROM sessions WHERE token_hash = ?1').bind(await sha256(t)).run();
      return json({ ok: true }, 200, { 'set-cookie': setCookie('', 0) });
    }

    // ---------- administrador (clave COACH_KEY) ----------
    if (path === 'check') return isAdmin(request, env) ? json({ ok: true }) : json({ error: 'bad_key' }, 401);
    if (path.startsWith('admin/')) {
      if (!isAdmin(request, env)) return json({ error: 'bad_key' }, 401);
      const sub = path.slice(6);
      if (sub === 'teams' && method === 'GET') {
        const r = await db.prepare(`SELECT t.id, t.name, t.active, t.created_at,
            (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'coach') AS coaches,
            (SELECT COUNT(*) FROM users u WHERE u.team_id = t.id AND u.role = 'player') AS players,
            (SELECT COUNT(*) FROM tvideos v WHERE v.team_id = t.id) AS games
          FROM teams t ORDER BY t.created_at DESC`).all();
        const legacy = await db.prepare('SELECT COUNT(*) AS n FROM plays').first();
        return json({ teams: r.results || [], legacy_plays: legacy ? legacy.n : 0 });
      }
      if (sub === 'teams' && method === 'POST') {
        const b = await body();
        const name = str(b.name, 80);
        if (!name) return json({ error: 'bad_request', message: 'Escribe el nombre del equipo.' }, 400);
        const id = randHex(6);
        await db.prepare('INSERT INTO teams (id, name, active, created_at) VALUES (?1, ?2, 1, ?3)').bind(id, name, Date.now()).run();
        const c = await createUser(db, id, { name: b.coach_name, username: b.coach_username, role: 'coach' });
        if (c.error) { await db.prepare('DELETE FROM teams WHERE id = ?1').bind(id).run(); return json({ error: 'bad_request', message: c.error }, 400); }
        return json({ team: { id, name }, ...c });
      }
      if (sub === 'teams/active' && method === 'POST') {
        const b = await body();
        await db.prepare('UPDATE teams SET active = ?1 WHERE id = ?2').bind(b.active ? 1 : 0, str(b.id, 20)).run();
        return json({ ok: true });
      }
      if (sub === 'users' && method === 'GET') {
        const r = await db.prepare('SELECT * FROM users WHERE team_id = ?1 ORDER BY role, name').bind(str(url.searchParams.get('team'), 20)).all();
        return json({ users: (r.results || []).map(publicUser) });
      }
      if (sub === 'users' && method === 'POST') {
        const b = await body();
        const team = await db.prepare('SELECT id FROM teams WHERE id = ?1').bind(str(b.team, 20)).first();
        if (!team) return json({ error: 'bad_request', message: 'Ese equipo no existe.' }, 400);
        const c = await createUser(db, team.id, b);
        return c.error ? json({ error: 'bad_request', message: c.error }, 400) : json(c);
      }
      if (sub === 'users/reset' && method === 'POST') {
        const b = await body();
        const temp = await resetUser(db, str(b.id, 20));
        return temp ? json({ temp_password: temp }) : json({ error: 'not_found' }, 404);
      }
      if (sub === 'migrate' && method === 'POST') {
        const b = await body();
        const team = await db.prepare('SELECT id FROM teams WHERE id = ?1').bind(str(b.team, 20)).first();
        if (!team) return json({ error: 'bad_request', message: 'Ese equipo no existe.' }, 400);
        await db.batch([
          db.prepare('INSERT OR IGNORE INTO tplays (team_id, video, id, data, updated_at) SELECT ?1, video, id, data, updated_at FROM plays').bind(team.id),
          db.prepare('INSERT OR IGNORE INTO tvideos (team_id, id, title, updated_at) SELECT ?1, id, title, updated_at FROM videos').bind(team.id),
        ]);
        const n = await db.prepare('SELECT COUNT(*) AS n FROM tplays WHERE team_id = ?1').bind(team.id).first();
        return json({ ok: true, plays: n ? n.n : 0 });
      }
      return json({ error: 'not_found' }, 404);
    }

    // ---------- cuestionario de contacto ----------
    if (path === 'leads') {
      if (method === 'POST') {
        const raw = await request.text();
        if (raw.length > 12000) return json({ error: 'too_large' }, 413);
        let b; try { b = JSON.parse(raw); } catch (e) { return json({ error: 'bad_request' }, 400); }
        if (b.sitio) return json({ ok: true }); // campo trampa para bots
        const list = (v, n) => (Array.isArray(v) ? v : []).slice(0, 10).map(x => str(x, n));
        const lead = {
          rol: str(b.rol, 60), categoria: list(b.categoria, 40), equipos: str(b.equipos, 10),
          grabacion: str(b.grabacion, 60), herramienta: str(b.herramienta, 60), prioridad: list(b.prioridad, 60),
          presupuesto: str(b.presupuesto, 40), nombre: str(b.nombre, 120), equipo: str(b.equipo, 120),
          ciudad: str(b.ciudad, 80), whatsapp: str(b.whatsapp, 30), correo: str(b.correo, 160),
          mensaje: str(b.mensaje, 1500), plan: str(b.plan, 40),
        };
        if (!lead.nombre || (!lead.whatsapp && !lead.correo)) return json({ error: 'missing_contact' }, 400);
        await db.prepare('INSERT INTO leads (created_at, data) VALUES (?1, ?2)').bind(Date.now(), JSON.stringify(lead)).run();
        return json({ ok: true });
      }
      if (method === 'GET') {
        if (!isAdmin(request, env)) return json({ error: 'bad_key' }, 401);
        const r = await db.prepare('SELECT id, created_at, data FROM leads ORDER BY created_at DESC LIMIT 500').all();
        const leads = (r.results || []).map(row => { try { return { id: row.id, created_at: row.created_at, ...JSON.parse(row.data) }; } catch (e) { return null; } }).filter(Boolean);
        return json({ leads });
      }
    }

    // ---------- todo lo demás requiere sesión ----------
    const u = await currentUser(request, db);
    if (!u) return json({ error: 'no_session' }, 401);
    const coach = u.role === 'coach';
    const team = u.team_id;

    if (path === 'me' && method === 'GET') return json(me(u));

    if (path === 'password' && method === 'POST') {
      const b = await body();
      const next = String(b.new || '');
      if (!(await checkPass(String(b.current || ''), u.pass))) return json({ error: 'bad_password', message: 'La contraseña actual no es correcta.' }, 400);
      if (next.length < 8) return json({ error: 'weak', message: 'La nueva contraseña debe tener al menos 8 caracteres.' }, 400);
      await db.prepare('UPDATE users SET pass = ?1, must_change = 0 WHERE id = ?2').bind(await hashPass(next), u.id).run();
      return json({ ok: true });
    }

    // usuarios del equipo (coaches)
    if (path.startsWith('team/users')) {
      if (!coach) return json({ error: 'forbidden', message: 'Solo los coaches administran el equipo.' }, 403);
      if (path === 'team/users' && method === 'GET') {
        const r = await db.prepare('SELECT * FROM users WHERE team_id = ?1 ORDER BY role, name').bind(team).all();
        return json({ users: (r.results || []).map(publicUser) });
      }
      if (path === 'team/users' && method === 'POST') {
        const c = await createUser(db, team, await body());
        return c.error ? json({ error: 'bad_request', message: c.error }, 400) : json(c);
      }
      if (path === 'team/users/reset' && method === 'POST') {
        const b = await body();
        if (str(b.id, 20) === u.id) return json({ error: 'bad_request', message: 'Para tu propia contraseña usa «Cambiar contraseña».' }, 400);
        const temp = await resetUser(db, str(b.id, 20), team);
        return temp ? json({ temp_password: temp }) : json({ error: 'not_found' }, 404);
      }
      if (path === 'team/users' && method === 'DELETE') {
        const id = str(url.searchParams.get('id'), 20);
        if (id === u.id) return json({ error: 'bad_request', message: 'No puedes darte de baja a ti mismo.' }, 400);
        await db.batch([
          db.prepare('DELETE FROM sessions WHERE user_id = ?1').bind(id),
          db.prepare('DELETE FROM users WHERE id = ?1 AND team_id = ?2').bind(id, team),
        ]);
        return json({ ok: true });
      }
    }

    if (path === 'videos') {
      if (method === 'GET') {
        const r = await db.prepare('SELECT id, title, updated_at FROM tvideos WHERE team_id = ?1 ORDER BY updated_at DESC LIMIT 200').bind(team).all();
        return json({ videos: r.results || [] });
      }
      if (method === 'POST') {
        if (!coach) return json({ error: 'forbidden' }, 403);
        const b = await body();
        if (!VID.test(b.id || '')) return json({ error: 'bad_video' }, 400);
        await db.prepare(`INSERT INTO tvideos (team_id, id, title, updated_at) VALUES (?1, ?2, ?3, ?4)
          ON CONFLICT(team_id, id) DO UPDATE SET title = excluded.title, updated_at = excluded.updated_at`)
          .bind(team, b.id, str(b.title || b.id, 200), Date.now()).run();
        return json({ ok: true });
      }
    }

    if (path === 'plays') {
      if (method === 'GET') {
        const v = url.searchParams.get('v') || '';
        if (!VID.test(v)) return json({ error: 'bad_video' }, 400);
        const r = await db.prepare('SELECT id, data FROM tplays WHERE team_id = ?1 AND video = ?2').bind(team, v).all();
        const plays = (r.results || []).map(row => { try { return { ...JSON.parse(row.data), id: row.id }; } catch (e) { return null; } }).filter(Boolean);
        return json({ plays });
      }
      if (!coach) return json({ error: 'forbidden' }, 403);
      if (method === 'POST') {
        const b = await body();
        if (!VID.test(b.video || '') || !PID.test(b.id || '')) return json({ error: 'bad_request' }, 400);
        const data = JSON.stringify(b.data || {});
        if (data.length > 500000) return json({ error: 'too_large' }, 413);
        const now = Date.now();
        await db.batch([
          db.prepare(`INSERT INTO tplays (team_id, video, id, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(team_id, video, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`).bind(team, b.video, b.id, data, now),
          db.prepare(`INSERT INTO tvideos (team_id, id, title, updated_at) VALUES (?1, ?2, ?2, ?3)
            ON CONFLICT(team_id, id) DO UPDATE SET updated_at = excluded.updated_at`).bind(team, b.video, now),
        ]);
        return json({ ok: true });
      }
      if (method === 'DELETE') {
        const v = url.searchParams.get('v') || '', id = url.searchParams.get('id') || '';
        if (!VID.test(v) || !PID.test(id)) return json({ error: 'bad_request' }, 400);
        await db.prepare('DELETE FROM tplays WHERE team_id = ?1 AND video = ?2 AND id = ?3').bind(team, v, id).run();
        return json({ ok: true });
      }
    }

    return json({ error: 'not_found' }, 404);
  } catch (e) {
    return json({ error: 'server_error', message: String(e && e.message || e) }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return handleApi(request, env, url.pathname.slice(5).replace(/\/+$/, ''));
    }
    return env.ASSETS.fetch(request);
  },
};
