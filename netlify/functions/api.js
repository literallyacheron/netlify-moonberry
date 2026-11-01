// Netlify Function version of the panel backend (stateless: sessions are signed cookies).
const crypto = require('crypto');
const SftpClient = require('ssh2-sftp-client');

const env = process.env;
const sftpCfg = {
  host: env.SFTP_HOST, port: +env.SFTP_PORT || 22, username: env.SFTP_USER,
  ...(env.SFTP_KEY_B64 ? { privateKey: Buffer.from(env.SFTP_KEY_B64, 'base64') } : { password: env.SFTP_PASS }),
  readyTimeout: 8000,
};
const PATHS = {
  profiles: env.PROFILE_DIR || '/plugins/webpanel/profiles',
  shops: env.CHESTSHOP_FILE || '/plugins/data/chestshops.json',
  warps: env.PLAYERWARPS_FILE || '/plugins/data/playerwarps.json',
};
const BEDROCK_PREFIX = env.BEDROCK_PREFIX || '_';
const SECRET = env.SESSION_SECRET;
const TTL = 8 * 3600;

async function withSftp(fn) {
  const c = new SftpClient();
  try { await c.connect(sftpCfg); return await fn(c); }
  finally { await c.end().catch(() => {}); }
}
const readJson = async (c, p) => JSON.parse((await c.get(p)).toString('utf8'));

const hash = (pw) => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(pw, s, 64).toString('hex'); };
const verify = (pw, stored) => {
  const [s, h] = String(stored || '').split(':');
  if (!s || !h) return false;
  const a = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const validName = (n) => typeof n === 'string' && /^[A-Za-z0-9_]{2,16}$/.test(n);
const profilePath = (n) => `${PATHS.profiles}/${n}.json`.toLowerCase();
const resolveName = ({ username, bedrock }) => {
  if (typeof username !== 'string') return username;
  const u = username.trim();
  if (!bedrock || u.startsWith(BEDROCK_PREFIX)) return u;
  return (BEDROCK_PREFIX + u.replace(/ /g, '_')).slice(0, 16); // Floodgate truncates to 16
};

// ---- signed-cookie sessions ----
const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');
const makeToken = (u) => { const d = Buffer.from(JSON.stringify({ u, exp: Date.now() + TTL * 1000 })).toString('base64url'); return d + '.' + sign(d); };
const readToken = (event) => {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(event.headers.cookie || '');
  if (!m) return null;
  const [d, sig] = m[1].split('.');
  if (!d || !sig || !crypto.timingSafeEqual(Buffer.from(sign(d)), Buffer.from(sig.padEnd(43, '=').slice(0, 43)))) return null;
  try { const p = JSON.parse(Buffer.from(d, 'base64url')); return p.exp > Date.now() ? p.u : null; } catch { return null; }
};
const cookieHeader = (v, age) => `sid=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;

// best-effort throttle (per warm instance only)
const attempts = new Map();
const throttled = (ip) => {
  const now = Date.now(), a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60e3);
  a.push(now); attempts.set(ip, a); return a.length > 10;
};

const reply = (code, obj, headers = {}) => ({ statusCode: code, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }, body: JSON.stringify(obj) });

exports.handler = async (event) => {
  if (!SECRET || SECRET.length < 32) return reply(500, { error: 'Server is not configured.' });
  const route = event.path.split('/').pop();
  const ip = event.headers['x-nf-client-connection-ip'] || String(event.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
  let body = {};
  try { body = event.body ? JSON.parse(event.body) : {}; } catch { return reply(400, { error: 'Bad request.' }); }
  const down = (e) => { console.error(e.message); return reply(502, { error: 'Could not reach the server. Try again shortly.' }); };

  if (route === 'login' && event.httpMethod === 'POST') {
    if (throttled(ip)) return reply(429, { error: 'Too many attempts. Try again in 15 minutes.' });
    const name = resolveName(body), fail = () => reply(401, { error: 'Username or password is incorrect.' });
    if (!validName(name) || typeof body.password !== 'string') return fail();
    try {
      const profile = await withSftp((c) => readJson(c, profilePath(name)).catch(() => null));
      if (!profile || !verify(body.password, profile.passwordHash)) return fail();
      return reply(200, { ok: true }, { 'Set-Cookie': cookieHeader(makeToken(name), TTL) });
    } catch (e) { return down(e); }
  }

  if (route === 'register' && event.httpMethod === 'POST') {
    if (throttled(ip)) return reply(429, { error: 'Too many attempts. Try again in 15 minutes.' });
    const name = resolveName(body);
    if (!validName(name) || typeof body.password !== 'string' || body.password.length < 8)
      return reply(400, { error: 'Use a valid username and a password of at least 8 characters.' });
    try {
      const ok = await withSftp(async (c) => {
        const p = profilePath(name), profile = await readJson(c, p).catch(() => null);
        if (!profile || profile.passwordHash) return false;
        profile.passwordHash = hash(body.password);
        await c.put(Buffer.from(JSON.stringify(profile, null, 2)), p);
        return true;
      });
      if (!ok) return reply(403, { error: 'No new panel is waiting for this username. Ask staff to set one up.' });
      return reply(200, { ok: true }, { 'Set-Cookie': cookieHeader(makeToken(name), TTL) });
    } catch (e) { return down(e); }
  }

  if (route === 'logout') return reply(200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });

  if (route === 'me' && event.httpMethod === 'GET') {
    const user = readToken(event);
    if (!user) return reply(401, { error: 'Not logged in.' });
    const mine = (l) => (Array.isArray(l) ? l : []).filter((x) => String(x.owner || '').toLowerCase() === user.toLowerCase()).length;
    try {
      const out = await withSftp(async (c) => ({
        chestshops: mine(await readJson(c, PATHS.shops).catch(() => [])),
        playerwarps: mine(await readJson(c, PATHS.warps).catch(() => [])),
      }));
      return reply(200, { username: user, ...out });
    } catch (e) { return down(e); }
  }

  return reply(404, { error: 'Not found.' });
};
