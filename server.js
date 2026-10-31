// MoonberrySMP Control Panel backend.
// Browsers cannot speak SFTP, so this small server does it and exposes a JSON API.
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const SftpClient = require('ssh2-sftp-client');

const env = process.env;
const sftpCfg = {
  host: env.SFTP_HOST, port: +env.SFTP_PORT || 22, username: env.SFTP_USER,
  ...(env.SFTP_KEY ? { privateKey: fs.readFileSync(env.SFTP_KEY) } : { password: env.SFTP_PASS }),
};
const PATHS = {
  profiles: env.PROFILE_DIR || '/panel/profiles',
  shops: env.CHESTSHOP_FILE || '/plugins/data/chestshops.json',
  warps: env.PLAYERWARPS_FILE || '/plugins/data/playerwarps.json',
};
const BEDROCK_PREFIX = env.BEDROCK_PREFIX || '.';

async function withSftp(fn) {
  const c = new SftpClient();
  try { await c.connect(sftpCfg); return await fn(c); }
  finally { await c.end().catch(() => {}); }
}
const readJson = async (c, p) => JSON.parse((await c.get(p)).toString('utf8'));

// ---- passwords: scrypt, never stored in plain text ----
const hash = (pw) => {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
};
const verify = (pw, stored) => {
  const [s, h] = String(stored || '').split(':');
  if (!s || !h) return false;
  const a = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64), b = Buffer.from(h, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// ---- usernames -> safe profile file names ----
const validName = (n) => typeof n === 'string' && /^\.?[A-Za-z0-9_]{2,16}$/.test(n);
const profilePath = (n) => `${PATHS.profiles}/${n.startsWith('.') ? 'bedrock_' + n.slice(1) : n}.json`.toLowerCase();

// ---- sessions + login throttling (in memory) ----
const sessions = new Map(), attempts = new Map();
const TTL = 8 * 3600e3;
const throttled = (ip) => {
  const now = Date.now(), a = (attempts.get(ip) || []).filter((t) => now - t < 15 * 60e3);
  a.push(now); attempts.set(ip, a); return a.length > 10;
};
const cookie = (req) => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((p) => p.split('=')));
const auth = (req, res, next) => {
  const s = sessions.get(cookie(req).sid);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Not logged in.' });
  req.user = s.user; next();
};
const startSession = (res, user) => {
  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { user, exp: Date.now() + TTL });
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL / 1000}${env.NODE_ENV === 'production' ? '; Secure' : ''}`);
};

const app = express();
app.use(express.json({ limit: '4kb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/login', async (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { username, password, bedrock } = req.body || {};
  const name = bedrock && validName(username) && !username.startsWith('.') ? BEDROCK_PREFIX + username : username;
  const fail = () => res.status(401).json({ error: 'Username or password is incorrect.' });
  if (!validName(name) || typeof password !== 'string') return fail();
  try {
    const profile = await withSftp((c) => readJson(c, profilePath(name)).catch(() => null));
    if (!profile || !verify(password, profile.passwordHash)) return fail();
    startSession(res, name);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(502).json({ error: 'Could not reach the server. Try again shortly.' }); }
});

// First login: an admin creates profiles/<name>.json with "passwordHash": null, the player then sets a password.
app.post('/api/register', async (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const { username, password, bedrock } = req.body || {};
  const name = bedrock && validName(username) && !username.startsWith('.') ? BEDROCK_PREFIX + username : username;
  if (!validName(name) || typeof password !== 'string' || password.length < 8)
    return res.status(400).json({ error: 'Use a valid username and a password of at least 8 characters.' });
  try {
    const ok = await withSftp(async (c) => {
      const p = profilePath(name), profile = await readJson(c, p).catch(() => null);
      if (!profile || profile.passwordHash) return false;
      profile.passwordHash = hash(password);
      await c.put(Buffer.from(JSON.stringify(profile, null, 2)), p);
      return true;
    });
    if (!ok) return res.status(403).json({ error: 'No new panel is waiting for this username. Ask staff to set one up.' });
    startSession(res, name);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(502).json({ error: 'Could not reach the server. Try again shortly.' }); }
});

app.post('/api/logout', (req, res) => {
  sessions.delete(cookie(req).sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const mine = (list) => (Array.isArray(list) ? list : []).filter((x) => String(x.owner || '').toLowerCase() === req.user.toLowerCase()).length;
  try {
    const out = await withSftp(async (c) => ({
      chestshops: mine(await readJson(c, PATHS.shops).catch(() => [])),
      playerwarps: mine(await readJson(c, PATHS.warps).catch(() => [])),
    }));
    res.json({ username: req.user, ...out });
  } catch (e) { console.error(e.message); res.status(502).json({ error: 'Could not load your data.' }); }
});

app.listen(env.PORT || 3000, () => console.log('Panel running on port ' + (env.PORT || 3000)));
