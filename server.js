const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), crypto = require('crypto');
const db = new Database(process.env.DB || 'data.db');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member', disabled INTEGER NOT NULL DEFAULT 0,
  profile TEXT NOT NULL DEFAULT '{}', privacy TEXT NOT NULL DEFAULT '{}', design TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, uid INTEGER NOT NULL, exp INTEGER NOT NULL);`);

const F = ['name', 'age', 'trait', 'motto', 'bio', 'photo', 'hobbies', 'contact', 'social'];
const OPEN = ['name', 'age', 'trait', 'motto', 'bio', 'photo', 'hobbies']; // 联系方式、社交账号默认不公开
const LAYOUTS = ['left', 'right', 'center', 'full'], THEMES = ['aurora', 'sunset', 'forest', 'mono', 'stars', 'ocean'];
const RANK = { member: 0, admin: 1, super: 2 };
const J = s => { try { return JSON.parse(s); } catch { return {}; } };

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static('public'));

const cookie = req => (req.headers.cookie || '').split(';').map(c => c.trim().split('=')).find(c => c[0] === 'sid')?.[1];
function start(res, uid) {
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(t, uid, Date.now() + 30 * 864e5);
  res.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 86400}`);
}
const auth = (req, res, next) => {
  const t = cookie(req);
  const u = t && db.prepare('SELECT u.* FROM sessions s JOIN users u ON u.id=s.uid WHERE s.token=? AND s.exp>?').get(t, Date.now());
  if (!u || u.disabled) return res.status(401).json({ error: '请先登录' });
  req.user = u; next();
};
const need = role => (req, res, next) => RANK[req.user.role] >= RANK[role] ? next() : res.status(403).json({ error: '没有权限' });

const self = u => ({
  id: u.id, username: u.username, role: u.role, profile: J(u.profile),
  privacy: { ...Object.fromEntries(F.map(f => [f, OPEN.includes(f)])), ...J(u.privacy) },
  design: { layout: 'left', theme: 'aurora', ...J(u.design) },
});
// 对其他成员只返回对方设为公开的字段
const pub = u => {
  const s = self(u), p = {};
  for (const f of F) if (s.privacy[f]) p[f] = s.profile[f];
  if (!p.name) p.name = '匿名成员';
  return { id: u.id, profile: p, design: s.design };
};

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!/^[\w\u4e00-\u9fa5]{2,20}$/.test(username || '')) return res.status(400).json({ error: '用户名需 2–20 位字母、数字、下划线或汉字' });
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: '密码至少 8 位' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) return res.status(409).json({ error: '用户名已被使用' });
  const first = !db.prepare('SELECT 1 FROM users').get(); // 第一个注册的人成为超级管理员
  const id = db.prepare('INSERT INTO users(username,hash,role) VALUES(?,?,?)').run(username, bcrypt.hashSync(password, 10), first ? 'super' : 'member').lastInsertRowid;
  start(res, id); res.json({ ok: true });
});
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || ''));
  if (!u || !bcrypt.compareSync(String(password || ''), u.hash)) return res.status(401).json({ error: '用户名或密码错误' });
  if (u.disabled) return res.status(403).json({ error: '账号已被禁用' });
  start(res, u.id); res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token=?').run(cookie(req) || '');
  res.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); res.json({ ok: true });
});
app.get('/api/me', auth, (req, res) => res.json(self(req.user)));
app.put('/api/me', auth, (req, res) => { // 只能改自己的资料
  const b = req.body || {}, cur = self(req.user), p = {}, pr = {};
  for (const f of F) { p[f] = String(b.profile?.[f] ?? '').slice(0, f === 'bio' ? 1000 : 200); pr[f] = !!b.privacy?.[f]; }
  if (p.photo && !/^https?:\/\//i.test(p.photo)) return res.status(400).json({ error: '照片需为 http(s) 图片链接' });
  const d = {
    layout: LAYOUTS.includes(b.design?.layout) ? b.design.layout : cur.design.layout,
    theme: THEMES.includes(b.design?.theme) ? b.design.theme : cur.design.theme,
  };
  db.prepare('UPDATE users SET profile=?,privacy=?,design=? WHERE id=?').run(JSON.stringify(p), JSON.stringify(pr), JSON.stringify(d), req.user.id);
  res.json({ ok: true });
});
app.get('/api/members', auth, (req, res) => res.json(db.prepare('SELECT * FROM users WHERE disabled=0').all().map(pub)));

app.get('/api/admin/users', auth, need('admin'), (req, res) =>
  res.json(db.prepare('SELECT id,username,role,disabled,profile FROM users').all()
    .map(u => ({ id: u.id, username: u.username, role: u.role, disabled: u.disabled, name: J(u.profile).name || '' }))));
app.post('/api/admin/users/:id', auth, need('admin'), (req, res) => {
  const t = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id), me = req.user, a = req.body?.action;
  if (!t) return res.status(404).json({ error: '用户不存在' });
  // 不能操作自己、超级管理员，也不能操作同级或更高级
  if (t.id === me.id || t.role === 'super' || RANK[t.role] >= RANK[me.role]) return res.status(403).json({ error: '不能操作该用户' });
  if ((a === 'promote' || a === 'demote') && me.role !== 'super') return res.status(403).json({ error: '仅超级管理员可设置管理员' });
  const sql = {
    disable: 'UPDATE users SET disabled=1 WHERE id=?', enable: 'UPDATE users SET disabled=0 WHERE id=?',
    reset: "UPDATE users SET profile='{}',privacy='{}',design='{}' WHERE id=?",
    promote: "UPDATE users SET role='admin' WHERE id=?", demote: "UPDATE users SET role='member' WHERE id=?",
  }[a];
  if (a === 'delete') { db.prepare('DELETE FROM sessions WHERE uid=?').run(t.id); db.prepare('DELETE FROM users WHERE id=?').run(t.id); }
  else if (sql) { db.prepare(sql).run(t.id); if (a === 'disable') db.prepare('DELETE FROM sessions WHERE uid=?').run(t.id); }
  else return res.status(400).json({ error: '未知操作' });
  res.json({ ok: true });
});

app.listen(process.env.PORT || 3000, () => console.log('http://localhost:' + (process.env.PORT || 3000)));
