// HR System Backend - Sout Network
// Node.js + Express + sql.js (Pure JS, no native build)

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'soutnetwork-hr-secret-2026-change-me';
const DB_PATH = path.join(__dirname, 'hr.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db, SQL;
function run(sql, params = []) { db.run(sql, params); saveDb(); }
function get(sql, params = []) { const s = db.prepare(sql); s.bind(params); const r = s.step() ? s.getAsObject() : null; s.free(); return r; }
function all(sql, params = []) { const s = db.prepare(sql); s.bind(params); const out = []; while (s.step()) out.push(s.getAsObject()); s.free(); return out; }
function runReturn(sql, params = []) { db.run(sql, params); const id = db.exec("SELECT last_insert_rowid() AS id")[0].values[0][0]; saveDb(); return { lastInsertRowid: id }; }
function saveDb() { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); }

async function initDb() {
  SQL = await initSqlJs();
  db = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'employee',
      job_title TEXT, daily_hours INTEGER DEFAULT 8,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      clock_in DATETIME NOT NULL, clock_out DATETIME, status TEXT DEFAULT 'online'
    );
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      title TEXT NOT NULL, description TEXT, status TEXT DEFAULT 'pending',
      assigned_date DATE DEFAULT CURRENT_DATE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      started_at DATETIME, completed_at DATETIME, time_spent_seconds INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS team_tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT,
      status TEXT DEFAULT 'todo', assignee_id INTEGER, priority TEXT DEFAULT 'normal',
      created_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      message TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
  // migrations for older DBs
  try { db.run(`ALTER TABLE users ADD COLUMN daily_hours INTEGER DEFAULT 8`); } catch(e){}
  try { db.run(`ALTER TABLE tasks ADD COLUMN started_at DATETIME`); } catch(e){}
  try { db.run(`ALTER TABLE tasks ADD COLUMN time_spent_seconds INTEGER DEFAULT 0`); } catch(e){}

  if (!get('SELECT id FROM users WHERE username = ?', ['admin'])) {
    const hash = bcrypt.hashSync('admin123', 10);
    run(`INSERT INTO users (username, password_hash, full_name, role, job_title) VALUES (?,?,?,?,?)`,
      ['admin', hash, 'System Administrator', 'admin', 'Administrator']);
    console.log('Admin created: admin / admin123');
  }
  saveDb();
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Invalid token' }); }
}
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ===== AUTH =====
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = get('SELECT * FROM users WHERE username = ?', [username]);
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, full_name: user.full_name, daily_hours: user.daily_hours }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role, job_title: user.job_title, daily_hours: user.daily_hours } });
});

// ===== CHANGE PASSWORD (any logged-in user) =====
app.post('/api/change-password', authenticate, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'All fields required' });
  if (new_password.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  const user = get('SELECT * FROM users WHERE id=?', [req.user.id]);
  if (!user || !bcrypt.compareSync(current_password, user.password_hash))
    return res.status(401).json({ error: 'Current password is incorrect' });
  const hash = bcrypt.hashSync(new_password, 10);
  run('UPDATE users SET password_hash=? WHERE id=?', [hash, req.user.id]);
  res.json({ success: true });
});

// ===== ATTENDANCE (flexible, no fixed shift) =====
app.post('/api/clock-in', authenticate, (req, res) => {
  if (get(`SELECT id FROM attendance WHERE user_id=? AND clock_out IS NULL`, [req.user.id]))
    return res.status(400).json({ error: 'Already clocked in' });
  const r = runReturn(`INSERT INTO attendance (user_id, clock_in, status) VALUES (?, datetime('now'), 'online')`, [req.user.id]);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.post('/api/clock-out', authenticate, (req, res) => {
  const open = get(`SELECT id FROM attendance WHERE user_id=? AND clock_out IS NULL`, [req.user.id]);
  if (!open) return res.status(400).json({ error: 'No active session' });
  run(`UPDATE attendance SET clock_out=datetime('now'), status='offline' WHERE id=?`, [open.id]);
  res.json({ success: true });
});
app.get('/api/my-status', authenticate, (req, res) => {
  const s = get(`SELECT * FROM attendance WHERE user_id=? AND clock_out IS NULL`, [req.user.id]);
  const u = get(`SELECT daily_hours FROM users WHERE id=?`, [req.user.id]);
  res.json({ online: !!s, status: s?.status || 'offline', clock_in: s?.clock_in || null, daily_hours: u?.daily_hours || 8 });
});
app.get('/api/my-attendance', authenticate, (req, res) => {
  res.json(all(`SELECT id, clock_in, clock_out, CASE WHEN clock_out IS NOT NULL THEN ROUND((julianday(clock_out)-julianday(clock_in))*24,2) ELSE NULL END AS hours_worked FROM attendance WHERE user_id=? ORDER BY clock_in DESC LIMIT 30`, [req.user.id]));
});

// ===== PERSONAL TASKS (with time tracking) =====
app.get('/api/my-tasks', authenticate, (req, res) => {
  res.json(all(`SELECT * FROM tasks WHERE user_id=? AND assigned_date=date('now') ORDER BY CASE status WHEN 'in_progress' THEN 1 WHEN 'pending' THEN 2 WHEN 'done' THEN 3 END, created_at`, [req.user.id]));
});
app.patch('/api/tasks/:id', authenticate, (req, res) => {
  const { status } = req.body;
  const task = get('SELECT * FROM tasks WHERE id=?', [req.params.id]);
  if (!task) return res.status(404).json({ error: 'Not found' });
  if (task.user_id !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not your task' });
  if (status === 'in_progress') {
    run(`UPDATE tasks SET status=?, started_at=datetime('now') WHERE id=?`, [status, req.params.id]);
  } else if (status === 'done') {
    let extra = 0;
    if (task.started_at) {
      const sec = get(`SELECT CAST((julianday('now')-julianday(?))*86400 AS INTEGER) AS s`, [task.started_at]);
      extra = sec?.s || 0;
    }
    run(`UPDATE tasks SET status='done', completed_at=datetime('now'), time_spent_seconds=time_spent_seconds+? WHERE id=?`, [extra, req.params.id]);
  } else {
    run(`UPDATE tasks SET status=? WHERE id=?`, [status, req.params.id]);
  }
  res.json({ success: true });
});

// ===== TEAM TASKS (Jira-like board) =====
app.get('/api/team-tasks', authenticate, (req, res) => {
  res.json(all(`SELECT tt.*, u.full_name AS assignee_name FROM team_tasks tt LEFT JOIN users u ON tt.assignee_id=u.id ORDER BY tt.created_at DESC LIMIT 200`));
});
app.post('/api/team-tasks', authenticate, (req, res) => {
  const { title, description, assignee_id, priority } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const r = runReturn(`INSERT INTO team_tasks (title, description, assignee_id, priority, created_by) VALUES (?,?,?,?,?)`,
    [title, description || '', assignee_id || null, priority || 'normal', req.user.id]);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.patch('/api/team-tasks/:id', authenticate, (req, res) => {
  const { status } = req.body;
  if (status === 'done') run(`UPDATE team_tasks SET status=?, completed_at=datetime('now') WHERE id=?`, [status, req.params.id]);
  else run(`UPDATE team_tasks SET status=? WHERE id=?`, [status, req.params.id]);
  res.json({ success: true });
});
app.delete('/api/team-tasks/:id', authenticate, (req, res) => {
  run(`DELETE FROM team_tasks WHERE id=?`, [req.params.id]);
  res.json({ success: true });
});

// ===== TEAM CHAT =====
app.get('/api/chat', authenticate, (req, res) => {
  res.json(all(`SELECT c.id, c.message, c.created_at, u.full_name FROM chat_messages c JOIN users u ON c.user_id=u.id ORDER BY c.id DESC LIMIT 100`).reverse());
});
app.post('/api/chat', authenticate, (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Empty message' });
  runReturn(`INSERT INTO chat_messages (user_id, message) VALUES (?,?)`, [req.user.id, message.trim()]);
  res.json({ success: true });
});

// ===== ADMIN =====
app.get('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
  res.json(all(`SELECT u.id, u.username, u.full_name, u.job_title, u.daily_hours, a.status, a.clock_in,
    CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END AS is_online,
    (SELECT COUNT(*) FROM tasks WHERE user_id=u.id AND status='done' AND assigned_date=date('now')) AS tasks_done_today
    FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.clock_out IS NULL
    WHERE u.role='employee' ORDER BY is_online DESC, u.full_name`));
});
app.post('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
  const { username, password, full_name, job_title, daily_hours } = req.body;
  if (!username || !password || !full_name) return res.status(400).json({ error: 'Missing data' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = runReturn(`INSERT INTO users (username, password_hash, full_name, job_title, daily_hours, role) VALUES (?,?,?,?,?,'employee')`,
      [username, hash, full_name, job_title || '', daily_hours || 8]);
    res.json({ success: true, id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: 'Username already exists' }); }
});
app.delete('/api/admin/employees/:id', authenticate, requireAdmin, (req, res) => {
  run('DELETE FROM attendance WHERE user_id=?', [req.params.id]);
  run('DELETE FROM tasks WHERE user_id=?', [req.params.id]);
  run('DELETE FROM users WHERE id=? AND role!=?', [req.params.id, 'admin']);
  res.json({ success: true });
});
app.post('/api/admin/tasks', authenticate, requireAdmin, (req, res) => {
  const { user_id, title, description } = req.body;
  if (!user_id || !title) return res.status(400).json({ error: 'Missing data' });
  const r = runReturn(`INSERT INTO tasks (user_id, title, description) VALUES (?,?,?)`, [user_id, title, description || '']);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.delete('/api/admin/tasks/:id', authenticate, requireAdmin, (req, res) => {
  run('DELETE FROM tasks WHERE id=?', [req.params.id]); res.json({ success: true });
});
app.get('/api/admin/attendance/:userId', authenticate, requireAdmin, (req, res) => {
  res.json(all(`SELECT id, clock_in, clock_out, CASE WHEN clock_out IS NOT NULL THEN ROUND((julianday(clock_out)-julianday(clock_in))*24,2) ELSE NULL END AS hours_worked FROM attendance WHERE user_id=? ORDER BY clock_in DESC LIMIT 60`, [req.params.userId]));
});
app.get('/api/admin/tasks/:userId', authenticate, requireAdmin, (req, res) => {
  res.json(all(`SELECT * FROM tasks WHERE user_id=? ORDER BY assigned_date DESC, created_at DESC LIMIT 100`, [req.params.userId]));
});

initDb().then(() => app.listen(PORT, () => console.log(`HR System on port ${PORT}`)));
