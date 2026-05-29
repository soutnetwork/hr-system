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
      team TEXT DEFAULT '', is_lead INTEGER DEFAULT 0,
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
      team TEXT DEFAULT '', created_by INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME
    );
    CREATE TABLE IF NOT EXISTS task_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT, team_task_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL, comment TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS schedule (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      day DATE NOT NULL, shift TEXT DEFAULT '', note TEXT DEFAULT '',
      UNIQUE(user_id, day)
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY, value TEXT
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
      message TEXT NOT NULL, room_id INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS chat_rooms (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      team TEXT DEFAULT '', is_company INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS chat_mutes (
      room_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
      PRIMARY KEY (room_id, user_id)
    );
  `);
  // migrations for older DBs
  try { db.run(`ALTER TABLE users ADD COLUMN daily_hours INTEGER DEFAULT 8`); } catch(e){}
  try { db.run(`ALTER TABLE tasks ADD COLUMN started_at DATETIME`); } catch(e){}
  try { db.run(`ALTER TABLE tasks ADD COLUMN time_spent_seconds INTEGER DEFAULT 0`); } catch(e){}
  try { db.run(`ALTER TABLE users ADD COLUMN team TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE users ADD COLUMN is_lead INTEGER DEFAULT 0`); } catch(e){}
  try { db.run(`ALTER TABLE team_tasks ADD COLUMN team TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE chat_messages ADD COLUMN room_id INTEGER DEFAULT 0`); } catch(e){}

  // ensure a default Company room exists (id=1)
  if (!get(`SELECT id FROM chat_rooms WHERE is_company=1`)) {
    run(`INSERT INTO chat_rooms (name, team, is_company) VALUES ('Company', '', 1)`);
    // migrate any pre-existing messages (room_id=0) into the company room
    const company = get(`SELECT id FROM chat_rooms WHERE is_company=1`);
    if (company) run(`UPDATE chat_messages SET room_id=? WHERE room_id=0 OR room_id IS NULL`, [company.id]);
  }

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
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role, full_name: user.full_name, daily_hours: user.daily_hours, team: user.team, is_lead: user.is_lead }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role, job_title: user.job_title, daily_hours: user.daily_hours, team: user.team, is_lead: user.is_lead } });
});

// ===== PROFILE (any user — view/edit own profile, including avatar) =====
app.get('/api/profile', authenticate, (req, res) => {
  const u = get('SELECT id, username, full_name, role, job_title, team, is_lead, daily_hours, avatar FROM users WHERE id=?', [req.user.id]);
  res.json(u || {});
});
app.put('/api/profile', authenticate, (req, res) => {
  const { avatar, full_name } = req.body;
  if (avatar !== undefined) {
    if (avatar && avatar.length > 200000) return res.status(400).json({ error: 'Image too large (max ~150KB after encoding). Please use a smaller image.' });
    run('UPDATE users SET avatar=? WHERE id=?', [avatar || '', req.user.id]);
  }
  if (full_name !== undefined && full_name.trim()) {
    run('UPDATE users SET full_name=? WHERE id=?', [full_name.trim(), req.user.id]);
  }
  res.json({ success: true });
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

// ===== TEAM TASKS (Jira-like board, filtered by team) =====
// Admin sees all. Employee sees only tasks for their team (or unassigned-team tasks).
app.get('/api/team-tasks', authenticate, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = all(`SELECT tt.*, u.full_name AS assignee_name,
      (SELECT COUNT(*) FROM task_comments WHERE team_task_id=tt.id) AS comment_count
      FROM team_tasks tt LEFT JOIN users u ON tt.assignee_id=u.id ORDER BY tt.created_at DESC LIMIT 300`);
  } else {
    const me = get('SELECT team FROM users WHERE id=?', [req.user.id]);
    const team = me?.team || '';
    rows = all(`SELECT tt.*, u.full_name AS assignee_name,
      (SELECT COUNT(*) FROM task_comments WHERE team_task_id=tt.id) AS comment_count
      FROM team_tasks tt LEFT JOIN users u ON tt.assignee_id=u.id
      WHERE tt.team=? OR tt.team='' OR tt.assignee_id=? ORDER BY tt.created_at DESC LIMIT 300`, [team, req.user.id]);
  }
  res.json(rows);
});
app.post('/api/team-tasks', authenticate, (req, res) => {
  // only admin or team lead can create team tasks
  if (req.user.role !== 'admin' && !req.user.is_lead)
    return res.status(403).json({ error: 'Only admin or team lead can create team tasks' });
  const { title, description, assignee_id, priority, team } = req.body;
  if (!title) return res.status(400).json({ error: 'Title required' });
  const r = runReturn(`INSERT INTO team_tasks (title, description, assignee_id, priority, team, created_by) VALUES (?,?,?,?,?,?)`,
    [title, description || '', assignee_id || null, priority || 'normal', team || '', req.user.id]);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.patch('/api/team-tasks/:id', authenticate, (req, res) => {
  const { status, assignee_id } = req.body;
  if (assignee_id !== undefined) {
    run(`UPDATE team_tasks SET assignee_id=? WHERE id=?`, [assignee_id || null, req.params.id]);
  }
  if (status !== undefined) {
    if (status === 'done') run(`UPDATE team_tasks SET status=?, completed_at=datetime('now') WHERE id=?`, [status, req.params.id]);
    else run(`UPDATE team_tasks SET status=? WHERE id=?`, [status, req.params.id]);
  }
  res.json({ success: true });
});
app.delete('/api/team-tasks/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin' && !req.user.is_lead)
    return res.status(403).json({ error: 'Not allowed' });
  run(`DELETE FROM task_comments WHERE team_task_id=?`, [req.params.id]);
  run(`DELETE FROM team_tasks WHERE id=?`, [req.params.id]);
  res.json({ success: true });
});
// assign a team task to myself
app.post('/api/team-tasks/:id/claim', authenticate, (req, res) => {
  run(`UPDATE team_tasks SET assignee_id=? WHERE id=?`, [req.user.id, req.params.id]);
  res.json({ success: true });
});

// ===== TASK COMMENTS (replies, Jira-like) =====
app.get('/api/team-tasks/:id/comments', authenticate, (req, res) => {
  res.json(all(`SELECT tc.id, tc.comment, tc.created_at, u.full_name FROM task_comments tc JOIN users u ON tc.user_id=u.id WHERE tc.team_task_id=? ORDER BY tc.id ASC`, [req.params.id]));
});
app.post('/api/team-tasks/:id/comments', authenticate, (req, res) => {
  const { comment } = req.body;
  if (!comment || !comment.trim()) return res.status(400).json({ error: 'Empty comment' });
  runReturn(`INSERT INTO task_comments (team_task_id, user_id, comment) VALUES (?,?,?)`, [req.params.id, req.user.id, comment.trim()]);
  res.json({ success: true });
});

// list of teammates (for assignee dropdowns) — available to leads too
app.get('/api/teammates', authenticate, (req, res) => {
  res.json(all(`SELECT id, full_name, team FROM users WHERE role='employee' ORDER BY full_name`));
});

// ===== SHIFT TIME SETTINGS =====
const DEFAULT_SHIFTS = JSON.stringify({ Morning: '09:00 - 17:00', Mid: '13:00 - 21:00', Night: '21:00 - 05:00' });
const DEFAULT_COLORS = JSON.stringify({ Morning: '#5fb878', Mid: '#6b8cce', Night: '#9b78ce', Off: '#d6584f' });
app.get('/api/shift-settings', authenticate, (req, res) => {
  const row = get(`SELECT value FROM settings WHERE key='shifts'`);
  res.json(JSON.parse(row?.value || DEFAULT_SHIFTS));
});
app.put('/api/shift-settings', authenticate, requireAdmin, (req, res) => {
  const { Morning, Mid, Night } = req.body;
  const val = JSON.stringify({ Morning: Morning || '', Mid: Mid || '', Night: Night || '' });
  if (get(`SELECT key FROM settings WHERE key='shifts'`)) run(`UPDATE settings SET value=? WHERE key='shifts'`, [val]);
  else run(`INSERT INTO settings (key, value) VALUES ('shifts', ?)`, [val]);
  res.json({ success: true });
});
app.get('/api/shift-colors', authenticate, (req, res) => {
  const row = get(`SELECT value FROM settings WHERE key='shift_colors'`);
  res.json(JSON.parse(row?.value || DEFAULT_COLORS));
});
app.put('/api/shift-colors', authenticate, requireAdmin, (req, res) => {
  const { Morning, Mid, Night, Off } = req.body;
  const def = JSON.parse(DEFAULT_COLORS);
  const val = JSON.stringify({ Morning: Morning || def.Morning, Mid: Mid || def.Mid, Night: Night || def.Night, Off: Off || def.Off });
  if (get(`SELECT key FROM settings WHERE key='shift_colors'`)) run(`UPDATE settings SET value=? WHERE key='shift_colors'`, [val]);
  else run(`INSERT INTO settings (key, value) VALUES ('shift_colors', ?)`, [val]);
  res.json({ success: true });
});

// ===== SCHEDULE (monthly grid) =====
app.get('/api/schedule', authenticate, (req, res) => {
  const month = (req.query.month || '').slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ error: 'Invalid month' });
  res.json(all(`SELECT user_id, day, shift, note FROM schedule WHERE day LIKE ?`, [month + '-%']));
});
app.put('/api/schedule', authenticate, requireAdmin, (req, res) => {
  const { user_id, day, shift, note } = req.body;
  if (!user_id || !day) return res.status(400).json({ error: 'Missing data' });
  const existing = get(`SELECT id FROM schedule WHERE user_id=? AND day=?`, [user_id, day]);
  if (existing) run(`UPDATE schedule SET shift=?, note=? WHERE id=?`, [shift || '', note || '', existing.id]);
  else run(`INSERT INTO schedule (user_id, day, shift, note) VALUES (?,?,?,?)`, [user_id, day, shift || '', note || '']);
  res.json({ success: true });
});

// ===== CHAT ROOMS & MESSAGES =====
// Helper: can current user access this room?
function canAccessRoom(user, room) {
  if (!room) return false;
  if (user.role === 'admin') return true;
  if (room.is_company) return true;
  if (!room.team) return true; // a general room with no team restriction
  return (user.team || '') === room.team;
}

// List rooms the current user can see
app.get('/api/chat-rooms', authenticate, (req, res) => {
  const me = get('SELECT team FROM users WHERE id=?', [req.user.id]);
  const team = me?.team || '';
  let rooms;
  if (req.user.role === 'admin') {
    rooms = all(`SELECT id, name, team, is_company FROM chat_rooms ORDER BY is_company DESC, name`);
  } else {
    rooms = all(`SELECT id, name, team, is_company FROM chat_rooms WHERE is_company=1 OR team='' OR team=? ORDER BY is_company DESC, name`, [team]);
  }
  res.json(rooms);
});

// Admin creates a new chat room (e.g., per team)
app.post('/api/chat-rooms', authenticate, requireAdmin, (req, res) => {
  const { name, team } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Name required' });
  const r = runReturn(`INSERT INTO chat_rooms (name, team, is_company) VALUES (?,?,0)`, [name.trim(), team || '']);
  res.json({ success: true, id: r.lastInsertRowid });
});

// Admin can delete a non-company room (and its messages)
app.delete('/api/chat-rooms/:id', authenticate, requireAdmin, (req, res) => {
  const room = get('SELECT * FROM chat_rooms WHERE id=?', [req.params.id]);
  if (!room) return res.status(404).json({ error: 'Not found' });
  if (room.is_company) return res.status(400).json({ error: 'Cannot delete the company room' });
  run(`DELETE FROM chat_messages WHERE room_id=?`, [req.params.id]);
  run(`DELETE FROM chat_rooms WHERE id=?`, [req.params.id]);
  res.json({ success: true });
});

// Get messages of a specific room (with sender info)
app.get('/api/chat', authenticate, (req, res) => {
  const room_id = parseInt(req.query.room_id, 10);
  if (!room_id) return res.status(400).json({ error: 'room_id required' });
  const room = get('SELECT * FROM chat_rooms WHERE id=?', [room_id]);
  if (!canAccessRoom(req.user, room)) return res.status(403).json({ error: 'Not allowed' });
  const msgs = all(`
    SELECT c.id, c.message, c.created_at, c.user_id,
           u.full_name, u.job_title, u.avatar
    FROM chat_messages c JOIN users u ON c.user_id=u.id
    WHERE c.room_id=? ORDER BY c.id DESC LIMIT 200`, [room_id]).reverse();
  res.json(msgs);
});

// Post a message into a room
app.post('/api/chat', authenticate, (req, res) => {
  const { message, room_id } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ error: 'Empty message' });
  if (!room_id) return res.status(400).json({ error: 'room_id required' });
  const room = get('SELECT * FROM chat_rooms WHERE id=?', [room_id]);
  if (!canAccessRoom(req.user, room)) return res.status(403).json({ error: 'Not allowed' });
  // Muted users can't send (admin is never muted)
  if (req.user.role !== 'admin') {
    const muted = get('SELECT 1 AS m FROM chat_mutes WHERE room_id=? AND user_id=?', [room_id, req.user.id]);
    if (muted) return res.status(403).json({ error: 'You are muted in this chat' });
  }
  runReturn(`INSERT INTO chat_messages (user_id, message, room_id) VALUES (?,?,?)`, [req.user.id, message.trim(), room_id]);
  res.json({ success: true });
});

// List members of a room (users who can access it) + their mute status
app.get('/api/chat-rooms/:id/members', authenticate, requireAdmin, (req, res) => {
  const room = get('SELECT * FROM chat_rooms WHERE id=?', [req.params.id]);
  if (!room) return res.status(404).json({ error: 'Not found' });
  let users;
  if (room.is_company || !room.team) {
    users = all(`SELECT id, full_name, job_title, team, avatar FROM users WHERE role='employee' ORDER BY full_name`);
  } else {
    users = all(`SELECT id, full_name, job_title, team, avatar FROM users WHERE role='employee' AND team=? ORDER BY full_name`, [room.team]);
  }
  const muted = new Set(all('SELECT user_id FROM chat_mutes WHERE room_id=?', [req.params.id]).map(r => r.user_id));
  res.json(users.map(u => ({ ...u, muted: muted.has(u.id) })));
});

// Mute / unmute a user in a room
app.post('/api/chat-rooms/:id/mute', authenticate, requireAdmin, (req, res) => {
  const { user_id, muted } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id required' });
  if (muted) {
    if (!get('SELECT 1 AS m FROM chat_mutes WHERE room_id=? AND user_id=?', [req.params.id, user_id])) {
      run('INSERT INTO chat_mutes (room_id, user_id) VALUES (?,?)', [req.params.id, user_id]);
    }
  } else {
    run('DELETE FROM chat_mutes WHERE room_id=? AND user_id=?', [req.params.id, user_id]);
  }
  res.json({ success: true });
});

// Useful: list of mentionable users for the current room (filtered by team scope)
app.get('/api/chat-rooms/:id/mentionable', authenticate, (req, res) => {
  const room = get('SELECT * FROM chat_rooms WHERE id=?', [req.params.id]);
  if (!canAccessRoom(req.user, room)) return res.status(403).json({ error: 'Not allowed' });
  let users;
  if (room.is_company || !room.team) {
    users = all(`SELECT id, full_name, job_title FROM users WHERE role='employee' OR role='admin' ORDER BY full_name`);
  } else {
    users = all(`SELECT id, full_name, job_title FROM users WHERE (role='employee' AND team=?) OR role='admin' ORDER BY full_name`, [room.team]);
  }
  res.json(users);
});

// ===== ADMIN =====
app.get('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
  res.json(all(`SELECT u.id, u.username, u.full_name, u.job_title, u.daily_hours, u.team, u.is_lead, a.status, a.clock_in,
    CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END AS is_online,
    (SELECT COUNT(*) FROM tasks WHERE user_id=u.id AND status='done' AND assigned_date=date('now')) AS tasks_done_today
    FROM users u LEFT JOIN attendance a ON u.id=a.user_id AND a.clock_out IS NULL
    WHERE u.role='employee' ORDER BY is_online DESC, u.full_name`));
});
app.post('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
  const { username, password, full_name, job_title, daily_hours, team, is_lead } = req.body;
  if (!username || !password || !full_name) return res.status(400).json({ error: 'Missing data' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const r = runReturn(`INSERT INTO users (username, password_hash, full_name, job_title, daily_hours, team, is_lead, role) VALUES (?,?,?,?,?,?,?,'employee')`,
      [username, hash, full_name, job_title || '', daily_hours || 8, team || '', is_lead ? 1 : 0]);
    res.json({ success: true, id: r.lastInsertRowid });
  } catch (e) { res.status(400).json({ error: 'Username already exists' }); }
});
// edit employee team/lead
app.patch('/api/admin/employees/:id', authenticate, requireAdmin, (req, res) => {
  const { team, is_lead, daily_hours, full_name, job_title, new_password } = req.body;
  if (full_name !== undefined && full_name.trim()) run(`UPDATE users SET full_name=? WHERE id=?`, [full_name.trim(), req.params.id]);
  if (job_title !== undefined) run(`UPDATE users SET job_title=? WHERE id=?`, [job_title, req.params.id]);
  if (team !== undefined) run(`UPDATE users SET team=? WHERE id=?`, [team, req.params.id]);
  if (is_lead !== undefined) run(`UPDATE users SET is_lead=? WHERE id=?`, [is_lead ? 1 : 0, req.params.id]);
  if (daily_hours !== undefined) run(`UPDATE users SET daily_hours=? WHERE id=?`, [daily_hours, req.params.id]);
  if (new_password) {
    if (new_password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const hash = bcrypt.hashSync(new_password, 10);
    run(`UPDATE users SET password_hash=? WHERE id=?`, [hash, req.params.id]);
  }
  res.json({ success: true });
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
