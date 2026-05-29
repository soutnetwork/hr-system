// HR System Backend - Sout Network
// Node.js + Express + sql.js (Pure JS, no native build)

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'soutnetwork-hr-secret-2026-change-me';
const ENC_SECRET = process.env.ENC_SECRET || 'soutnetwork-tools-enc-2026-change-me';
const ENC_KEY = crypto.createHash('sha256').update(ENC_SECRET).digest(); // 32 bytes

function encryptPwd(plain) {
  if (!plain) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store as base64: iv|tag|ciphertext
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decryptPwd(blob) {
  if (!blob) return '';
  try {
    const buf = Buffer.from(blob, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const enc = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
  } catch (e) {
    return '';
  }
}
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
    CREATE TABLE IF NOT EXISTS teams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS tools (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      icon TEXT DEFAULT '',
      username TEXT DEFAULT '',
      password_enc TEXT DEFAULT '',
      teams_csv TEXT DEFAULT '',
      sort_order INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS time_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      entry_date DATE NOT NULL,
      task_name TEXT NOT NULL,
      project TEXT DEFAULT '',
      client_tag TEXT DEFAULT '',
      start_time TEXT DEFAULT '',
      end_time TEXT DEFAULT '',
      duration_minutes INTEGER DEFAULT 0,
      note TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
  try { db.run(`ALTER TABLE tools ADD COLUMN username TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE tools ADD COLUMN password_enc TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE tools ADD COLUMN teams_csv TEXT DEFAULT ''`); } catch(e){}
  try { db.run(`ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''`); } catch(e){}

  // ensure a default Company room exists (id=1)
  if (!get(`SELECT id FROM chat_rooms WHERE is_company=1`)) {
    run(`INSERT INTO chat_rooms (name, team, is_company) VALUES ('Company', '', 1)`);
    // migrate any pre-existing messages (room_id=0) into the company room
    const company = get(`SELECT id FROM chat_rooms WHERE is_company=1`);
    if (company) run(`UPDATE chat_messages SET room_id=? WHERE room_id=0 OR room_id IS NULL`, [company.id]);
  }
  // seed default teams (first run); also pull in any team names already assigned to users
  const defaultTeams = ['Copyright', 'Distribution', 'Account Managers', 'Marketing'];
  for (const t of defaultTeams) {
    try { db.run(`INSERT OR IGNORE INTO teams (name) VALUES (?)`, [t]); } catch(e){}
  }
  try {
    const existing = all(`SELECT DISTINCT team FROM users WHERE team!='' AND team IS NOT NULL`);
    for (const r of existing) { db.run(`INSERT OR IGNORE INTO teams (name) VALUES (?)`, [r.team]); }
    saveDb();
  } catch(e){}

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
  const u = get('SELECT id, username, full_name, role, job_title, team, is_lead, daily_hours, avatar, bio FROM users WHERE id=?', [req.user.id]);
  res.json(u || {});
});
app.put('/api/profile', authenticate, (req, res) => {
  const { avatar, full_name, bio } = req.body;
  if (avatar !== undefined) {
    if (avatar && avatar.length > 200000) return res.status(400).json({ error: 'Image too large (max ~150KB after encoding). Please use a smaller image.' });
    run('UPDATE users SET avatar=? WHERE id=?', [avatar || '', req.user.id]);
  }
  if (full_name !== undefined && full_name.trim()) {
    run('UPDATE users SET full_name=? WHERE id=?', [full_name.trim(), req.user.id]);
  }
  if (bio !== undefined) {
    if (bio && bio.length > 2000) return res.status(400).json({ error: 'Bio too long (max 2000 chars).' });
    run('UPDATE users SET bio=? WHERE id=?', [bio || '', req.user.id]);
  }
  res.json({ success: true });
});

// Public profile view (other users can see this)
app.get('/api/users/:id/profile', authenticate, (req, res) => {
  const u = get('SELECT id, full_name, role, job_title, team, is_lead, avatar, bio FROM users WHERE id=?', [req.params.id]);
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json(u);
});

// Directory: everyone grouped by team (employees only)
app.get('/api/directory', authenticate, (req, res) => {
  const users = all(`SELECT id, full_name, job_title, team, is_lead, avatar FROM users WHERE role='employee' ORDER BY team, full_name`);
  res.json(users);
});

// ===== TIME ENTRIES (Clockify-like) =====
// List entries: employees see their own; admin can pass ?user_id=N or ?team=NAME
app.get('/api/time-entries', authenticate, (req, res) => {
  const from = req.query.from || '1900-01-01';
  const to   = req.query.to   || '2999-12-31';
  if (req.user.role === 'admin') {
    if (req.query.user_id) {
      res.json(all(`SELECT te.*, u.full_name FROM time_entries te JOIN users u ON te.user_id=u.id
                    WHERE te.user_id=? AND te.entry_date BETWEEN ? AND ?
                    ORDER BY te.entry_date DESC, te.id DESC LIMIT 300`, [req.query.user_id, from, to]));
    } else if (req.query.team) {
      res.json(all(`SELECT te.*, u.full_name FROM time_entries te JOIN users u ON te.user_id=u.id
                    WHERE u.team=? AND te.entry_date BETWEEN ? AND ?
                    ORDER BY te.entry_date DESC, te.id DESC LIMIT 500`, [req.query.team, from, to]));
    } else {
      res.json(all(`SELECT te.*, u.full_name FROM time_entries te JOIN users u ON te.user_id=u.id
                    WHERE te.entry_date BETWEEN ? AND ?
                    ORDER BY te.entry_date DESC, te.id DESC LIMIT 500`, [from, to]));
    }
  } else {
    res.json(all(`SELECT te.*, u.full_name FROM time_entries te JOIN users u ON te.user_id=u.id
                  WHERE te.user_id=? AND te.entry_date BETWEEN ? AND ?
                  ORDER BY te.entry_date DESC, te.id DESC LIMIT 300`, [req.user.id, from, to]));
  }
});
// Create a new time entry (anyone for themselves; admin can pass user_id for someone else)
app.post('/api/time-entries', authenticate, (req, res) => {
  const { entry_date, task_name, project, client_tag, start_time, end_time, duration_minutes, note, user_id } = req.body;
  if (!task_name || !task_name.trim()) return res.status(400).json({ error: 'Task name required' });
  if (!entry_date) return res.status(400).json({ error: 'Date required' });
  const uid = (req.user.role === 'admin' && user_id) ? user_id : req.user.id;
  // calculate duration if start/end given but duration not provided
  let dur = parseInt(duration_minutes, 10) || 0;
  if (!dur && start_time && end_time) {
    const [sh, sm] = start_time.split(':').map(n=>parseInt(n,10));
    const [eh, em] = end_time.split(':').map(n=>parseInt(n,10));
    if(!isNaN(sh) && !isNaN(eh)) {
      let mins = (eh*60+em) - (sh*60+sm);
      if (mins < 0) mins += 24*60; // crossed midnight
      dur = mins;
    }
  }
  const r = runReturn(`INSERT INTO time_entries (user_id, entry_date, task_name, project, client_tag, start_time, end_time, duration_minutes, note)
                       VALUES (?,?,?,?,?,?,?,?,?)`,
                       [uid, entry_date, task_name.trim(), project||'', client_tag||'', start_time||'', end_time||'', dur, note||'']);
  res.json({ success: true, id: r.lastInsertRowid });
});
// Update a time entry (owner or admin)
app.patch('/api/time-entries/:id', authenticate, (req, res) => {
  const e = get('SELECT user_id FROM time_entries WHERE id=?', [req.params.id]);
  if (!e) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && e.user_id !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  const { entry_date, task_name, project, client_tag, start_time, end_time, duration_minutes, note } = req.body;
  const fields = []; const vals = [];
  if (entry_date !== undefined) { fields.push('entry_date=?'); vals.push(entry_date); }
  if (task_name !== undefined) { fields.push('task_name=?'); vals.push(task_name); }
  if (project !== undefined) { fields.push('project=?'); vals.push(project); }
  if (client_tag !== undefined) { fields.push('client_tag=?'); vals.push(client_tag); }
  if (start_time !== undefined) { fields.push('start_time=?'); vals.push(start_time); }
  if (end_time !== undefined) { fields.push('end_time=?'); vals.push(end_time); }
  if (duration_minutes !== undefined) { fields.push('duration_minutes=?'); vals.push(duration_minutes); }
  if (note !== undefined) { fields.push('note=?'); vals.push(note); }
  if (!fields.length) return res.json({ success: true });
  vals.push(req.params.id);
  run(`UPDATE time_entries SET ${fields.join(', ')} WHERE id=?`, vals);
  res.json({ success: true });
});
// Delete a time entry (owner or admin)
app.delete('/api/time-entries/:id', authenticate, (req, res) => {
  const e = get('SELECT user_id FROM time_entries WHERE id=?', [req.params.id]);
  if (!e) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && e.user_id !== req.user.id) return res.status(403).json({ error: 'Not allowed' });
  run('DELETE FROM time_entries WHERE id=?', [req.params.id]);
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
  // Admin can pass ?team=NAME to filter; without it, returns everyone.
  // Non-admin always gets only members of their own team.
  let teamFilter = null;
  if (req.user.role === 'admin') {
    if (req.query.team !== undefined && req.query.team !== '') teamFilter = req.query.team;
  } else {
    const me = get('SELECT team FROM users WHERE id=?', [req.user.id]);
    teamFilter = me?.team || '';
  }
  if (teamFilter === null) {
    res.json(all(`SELECT id, full_name, team, job_title FROM users WHERE role='employee' ORDER BY full_name`));
  } else {
    res.json(all(`SELECT id, full_name, team, job_title FROM users WHERE role='employee' AND team=? ORDER BY full_name`, [teamFilter]));
  }
});

// ===== TEAMS =====
// List teams (everyone can read; needed for filters/dropdowns)
// ===== TOOLS (custom external links shown in top bar) =====
// Helper: turn array of team names into a CSV string
function toolsTeamsToCsv(arr){
  if (!Array.isArray(arr)) return '';
  return arr.map(s => String(s||'').trim()).filter(Boolean).join(',');
}
function toolsCsvToArray(csv){
  if (!csv) return [];
  return String(csv).split(',').map(s => s.trim()).filter(Boolean);
}

// List tools — admin sees all; employees see only ones for their team (or unrestricted ones)
app.get('/api/tools', authenticate, (req, res) => {
  const rows = all(`SELECT id, name, url, icon, username, password_enc, teams_csv, sort_order FROM tools ORDER BY sort_order, id`);
  let visible;
  if (req.user.role === 'admin') {
    visible = rows; // admin sees everything
  } else {
    const me = get('SELECT team FROM users WHERE id=?', [req.user.id]);
    const myTeam = (me?.team || '').toLowerCase();
    visible = rows.filter(r => {
      const list = toolsCsvToArray(r.teams_csv);
      if (!list.length) return true; // empty teams = visible to everyone
      return list.some(t => t.toLowerCase() === myTeam);
    });
  }
  res.json(visible.map(r => ({
    id: r.id, name: r.name, url: r.url, icon: r.icon, sort_order: r.sort_order,
    username: r.username || '',
    has_password: !!(r.password_enc && r.password_enc.length),
    teams: toolsCsvToArray(r.teams_csv)
  })));
});
// Reveal password (admin only) — separate endpoint so it's an explicit action
app.get('/api/tools/:id/credentials', authenticate, requireAdmin, (req, res) => {
  const t = get(`SELECT username, password_enc FROM tools WHERE id=?`, [req.params.id]);
  if (!t) return res.status(404).json({ error: 'Not found' });
  res.json({ username: t.username || '', password: decryptPwd(t.password_enc || '') });
});
app.post('/api/tools', authenticate, requireAdmin, (req, res) => {
  const { name, url, icon, username, password, teams, sort_order } = req.body;
  if (!name || !url) return res.status(400).json({ error: 'Name and URL are required' });
  if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'URL must start with http:// or https://' });
  const enc = password ? encryptPwd(password) : '';
  const csv = toolsTeamsToCsv(teams);
  const r = runReturn(`INSERT INTO tools (name, url, icon, username, password_enc, teams_csv, sort_order) VALUES (?,?,?,?,?,?,?)`,
    [name.trim(), url.trim(), (icon || '').trim(), (username || '').trim(), enc, csv, sort_order || 0]);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.patch('/api/tools/:id', authenticate, requireAdmin, (req, res) => {
  const { name, url, icon, username, password, teams, sort_order } = req.body;
  if (name !== undefined) run(`UPDATE tools SET name=? WHERE id=?`, [name, req.params.id]);
  if (url !== undefined) {
    if (!/^https?:\/\//i.test(url)) return res.status(400).json({ error: 'URL must start with http:// or https://' });
    run(`UPDATE tools SET url=? WHERE id=?`, [url, req.params.id]);
  }
  if (icon !== undefined) run(`UPDATE tools SET icon=? WHERE id=?`, [icon, req.params.id]);
  if (username !== undefined) run(`UPDATE tools SET username=? WHERE id=?`, [username, req.params.id]);
  if (password !== undefined) {
    // empty string clears the password; non-empty replaces it
    run(`UPDATE tools SET password_enc=? WHERE id=?`, [password ? encryptPwd(password) : '', req.params.id]);
  }
  if (teams !== undefined) run(`UPDATE tools SET teams_csv=? WHERE id=?`, [toolsTeamsToCsv(teams), req.params.id]);
  if (sort_order !== undefined) run(`UPDATE tools SET sort_order=? WHERE id=?`, [sort_order, req.params.id]);
  res.json({ success: true });
});
app.delete('/api/tools/:id', authenticate, requireAdmin, (req, res) => {
  run(`DELETE FROM tools WHERE id=?`, [req.params.id]);
  res.json({ success: true });
});

// ===== TEAMS =====
app.get('/api/teams', authenticate, (req, res) => {
  res.json(all(`SELECT id, name FROM teams ORDER BY name`));
});
// Admin creates a new team
app.post('/api/teams', authenticate, requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Team name required' });
  const clean = name.trim();
  if (get(`SELECT id FROM teams WHERE name=?`, [clean])) return res.status(400).json({ error: 'Team already exists' });
  const r = runReturn(`INSERT INTO teams (name) VALUES (?)`, [clean]);
  res.json({ success: true, id: r.lastInsertRowid, name: clean });
});
// Admin deletes a team — only if no employees still on it (safety)
app.delete('/api/teams/:id', authenticate, requireAdmin, (req, res) => {
  const t = get(`SELECT name FROM teams WHERE id=?`, [req.params.id]);
  if (!t) return res.status(404).json({ error: 'Not found' });
  const inUse = get(`SELECT COUNT(*) AS c FROM users WHERE team=?`, [t.name]);
  if (inUse && inUse.c > 0) return res.status(400).json({ error: 'Cannot delete: '+inUse.c+' employees are still on this team. Move them first.' });
  run(`DELETE FROM teams WHERE id=?`, [req.params.id]);
  res.json({ success: true });
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
  // Optional team scope: admin can request any team; non-admin is forced to their own team.
  let teamFilter = null;
  if (req.user.role === 'admin') {
    if (req.query.team !== undefined && req.query.team !== '') teamFilter = req.query.team;
  } else {
    const me = get('SELECT team FROM users WHERE id=?', [req.user.id]);
    teamFilter = me?.team || '';
  }
  if (teamFilter === null) {
    res.json(all(`SELECT user_id, day, shift, note FROM schedule WHERE day LIKE ?`, [month + '-%']));
  } else {
    // join users to keep only people in that team
    res.json(all(`SELECT s.user_id, s.day, s.shift, s.note FROM schedule s JOIN users u ON s.user_id=u.id WHERE s.day LIKE ? AND u.team=?`, [month + '-%', teamFilter]));
  }
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
  const { user_id, user_ids, team, title, description } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });

  // Build the list of target user IDs from any of: user_id, user_ids[], team
  const targets = new Set();
  if (user_id) targets.add(parseInt(user_id, 10));
  if (Array.isArray(user_ids)) for (const u of user_ids) { const n = parseInt(u, 10); if (n) targets.add(n); }
  if (team) {
    const members = all(`SELECT id FROM users WHERE role='employee' AND team=?`, [team]);
    for (const m of members) targets.add(m.id);
  }
  if (targets.size === 0) return res.status(400).json({ error: 'Pick at least one employee or a team' });

  // Insert one row per target so each person can track their own progress
  const ids = [];
  for (const uid of targets) {
    const r = runReturn(`INSERT INTO tasks (user_id, title, description) VALUES (?,?,?)`, [uid, title, description || '']);
    ids.push(r.lastInsertRowid);
  }
  res.json({ success: true, count: ids.length, ids });
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

// ===== ANALYTICS / DETAILED REPORTS =====
// Returns per-team and per-user stats for a date range, with optional team filter.
// Query: ?from=YYYY-MM-DD&to=YYYY-MM-DD&team=NAME
app.get('/api/admin/analytics', authenticate, requireAdmin, (req, res) => {
  const from = req.query.from || '1900-01-01';
  const to   = req.query.to   || '2999-12-31';
  const teamFilter = req.query.team && req.query.team !== '__ALL__' ? req.query.team : null;

  // Pull all employees (optionally filtered by team)
  const emps = teamFilter
    ? all(`SELECT id, full_name, team, job_title, daily_hours FROM users WHERE role='employee' AND team=? ORDER BY team, full_name`, [teamFilter])
    : all(`SELECT id, full_name, team, job_title, daily_hours FROM users WHERE role='employee' ORDER BY team, full_name`);

  if (!emps.length) return res.json({ from, to, team: teamFilter, teams: [], employees: [], totals: {} });

  const ids = emps.map(e => e.id);
  const placeholders = ids.map(()=>'?').join(',');

  // Attendance per user (sessions overlapping the date range)
  // We sum hours_worked for sessions whose clock_in falls in [from..to].
  const attendance = all(
    `SELECT user_id,
            COUNT(*) AS sessions,
            SUM(CASE WHEN clock_out IS NOT NULL THEN (julianday(clock_out)-julianday(clock_in))*24 ELSE 0 END) AS hours_worked,
            SUM(CASE WHEN clock_out IS NULL THEN 1 ELSE 0 END) AS open_sessions
       FROM attendance
      WHERE user_id IN (${placeholders}) AND date(clock_in) BETWEEN ? AND ?
   GROUP BY user_id`,
    [...ids, from, to]
  );
  const attMap = {}; attendance.forEach(r => { attMap[r.user_id] = r; });

  // Personal tasks per user, grouped by status
  const tasks = all(
    `SELECT user_id, status, COUNT(*) AS c, SUM(COALESCE(time_spent_seconds,0)) AS sec
       FROM tasks
      WHERE user_id IN (${placeholders}) AND assigned_date BETWEEN ? AND ?
   GROUP BY user_id, status`,
    [...ids, from, to]
  );
  const taskMap = {}; // {user_id: {done, in_progress, pending, total_sec, total}}
  tasks.forEach(r => {
    if (!taskMap[r.user_id]) taskMap[r.user_id] = { done:0, in_progress:0, pending:0, total_sec:0, total:0 };
    taskMap[r.user_id][r.status] = r.c;
    taskMap[r.user_id].total += r.c;
    if (r.status === 'done') taskMap[r.user_id].total_sec += (r.sec || 0);
  });

  // Team task contributions per user (assignee) within the period
  const teamTaskDone = all(
    `SELECT assignee_id AS user_id, COUNT(*) AS c
       FROM team_tasks
      WHERE assignee_id IN (${placeholders}) AND status='done'
        AND date(COALESCE(completed_at, created_at)) BETWEEN ? AND ?
   GROUP BY assignee_id`,
    [...ids, from, to]
  );
  const teamTaskOpen = all(
    `SELECT assignee_id AS user_id, COUNT(*) AS c
       FROM team_tasks
      WHERE assignee_id IN (${placeholders}) AND status!='done'
        AND date(created_at) BETWEEN ? AND ?
   GROUP BY assignee_id`,
    [...ids, from, to]
  );
  const ttDone = {}; teamTaskDone.forEach(r => { ttDone[r.user_id] = r.c; });
  const ttOpen = {}; teamTaskOpen.forEach(r => { ttOpen[r.user_id] = r.c; });

  // Recent completed tasks (personal + team) per user — small sample
  const recentPersonal = all(
    `SELECT user_id, title, time_spent_seconds, completed_at
       FROM tasks
      WHERE user_id IN (${placeholders}) AND status='done'
        AND date(COALESCE(completed_at, assigned_date)) BETWEEN ? AND ?
   ORDER BY COALESCE(completed_at, assigned_date) DESC
      LIMIT 200`,
    [...ids, from, to]
  );
  const recentTeam = all(
    `SELECT assignee_id AS user_id, title, completed_at
       FROM team_tasks
      WHERE assignee_id IN (${placeholders}) AND status='done'
        AND date(COALESCE(completed_at, created_at)) BETWEEN ? AND ?
   ORDER BY COALESCE(completed_at, created_at) DESC
      LIMIT 200`,
    [...ids, from, to]
  );
  const recentMap = {};
  recentPersonal.forEach(r => { (recentMap[r.user_id] ||= []).push({ kind:'personal', title:r.title, time:r.time_spent_seconds||0, at:r.completed_at }); });
  recentTeam.forEach(r => { (recentMap[r.user_id] ||= []).push({ kind:'team', title:r.title, time:0, at:r.completed_at }); });
  // keep top 5 per user
  for (const k of Object.keys(recentMap)) recentMap[k] = recentMap[k].slice(0, 5);

  // Build per-employee rows
  const employees = emps.map(e => {
    const a = attMap[e.id] || { sessions:0, hours_worked:0, open_sessions:0 };
    const t = taskMap[e.id] || { done:0, in_progress:0, pending:0, total_sec:0, total:0 };
    return {
      id: e.id,
      full_name: e.full_name,
      team: e.team || '',
      job_title: e.job_title || '',
      daily_hours: e.daily_hours || 8,
      sessions: a.sessions || 0,
      hours_worked: Math.round((a.hours_worked || 0) * 100) / 100,
      open_sessions: a.open_sessions || 0,
      personal_tasks: { done:t.done||0, in_progress:t.in_progress||0, pending:t.pending||0, total:t.total||0, time_spent_sec:t.total_sec||0 },
      team_tasks: { done: ttDone[e.id] || 0, open: ttOpen[e.id] || 0 },
      recent_done: recentMap[e.id] || []
    };
  });

  // Aggregate by team
  const teamsAgg = {};
  for (const e of employees) {
    const k = e.team || '(No team)';
    if (!teamsAgg[k]) teamsAgg[k] = { name:k, employees:0, hours_worked:0, personal_done:0, personal_pending:0, personal_in_progress:0, team_done:0, team_open:0, time_spent_sec:0 };
    const g = teamsAgg[k];
    g.employees += 1;
    g.hours_worked += e.hours_worked;
    g.personal_done += e.personal_tasks.done;
    g.personal_in_progress += e.personal_tasks.in_progress;
    g.personal_pending += e.personal_tasks.pending;
    g.time_spent_sec += e.personal_tasks.time_spent_sec;
    g.team_done += e.team_tasks.done;
    g.team_open += e.team_tasks.open;
  }
  const teams = Object.values(teamsAgg).map(t => ({ ...t, hours_worked: Math.round(t.hours_worked*100)/100 })).sort((a,b)=>a.name.localeCompare(b.name));

  // Company totals
  const totals = {
    employees: employees.length,
    teams: teams.length,
    hours_worked: Math.round(employees.reduce((s,e)=>s+e.hours_worked,0)*100)/100,
    personal_done: employees.reduce((s,e)=>s+e.personal_tasks.done,0),
    personal_pending: employees.reduce((s,e)=>s+e.personal_tasks.pending,0),
    personal_in_progress: employees.reduce((s,e)=>s+e.personal_tasks.in_progress,0),
    team_done: employees.reduce((s,e)=>s+e.team_tasks.done,0),
    team_open: employees.reduce((s,e)=>s+e.team_tasks.open,0)
  };

  res.json({ from, to, team: teamFilter, totals, teams, employees });
});

initDb().then(() => app.listen(PORT, () => console.log(`HR System on port ${PORT}`)));
