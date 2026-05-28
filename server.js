// HR System Backend - Node.js + Express + sql.js (Pure JS, no native build)
// Run: npm install && npm start

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const DB_PATH = path.join(__dirname, 'hr.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let db;
let SQL;

// Helper functions to mimic better-sqlite3 API
function run(sql, params = []) {
    db.run(sql, params);
    saveDb();
}

function get(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
}

function all(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) results.push(stmt.getAsObject());
    stmt.free();
    return results;
}

function runReturn(sql, params = []) {
    db.run(sql, params);
    const lastId = db.exec("SELECT last_insert_rowid() AS id")[0].values[0][0];
    saveDb();
    return { lastInsertRowid: lastId };
}

function saveDb() {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// Initialize DB
async function initDb() {
    SQL = await initSqlJs();

    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }

    // Create tables
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            job_title TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            clock_in DATETIME NOT NULL,
            clock_out DATETIME,
            status TEXT DEFAULT 'online',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'pending',
            assigned_date DATE DEFAULT CURRENT_DATE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `);

    // Create default admin if not exists
    const adminExists = get('SELECT id FROM users WHERE username = ?', ['admin']);
    if (!adminExists) {
        const hash = bcrypt.hashSync('admin123', 10);
        run(`INSERT INTO users (username, password_hash, full_name, role, job_title)
             VALUES (?, ?, ?, ?, ?)`,
            ['admin', hash, 'System Administrator', 'admin', 'Administrator']);
        console.log('✓ Default admin created — username: admin, password: admin123');
    }

    saveDb();
}

// ============ AUTH MIDDLEWARE ============
function authenticate(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    next();
}

// ============ AUTH ROUTES ============
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = get('SELECT * FROM users WHERE username = ?', [username]);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, full_name: user.full_name },
        JWT_SECRET,
        { expiresIn: '12h' }
    );

    res.json({
        token,
        user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role, job_title: user.job_title }
    });
});

// ============ ATTENDANCE ROUTES ============
app.post('/api/clock-in', authenticate, (req, res) => {
    const open = get(`SELECT id FROM attendance WHERE user_id = ? AND clock_out IS NULL`, [req.user.id]);
    if (open) return res.status(400).json({ error: 'Already clocked in' });

    const result = runReturn(`INSERT INTO attendance (user_id, clock_in, status)
                              VALUES (?, datetime('now'), 'online')`, [req.user.id]);
    res.json({ success: true, id: result.lastInsertRowid });
});

app.post('/api/clock-out', authenticate, (req, res) => {
    const open = get(`SELECT id FROM attendance WHERE user_id = ? AND clock_out IS NULL`, [req.user.id]);
    if (!open) return res.status(400).json({ error: 'No active session' });

    run(`UPDATE attendance SET clock_out = datetime('now'), status = 'offline' WHERE id = ?`, [open.id]);
    res.json({ success: true });
});

app.post('/api/break', authenticate, (req, res) => {
    const open = get(`SELECT * FROM attendance WHERE user_id = ? AND clock_out IS NULL`, [req.user.id]);
    if (!open) return res.status(400).json({ error: 'لازم تعمل Clock In الأول' });

    const newStatus = open.status === 'break' ? 'online' : 'break';
    run(`UPDATE attendance SET status = ? WHERE id = ?`, [newStatus, open.id]);
    res.json({ success: true, status: newStatus });
});

app.get('/api/my-status', authenticate, (req, res) => {
    const session = get(`SELECT * FROM attendance WHERE user_id = ? AND clock_out IS NULL`, [req.user.id]);
    res.json({
        online: !!session,
        status: session?.status || 'offline',
        clock_in: session?.clock_in || null
    });
});

app.get('/api/my-attendance', authenticate, (req, res) => {
    const records = all(`
        SELECT id, clock_in, clock_out, status,
               CASE WHEN clock_out IS NOT NULL
                    THEN ROUND((julianday(clock_out) - julianday(clock_in)) * 24, 2)
                    ELSE NULL END AS hours_worked
        FROM attendance
        WHERE user_id = ?
        ORDER BY clock_in DESC
        LIMIT 30
    `, [req.user.id]);
    res.json(records);
});

// ============ TASKS ROUTES ============
app.get('/api/my-tasks', authenticate, (req, res) => {
    const tasks = all(`
        SELECT * FROM tasks
        WHERE user_id = ? AND assigned_date = date('now')
        ORDER BY
          CASE status WHEN 'in_progress' THEN 1 WHEN 'pending' THEN 2 WHEN 'done' THEN 3 END,
          created_at ASC
    `, [req.user.id]);
    res.json(tasks);
});

app.patch('/api/tasks/:id', authenticate, (req, res) => {
    const { status } = req.body;
    const task = get('SELECT * FROM tasks WHERE id = ?', [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    if (task.user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Not your task' });
    }
    if (status === 'done') {
        run(`UPDATE tasks SET status = ?, completed_at = datetime('now') WHERE id = ?`, [status, req.params.id]);
    } else {
        run(`UPDATE tasks SET status = ?, completed_at = NULL WHERE id = ?`, [status, req.params.id]);
    }
    res.json({ success: true });
});

// ============ ADMIN ROUTES ============
app.get('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
    const employees = all(`
        SELECT
            u.id, u.username, u.full_name, u.job_title,
            a.status, a.clock_in,
            CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END AS is_online,
            (SELECT COUNT(*) FROM tasks WHERE user_id = u.id AND status = 'done' AND assigned_date = date('now')) AS tasks_done_today
        FROM users u
        LEFT JOIN attendance a ON u.id = a.user_id AND a.clock_out IS NULL
        WHERE u.role = 'employee'
        ORDER BY is_online DESC, u.full_name
    `);
    res.json(employees);
});

app.post('/api/admin/employees', authenticate, requireAdmin, (req, res) => {
    const { username, password, full_name, job_title } = req.body;
    if (!username || !password || !full_name) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hash = bcrypt.hashSync(password, 10);
        const result = runReturn(`INSERT INTO users (username, password_hash, full_name, job_title, role)
                                  VALUES (?, ?, ?, ?, 'employee')`,
                                 [username, hash, full_name, job_title || '']);
        res.json({ success: true, id: result.lastInsertRowid });
    } catch (e) {
        res.status(400).json({ error: 'اسم المستخدم موجود بالفعل' });
    }
});

app.delete('/api/admin/employees/:id', authenticate, requireAdmin, (req, res) => {
    run('DELETE FROM attendance WHERE user_id = ?', [req.params.id]);
    run('DELETE FROM tasks WHERE user_id = ?', [req.params.id]);
    run('DELETE FROM users WHERE id = ? AND role != ?', [req.params.id, 'admin']);
    res.json({ success: true });
});

app.post('/api/admin/tasks', authenticate, requireAdmin, (req, res) => {
    const { user_id, title, description } = req.body;
    if (!user_id || !title) return res.status(400).json({ error: 'Missing data' });
    const result = runReturn(`INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)`,
                             [user_id, title, description || '']);
    res.json({ success: true, id: result.lastInsertRowid });
});

app.delete('/api/admin/tasks/:id', authenticate, requireAdmin, (req, res) => {
    run('DELETE FROM tasks WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

app.get('/api/admin/attendance/:userId', authenticate, requireAdmin, (req, res) => {
    const records = all(`
        SELECT id, clock_in, clock_out, status,
               CASE WHEN clock_out IS NOT NULL
                    THEN ROUND((julianday(clock_out) - julianday(clock_in)) * 24, 2)
                    ELSE NULL END AS hours_worked
        FROM attendance
        WHERE user_id = ?
        ORDER BY clock_in DESC
        LIMIT 60
    `, [req.params.userId]);
    res.json(records);
});

app.get('/api/admin/tasks/:userId', authenticate, requireAdmin, (req, res) => {
    const tasks = all(`SELECT * FROM tasks WHERE user_id = ? ORDER BY assigned_date DESC, created_at DESC LIMIT 100`,
                      [req.params.userId]);
    res.json(tasks);
});

// ============ START SERVER ============
initDb().then(() => {
    app.listen(PORT, () => {
        console.log(`✓ HR System running on http://localhost:${PORT}`);
        console.log(`✓ Login: admin / admin123 (غيّرها فوراً)`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
});
