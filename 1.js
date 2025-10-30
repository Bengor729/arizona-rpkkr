// app.js
// Один файл: backend + frontend для простого Arizona RP сайта.
// Зависимости: express, sqlite3, bcrypt, jsonwebtoken, body-parser, cors, dotenv
//
// Установка:
// npm init -y
// npm i express sqlite3 bcrypt jsonwebtoken body-parser cors dotenv
// node app.js
//
// По умолчанию запускается на порту 4000 (переменная PORT в окружении).

const fs = require('fs');
const path = require('path');
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production';
const DB_FILE = process.env.DATABASE_FILE || path.join(__dirname, 'arizonarp.sqlite');

if (!fs.existsSync(DB_FILE)) {
  console.log('БД не найдена, будет создана:', DB_FILE);
}
const db = new sqlite3.Database(DB_FILE);

// Инициализация БД (создаёт таблицы, если их нет)
const initSql = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email TEXT,
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS news (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  author_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS threads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  author_id INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(author_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(thread_id) REFERENCES threads(id),
  FOREIGN KEY(author_id) REFERENCES users(id)
);
`;

db.exec(initSql, (err) => {
  if (err) console.error('Ошибка инициализации БД:', err);
  else console.log('База данных готова.');
  // Создадим тестового админа, если нет
  db.get("SELECT * FROM users WHERE username = ?", ['admin'], async (err, row) => {
    if (err) return console.error(err);
    if (!row) {
      const pw = 'admin123';
      const hash = await bcrypt.hash(pw, 10);
      db.run("INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, 'admin')",
        ['admin', hash, 'admin@arizona.local'], (err) => {
          if (err) console.error('Не удалось создать администратора:', err);
          else console.log('Создан тестовый администратор: admin / admin123');
        });
    }
  });
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

// --- Utility: JWT middleware ---
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid token' });
  const token = parts[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = payload; // { id, username, role }
    next();
  });
}

function adminOnly(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'No token' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// --- API: Auth ---
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
      [username, hash, email || null], function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) return res.status(400).json({ error: 'username exists' });
          return res.status(500).json({ error: 'db error', details: err.message });
        }
        const user = { id: this.lastID, username, role: 'user' };
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user });
      });
  } catch (e) {
    res.status(500).json({ error: 'server error', details: e.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  db.get("SELECT id, username, password_hash, role FROM users WHERE username = ?", [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(400).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(400).json({ error: 'invalid credentials' });
    const user = { id: row.id, username: row.username, role: row.role };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  db.get("SELECT id, username, email, role, created_at FROM users WHERE id = ?", [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ user: row });
  });
});

// --- API: News ---
app.get('/api/news', (req, res) => {
  db.all("SELECT n.id, n.title, n.content, n.created_at, u.username AS author FROM news n LEFT JOIN users u ON n.author_id = u.id ORDER BY n.created_at DESC LIMIT 50", [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

app.post('/api/news', authMiddleware, adminOnly, (req, res) => {
  const { title, content } = req.body || {};
  if (!title || !content) return res.status(400).json({ error: 'title and content required' });
  db.run("INSERT INTO news (title, content, author_id) VALUES (?, ?, ?)", [title, content, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ id: this.lastID, title, content });
  });
});

// --- API: Forum ---
app.get('/api/threads', (req, res) => {
  db.all(`SELECT t.id, t.title, t.created_at, u.username AS author,
    (SELECT COUNT(*) FROM posts p WHERE p.thread_id = t.id) AS replies
    FROM threads t JOIN users u ON t.author_id = u.id
    ORDER BY t.created_at DESC LIMIT 100`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

app.post('/api/threads', authMiddleware, (req, res) => {
  const { title } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  db.run("INSERT INTO threads (title, author_id) VALUES (?, ?)", [title, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: 'db error' });
    const tid = this.lastID;
    db.get("SELECT id, title, created_at FROM threads WHERE id = ?", [tid], (err, row) => {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json(row);
    });
  });
});

app.get('/api/thread/:id', (req, res) => {
  const tid = +req.params.id;
  db.get("SELECT t.id, t.title, t.created_at, u.username AS author FROM threads t JOIN users u ON t.author_id = u.id WHERE t.id = ?", [tid], (err, thread) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!thread) return res.status(404).json({ error: 'not found' });
    db.all("SELECT p.id, p.content, p.created_at, u.username AS author FROM posts p JOIN users u ON p.author_id = u.id WHERE p.thread_id = ? ORDER BY p.created_at ASC", [tid], (err, posts) => {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json({ thread, posts });
    });
  });
});

app.post('/api/thread/:id/post', authMiddleware, (req, res) => {
  const tid = +req.params.id;
  const { content } = req.body || {};
  if (!content) return res.status(400).json({ error: 'content required' });
  db.run("INSERT INTO posts (thread_id, author_id, content) VALUES (?, ?, ?)", [tid, req.user.id, content], function(err) {
    if (err) return res.status(500).json({ error: 'db error' });
    db.get("SELECT p.id, p.content, p.created_at, u.username AS author FROM posts p JOIN users u ON p.author_id = u.id WHERE p.id = ?", [this.lastID], (err, post) => {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json(post);
    });
  });
});

// --- API: Server status (просто демонстрация) ---
app.get('/api/servers', (req, res) => {
  // В реальности сюда можно подставить ping к игровому серверу, либо интеграцию с мониторингом.
  // Для демонстрации вернём пару фиктивных серверов с рандомной нагрузкой.
  const servers = [
    { id: 1, name: 'Arizona RP | Main', ip: 'play.arizona-rp.local', port: 7777, online: true, players: Math.floor(Math.random()*150) },
    { id: 2, name: 'Arizona RP | Roleplay 2', ip: 'rp2.arizona.local', port: 7778, online: Math.random()>0.2, players: Math.floor(Math.random()*80) },
  ];
  res.json(servers);
});

// --- Простая админ-панель (только интерфейс) ---
app.get('/api/admin/stats', authMiddleware, adminOnly, (req, res) => {
  db.get("SELECT COUNT(*) AS users FROM users", [], (err, u) => {
    if (err) return res.status(500).json({ error: 'db error' });
    db.get("SELECT COUNT(*) AS threads FROM threads", [], (err, t) => {
      if (err) return res.status(500).json({ error: 'db error' });
      db.get("SELECT COUNT(*) AS posts FROM posts", [], (err, p) => {
        if (err) return res.status(500).json({ error: 'db error' });
        res.json({ users: u.users, threads: t.threads, posts: p.posts });
      });
    });
  });
});

// --- Статика: отдать фронтенд — одностраничное приложение ---
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(indexHtml);
});

// --- Отдача веб-ресурсов (favicon) ---
app.get('/favicon.ico', (req, res) => res.status(204).end());

// --- Запуск ---
app.listen(PORT, () => {
  console.log(`Arizona RP demo site запущен: http://localhost:${PORT}`);
});

// ----------------------------------------------
// Встроенный фронтенд (HTML + CSS + JS)
// ----------------------------------------------
const indexHtml = 