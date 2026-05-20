import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcrypt';
import Database from 'better-sqlite3';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';
import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';

const require = createRequire(import.meta.url);
const SqliteStore = require('connect-sqlite3')(session);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.set('trust proxy', 1);

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Multer — memory storage, max 2MB
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Только изображения'));
    cb(null, true);
  }
});
const PORT = process.env.PORT || 3000;

// DOMPurify for server-side XSS sanitization
const window = new JSDOM('').window;
const purify = DOMPurify(window);

// ---- DATABASE ----
const db = new Database(path.join(__dirname, 'data.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    avatar_color TEXT NOT NULL DEFAULT '#4a76a8',
    bio TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS likes (
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    PRIMARY KEY(post_id, user_id),
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// ---- MIDDLEWARE ----
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
    }
  }
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Sessions
app.use(session({
  store: new SqliteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'kontakty-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 10,
  message: { error: 'Слишком много попыток. Подождите 15 минут.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const postLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 5,
  message: { error: 'Слишком много постов. Подождите минуту.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Слишком много запросов.' },
});

app.use('/api/', apiLimiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ---- HELPERS ----
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return purify.sanitize(str.trim());
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

function validateUsername(u) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(u);
}

function validatePassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 128;
}

const AVATAR_COLORS = ['#4a76a8','#e64646','#4caf50','#ff9800','#9c27b0','#00bcd4','#f44336','#3f51b5'];

// ---- AUTH ROUTES ----
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const username = sanitize(req.body.username || '').toLowerCase();
    const display_name = sanitize(req.body.display_name || '');
    const password = req.body.password || '';

    if (!validateUsername(username))
      return res.status(400).json({ error: 'Логин: 3-24 символа, только буквы/цифры/_' });
    if (!display_name || display_name.length < 2 || display_name.length > 50)
      return res.status(400).json({ error: 'Имя: 2-50 символов' });
    if (!validatePassword(password))
      return res.status(400).json({ error: 'Пароль: минимум 6 символов' });

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (existing) return res.status(400).json({ error: 'Логин уже занят' });

    const hash = await bcrypt.hash(password, 12);
    const color = AVATAR_COLORS[Math.floor(Math.random() * AVATAR_COLORS.length)];

    const result = db.prepare(
      'INSERT INTO users (username, display_name, password_hash, avatar_color) VALUES (?, ?, ?, ?)'
    ).run(username, display_name, hash, color);

    req.session.userId = result.lastInsertRowid;
    req.session.username = username;

    res.json({ ok: true, user: { id: result.lastInsertRowid, username, display_name, avatar_color: color } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const username = sanitize(req.body.username || '').toLowerCase();
    const password = req.body.password || '';

    if (!username || !password)
      return res.status(400).json({ error: 'Заполните все поля' });

    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    // Always run bcrypt to prevent timing attacks
    const hash = user ? user.password_hash : '$2b$12$invalid.hash.to.prevent.timing';
    const match = await bcrypt.compare(password, hash);

    if (!user || !match)
      return res.status(401).json({ error: 'Неверный логин или пароль' });

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ ok: true, user: { id: user.id, username: user.username, display_name: user.display_name, avatar_color: user.avatar_color } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, username, display_name, avatar_color, avatar_url, bio FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user: user || null });
});

// ---- POSTS ROUTES ----
app.get('/api/posts', (req, res) => {
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const limit = 20;
  const offset = (page - 1) * limit;

  const posts = db.prepare(`
    SELECT p.id, p.content, p.created_at,
           u.username, u.display_name, u.avatar_color,
           COUNT(l.post_id) as likes_count
    FROM posts p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN likes l ON l.post_id = p.id
    GROUP BY p.id
    ORDER BY p.created_at DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);

  // Check if current user liked each post
  const userId = req.session.userId;
  const result = posts.map(p => ({
    ...p,
    liked: userId ? !!db.prepare('SELECT 1 FROM likes WHERE post_id=? AND user_id=?').get(p.id, userId) : false
  }));

  res.json({ posts: result, page, hasMore: posts.length === limit });
});

app.post('/api/posts', requireAuth, postLimiter, (req, res) => {
  try {
    const content = sanitize(req.body.content || '');
    if (!content || content.length < 1)
      return res.status(400).json({ error: 'Пост не может быть пустым' });
    if (content.length > 1000)
      return res.status(400).json({ error: 'Максимум 1000 символов' });

    const result = db.prepare(
      'INSERT INTO posts (user_id, content) VALUES (?, ?)'
    ).run(req.session.userId, content);

    const post = db.prepare(`
      SELECT p.id, p.content, p.created_at,
             u.username, u.display_name, u.avatar_color
      FROM posts p JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `).get(result.lastInsertRowid);

    res.json({ ok: true, post: { ...post, likes_count: 0, liked: false } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const post = db.prepare('SELECT user_id FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });
  if (post.user_id !== req.session.userId) return res.status(403).json({ error: 'Нет прав' });
  db.prepare('DELETE FROM likes WHERE post_id = ?').run(req.params.id);
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', requireAuth, (req, res) => {
  const postId = parseInt(req.params.id);
  const userId = req.session.userId;
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(postId);
  if (!post) return res.status(404).json({ error: 'Пост не найден' });

  const existing = db.prepare('SELECT 1 FROM likes WHERE post_id=? AND user_id=?').get(postId, userId);
  if (existing) {
    db.prepare('DELETE FROM likes WHERE post_id=? AND user_id=?').run(postId, userId);
  } else {
    db.prepare('INSERT INTO likes (post_id, user_id) VALUES (?, ?)').run(postId, userId);
  }
  const count = db.prepare('SELECT COUNT(*) as c FROM likes WHERE post_id=?').get(postId).c;
  res.json({ ok: true, liked: !existing, likes_count: count });
});

// ---- PROFILE ROUTES ----

// Get profile
app.get('/api/profile/:username', (req, res) => {
  const user = db.prepare(
    'SELECT id, username, display_name, avatar_color, avatar_url, bio, created_at FROM users WHERE username = ?'
  ).get(req.params.username);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  const postCount = db.prepare('SELECT COUNT(*) as c FROM posts WHERE user_id = ?').get(user.id).c;
  res.json({ user: { ...user, post_count: postCount } });
});

// Update profile
app.put('/api/profile', requireAuth, rateLimit({ windowMs: 60*1000, max: 5 }), async (req, res) => {
  try {
    const display_name = sanitize(req.body.display_name || '');
    const bio = sanitize(req.body.bio || '');
    const avatar_color = req.body.avatar_color || '';

    if (display_name && (display_name.length < 2 || display_name.length > 50))
      return res.status(400).json({ error: 'Имя: 2-50 символов' });
    if (bio.length > 200)
      return res.status(400).json({ error: 'Описание: максимум 200 символов' });
    if (avatar_color && !/^#[0-9a-fA-F]{6}$/.test(avatar_color))
      return res.status(400).json({ error: 'Неверный цвет' });

    const updates = [];
    const values = [];
    if (display_name) { updates.push('display_name = ?'); values.push(display_name); }
    if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
    if (avatar_color) { updates.push('avatar_color = ?'); values.push(avatar_color); }
    if (!updates.length) return res.status(400).json({ error: 'Нечего обновлять' });

    values.push(req.session.userId);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);

    const user = db.prepare('SELECT id, username, display_name, avatar_color, avatar_url, bio FROM users WHERE id = ?').get(req.session.userId);
    res.json({ ok: true, user });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Upload avatar
app.post('/api/profile/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });

    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder: 'kontakty_avatars',
          public_id: `user_${req.session.userId}`,
          overwrite: true,
          transformation: [{ width: 200, height: 200, crop: 'fill', gravity: 'face' }],
          format: 'webp',
        },
        (err, result) => err ? reject(err) : resolve(result)
      );
      stream.end(req.file.buffer);
    });

    db.prepare('UPDATE users SET avatar_url = ? WHERE id = ?').run(result.secure_url, req.session.userId);
    res.json({ ok: true, avatar_url: result.secure_url });
  } catch(e) {
    console.error(e);
    res.status(500).json({ error: 'Ошибка загрузки' });
  }
});

// ---- SERVE FRONTEND ----
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Kontakty running on port ${PORT}`));
