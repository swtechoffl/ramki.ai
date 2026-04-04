'use strict';

require('dotenv').config(); // loads .env file in development

// ═══════════════════════════════════════════════════════════
//  RAMKI WEBSITE — Supabase Backend
//  Database  : Supabase (PostgreSQL)
//  Storage   : Supabase Storage (bucket: uploads)
//  Auth      : JWT in HttpOnly signed cookie
//  Hosting   : Hostinger Node.js
// ═══════════════════════════════════════════════════════════

const express      = require('express');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const bcrypt       = require('bcryptjs');
const multer       = require('multer');
const path         = require('path');
const crypto       = require('crypto');
const fileType     = require('file-type');
const nodemailer   = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

const app  = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════
//  SUPABASE CLIENT
// ═══════════════════════════════════════════════════════════
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('\n❌  FATAL: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set.');
  console.error('    See .env.example for required variables.\n');
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  { auth: { persistSession: false } }
);

// ═══════════════════════════════════════════════════════════
//  JWT & COOKIE CONFIG
// ═══════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('\n❌  FATAL: JWT_SECRET environment variable is not set.');
    console.error('    Generate one: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"\n');
    process.exit(1);
  }
  console.warn('\n⚠️  WARNING: JWT_SECRET not set. Using ephemeral random secret (dev only).\n');
}
const EFFECTIVE_SECRET = JWT_SECRET || crypto.randomBytes(64).toString('hex');
const COOKIE_SECRET    = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_COOKIE       = 'ramki_token';
const JWT_EXPIRY       = '7d';
const JWT_EXPIRY_S     = 7 * 24 * 60 * 60;

// ═══════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════

// Validate UUID format (Supabase primary keys)
function sanitiseId(id) {
  if (typeof id !== 'string') return null;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return null;
  return id;
}

// Map Supabase row to frontend-compatible shape (snake_case → camelCase, id → _id)
function mapBlog(doc) {
  if (!doc) return null;
  const { id, created_at, updated_at, ...rest } = doc;
  return { ...rest, _id: id, createdAt: created_at, updatedAt: updated_at };
}

// Delete file from Supabase Storage by public URL
async function deleteStorageFile(publicUrl) {
  if (!publicUrl) return;
  try {
    const marker = '/storage/v1/object/public/uploads/';
    const idx = publicUrl.indexOf(marker);
    if (idx !== -1) {
      await supabase.storage.from('uploads').remove([publicUrl.slice(idx + marker.length)]);
    }
  } catch (e) {
    console.error('[STORAGE] Delete failed:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════
//  SEED (first run only)
// ═══════════════════════════════════════════════════════════
async function seed() {
  // Admin user
  const { data: users } = await supabase.from('users').select('id').limit(1);
  if (!users || users.length === 0) {
    const pw = crypto.randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '').slice(0, 14);
    await supabase.from('users').insert({
      username: 'ramki',
      password: bcrypt.hashSync(pw, 12),
      role    : 'admin',
    });
    console.log('\n' + '═'.repeat(55));
    console.log('  🔐  FIRST RUN — ADMIN CREDENTIALS (one-time display)');
    console.log('  Username : ramki');
    console.log(`  Password : ${pw}`);
    console.log('  ⚠️  Change this password immediately after first login!');
    console.log('═'.repeat(55) + '\n');
  }

  // Default site settings
  const { data: settings } = await supabase.from('settings').select('id').eq('key', 'site').maybeSingle();
  if (!settings) {
    await supabase.from('settings').insert({
      key  : 'site',
      value: {
        title    : 'RAMKI — Ramakrishnan T.B.',
        sebi     : 'INH000010496',
        email    : 'grievance@sharewealthindia.com',
        heroPhoto: '',
      },
    });
  }
}

// ═══════════════════════════════════════════════════════════
//  SECURITY MIDDLEWARE STACK
// ═══════════════════════════════════════════════════════════

// 1. HTTPS redirect (production)
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' &&
      req.headers['x-forwarded-proto'] !== 'https' &&
      req.hostname !== 'localhost') {
    return res.redirect(301, `https://${req.hostname}${req.url}`);
  }
  next();
});

// 2. Helmet — security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc   : ["'self'"],
      scriptSrc    : ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc     : ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc      : ["'self'", 'https://fonts.gstatic.com'],
      imgSrc       : ["'self'", 'data:', 'blob:', 'https:'], // https: allows Supabase Storage URLs
      connectSrc   : ["'self'"],
      frameSrc     : ["'none'"],
      objectSrc    : ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
  },
  hsts: process.env.NODE_ENV === 'production'
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false,
  frameguard            : { action: 'deny' },
  noSniff               : true,
  referrerPolicy        : { policy: 'strict-origin-when-cross-origin' },
  xssFilter             : true,
  hidePoweredBy         : true,
  crossOriginEmbedderPolicy: false,
}));

// 3. Cookie parser (signed cookies)
app.use(cookieParser(COOKIE_SECRET));

// 4. JSON body parser
app.use(express.json({ limit: '50kb' }));

// 5. Static files
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════
//  RATE LIMITERS
// ═══════════════════════════════════════════════════════════
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  handler: (req, res, _next, options) => {
    console.warn(`[SECURITY] Login rate limit hit from IP: ${req.ip}`);
    res.status(429).json(options.message);
  },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 200,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Rate limit exceeded. Please slow down.' },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 20,
  message: { error: 'Upload limit exceeded. Maximum 20 uploads per hour.' },
});

const analyticsLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { ok: true },
});

app.use('/api/', apiLimiter);

// ═══════════════════════════════════════════════════════════
//  MULTER — MEMORY STORAGE + SUPABASE STORAGE UPLOAD
// ═══════════════════════════════════════════════════════════
const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_, file, cb) => {
    ALLOWED_MIME_TYPES.has(file.mimetype)
      ? cb(null, true)
      : cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'), false);
  },
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
});

// Validates magic bytes then uploads to Supabase Storage
async function validateAndUpload(req, res, next) {
  if (!req.file) return next();
  try {
    const type = await fileType.fromBuffer(req.file.buffer);
    if (!type || !ALLOWED_MIME_TYPES.has(type.mime)) {
      return res.status(400).json({ error: 'File content does not match an allowed image format.' });
    }
    const filename = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}.${type.ext}`;
    const { error } = await supabase.storage
      .from('uploads')
      .upload(filename, req.file.buffer, { contentType: type.mime, upsert: false });
    if (error) throw new Error('Storage upload failed: ' + error.message);
    const { data: { publicUrl } } = supabase.storage.from('uploads').getPublicUrl(filename);
    req.uploadedUrl = publicUrl;
    next();
  } catch (err) {
    next(err);
  }
}

// ═══════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════
function setAuthCookie(res, token) {
  res.cookie(JWT_COOKIE, token, {
    httpOnly: true,
    secure  : process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    signed  : true,
    maxAge  : JWT_EXPIRY_S * 1000,
  });
}

async function auth(req, res, next) {
  const token = req.signedCookies?.[JWT_COOKIE] || req.cookies?.[JWT_COOKIE];
  if (!token) return res.status(401).json({ error: 'Authentication required.' });

  let payload;
  try {
    payload = jwt.verify(token, EFFECTIVE_SECRET);
  } catch {
    res.clearCookie(JWT_COOKIE);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }

  if (payload.jti) {
    const { data } = await supabase.from('revoked_tokens').select('id').eq('jti', payload.jti).maybeSingle();
    if (data) {
      res.clearCookie(JWT_COOKIE);
      return res.status(401).json({ error: 'Session has been revoked. Please log in again.' });
    }
  }

  req.user = payload;
  next();
}

// ═══════════════════════════════════════════════════════════
//  CSRF TOKEN
// ═══════════════════════════════════════════════════════════
app.get('/api/csrf-token', (req, res) => {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  res.cookie('_csrf', csrfToken, {
    httpOnly: false,
    secure  : process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    signed  : true,
    maxAge  : 3600000,
  });
  res.json({ csrfToken });
});

// ═══════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password ||
      typeof username !== 'string' || typeof password !== 'string' ||
      username.length > 64 || password.length > 128) {
    return res.status(400).json({ error: 'Invalid input.' });
  }

  try {
    const { data: user } = await supabase
      .from('users').select('*').eq('username', username.trim().toLowerCase()).maybeSingle();

    // Always run bcrypt to prevent timing attacks
    const hashToCheck = user?.password || '$2a$12$invalidsaltinvalidhashXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const match = bcrypt.compareSync(password, hashToCheck);

    if (!user || !match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const jti   = crypto.randomBytes(16).toString('hex');
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, jti },
      EFFECTIVE_SECRET,
      { expiresIn: JWT_EXPIRY }
    );
    setAuthCookie(res, token);
    res.json({ user: { username: user.username, role: user.role } });
  } catch {
    res.status(500).json({ error: 'Authentication failed.' });
  }
});

app.post('/api/logout', auth, async (req, res) => {
  if (req.user?.jti) {
    const expiresAt = new Date(Date.now() + JWT_EXPIRY_S * 1000 + 3600000).toISOString();
    await supabase.from('revoked_tokens').insert({ jti: req.user.jti, expires_at: expiresAt });
  }
  res.clearCookie(JWT_COOKIE);
  res.json({ success: true });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ user: { username: req.user.username, role: req.user.role } });
});

app.post('/api/change-password', auth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword ||
      typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (newPassword.length < 8)   return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  if (newPassword.length > 128) return res.status(400).json({ error: 'Password too long.' });
  if (!/[a-zA-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
    return res.status(400).json({ error: 'Password must contain at least one letter and one number.' });
  }

  try {
    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).maybeSingle();
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (!bcrypt.compareSync(currentPassword, user.password)) {
      return res.status(403).json({ error: 'Current password is incorrect.' });
    }

    await supabase.from('users').update({
      password  : bcrypt.hashSync(newPassword, 12),
      updated_at: new Date().toISOString(),
    }).eq('id', req.user.id);

    if (req.user?.jti) {
      const expiresAt = new Date(Date.now() + JWT_EXPIRY_S * 1000 + 3600000).toISOString();
      await supabase.from('revoked_tokens').insert({ jti: req.user.jti, expires_at: expiresAt });
    }
    res.clearCookie(JWT_COOKIE);
    res.json({ success: true, message: 'Password changed. Please log in with your new password.' });
  } catch {
    res.status(500).json({ error: 'Failed to update password.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  BLOG ROUTES
// ═══════════════════════════════════════════════════════════
app.get('/api/blogs', async (req, res) => {
  try {
    let query = supabase.from('blogs').select('*').eq('status', 'published').order('created_at', { ascending: false });

    if (req.query.category && req.query.category !== 'all') {
      const allowed = ['Market Analysis','Equity Research','Commodities','Portfolio Strategy','AI & Finance','Economy','Investor Education'];
      if (allowed.includes(req.query.category)) query = query.eq('category', req.query.category);
    }

    const { data, error } = await query;
    if (error) throw error;
    res.json((data || []).map(mapBlog));
  } catch {
    res.status(500).json({ error: 'Failed to fetch blogs.' });
  }
});

app.get('/api/admin/blogs', auth, async (_, res) => {
  try {
    const { data, error } = await supabase.from('blogs').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(mapBlog));
  } catch {
    res.status(500).json({ error: 'Failed to fetch blogs.' });
  }
});

app.get('/api/blogs/:id', async (req, res) => {
  const id = sanitiseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID.' });

  try {
    const { data, error } = await supabase.from('blogs').select('*').eq('id', id).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Not found.' });

    await supabase.from('blogs').update({ views: (data.views || 0) + 1 }).eq('id', id);
    res.json(mapBlog({ ...data, views: (data.views || 0) + 1 }));
  } catch {
    res.status(500).json({ error: 'Failed to fetch blog.' });
  }
});

app.post('/api/blogs', auth, upload.single('photo'), validateAndUpload, async (req, res) => {
  const { title, category, excerpt, content, emoji, status, tags } = req.body;
  if (!title || typeof title !== 'string' || title.trim().length === 0) {
    return res.status(400).json({ error: 'Title is required.' });
  }

  const allowedStatuses    = ['draft', 'published'];
  const allowedCategories  = ['Market Analysis','Equity Research','Commodities','Portfolio Strategy','AI & Finance','Economy','Investor Education','Article'];

  try {
    const { data, error } = await supabase.from('blogs').insert({
      title   : title.trim().slice(0, 200),
      category: allowedCategories.includes(category) ? category : 'Article',
      excerpt : typeof excerpt === 'string' ? excerpt.slice(0, 500) : '',
      content : typeof content === 'string' ? content.slice(0, 50000) : '',
      emoji   : typeof emoji === 'string' ? emoji.slice(0, 8) : '📊',
      status  : allowedStatuses.includes(status) ? status : 'draft',
      tags    : typeof tags === 'string' ? tags.split(',').map(t => t.trim()).filter(Boolean).slice(0, 10) : [],
      photo   : req.uploadedUrl || '',
      views   : 0,
    }).select().single();

    if (error) throw error;
    res.json(mapBlog(data));
  } catch {
    res.status(500).json({ error: 'Failed to create blog.' });
  }
});

app.put('/api/blogs/:id', auth, upload.single('photo'), validateAndUpload, async (req, res) => {
  const id = sanitiseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID.' });

  const { title, category, excerpt, content, emoji, status, tags, removePhoto } = req.body;
  const allowedStatuses    = ['draft', 'published'];
  const allowedCategories  = ['Market Analysis','Equity Research','Commodities','Portfolio Strategy','AI & Finance','Economy','Investor Education','Article'];

  try {
    const { data: existing } = await supabase.from('blogs').select('*').eq('id', id).maybeSingle();
    if (!existing) return res.status(404).json({ error: 'Not found.' });

    if ((req.uploadedUrl || removePhoto === 'true') && existing.photo) {
      await deleteStorageFile(existing.photo);
    }

    const u = {
      title     : title ? title.trim().slice(0, 200) : existing.title,
      category  : allowedCategories.includes(category) ? category : existing.category,
      excerpt   : typeof excerpt === 'string' ? excerpt.slice(0, 500) : existing.excerpt,
      content   : typeof content === 'string' ? content.slice(0, 50000) : existing.content,
      emoji     : typeof emoji === 'string' ? emoji.slice(0, 8) : existing.emoji,
      status    : allowedStatuses.includes(status) ? status : existing.status,
      tags      : typeof tags === 'string' ? tags.split(',').map(t => t.trim()).filter(Boolean).slice(0, 10) : existing.tags,
      photo     : req.uploadedUrl || (removePhoto === 'true' ? '' : existing.photo),
      updated_at: new Date().toISOString(),
    };

    const { data, error } = await supabase.from('blogs').update(u).eq('id', id).select().single();
    if (error) throw error;
    res.json(mapBlog(data));
  } catch {
    res.status(500).json({ error: 'Update failed.' });
  }
});

app.patch('/api/blogs/:id/toggle', auth, async (req, res) => {
  const id = sanitiseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID.' });

  try {
    const { data: doc } = await supabase.from('blogs').select('status').eq('id', id).maybeSingle();
    if (!doc) return res.status(404).json({ error: 'Not found.' });

    const newStatus = doc.status === 'published' ? 'draft' : 'published';
    await supabase.from('blogs').update({ status: newStatus, updated_at: new Date().toISOString() }).eq('id', id);
    res.json({ status: newStatus });
  } catch {
    res.status(500).json({ error: 'Update failed.' });
  }
});

app.delete('/api/blogs/:id', auth, async (req, res) => {
  const id = sanitiseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID.' });

  try {
    const { data: doc } = await supabase.from('blogs').select('photo').eq('id', id).maybeSingle();
    if (doc?.photo) await deleteStorageFile(doc.photo);
    await supabase.from('blogs').delete().eq('id', id);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Delete failed.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  UPLOAD ROUTES
// ═══════════════════════════════════════════════════════════
app.post('/api/upload/hero-photo', auth, uploadLimiter, upload.single('photo'), validateAndUpload, async (req, res) => {
  if (!req.uploadedUrl) return res.status(400).json({ error: 'No file provided.' });

  try {
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    if (settings?.value?.heroPhoto) await deleteStorageFile(settings.value.heroPhoto);

    const newValue = { ...(settings?.value || {}), heroPhoto: req.uploadedUrl };
    await supabase.from('settings').update({ value: newValue }).eq('key', 'site');
    res.json({ url: req.uploadedUrl });
  } catch {
    res.status(500).json({ error: 'Upload failed.' });
  }
});

app.delete('/api/upload/hero-photo', auth, async (req, res) => {
  try {
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    if (settings?.value?.heroPhoto) await deleteStorageFile(settings.value.heroPhoto);
    const newValue = { ...(settings?.value || {}), heroPhoto: '' };
    await supabase.from('settings').update({ value: newValue }).eq('key', 'site');
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to remove photo.' });
  }
});

app.post('/api/upload/about-photo', auth, uploadLimiter, upload.single('photo'), validateAndUpload, async (req, res) => {
  if (!req.uploadedUrl) return res.status(400).json({ error: 'No file provided.' });
  try {
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    if (settings?.value?.aboutPhoto) await deleteStorageFile(settings.value.aboutPhoto);
    const newValue = { ...(settings?.value || {}), aboutPhoto: req.uploadedUrl };
    await supabase.from('settings').update({ value: newValue }).eq('key', 'site');
    res.json({ url: req.uploadedUrl });
  } catch {
    res.status(500).json({ error: 'Upload failed.' });
  }
});

app.delete('/api/upload/about-photo', auth, async (_, res) => {
  try {
    const { data: settings } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    if (settings?.value?.aboutPhoto) await deleteStorageFile(settings.value.aboutPhoto);
    const newValue = { ...(settings?.value || {}), aboutPhoto: '' };
    await supabase.from('settings').update({ value: newValue }).eq('key', 'site');
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to remove photo.' });
  }
});

app.post('/api/upload/blog-image', auth, uploadLimiter, upload.single('image'), validateAndUpload, (req, res) => {
  if (!req.uploadedUrl) return res.status(400).json({ error: 'No file provided.' });
  res.json({ url: req.uploadedUrl });
});

// ═══════════════════════════════════════════════════════════
//  ANALYTICS
// ═══════════════════════════════════════════════════════════
app.post('/api/analytics/pageview', analyticsLimiter, async (req, res) => {
  res.json({ ok: true }); // respond immediately, track async
  try {
    const today    = new Date().toISOString().split('T')[0];
    const dailyKey = `daily:${today}`;

    const { data: daily } = await supabase.from('analytics').select('*').eq('key', dailyKey).maybeSingle();
    if (daily) {
      await supabase.from('analytics').update({ count: (daily.count || 0) + 1 }).eq('key', dailyKey);
    } else {
      await supabase.from('analytics').insert({ key: dailyKey, count: 1, page_views: 0 });
    }

    const { data: total } = await supabase.from('analytics').select('*').eq('key', 'total').maybeSingle();
    if (total) {
      await supabase.from('analytics').update({ page_views: (total.page_views || 0) + 1 }).eq('key', 'total');
    } else {
      await supabase.from('analytics').insert({ key: 'total', count: 0, page_views: 1 });
    }
  } catch {}
});

app.get('/api/analytics', auth, async (_, res) => {
  try {
    const days = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      days.push(d.toISOString().split('T')[0]);
    }

    const [
      { data: dailyRows },
      { data: totalRow  },
      { count: pub      },
      { count: dr       },
      { count: all      },
      { data: recent    },
    ] = await Promise.all([
      supabase.from('analytics').select('*').in('key', days.map(d => `daily:${d}`)),
      supabase.from('analytics').select('*').eq('key', 'total').maybeSingle(),
      supabase.from('blogs').select('*', { count: 'exact', head: true }).eq('status', 'published'),
      supabase.from('blogs').select('*', { count: 'exact', head: true }).eq('status', 'draft'),
      supabase.from('blogs').select('*', { count: 'exact', head: true }),
      supabase.from('blogs').select('*').order('created_at', { ascending: false }).limit(5),
    ]);

    const dm = {};
    (dailyRows || []).forEach(r => { dm[r.key.replace('daily:', '')] = r.count; });

    res.json({
      pageViews     : totalRow?.page_views || 0,
      publishedBlogs: pub || 0,
      draftBlogs    : dr  || 0,
      totalBlogs    : all || 0,
      dailyViews    : days.map(d => ({ date: d, count: dm[d] || 0 })),
      recentBlogs   : (recent || []).map(mapBlog),
    });
  } catch {
    res.status(500).json({ error: 'Failed to fetch analytics.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  CONTACT / EMAIL
// ═══════════════════════════════════════════════════════════

// Strict limiter: 5 messages per hour per IP
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  message: { error: 'Too many messages sent. Please try again in an hour.' },
});

// Lazy-create transporter so server starts even if SMTP is not configured
function createTransporter() {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null;
  return nodemailer.createTransport({
    host  : process.env.SMTP_HOST,
    port  : parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_PORT === '465',
    auth  : { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

app.post('/api/contact', contactLimiter, async (req, res) => {
  const { name, email, phone, subject, message } = req.body;

  // Basic validation
  if (!name || !email || !message ||
      typeof name !== 'string' || typeof email !== 'string' || typeof message !== 'string') {
    return res.status(400).json({ error: 'Name, email and message are required.' });
  }
  if (name.length > 100 || email.length > 200 || message.length > 3000) {
    return res.status(400).json({ error: 'Input too long.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  const transporter = createTransporter();
  if (!transporter) {
    console.warn('[CONTACT] SMTP not configured — message not delivered.');
    // Still return success so the UX is not broken during development
    return res.json({ success: true, note: 'SMTP not configured.' });
  }

  const toEmail   = process.env.CONTACT_EMAIL || 'grievance@sharewealthindia.com';
  const safePhone = typeof phone === 'string' ? phone.slice(0, 20).replace(/[^0-9+\-() ]/g, '') : '—';
  const safeSubj  = typeof subject === 'string' ? subject.slice(0, 100) : 'General Enquiry';

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f8f8f8;padding:32px;border-radius:12px">
      <div style="background:linear-gradient(135deg,#6C63FF,#00D4FF);padding:24px 28px;border-radius:8px 8px 0 0;margin:-32px -32px 24px">
        <h2 style="color:#fff;margin:0;font-size:20px">New Message — RAMKI Website</h2>
        <p style="color:rgba(255,255,255,.75);margin:4px 0 0;font-size:13px">Via the contact form</p>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <tr><td style="padding:10px 0;color:#888;width:100px;vertical-align:top">Name</td><td style="padding:10px 0;color:#111;font-weight:600">${name}</td></tr>
        <tr><td style="padding:10px 0;color:#888;vertical-align:top">Email</td><td style="padding:10px 0"><a href="mailto:${email}" style="color:#6C63FF">${email}</a></td></tr>
        <tr><td style="padding:10px 0;color:#888;vertical-align:top">Phone</td><td style="padding:10px 0;color:#111">${safePhone}</td></tr>
        <tr><td style="padding:10px 0;color:#888;vertical-align:top">Subject</td><td style="padding:10px 0;color:#111">${safeSubj}</td></tr>
      </table>
      <div style="background:#fff;border:1px solid #e8e8e8;border-radius:8px;padding:20px;margin-top:16px">
        <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#888;margin-bottom:10px">Message</div>
        <p style="font-size:14px;color:#222;line-height:1.7;margin:0;white-space:pre-wrap">${message.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</p>
      </div>
      <div style="margin-top:20px;padding:14px 16px;background:#fff3cd;border-radius:8px;font-size:12px;color:#856404">
        Reply directly to this email to respond to ${name}.
      </div>
    </div>`;

  try {
    await transporter.sendMail({
      from   : `"RAMKI Website" <${process.env.SMTP_USER}>`,
      to     : toEmail,
      replyTo: `"${name}" <${email}>`,
      subject: `[RAMKI] ${safeSubj} — from ${name}`,
      html,
    });
    res.json({ success: true });
  } catch (e) {
    console.error('[CONTACT] Email send failed:', e.message);
    res.status(500).json({ error: 'Failed to send message. Please try again or email directly.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════════════════
app.get('/api/settings', async (_, res) => {
  try {
    const { data } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    res.json(data?.value || {});
  } catch {
    res.json({});
  }
});

app.put('/api/settings', auth, async (req, res) => {
  const allowed = ['title', 'sebi', 'email', 'heroPhoto', 'aboutPhoto'];
  const safe    = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) safe[k] = String(req.body[k]).slice(0, 200); });

  try {
    const { data: existing } = await supabase.from('settings').select('value').eq('key', 'site').maybeSingle();
    const newValue = { ...(existing?.value || {}), ...safe };
    await supabase.from('settings').upsert({ key: 'site', value: newValue });
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Failed to save settings.' });
  }
});

// ═══════════════════════════════════════════════════════════
//  ERROR HANDLERS
// ═══════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: 'File too large. Maximum size is 8MB.' });
    return res.status(400).json({ error: 'File upload error.' });
  }
  if (err?.message?.includes('Invalid file type')) {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

app.use((err, req, res, _next) => {
  const isDev = process.env.NODE_ENV !== 'production';
  console.error('[ERROR]', err.message, isDev ? err.stack : '');
  res.status(err.status || 500).json({ error: isDev ? err.message : 'An unexpected error occurred.' });
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Endpoint not found.' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ═══════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════
seed()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`\n✅  RAMKI site running → http://localhost:${PORT}`);
      console.log(`   Mode     : ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Supabase : ${process.env.SUPABASE_URL}`);
      console.log(`   JWT      : ${JWT_SECRET ? 'from environment ✓' : 'ephemeral (dev only) ⚠️'}\n`);
    });
  })
  .catch(err => {
    console.error('Startup failed:', err.message);
    process.exit(1);
  });
