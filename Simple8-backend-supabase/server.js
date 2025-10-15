// server.js — Supabase-backed auth API (CORS & anti-cache ready)

require('dotenv').config(); // an toàn khi chạy local; trên Render không bắt buộc

// ===== Imports =====
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const morgan = require('morgan');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

// ===== Env =====
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_CODE  = process.env.ADMIN_CODE  || '';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE =
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE || '';

const PERMISSIVE_CORS = String(process.env.PERMISSIVE_CORS || 'true').toLowerCase() === 'true';

// ===== Guards =====
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn('[WARN] Missing SUPABASE_URL or SERVICE_ROLE key — please set on Render.');
}

// ===== Supabase admin client (server-side) =====
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false, autoRefreshToken: false }
});

// ===== App =====
const app = express();

// ===== Anti-cache for API responses (đặt rất sớm) =====
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ===== CORS =====
const ALLOWED_ORIGINS = [
  'https://phongnews.netlify.app',
  'http://localhost:5173',
  'http://localhost:3000'
];

app.use((req, res, next) => {
  if (PERMISSIVE_CORS) {
    // Dễ dãi: mở cho tất cả origin (KHÔNG dùng credentials)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  } else {
    // Whitelist: chỉ các origin đã cho phép
    const origin = req.headers.origin;
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin || 'https://phongnews.netlify.app');
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      // chỉ bật khi thật sự dùng cookies/credentials từ frontend:
      // res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204); // trả preflight sớm
  next();
});

// ===== Parsers & logger =====
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan('tiny'));

// ===== SMTP transporter (optional) =====
function getTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) return null;
  return nodemailer.createTransport({
    host, port, secure,
    auth: { user, pass }
  });
}

async function sendMail({ to, subject, text, html }) {
  try {
    const tp = getTransporter();
    if (!tp) return; // không có cấu hình SMTP thì bỏ qua
    await tp.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to, subject, text, html
    });
  } catch (e) {
    console.error('[mail]', e);
  }
}

// ===== Helpers =====
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function auth(req, res, next) {
  const m = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ===== Health & probe =====
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));
app.post('/api/__cors_probe', (req, res) => res.json({ ok: true, path: '/api/__cors_probe' }));

// ===== Auth routes =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Thiếu trường bắt buộc' });
    }
    const lower = String(email).trim().toLowerCase();

    const { data: exist, error: e1 } =
      await supabase.from('users').select('id').eq('email', lower).maybeSingle();
    if (e1) throw e1;
    if (exist) return res.status(400).json({ message: 'Email đã tồn tại' });

    const pass_hash = await bcrypt.hash(password, 8);
    const { error: e2 } =
      await supabase.from('users').insert({ name, email: lower, pass_hash, approved: false });
    if (e2) throw e2;

    // Thông báo cho admin (nếu cấu hình)
    if (ADMIN_EMAIL) {
      await sendMail({
        to: ADMIN_EMAIL,
        subject: '[PhongNew] Đăng ký mới',
        text: `Người dùng mới: ${name} <${lower}>. Dùng ADMIN_CODE để duyệt qua /api/auth/approve.`
      });
    }

    res.json({ message: 'Đăng ký thành công. Vui lòng đợi admin phê duyệt.' });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// Approve
app.post('/api/auth/approve', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ message: 'Thiếu email hoặc code' });
    if (String(code) !== String(ADMIN_CODE)) return res.status(403).json({ message: 'Sai ADMIN_CODE' });

    const lower = String(email).trim().toLowerCase();
    const { error } = await supabase.from('users').update({ approved: true }).eq('email', lower);
    if (error) throw error;

    res.json({ message: 'Đã duyệt' });
  } catch (e) {
    console.error('[approve]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    if (!lower || !password) return res.status(400).json({ message: 'Thiếu email hoặc mật khẩu' });

    const { data: u, error } =
      await supabase.from('users')
        .select('id,name,email,pass_hash,approved')
        .eq('email', lower)
        .maybeSingle();
    if (error) throw error;
    if (!u) return res.status(400).json({ message: 'Email hoặc mật khẩu sai' });
    if (!u.approved) return res.status(403).json({ message: 'Tài khoản chưa được duyệt' });

    const ok = await bcrypt.compare(password, u.pass_hash || '');
    if (!ok) return res.status(400).json({ message: 'Email hoặc mật khẩu sai' });

    const token = signToken({ uid: u.id, email: u.email, name: u.name });
    res.json({ token, user: { id: u.id, email: u.email, name: u.name } });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// Forgot
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    if (!lower) return res.status(400).json({ message: 'Thiếu email' });

    const { data: u, error } =
      await supabase.from('users').select('id,email').eq('email', lower).maybeSingle();
    if (error) throw error;

    if (u) {
      const token = crypto.randomBytes(24).toString('hex');
      const expires_at = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30 phút
      const { error: e2 } = await supabase.from('resets').insert({ email: lower, token, expires_at });
      if (e2) throw e2;

      await sendMail({
        to: lower,
        subject: 'Đặt lại mật khẩu',
        text: `Mã đặt lại: ${token}\nHết hạn sau 30 phút.`
      });
    }

    res.json({ message: 'Nếu email tồn tại, chúng tôi đã gửi hướng dẫn.' });
  } catch (e) {
    console.error('[forgot]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// Reset
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    if (!lower || !token || !newPassword) {
      return res.status(400).json({ message: 'Thiếu thông tin' });
    }

    const { data: r, error } =
      await supabase.from('resets')
        .select('id,expires_at')
        .eq('email', lower)
        .eq('token', token)
        .maybeSingle();
    if (error) throw error;
    if (!r) return res.status(400).json({ message: 'Token không hợp lệ' });
    if (new Date(r.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ message: 'Token đã hết hạn' });
    }

    const pass_hash = await bcrypt.hash(newPassword, 8);
    const { error: e2 } = await supabase.from('users').update({ pass_hash }).eq('email', lower);
    if (e2) throw e2;

    await supabase.from('resets').delete().eq('id', r.id);
    res.json({ message: 'Đã đặt lại mật khẩu' });
  } catch (e) {
    console.error('[reset]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// Change password (auth)
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!newPassword) return res.status(400).json({ message: 'Thiếu mật khẩu mới' });

    const { data: u, error } =
      await supabase.from('users').select('id,pass_hash').eq('id', req.user.uid).maybeSingle();
    if (error) throw error;
    if (!u) return res.status(404).json({ message: 'Không tìm thấy người dùng' });

    if (u.pass_hash) {
      const ok = await bcrypt.compare(oldPassword || '', u.pass_hash);
      if (!ok) return res.status(400).json({ message: 'Mật khẩu cũ không đúng' });
    }

    const pass_hash = await bcrypt.hash(newPassword, 8);
    const { error: e2 } = await supabase.from('users').update({ pass_hash }).eq('id', req.user.uid);
    if (e2) throw e2;

    res.json({ message: 'Đã đổi mật khẩu' });
  } catch (e) {
    console.error('[change-password]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// ===== Error handler (cuối cùng) =====
app.use((err, req, res, next) => {
  console.error('ERR:', err);
  res.status(500).json({ message: 'Internal error' });
});

// ===== Start =====
app.listen(PORT, () => {
  console.log(`[server] running on port ${PORT}`);
});
