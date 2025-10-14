
// server.js — Supabase-backed storage
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const morgan = require('morgan');
require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');

// --- ENV ---
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_CODE = process.env.ADMIN_CODE || '';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

// Supabase admin client (server-side only)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// --- App ---
const app = express();
app.use(express.json());
app.use(morgan('tiny'));

// --- Mailer ---
function getTransporter() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) return null;
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: false,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}
async function sendMail({ to, subject, text, html }) {
  const tp = getTransporter();
  if (!tp) return;
  await tp.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to, subject, text, html,
  });
}

// --- Helpers ---
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ message: 'Missing token' });
  try {
    req.user = jwt.verify(m[1], JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// --- Health ---
app.get('/api/health', (req, res) => res.json({ ok: true }));

// --- Register ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ message: 'Thiếu trường bắt buộc' });

    const lower = String(email).trim().toLowerCase();
    // check existing
    const { data: exist, error: e1 } = await supabase.from('users').select('id').eq('email', lower).maybeSingle();
    if (e1) throw e1;
    if (exist) return res.status(400).json({ message: 'Email đã tồn tại' });

    const pass_hash = await bcrypt.hash(password, 8);
    const { error: e2 } = await supabase.from('users').insert({ name, email: lower, pass_hash, approved: false });
    if (e2) throw e2;

    // notify admin
    if (ADMIN_EMAIL) {
      await sendMail({
        to: ADMIN_EMAIL,
        subject: 'Yêu cầu duyệt tài khoản mới',
        text: `Người dùng mới: ${name} <${lower}>. Dùng code ADMIN_CODE để duyệt qua API /api/auth/approve.`
      });
    }

    res.json({ message: 'Đăng ký thành công. Vui lòng đợi admin phê duyệt.' });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// --- Approve ---
app.post('/api/auth/approve', async (req, res) => {
  try {
    const { email, code } = req.body || {};
    if (!email || !code) return res.status(400).json({ message: 'Thiếu email/code' });
    if (!ADMIN_CODE || code !== ADMIN_CODE) return res.status(403).json({ message: 'Sai mã admin' });

    const lower = String(email).trim().toLowerCase();
    const { error } = await supabase.from('users').update({ approved: true }).eq('email', lower);
    if (error) throw error;

    res.json({ message: 'Đã duyệt' });
  } catch (e) {
    console.error('[approve]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// --- Login ---
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    const { data: u, error } = await supabase.from('users')
      .select('id,name,email,pass_hash,approved')
      .eq('email', lower)
      .maybeSingle();
    if (error) throw error;
    if (!u) return res.status(400).json({ message: 'Email hoặc mật khẩu sai' });
    if (!u.approved) return res.status(403).json({ message: 'Tài khoản chưa được duyệt' });

    const ok = await bcrypt.compare(password || '', u.pass_hash);
    if (!ok) return res.status(400).json({ message: 'Email hoặc mật khẩu sai' });

    const token = signToken({ uid: u.id, email: u.email, name: u.name });
    res.json({ token, user: { id: u.id, email: u.email, name: u.name } });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// --- Forgot ---
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    const { data: u, error } = await supabase.from('users').select('id,email').eq('email', lower).maybeSingle();
    if (error) throw error;
    if (!u) return res.json({ message: 'Nếu email tồn tại, chúng tôi đã gửi hướng dẫn.' });

    const token = crypto.randomBytes(24).toString('hex');
    const expires_at = new Date(Date.now() + 1000 * 60 * 30).toISOString(); // 30m
    const { error: e2 } = await supabase.from('resets').insert({ email: lower, token, expires_at });
    if (e2) throw e2;

    if (ADMIN_EMAIL) {
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

// --- Reset ---
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body || {};
    const lower = String(email || '').trim().toLowerCase();
    const { data: r, error } = await supabase.from('resets').select('id,expires_at').eq('email', lower).eq('token', token).maybeSingle();
    if (error) throw error;
    if (!r) return res.status(400).json({ message: 'Token không hợp lệ' });
    if (new Date(r.expires_at).getTime() < Date.now()) return res.status(400).json({ message: 'Token đã hết hạn' });

    const pass_hash = await bcrypt.hash(newPassword || '', 8);
    const { error: e2 } = await supabase.from('users').update({ pass_hash }).eq('email', lower);
    if (e2) throw e2;
    await supabase.from('resets').delete().eq('id', r.id);

    res.json({ message: 'Đã đặt lại mật khẩu' });
  } catch (e) {
    console.error('[reset]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

// --- Change Password (auth) ---
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!newPassword) return res.status(400).json({ message: 'Thiếu mật khẩu mới' });

    const { data: u, error } = await supabase.from('users').select('id,pass_hash').eq('id', req.user.uid).maybeSingle();
    if (error) throw error;
    if (!u) return res.status(404).json({ message: 'Không tìm thấy người dùng' });
    const ok = await bcrypt.compare(oldPassword || '', u.pass_hash);
    if (!ok) return res.status(400).json({ message: 'Mật khẩu hiện tại không đúng' });

    const pass_hash = await bcrypt.hash(newPassword, 8);
    const { error: e2 } = await supabase.from('users').update({ pass_hash }).eq('id', req.user.uid);
    if (e2) throw e2;

    res.json({ message: 'Đã đổi mật khẩu' });
  } catch (e) {
    console.error('[change-password]', e);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

app.listen(PORT, () => console.log(`Auth backend listening on :${PORT}`));
const cors = require('cors');
const ALLOWED_ORIGINS = [
  'https://phongnews.netlify.app',
  'http://localhost:5173',
  'http://localhost:3000'
];

app.options('*', cors());
