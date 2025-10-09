# Simple8 Auth Backend — Supabase Storage

Giữ nguyên API `/api/auth/*` nhưng thay vì lưu `data/*.json`, backend lưu vào **Supabase Postgres**.
Dùng cho hướng **B**: Frontend vẫn gọi API cũ, dữ liệu **bền vững** nhờ Supabase.

## Bảng dữ liệu (SQL gợi ý)

```sql
-- users: lưu người dùng
create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  email text unique not null,
  pass_hash text not null,
  approved boolean not null default false,
  created_at timestamptz not null default now()
);

-- resets: token quên mật khẩu
create table if not exists public.resets (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  token text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
```

> Không cần bật RLS cho `users/resets` nếu chỉ truy cập **từ backend** bằng **service role**.  
> Không expose service role trên client.

## Chạy local

```bash
npm install
cp .env.example .env
# điền SUPABASE_URL, SUPABASE_SERVICE_ROLE, SMTP, ADMIN_EMAIL, ADMIN_CODE, JWT_SECRET
node server.js
# http://localhost:3000/api/health
```

## Deploy
- Push folder này lên GitHub → Render.com (Web Service)
- Start command: `node server.js`
- Thêm ENV như `.env.example`

## API (giữ giống bản cũ)
- `POST /api/auth/register` `{name,email,password}` → tạo user `approved=false`, gửi mail thông báo admin
- `POST /api/auth/login` `{email,password}` → chỉ login khi `approved=true`
- `POST /api/auth/forgot` `{email}` → tạo token, gửi email
- `POST /api/auth/reset` `{email,token,newPassword}`
- `POST /api/auth/change-password` (auth) `{oldPassword,newPassword}` (header `Authorization: Bearer <jwt>`)
- `POST /api/auth/approve` `{email, code}` (code = `ADMIN_CODE`)
```

