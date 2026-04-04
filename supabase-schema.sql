-- ═══════════════════════════════════════════════════════════
--  RAMKI SITE — Supabase Schema
--  Run this once in your Supabase project:
--  Dashboard → SQL Editor → paste & run
-- ═══════════════════════════════════════════════════════════

-- Users
create table if not exists users (
  id         uuid primary key default gen_random_uuid(),
  username   text unique not null,
  password   text not null,
  role       text not null default 'admin',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- Blogs
create table if not exists blogs (
  id         uuid primary key default gen_random_uuid(),
  title      text not null,
  category   text default 'Article',
  excerpt    text default '',
  content    text default '',
  emoji      text default '📊',
  status     text default 'draft',
  tags       text[] default '{}',
  photo      text default '',
  views      integer default 0,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create index if not exists blogs_created_at_idx on blogs(created_at desc);
create index if not exists blogs_status_idx     on blogs(status);

-- Analytics (key format: 'daily:YYYY-MM-DD' or 'total')
create table if not exists analytics (
  id         uuid primary key default gen_random_uuid(),
  key        text unique not null,
  count      integer default 0,
  page_views integer default 0
);

-- Site settings (key = 'site', value = jsonb object)
create table if not exists settings (
  id    uuid primary key default gen_random_uuid(),
  key   text unique not null,
  value jsonb default '{}'
);

-- Revoked JWT tokens (for logout / password change)
create table if not exists revoked_tokens (
  id         uuid primary key default gen_random_uuid(),
  jti        text unique not null,
  expires_at timestamptz not null,
  revoked_at timestamptz default now()
);
create index if not exists revoked_tokens_expires_idx on revoked_tokens(expires_at);

-- ═══════════════════════════════════════════════════════════
--  Row Level Security
--  Server uses the service role key → RLS is bypassed.
--  Disable RLS so accidental anon key usage is blocked.
-- ═══════════════════════════════════════════════════════════
alter table users          disable row level security;
alter table blogs          disable row level security;
alter table analytics      disable row level security;
alter table settings       disable row level security;
alter table revoked_tokens disable row level security;

-- ═══════════════════════════════════════════════════════════
--  Storage bucket
--  Create manually in Dashboard → Storage → New bucket
--  Name   : uploads
--  Public : true   (so image URLs work as <img src="...">)
-- ═══════════════════════════════════════════════════════════
