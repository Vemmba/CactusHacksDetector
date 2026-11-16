-- Migration: Add AI Inspection Queue and Status to MC Scan
-- Run this in your Supabase SQL Editor (Dashboard -> SQL Editor -> New Query -> Run)

-- 1. Add AI status and results columns to scans table
alter table public.scans add column if not exists ai_status text not null default 'none';
alter table public.scans add column if not exists ai_results jsonb not null default '[]'::jsonb;
alter table public.scans add column if not exists ai_analyzed_at timestamptz;
alter table public.scans add column if not exists category text;
create index if not exists scans_ai_status_idx on public.scans (ai_status);
create index if not exists scans_category_idx on public.scans (category);

-- 2. Create the AI jobs queue table
create table if not exists public.ai_jobs (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references public.scans(id) on delete cascade,
  mod_sha256     text not null,
  mod_file       text not null,
  status         text not null default 'pending', -- pending, processing, completed, failed
  attempts       int not null default 0,
  max_attempts   int not null default 3,
  evidence       jsonb not null default '{}'::jsonb,
  result         jsonb,
  error          text,
  next_run_at    timestamptz not null default now(),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create index if not exists ai_jobs_status_idx on public.ai_jobs (status, next_run_at);
create index if not exists ai_jobs_scan_idx on public.ai_jobs (scan_id);
create unique index if not exists ai_jobs_scan_mod_idx on public.ai_jobs (scan_id, mod_sha256);
create index if not exists ai_jobs_sha_completed_idx on public.ai_jobs (mod_sha256) where status = 'completed';

-- 3. Lock down permissions (RLS ON, only service role can access)
alter table public.ai_jobs enable row level security;
alter table public.ai_jobs force row level security;
revoke all on public.ai_jobs from public, anon, authenticated;
grant select, insert, update, delete on public.ai_jobs to service_role;

-- 4. Update the staff overview view to surface ai_status
create or replace view public.v_scan_overview with (security_invoker = true) as
select s.id, s.created_at, s.label as player, s.pc_id, s.verdict, s.threat_score, s.script_trusted, s.is_admin, s.native_ok,
       s.mod_count, s.ai_status,
       (select count(*) from public.scan_mods m where m.scan_id = s.id and m.class in ('CHEAT', 'MALWARE'))       as cheat_mods,
       (select count(*) from public.scan_hacks h where h.scan_id = s.id)                                           as hacks,
       (select count(*) from public.scan_findings f where f.scan_id = s.id and f.severity = 'high')                as high_findings,
       (select count(*) from public.scan_findings f where f.scan_id = s.id and f.severity = 'medium')              as medium_findings,
       s.reasons,
       (select count(*) from public.mod_files f where f.scan_id = s.id and f.uploaded_at is not null and f.deleted_at is null) as uploaded_files
  from public.scans s
 order by s.created_at desc;

revoke all on public.v_scan_overview from public, anon, authenticated;
grant select on public.v_scan_overview to service_role;
