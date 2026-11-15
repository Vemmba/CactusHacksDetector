-- MC Scan database schema for Supabase (Postgres).
-- Run this once in: Supabase dashboard -> SQL Editor -> New query -> paste -> Run.
-- Safe to re-run (everything is "if not exists" / "create or replace").
--
-- SECURITY MODEL
--   * The scanner on a player's PC only knows a public URL. It holds no database key.
--   * Every table has Row Level Security ON with NO policies, and all rights are revoked from the
--     public API roles (anon / authenticated). So even someone who copies the project URL and the
--     public anon key from the internet can read and write nothing.
--   * Only the Edge Function (which holds the service-role key as a server-side secret) touches the data.
--   * Players upload reports through the public /upload endpoint. They need no code and no account, but the
--     report must contain a valid schema and the client must send the explicit consent header. Uploads are
--     capped per IP per minute, per IP per day and globally per day, and an identical report is accepted only once.
--   * Flagged/unknown mod binaries go directly to the private `scan-mods` Storage bucket using a short-lived
--     signed upload URL issued by /mods/sign. The Edge Function never proxies the binary.
--   * Scan rows and JSON metadata are kept permanently. ONLY the binary objects are deleted after 48 hours
--     (the mod_files metadata row is marked deleted so the report still shows what was uploaded).
--   * Legacy staff codes are no longer issued. The old table/columns are retained only so historical scans
--     keep their labels; no function or route can create or consume a code.

-- New objects in this schema must not be reachable by the public API roles by default.
alter default privileges in schema public revoke all on tables from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;
alter default privileges in schema public revoke all on functions from public, anon, authenticated;

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------------------------
-- DEPRECATED: legacy staff codes. No code is issued any more. Kept only so old scans keep their
-- label / code link. Nothing in the Edge Function can insert or consume a code.
create table if not exists public.codes (
  id         bigserial primary key,
  code_hash  text        not null unique,               -- sha256 of the code; the code itself is never stored
  label      text,                                      -- who it was issued for (player name / ticket id)
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at    timestamptz,                               -- set on first (and only) use
  scan_id    uuid
);

create table if not exists public.scans (
  id             uuid primary key default gen_random_uuid(),
  created_at     timestamptz not null default now(),
  code_id        bigint references public.codes(id) on delete set null,
  label          text,                                  -- copied from the code
  pc_id          text,                                  -- one-way hash of the machine GUID (same PC -> same id)
  verdict        text        not null,                  -- NO FINDINGS / MINOR NOTES / REVIEW / HIGH RISK / MALWARE FOUND
  threat_score   int         not null default 0,
  reasons        jsonb       not null default '[]'::jsonb,
  counts         jsonb       not null default '{}'::jsonb,
  os             text,
  os_build       text,
  ps_version     text,
  is_admin       boolean,
  native_ok      boolean,                               -- false = class-file analyser did not compile (weaker scan)
  script_sha256  text,
  script_trusted boolean     not null default false,    -- true only if the hash is in ALLOWED_SCRIPT_SHA256
  lookback_hours int,
  duration_sec   int,
  game_running   boolean,
  mod_count      int         not null default 0,
  meta           jsonb       not null default '{}'::jsonb,
  ip_hash        text,                                  -- salted hash only; the IP address is never stored
  origin         text        not null default 'public', -- public = no-code upload; code = historical legacy row
  report_hash    text                                   -- SHA-256 of the exact upload body; duplicate guard
);
create index if not exists scans_created_idx on public.scans (created_at desc);
create index if not exists scans_pc_idx      on public.scans (pc_id);
create index if not exists scans_verdict_idx on public.scans (verdict);

-- Upgrade path for databases created before the no-code workflow.
alter table public.scans add column if not exists origin      text not null default 'public';
alter table public.scans add column if not exists report_hash text;
alter table public.scans add column if not exists ai_status   text not null default 'none';
alter table public.scans add column if not exists ai_results  jsonb not null default '[]'::jsonb;
alter table public.scans add column if not exists ai_analyzed_at timestamptz;
alter table public.scans add column if not exists category text;
alter table public.scans alter column origin set default 'public';
create unique index if not exists scans_report_hash_idx on public.scans (report_hash);
create index if not exists scans_ai_status_idx on public.scans (ai_status);
create index if not exists scans_category_idx on public.scans (category);

create table if not exists public.scan_mods (
  id            bigserial primary key,
  scan_id       uuid not null references public.scans(id) on delete cascade,
  file          text, folder text, size_kb int,
  sha1          text, sha256 text,
  mod_id        text, mod_name text, mod_version text, loader text,
  modrinth      text,                                   -- Modrinth project if the hash is an official download
  source        text, source_trust text,                -- where the file was downloaded from (Zone.Identifier)
  modified_utc  timestamptz,
  classes       int, nested_jars int, deep_scanned boolean,
  score         int, verdict text, class text           -- class: MALWARE / CHEAT / SUSPICIOUS / FP / VERIFIED / CLEAN
);
create index if not exists scan_mods_scan_idx on public.scan_mods (scan_id);
create index if not exists scan_mods_sha1_idx on public.scan_mods (sha1);

-- One row per hack/module found inside a mod, with the key that toggles it.
create table if not exists public.scan_hacks (
  id             bigserial primary key,
  scan_id        uuid not null references public.scans(id) on delete cascade,
  mod_file       text, mod_sha1 text, mod_class text,
  name           text,                                  -- e.g. KillAura
  kind           text,                                  -- Module / Client / Bypass / Keybind ...
  category       text,
  strength       text,
  evidence       text,
  keybind        text,                                  -- e.g. "R" or "Right Shift"
  keybind_source text                                   -- options.txt (exact) / config file / default key in code
);
create index if not exists scan_hacks_scan_idx on public.scan_hacks (scan_id);
create index if not exists scan_hacks_name_idx on public.scan_hacks (lower(name));

create table if not exists public.scan_findings (
  id         bigserial primary key,
  scan_id    uuid not null references public.scans(id) on delete cascade,
  scope      text not null,                             -- mod / system / jvm
  mod_file   text,
  severity   text not null,                             -- high / medium / low
  category   text, rule text, detail text, where_text text,
  event_time timestamptz,
  source     text
);
create index if not exists scan_findings_scan_idx on public.scan_findings (scan_id);
create index if not exists scan_findings_sev_idx  on public.scan_findings (severity);

create table if not exists public.scan_keybinds (
  id          bigserial primary key,
  scan_id     uuid not null references public.scans(id) on delete cascade,
  name        text, key text, source text, confidence text,
  matched_mod boolean
);
create index if not exists scan_keybinds_scan_idx on public.scan_keybinds (scan_id);

-- One row per flagged/unknown mod binary offered for review. The file itself lives in the private
-- `scan-mods` Storage bucket; this row is kept forever, while the object is deleted after 48 hours.
create table if not exists public.mod_files (
  id           uuid primary key,
  scan_id      uuid not null references public.scans(id) on delete cascade,
  created_at   timestamptz not null default now(),
  storage_path text not null unique,                    -- <scan_id>/<random>.bin (never a user-supplied path)
  file_name    text not null,                           -- original name, for display only
  sha256       text,
  sha1         text,
  size_bytes   bigint not null default 0,
  class        text,                                    -- MALWARE / CHEAT / SUSPICIOUS / CLEAN
  uploaded_at  timestamptz,                             -- set after the signed PUT is confirmed in Storage
  deleted_at   timestamptz,                             -- binary removed; metadata/report remains
  expires_at   timestamptz not null default (now() + interval '48 hours')
);
create index if not exists mod_files_scan_idx    on public.mod_files (scan_id);
create index if not exists mod_files_created_idx on public.mod_files (created_at desc);
create index if not exists mod_files_expiry_idx  on public.mod_files (expires_at) where deleted_at is null;
create unique index if not exists mod_files_scan_sha_idx on public.mod_files (scan_id, sha256) where sha256 is not null;

-- Hosted AI Inspection Queue: jobs for NVIDIA AI analysis of unknown/unverified mods.
-- FIFO by created_at; statuses queued / processing / done / failed. Works even when the scanner client's PC is off.
create table if not exists public.ai_jobs (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references public.scans(id) on delete cascade,
  mod_sha256     text not null,
  mod_file       text not null,
  status         text not null default 'queued' check (status in ('queued', 'processing', 'done', 'failed')),
  attempts       int not null default 0,
  max_attempts   int not null default 4,                -- 1 try + 3 retries
  requeues       int not null default 0,                -- times a stuck 'processing' job was put back
  evidence       jsonb not null default '{}'::jsonb,
  result         jsonb,
  error          text,
  next_run_at    timestamptz not null default now(),
  started_at     timestamptz,
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);
create index if not exists ai_jobs_queue_idx on public.ai_jobs (status, created_at);
create index if not exists ai_jobs_scan_idx on public.ai_jobs (scan_id);
create unique index if not exists ai_jobs_scan_mod_idx on public.ai_jobs (scan_id, mod_sha256);
create index if not exists ai_jobs_sha_done_idx on public.ai_jobs (mod_sha256) where status = 'done';
create index if not exists ai_jobs_started_idx on public.ai_jobs (started_at desc);

-- 2. Claim jobs: oldest first, atomic, never more than p_concurrency running at once across ALL workers,
--    and not sooner than p_min_gap_ms after the previous claim (spacing between NVIDIA calls).
create or replace function public.claim_ai_jobs(p_limit int default 1, p_concurrency int default 1, p_min_gap_ms int default 2000)
returns setof public.ai_jobs
language plpgsql security definer set search_path = public as $$
declare
  v_busy  int;
  v_slots int;
  v_last  timestamptz;
begin
  perform pg_advisory_xact_lock(hashtext('ai_jobs_claim'));
  select count(*) into v_busy from public.ai_jobs where status = 'processing';
  v_slots := least(p_limit, p_concurrency - v_busy);
  if v_slots <= 0 then return; end if;
  if p_min_gap_ms > 0 then
    select max(started_at) into v_last from public.ai_jobs;
    if v_last is not null and v_last > now() - make_interval(secs => p_min_gap_ms / 1000.0) then return; end if;
  end if;
  return query
  update public.ai_jobs j
     set status = 'processing', started_at = now(), updated_at = now()
   where j.id in (
     select q.id from public.ai_jobs q
      where q.status = 'queued' and q.next_run_at <= now()
      order by q.created_at asc, q.id asc
      limit v_slots
      for update skip locked)
  returning j.*;
end $$;

-- 3. Jobs stuck in 'processing' for p_minutes go back to the queue. A job that stalls p_max_requeues times is
--    given up: status 'failed' with a SUSPECT result. Returns every job it touched.
create or replace function public.requeue_stuck_ai_jobs(p_minutes int default 5, p_max_requeues int default 3)
returns setof public.ai_jobs
language plpgsql security definer set search_path = public as $$
begin
  perform pg_advisory_xact_lock(hashtext('ai_jobs_claim'));
  return query
  update public.ai_jobs j
     set requeues   = j.requeues + 1,
         updated_at = now(),
         status     = case when j.requeues + 1 >= p_max_requeues then 'failed' else 'queued' end,
         error      = case when j.requeues + 1 >= p_max_requeues then 'stalled in processing ' || (j.requeues + 1) || ' times' else j.error end,
         result     = case when j.requeues + 1 >= p_max_requeues then jsonb_build_object(
                        'file', j.mod_file, 'verdict', 'SUSPECT', 'cheating_score', 50, 'hack_name', 'None',
                        'troll_summary', 'Cactus AI could not get a clean read on this one, so it sits on the suspect list until a human looks.',
                        'explanation', 'AI inspection did not finish (job kept stalling). Marked SUSPECT for manual review.') else j.result end
   where j.status = 'processing' and j.updated_at < now() - make_interval(mins => p_minutes)
  returning j.*;
end $$;

-- 4. Queue position of a scan: its oldest unfinished job, counted from the front of the FIFO queue (1 = next / running).
create or replace function public.ai_queue_position(p_scan_id uuid)
returns table (queue_position int, queue_total int)
language sql stable security definer set search_path = public as $$
  select (count(*) filter (where a.created_at < me.created_at or (a.created_at = me.created_at and a.id <= me.id)))::int,
         count(*)::int
    from public.ai_jobs a,
         (select id, created_at from public.ai_jobs
           where scan_id = p_scan_id and status in ('queued', 'processing')
           order by created_at, id limit 1) me
   where a.status in ('queued', 'processing');
$$;

revoke all on function public.claim_ai_jobs(int, int, int)        from public, anon, authenticated;
revoke all on function public.requeue_stuck_ai_jobs(int, int)     from public, anon, authenticated;
revoke all on function public.ai_queue_position(uuid)             from public, anon, authenticated;
grant execute on function public.claim_ai_jobs(int, int, int)     to service_role;
grant execute on function public.requeue_stuck_ai_jobs(int, int)  to service_role;
grant execute on function public.ai_queue_position(uuid)          to service_role;

-- Private bucket for the binaries. 32 MiB matches MOD_MAX_FILE_BYTES in functions/mcscan-api/core.ts.
-- Objects are readable only through short-lived signed URLs created by the admin API (service role).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('scan-mods', 'scan-mods', false, 33554432, array['application/octet-stream', 'application/java-archive', 'application/zip'])
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- Per-IP request counters (salted IP hash + minute bucket).
create table if not exists public.rate (
  ip_hash text   not null,
  bucket  bigint not null,
  hits    int    not null default 0,
  primary key (ip_hash, bucket)
);

-- Per-IP and global daily upload counters for the public endpoint.
create table if not exists public.upload_daily (
  ip_hash text   not null,                              -- salted IP hash, or the literal 'global'
  day     bigint not null,                              -- days since the Unix epoch
  hits    int    not null default 0,
  primary key (ip_hash, day)
);

-- ---------------------------------------------------------------------------------------------
-- Lock everything down: RLS on, no policies, no rights for the public API roles.
alter table public.codes         enable row level security;
alter table public.scans         enable row level security;
alter table public.scan_mods     enable row level security;
alter table public.scan_hacks    enable row level security;
alter table public.scan_findings enable row level security;
alter table public.scan_keybinds enable row level security;
alter table public.mod_files     enable row level security;
alter table public.ai_jobs       enable row level security;
alter table public.rate          enable row level security;
alter table public.upload_daily  enable row level security;
alter table public.codes         force row level security;
alter table public.scans         force row level security;
alter table public.scan_mods     force row level security;
alter table public.scan_hacks    force row level security;
alter table public.scan_findings force row level security;
alter table public.scan_keybinds force row level security;
alter table public.mod_files     force row level security;
alter table public.ai_jobs       force row level security;
alter table public.rate          force row level security;
alter table public.upload_daily  force row level security;

revoke all on all tables    in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

-- The service role (used only by the Edge Function) bypasses RLS but still needs table rights.
grant select, insert, update, delete on all tables    in schema public to service_role;
grant usage, select                  on all sequences in schema public to service_role;
-- Explicit grant for tables created after the blanket grant above (safe to re-run).
grant select, insert, update, delete on public.mod_files to service_role;
grant select, insert, update, delete on public.ai_jobs to service_role;

-- ---------------------------------------------------------------------------------------------
-- Public no-code ingest. Stores the report in one transaction. The report hash is unique, so the same
-- exact upload cannot be replayed. Returns the new scan id, or NULL when an identical report already exists.
create or replace function public.ingest_public_scan(
  p_report_hash text, p_scan jsonb, p_mods jsonb, p_hacks jsonb, p_findings jsonb, p_keybinds jsonb
) returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_id uuid;
begin
  insert into public.scans (
    code_id, label, origin, report_hash, pc_id, verdict, threat_score, reasons, counts, os, os_build, ps_version,
    is_admin, native_ok, script_sha256, script_trusted, lookback_hours, duration_sec, game_running, mod_count, meta, ip_hash)
  select null, null, 'public', p_report_hash, x.pc_id, x.verdict, coalesce(x.threat_score, 0),
         coalesce(x.reasons, '[]'::jsonb), coalesce(x.counts, '{}'::jsonb), x.os, x.os_build, x.ps_version,
         x.is_admin, x.native_ok, x.script_sha256, coalesce(x.script_trusted, false),
         x.lookback_hours, x.duration_sec, x.game_running, coalesce(x.mod_count, 0), coalesce(x.meta, '{}'::jsonb), x.ip_hash
    from jsonb_to_record(p_scan) as x(
      pc_id text, verdict text, threat_score int, reasons jsonb, counts jsonb, os text, os_build text, ps_version text,
      is_admin boolean, native_ok boolean, script_sha256 text, script_trusted boolean, lookback_hours int,
      duration_sec int, game_running boolean, mod_count int, meta jsonb, ip_hash text)
  on conflict (report_hash) do nothing
  returning id into v_id;

  if v_id is null then
    return null;                                         -- identical report already stored
  end if;

  insert into public.scan_mods (scan_id, file, folder, size_kb, sha1, sha256, mod_id, mod_name, mod_version, loader,
                                modrinth, source, source_trust, modified_utc, classes, nested_jars, deep_scanned, score, verdict, class)
  select v_id, x.file, x.folder, x.size_kb, x.sha1, x.sha256, x.mod_id, x.mod_name, x.mod_version, x.loader,
         x.modrinth, x.source, x.source_trust, x.modified_utc, x.classes, x.nested_jars, x.deep_scanned, x.score, x.verdict, x.class
    from jsonb_to_recordset(coalesce(p_mods, '[]'::jsonb)) as x(
      file text, folder text, size_kb int, sha1 text, sha256 text, mod_id text, mod_name text, mod_version text, loader text,
      modrinth text, source text, source_trust text, modified_utc timestamptz, classes int, nested_jars int,
      deep_scanned boolean, score int, verdict text, class text);

  insert into public.scan_hacks (scan_id, mod_file, mod_sha1, mod_class, name, kind, category, strength, evidence, keybind, keybind_source)
  select v_id, x.mod_file, x.mod_sha1, x.mod_class, x.name, x.kind, x.category, x.strength, x.evidence, x.keybind, x.keybind_source
    from jsonb_to_recordset(coalesce(p_hacks, '[]'::jsonb)) as x(
      mod_file text, mod_sha1 text, mod_class text, name text, kind text, category text, strength text,
      evidence text, keybind text, keybind_source text);

  insert into public.scan_findings (scan_id, scope, mod_file, severity, category, rule, detail, where_text, event_time, source)
  select v_id, x.scope, x.mod_file, x.severity, x.category, x.rule, x.detail, x.where_text, x.event_time, x.source
    from jsonb_to_recordset(coalesce(p_findings, '[]'::jsonb)) as x(
      scope text, mod_file text, severity text, category text, rule text, detail text, where_text text,
      event_time timestamptz, source text);

  insert into public.scan_keybinds (scan_id, name, key, source, confidence, matched_mod)
  select v_id, x.name, x.key, x.source, x.confidence, x.matched_mod
    from jsonb_to_recordset(coalesce(p_keybinds, '[]'::jsonb)) as x(
      name text, key text, source text, confidence text, matched_mod boolean);

  return v_id;
end;
$$;

-- Per-IP counter. Returns how many requests this IP hash made in this minute bucket (including this one).
create or replace function public.bump_rate(p_ip_hash text, p_bucket bigint)
returns int
language sql
security definer
set search_path = public, pg_temp
as $$
  insert into public.rate (ip_hash, bucket, hits) values (p_ip_hash, p_bucket, 1)
  on conflict (ip_hash, bucket) do update set hits = public.rate.hits + 1
  returning hits;
$$;

-- Daily counter for the public upload endpoint. p_ip_hash is the salted IP hash or 'global'.
create or replace function public.bump_daily(p_ip_hash text, p_day bigint)
returns int
language sql
security definer
set search_path = public, pg_temp
as $$
  insert into public.upload_daily (ip_hash, day, hits) values (p_ip_hash, p_day, 1)
  on conflict (ip_hash, day) do update set hits = public.upload_daily.hits + 1
  returning hits;
$$;

-- Housekeeping: old/expired legacy codes and stale rate counters. Scans are NEVER deleted here.
-- The Edge Function deletes expired Storage objects (48 hours) and marks mod_files.deleted_at; the scan
-- row, mods, hacks, findings, keybinds and JSON stay in Postgres permanently.
create or replace function public.cleanup_old(p_days int)
returns int
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare v_n int;
begin
  delete from public.codes where (expires_at < now() - interval '1 day') or (created_at < now() - make_interval(days => greatest(p_days, 1)));
  get diagnostics v_n = row_count;
  delete from public.rate  where bucket < (extract(epoch from now())::bigint / 60) - 120;
  delete from public.upload_daily where day < (extract(epoch from now())::bigint / 86400) - 35;
  return v_n;
end;
$$;

-- Remove the old staff-code ingest function from existing deployments. Codes are no longer issued.
drop function if exists public.ingest_scan(text, jsonb, jsonb, jsonb, jsonb, jsonb);

revoke all on function public.ingest_public_scan(text, jsonb, jsonb, jsonb, jsonb, jsonb) from public, anon, authenticated;
revoke all on function public.bump_rate(text, bigint)                                     from public, anon, authenticated;
revoke all on function public.bump_daily(text, bigint)                                    from public, anon, authenticated;
revoke all on function public.cleanup_old(int)                                            from public, anon, authenticated;
grant execute on function public.ingest_public_scan(text, jsonb, jsonb, jsonb, jsonb, jsonb) to service_role;
grant execute on function public.bump_rate(text, bigint)                                     to service_role;
grant execute on function public.bump_daily(text, bigint)                                    to service_role;
grant execute on function public.cleanup_old(int)                                            to service_role;

-- ---------------------------------------------------------------------------------------------
-- Views for staff (use them in the Supabase Table Editor / SQL Editor).
-- security_invoker = the view runs with the caller's rights, so RLS still applies to anon/authenticated.

create or replace view public.v_hacks with (security_invoker = true) as
select s.created_at,
       s.label            as player,
       s.verdict          as scan_verdict,
       h.name             as hack,
       h.kind,
       h.keybind          as toggle_key,
       h.keybind_source   as key_source,
       h.mod_file         as suspicious_mod,
       h.mod_class,
       h.strength,
       h.evidence,
       h.mod_sha1,
       s.pc_id,
       s.id               as scan_id
  from public.scan_hacks h
  join public.scans s on s.id = h.scan_id
 order by s.created_at desc;

-- dropped first: CREATE OR REPLACE cannot insert the ai_status column into an existing view
drop view if exists public.v_scan_overview;
create view public.v_scan_overview with (security_invoker = true) as
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

create or replace view public.v_scan_files with (security_invoker = true) as
select s.created_at as scan_created_at, s.id as scan_id, s.verdict, s.label as player,
       f.id, f.file_name, f.class, f.sha256, f.sha1, f.size_bytes, f.uploaded_at, f.deleted_at, f.expires_at
  from public.mod_files f
  join public.scans s on s.id = f.scan_id
 order by s.created_at desc, f.created_at desc;

revoke all on public.v_hacks         from public, anon, authenticated;
revoke all on public.v_scan_overview from public, anon, authenticated;
revoke all on public.v_scan_files    from public, anon, authenticated;
grant select on public.v_hacks         to service_role;
grant select on public.v_scan_overview to service_role;
grant select on public.v_scan_files    to service_role;
