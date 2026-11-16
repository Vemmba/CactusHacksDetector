-- Migration: fair AI queue (FIFO; job statuses queued / processing / done / failed)
-- Run this once in the Supabase SQL Editor. It is self-contained and safe to run more than once: it works on a database
-- that never had the AI queue (creates it) and on one that already has the older ai_jobs table (upgrades it).
-- migration_ai_queue.sql (the older one) does not need to be run first.

-- 0. AI columns on scans + the ai_jobs table
alter table public.scans add column if not exists ai_status text not null default 'none';
alter table public.scans add column if not exists ai_results jsonb not null default '[]'::jsonb;
alter table public.scans add column if not exists ai_analyzed_at timestamptz;
alter table public.scans add column if not exists category text;
create index if not exists scans_ai_status_idx on public.scans (ai_status);
create index if not exists scans_category_idx on public.scans (category);

create table if not exists public.ai_jobs (
  id             uuid primary key default gen_random_uuid(),
  scan_id        uuid not null references public.scans(id) on delete cascade,
  mod_sha256     text not null,
  mod_file       text not null,
  status         text not null default 'queued',
  attempts       int not null default 0,
  max_attempts   int not null default 4,
  evidence       jsonb not null default '{}'::jsonb,
  result         jsonb,
  error          text,
  next_run_at    timestamptz not null default now(),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);
create index if not exists ai_jobs_scan_idx on public.ai_jobs (scan_id);
create unique index if not exists ai_jobs_scan_mod_idx on public.ai_jobs (scan_id, mod_sha256);

alter table public.ai_jobs enable row level security;
alter table public.ai_jobs force row level security;
revoke all on public.ai_jobs from public, anon, authenticated;
grant select, insert, update, delete on public.ai_jobs to service_role;

-- 1. Job statuses: pending -> queued, completed -> done
alter table public.ai_jobs drop constraint if exists ai_jobs_status_check;
update public.ai_jobs set status = 'queued' where status = 'pending';
update public.ai_jobs set status = 'done'   where status = 'completed';
alter table public.ai_jobs alter column status set default 'queued';
alter table public.ai_jobs add constraint ai_jobs_status_check check (status in ('queued', 'processing', 'done', 'failed'));

alter table public.ai_jobs add column if not exists started_at timestamptz;
alter table public.ai_jobs add column if not exists requeues   int not null default 0;
alter table public.ai_jobs alter column max_attempts set default 4;   -- 1 try + 3 retries

drop index if exists public.ai_jobs_status_idx;
drop index if exists public.ai_jobs_sha_completed_idx;
create index if not exists ai_jobs_queue_idx on public.ai_jobs (status, created_at);
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

-- 5. Staff overview view shows ai_status
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

revoke all on public.v_scan_overview from public, anon, authenticated;
grant select on public.v_scan_overview to service_role;
