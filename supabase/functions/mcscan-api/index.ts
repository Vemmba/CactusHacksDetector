import { createClient } from 'npm:@supabase/supabase-js@2';
import { createHandler, MOD_BUCKET, processAiQueue } from './core.ts';
import type { ModFile, ScanModMatch, Store, StorageOps } from './core.ts';

const url = Deno.env.get('SUPABASE_URL')!;
const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });

function must<T>(r: { data: T | null; error: { message: string } | null }): T {
  if (r.error) throw new Error(r.error.message);
  return r.data as T;
}

function absoluteUrl(value: string): string {
  if (/^https?:\/\//i.test(value)) return value;
  return url.replace(/\/+$/, '') + '/storage/v1' + (value.startsWith('/') ? value : '/' + value);
}

const store: Store = {
  async bump(ipHash, bucket) {
    return Number(must(await db.rpc('bump_rate', { p_ip_hash: ipHash, p_bucket: bucket })));
  },
  async bumpDaily(ipHash, day) {
    return Number(must(await db.rpc('bump_daily', { p_ip_hash: ipHash, p_day: day })));
  },
  async ingestPublic(reportHash, scan, mods, hacks, findings, keybinds) {
    const r = await db.rpc('ingest_public_scan', {
      p_report_hash: reportHash, p_scan: scan, p_mods: mods, p_hacks: hacks, p_findings: findings, p_keybinds: keybinds,
    });
    if (r.error) throw new Error(r.error.message);
    return (r.data as string | null) ?? null;
  },
  async findScanByReportHash(reportHash) {
    const r = await db.from('scans').select('id').eq('report_hash', reportHash).maybeSingle();
    if (r.error) throw new Error(r.error.message);
    return (r.data?.id as string | undefined) ?? null;
  },
  async getScanMod(scanId, fileName, sha256) {
    const r = await db.from('scan_mods').select('file, sha256, sha1, class, modrinth, score')
      .eq('scan_id', scanId).eq('file', fileName).limit(20);
    if (r.error) throw new Error(r.error.message);
    const rows = (r.data ?? []) as ScanModMatch[];
    return rows.find((row) => !!sha256 && row.sha256 === sha256) || rows[0] || null;
  },
  async getModFile(id) {
    const r = await db.from('mod_files').select('*').eq('id', id).maybeSingle();
    if (r.error) throw new Error(r.error.message);
    return (r.data as ModFile | null) ?? null;
  },
  async getModFileByHash(scanId, sha256) {
    const r = await db.from('mod_files').select('*').eq('scan_id', scanId).eq('sha256', sha256).limit(1).maybeSingle();
    if (r.error) throw new Error(r.error.message);
    return (r.data as ModFile | null) ?? null;
  },
  async createModFile(row) {
    const r = await db.from('mod_files').insert(row).select('*').single();
    if (r.error) return null;
    return (r.data as ModFile | null) ?? null;
  },
  async completeModFile(id, sizeBytes) {
    const r = await db.from('mod_files').update({ uploaded_at: new Date().toISOString(), size_bytes: sizeBytes })
      .eq('id', id).is('deleted_at', null);
    if (r.error) throw new Error(r.error.message);
    return true;
  },
  async listModFiles(scanId) {
    return must(await db.from('mod_files').select('*').eq('scan_id', scanId).order('created_at', { ascending: false })) ?? [];
  },
  async listRecentModFiles(limit) {
    return must(await db.from('mod_files').select('*').order('created_at', { ascending: false }).limit(limit)) ?? [];
  },
  async modFileUsage(scanId) {
    const rows = must(await db.from('mod_files').select('size_bytes').eq('scan_id', scanId)) ?? [];
    return { count: rows.length, bytes: rows.reduce((n: number, row: any) => n + (Number(row.size_bytes) || 0), 0) };
  },
  async deleteModFileRecord(id) {
    const r = await db.from('mod_files').update({ deleted_at: new Date().toISOString() }).eq('id', id);
    if (r.error) throw new Error(r.error.message);
    return true;
  },
  async listExpiredModFiles(_hours) {
    return must(await db.from('mod_files').select('*').is('deleted_at', null).lte('expires_at', new Date().toISOString()).limit(500)) ?? [];
  },
  async markModFilesDeleted(ids) {
    if (!ids.length) return 0;
    const r = await db.from('mod_files').update({ deleted_at: new Date().toISOString() }).in('id', ids).is('deleted_at', null);
    if (r.error) throw new Error(r.error.message);
    return ids.length;
  },
  async listScans(limit, verdict) {
    let q = db.from('v_scan_overview').select('*').limit(limit);
    if (verdict) q = q.eq('verdict', verdict);
    return must(await q) ?? [];
  },
  async getScan(id) {
    const scan = (await db.from('scans').select('*').eq('id', id).maybeSingle()).data;
    if (!scan) return null;
    const [mods, hacks, findings, keybinds, files] = await Promise.all([
      db.from('scan_mods').select('*').eq('scan_id', id).order('score', { ascending: false }),
      db.from('scan_hacks').select('*').eq('scan_id', id).order('mod_file'),
      db.from('scan_findings').select('*').eq('scan_id', id).order('id'),
      db.from('scan_keybinds').select('*').eq('scan_id', id).order('id'),
      db.from('mod_files').select('*').eq('scan_id', id).order('created_at', { ascending: false }),
    ]);
    return {
      scan, mods: must(mods) ?? [], hacks: must(hacks) ?? [], findings: must(findings) ?? [],
      keybinds: must(keybinds) ?? [], files: must(files) ?? [],
    };
  },
  async deleteScan(id) {

    const files = await db.from('mod_files').select('storage_path').eq('scan_id', id).is('deleted_at', null);
    if (files.error) throw new Error(files.error.message);
    const paths = (files.data ?? []).map((f: any) => f.storage_path).filter(Boolean) as string[];
    if (paths.length) {
      const rem = await db.storage.from(MOD_BUCKET).remove(paths);
      if (rem.error) throw new Error(rem.error.message);
    }
    const r = await db.from('scans').delete().eq('id', id).select('id');
    return !r.error && (r.data?.length ?? 0) > 0;
  },
  async listHacks(limit) {
    return must(await db.from('v_hacks').select('*').limit(limit)) ?? [];
  },
  async cleanup(days) {
    return Number(must(await db.rpc('cleanup_old', { p_days: days })) ?? 0);
  },
  async queueAiJobs(jobs) {
    if (!jobs.length) return 0;
    const scanId = jobs[0].scan_id;
    let queued = 0;
    for (const j of jobs) {

      const cached = await store.getCompletedAiResultByHash(j.mod_sha256);
      const r = await db.from('ai_jobs').upsert({
        scan_id: j.scan_id,
        mod_sha256: j.mod_sha256,
        mod_file: j.mod_file,
        evidence: j.evidence,
        ...(cached ? { status: 'done', result: { ...cached, file: j.mod_file } } : { status: 'queued' }),
      }, { onConflict: 'scan_id,mod_sha256', ignoreDuplicates: true });
      if (r.error) { console.error('ai_jobs insert failed: ' + r.error.message); continue; }
      queued++;
    }
    await refreshScanAi(scanId);
    return queued;
  },
  async getCompletedAiResultByHash(sha256) {
    if (!/^[0-9a-f]{64}$/i.test(sha256 || '')) return null;
    const r = await db.from('ai_jobs').select('result').eq('mod_sha256', sha256).eq('status', 'done')
      .order('created_at', { ascending: false }).limit(1).maybeSingle();
    return (r.data?.result as Record<string, any> | undefined) ?? null;
  },
  async claimAiJobs(limit, concurrency, minGapMs) {
    const r = await db.rpc('claim_ai_jobs', { p_limit: limit, p_concurrency: concurrency, p_min_gap_ms: minGapMs });
    if (r.error) throw new Error(r.error.message);
    const jobs = ((r.data ?? []) as any[]).sort((x, y) => String(x.created_at).localeCompare(String(y.created_at)));
    const scanIds = [...new Set(jobs.map((j) => j.scan_id as string))];
    if (scanIds.length) await db.from('scans').update({ ai_status: 'processing' }).in('id', scanIds).eq('ai_status', 'pending');
    return jobs;
  },
  async requeueStuckAiJobs(minutes, maxRequeues) {
    const r = await db.rpc('requeue_stuck_ai_jobs', { p_minutes: minutes, p_max_requeues: maxRequeues });
    if (r.error) throw new Error(r.error.message);
    const rows = (r.data ?? []) as any[];

    for (const scanId of new Set(rows.filter((j) => j.status === 'failed').map((j) => j.scan_id as string))) await refreshScanAi(scanId);
    return rows.length;
  },
  async completeAiJob(id, scanId, result) {
    await db.from('ai_jobs').update({ status: 'done', result, error: null, updated_at: new Date().toISOString() }).eq('id', id);
    await refreshScanAi(scanId);
    return true;
  },
  async retryAiJob(id, error, attempts, nextRunAt) {
    await db.from('ai_jobs').update({
      status: 'queued', attempts, error: error.slice(0, 300), next_run_at: nextRunAt, updated_at: new Date().toISOString(),
    }).eq('id', id);
    return true;
  },
  async failAiJob(id, scanId, error, attempts, fallback) {
    await db.from('ai_jobs').update({
      status: 'failed', attempts, error: error.slice(0, 300), result: fallback, updated_at: new Date().toISOString(),
    }).eq('id', id);
    await refreshScanAi(scanId);
    return true;
  },
  async getScanAiState(id) {
    const r = await db.from('scans').select('id, ai_status, category, threat_score, ai_results').eq('id', id).maybeSingle();
    if (r.error) throw new Error(r.error.message);
    return (r.data as any) ?? null;
  },
  async aiQueuePosition(scanId) {
    const r = await db.rpc('ai_queue_position', { p_scan_id: scanId });
    if (r.error) throw new Error(r.error.message);
    const row = (Array.isArray(r.data) ? r.data[0] : r.data) as { queue_position?: number; queue_total?: number } | undefined;
    return row && row.queue_position ? { position: Number(row.queue_position), total: Number(row.queue_total) } : null;
  },
  async listAiJobs(limit = 50) {
    const r = await db.from('ai_jobs').select('*').order('created_at', { ascending: false }).limit(limit);
    return (r.data as any[]) ?? [];
  },
};

async function refreshScanAi(scanId: string): Promise<void> {
  const nowIso = new Date().toISOString();
  const jobs = ((await db.from('ai_jobs').select('status, result').eq('scan_id', scanId)).data ?? []) as any[];
  if (!jobs.length) return;
  const active = jobs.filter((j) => j.status === 'queued' || j.status === 'processing');
  const allDone = active.length === 0;

  const results = jobs.filter((j) => (j.status === 'done' || j.status === 'failed') && j.result).map((j) => j.result);
  const aiStatus = allDone ? 'completed' : jobs.some((j) => j.status === 'processing') ? 'processing' : 'pending';
  await db.from('scans').update({ ai_status: aiStatus, ai_results: results, ai_analyzed_at: nowIso }).eq('id', scanId);
  if (!results.length) return;

  const hasAiCheat = results.some((res: any) => res.verdict === 'CHEAT');

  const hasAiSuspect = results.some((res: any) => res.verdict === 'SUSPECT' && Number(res.cheating_score ?? res.score ?? 50) >= 40);
  const isMinorIndicator = results.some((res: any) =>
    res.hack_name && /shield.*indicat|reach.*circle|reach.*indicat|fullbright|freecam|cps|hud/i.test(res.hack_name));

  const scanRes = await db.from('scans').select('verdict, threat_score, reasons, category').eq('id', scanId).single();
  if (!scanRes.data) return;
  const curVerdict = scanRes.data.verdict;
  const reasons = Array.isArray(scanRes.data.reasons) ? scanRes.data.reasons : [];
  let newVerdict = curVerdict;
  let newCategory: string | null = scanRes.data.category ?? null;
  let newScore = Number(scanRes.data.threat_score || 0);

  if (curVerdict === 'HIGH RISK' || curVerdict === 'MALWARE FOUND') {
    newCategory = 'cheater';
  } else if (hasAiCheat && !isMinorIndicator) {
    newVerdict = 'REVIEW';
    newCategory = 'suspect';
    newScore = Math.min(45, newScore + 25);
    if (!reasons.some((r: string) => r.includes('AI Mod Inspection'))) {
      reasons.unshift('AI Mod Inspection: flagged suspicious cheat module (Under Review)');
    }
  } else if (hasAiSuspect || isMinorIndicator || curVerdict === 'REVIEW') {
    newVerdict = 'REVIEW';
    newCategory = 'suspect';
    newScore = Math.max(newScore, 20);
    if (isMinorIndicator && !reasons.some((r: string) => r.includes('Minor assist / indicator'))) {
      reasons.unshift('Minor assist / indicator detected: Shield status indicator / Reach circle');
    }
  } else if (allDone) {
    newCategory = 'legit';
  }
  await db.from('scans').update({ verdict: newVerdict, category: newCategory, threat_score: newScore, reasons }).eq('id', scanId);
}

      const storage: StorageOps = {
        async createUploadUrl(path) {
          const r = await db.storage.from(MOD_BUCKET).createSignedUploadUrl(path);
          if (r.error || !r.data?.signedUrl) return null;
          return absoluteUrl(r.data.signedUrl);
        },
        async objectInfo(path) {
          const slash = path.lastIndexOf('/');
          const folder = slash > 0 ? path.slice(0, slash) : '';
          const name = path.slice(slash + 1);
          const r = await db.storage.from(MOD_BUCKET).list(folder, { limit: 100, search: name });
          if (r.error || !r.data) return null;
          const hit = r.data.find((o: any) => o.name === name);
          if (!hit) return null;
          const size = Number((hit.metadata as any)?.size ?? 0);
          return { size: Number.isFinite(size) ? size : 0 };
        },
        async createDownloadUrl(path, expiresIn, fileName) {

          const r = await db.storage.from(MOD_BUCKET).createSignedUrl(path, expiresIn, fileName ? { download: fileName } : undefined);
          if (r.error || !r.data?.signedUrl) return null;
          return absoluteUrl(r.data.signedUrl);
        },
        async remove(paths) {
          if (!paths.length) return 0;
          const r = await db.storage.from(MOD_BUCKET).remove(paths);
          if (r.error) throw new Error(r.error.message);
          return r.data?.length ?? 0;
        },
      };

      const env = {
        ADMIN_TOKEN: Deno.env.get('ADMIN_TOKEN') ?? undefined,
        IP_SALT: Deno.env.get('IP_SALT') ?? undefined,
        UPLOAD_TOKEN_SECRET: Deno.env.get('UPLOAD_TOKEN_SECRET') ?? undefined,
        ALLOWED_SCRIPT_SHA256: Deno.env.get('ALLOWED_SCRIPT_SHA256') ?? undefined,
        PUBLIC_PER_MIN_PER_IP: Deno.env.get('PUBLIC_PER_MIN_PER_IP') ?? undefined,
        PUBLIC_PER_DAY_PER_IP: Deno.env.get('PUBLIC_PER_DAY_PER_IP') ?? undefined,
        PUBLIC_PER_DAY_GLOBAL: Deno.env.get('PUBLIC_PER_DAY_GLOBAL') ?? undefined,
        NVIDIA_API_KEY: Deno.env.get('NVIDIA_API_KEY') ?? undefined,
        NVIDIA_AI_MODEL: Deno.env.get('NVIDIA_AI_MODEL') ?? undefined,
        NVIDIA_AI_FALLBACK_MODEL: Deno.env.get('NVIDIA_AI_FALLBACK_MODEL') ?? undefined,
        NVIDIA_AI_HEDGE_MS: Deno.env.get('NVIDIA_AI_HEDGE_MS') ?? undefined,
        NVIDIA_AI_CONCURRENCY: Deno.env.get('NVIDIA_AI_CONCURRENCY') ?? undefined,
        NVIDIA_AI_DELAY_MS: Deno.env.get('NVIDIA_AI_DELAY_MS') ?? undefined,
      };

      const handler = createHandler({
        store,
        storage,
        env,
        processAiQueue: async () => {
          const run = () => processAiQueue({ store, env, log: (m) => console.error(m) });

          if (typeof EdgeRuntime !== 'undefined' && EdgeRuntime.waitUntil) {

            EdgeRuntime.waitUntil(run());
          } else {
            run().catch((e) => console.error('background AI process error:', e));
          }
          return { processed: 0, errors: 0 };
        },
      });

      Deno.serve(handler);
