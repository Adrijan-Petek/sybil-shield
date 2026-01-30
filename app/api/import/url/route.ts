import { NextResponse } from 'next/server';
import Papa from 'papaparse';
import { extractUrlsFromText, resolveUrlVariants } from '../../../../lib/urlResolvers';
import { rateLimit } from '../../../../lib/rateLimit';
import { safeFetchTextWithLimit } from '../../../../lib/safeFetch';

type ImportRequestBody = {
  urls?: unknown;
};

type LogEntry = {
  timestamp: string;
  actor: string;
  target: string;
  action: string;
  platform: string;
  bio?: string;
  links?: string[];
  followerCount?: number;
  followingCount?: number;
  amount?: number;
  txHash?: string;
  blockNumber?: number;
  meta?: string;
  targetType?: string;
};

const MAX_BYTES = 2_000_000;

function isBlockedHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (h === 'localhost' || h.endsWith('.local')) return true;
  if (h === '127.0.0.1' || h === '0.0.0.0' || h === '::1') return true;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a, b] = h.split('.').map((x) => Number.parseInt(x, 10));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
  }
  return false;
}

function normalizeUrlInput(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (isBlockedHost(url.hostname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function coerceLogEntry(record: Record<string, unknown>): LogEntry | null {
  const timestamp = typeof record.timestamp === 'string' ? record.timestamp : String(record.timestamp ?? '');
  const actor = typeof record.actor === 'string' ? record.actor : String(record.actor ?? '');
  const target = typeof record.target === 'string' ? record.target : String(record.target ?? '');
  const action = typeof record.action === 'string' ? record.action : String(record.action ?? '');
  const platform = typeof record.platform === 'string' ? record.platform : String(record.platform ?? '');
  if (!timestamp || !actor || !target || !action || !platform) return null;
  return {
    timestamp,
    actor,
    target,
    action,
    platform,
    bio: typeof record.bio === 'string' ? record.bio : undefined,
    links: Array.isArray(record.links) ? (record.links as unknown[]).map(String) : undefined,
    followerCount: typeof record.followerCount === 'number' ? record.followerCount : undefined,
    followingCount: typeof record.followingCount === 'number' ? record.followingCount : undefined,
    amount: typeof record.amount === 'number' ? record.amount : undefined,
    txHash: typeof record.txHash === 'string' ? record.txHash : undefined,
    blockNumber: typeof record.blockNumber === 'number' ? record.blockNumber : undefined,
    meta: typeof record.meta === 'string' ? record.meta : undefined,
    targetType: typeof record.targetType === 'string' ? record.targetType : undefined,
  };
}

async function fetchTextWithLimit(url: string): Promise<{ contentType: string; text: string }> {
  const res = await safeFetchTextWithLimit(url, { maxBytes: MAX_BYTES, timeoutMs: 12_000, userAgent: 'sybil-shield', allowHttp: true, maxRedirects: 3 });
  return { contentType: res.contentType, text: res.text };
}

function parseCsv(text: string): LogEntry[] {
  const parsed = Papa.parse<Record<string, string | undefined>>(text, { header: true, skipEmptyLines: true });
  const rows = Array.isArray(parsed.data) ? parsed.data : [];
  return rows.flatMap((row) => {
    const timestamp = (row.timestamp ?? '').trim();
    const actor = (row.actor ?? '').trim();
    const target = (row.target ?? '').trim();
    const action = (row.action ?? '').trim();
    const platform = (row.platform ?? '').trim();
    if (!timestamp || !actor || !target || !action || !platform) return [];
    return [
      {
        timestamp,
        actor,
        target,
        action,
        platform,
        bio: row.bio,
      },
    ];
  });
}

function parseJson(text: string): LogEntry[] {
  const raw = JSON.parse(text) as unknown;
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((row): LogEntry[] => {
    if (typeof row !== 'object' || row === null) return [];
    const entry = coerceLogEntry(row as Record<string, unknown>);
    return entry ? [entry] : [];
  });
}

export async function POST(req: Request) {
  const rl = rateLimit(req, { key: 'import_url', max: 20, windowMs: 60_000 });
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited. Try again later.' }, { status: 429 });

  const body = (await req.json().catch(() => ({}))) as ImportRequestBody;
  const urls = Array.isArray(body.urls) ? body.urls.map(String) : [];

  const expandedInputs = urls.flatMap((u) => extractUrlsFromText(u));
  const normalized = (expandedInputs.length > 0 ? expandedInputs : urls)
    .map(normalizeUrlInput)
    .filter((u): u is string => Boolean(u));

  if (normalized.length === 0) {
    return NextResponse.json({ error: 'No valid URLs provided.' }, { status: 400 });
  }

  const results: { url: string; resolvedUrl?: string; ok: boolean; error?: string; count?: number }[] = [];
  const allLogs: LogEntry[] = [];

  for (const url of normalized) {
    try {
      const candidates = resolveUrlVariants(url).map((v) => v.url);
      let imported = false;
      let lastError: string | null = null;
      for (const candidate of candidates) {
        try {
          const { contentType, text } = await fetchTextWithLimit(candidate);
          const isCsv = contentType.includes('text/csv') || candidate.toLowerCase().endsWith('.csv');
          const isJson = contentType.includes('application/json') || candidate.toLowerCase().endsWith('.json');
          if (!isCsv && !isJson) throw new Error(`Unsupported content type: ${contentType || 'unknown'}`);
          const parsed = isCsv ? parseCsv(text) : parseJson(text);
          allLogs.push(...parsed);
          results.push({ url, resolvedUrl: candidate, ok: true, count: parsed.length });
          imported = true;
          break;
        } catch (e) {
          lastError = e instanceof Error ? e.message : 'Import failed';
        }
      }
      if (!imported) throw new Error(lastError || 'Import failed');
    } catch (e) {
      results.push({ url, ok: false, error: e instanceof Error ? e.message : 'Import failed' });
    }
  }

  return NextResponse.json({
    fetchedAt: new Date().toISOString(),
    results,
    logs: allLogs,
  });
}
