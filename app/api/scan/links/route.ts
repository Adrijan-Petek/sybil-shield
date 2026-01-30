import { NextResponse } from 'next/server';
import { extractUrlsFromText, resolveUrlVariants } from '../../../../lib/urlResolvers';
import { rateLimit } from '../../../../lib/rateLimit';
import { safeFetchTextWithLimit } from '../../../../lib/safeFetch';

type ScanRequestBody = {
  urls?: unknown;
};

const MAX_BYTES = 1_500_000;
const MAX_LINKS_PER_PAGE = 200;

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

function normalizeHttpUrl(raw: string): string | null {
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

function looksLikeDataFile(url: string, contentType: string): boolean {
  const lower = url.toLowerCase();
  if (lower.endsWith('.csv') || lower.endsWith('.json')) return true;
  if (contentType.includes('text/csv') || contentType.includes('application/json')) return true;
  return false;
}

function extractCandidateUrlsFromHtml(html: string): string[] {
  const found: string[] = [];

  // href="..." src="..."
  const attr = /\b(?:href|src)\s*=\s*["']([^"']+)["']/gi;
  for (let m = attr.exec(html); m; m = attr.exec(html)) {
    found.push(m[1]);
    if (found.length >= MAX_LINKS_PER_PAGE) break;
  }

  // fallback: raw URLs
  if (found.length < MAX_LINKS_PER_PAGE) {
    const raw = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
    for (let m = raw.exec(html); m; m = raw.exec(html)) {
      found.push(m[0]);
      if (found.length >= MAX_LINKS_PER_PAGE) break;
    }
  }

  return found;
}

function resolveAgainstBase(baseUrl: string, maybeRelative: string): string | null {
  const trimmed = maybeRelative.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('#')) return null;
  try {
    return new URL(trimmed, baseUrl).toString();
  } catch {
    return null;
  }
}

async function fetchTextWithLimit(url: string): Promise<{ contentType: string; text: string }> {
  const res = await safeFetchTextWithLimit(url, { maxBytes: MAX_BYTES, timeoutMs: 12_000, userAgent: 'sybil-shield', allowHttp: true, maxRedirects: 3 });
  return { contentType: res.contentType, text: res.text };
}

export async function POST(req: Request) {
  const rl = rateLimit(req, { key: 'scan_links', max: 20, windowMs: 60_000 });
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited. Try again later.' }, { status: 429 });

  const body = (await req.json().catch(() => ({}))) as ScanRequestBody;
  const urls = Array.isArray(body.urls) ? body.urls.map(String) : [];
  const expandedInputs = urls.flatMap((u) => extractUrlsFromText(u));
  const normalized = (expandedInputs.length > 0 ? expandedInputs : urls).map(normalizeHttpUrl).filter((u): u is string => Boolean(u));

  if (normalized.length === 0) {
    return NextResponse.json({ error: 'No valid URLs provided.' }, { status: 400 });
  }

  const pages: Array<{
    url: string;
    ok: boolean;
    contentType?: string;
    error?: string;
    discoveredLinks?: string[];
    discoveredDataFiles?: string[];
  }> = [];

  const allLinks = new Set<string>();
  const allDataFiles = new Set<string>();

  for (const url of normalized) {
    try {
      const { contentType, text } = await fetchTextWithLimit(url);
      const isData = looksLikeDataFile(url, contentType);
      if (isData) {
        allDataFiles.add(url);
        pages.push({ url, ok: true, contentType, discoveredLinks: [], discoveredDataFiles: [url] });
        continue;
      }

      const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml') || contentType === '';
      if (!isHtml) {
        const rawLinks = extractUrlsFromText(text).map((u) => normalizeHttpUrl(u)).filter((u): u is string => Boolean(u));
        const variants = rawLinks.flatMap((u) => resolveUrlVariants(u).map((v) => normalizeHttpUrl(v.url))).filter((u): u is string => Boolean(u));
        const unique = Array.from(new Set([...rawLinks, ...variants])).slice(0, MAX_LINKS_PER_PAGE);
        const dataFiles = unique.filter((u) => u.toLowerCase().endsWith('.csv') || u.toLowerCase().endsWith('.json'));
        unique.forEach((u) => allLinks.add(u));
        dataFiles.forEach((u) => allDataFiles.add(u));
        pages.push({ url, ok: true, contentType, discoveredLinks: unique, discoveredDataFiles: dataFiles });
        continue;
      }

      const candidates = extractCandidateUrlsFromHtml(text);
      const resolved = candidates
        .map((c) => resolveAgainstBase(url, c))
        .filter((u): u is string => Boolean(u))
        .map((u) => normalizeHttpUrl(u))
        .filter((u): u is string => Boolean(u));

      const variantResolved = resolved.flatMap((u) => resolveUrlVariants(u).map((v) => normalizeHttpUrl(v.url))).filter((u): u is string => Boolean(u));
      const unique = Array.from(new Set([...resolved, ...variantResolved])).slice(0, MAX_LINKS_PER_PAGE);
      const dataFiles = unique.filter((u) => u.toLowerCase().endsWith('.csv') || u.toLowerCase().endsWith('.json'));

      unique.forEach((u) => allLinks.add(u));
      dataFiles.forEach((u) => allDataFiles.add(u));

      pages.push({ url, ok: true, contentType, discoveredLinks: unique, discoveredDataFiles: dataFiles });
    } catch (e) {
      pages.push({ url, ok: false, error: e instanceof Error ? e.message : 'Scan failed' });
    }
  }

  return NextResponse.json({
    scannedAt: new Date().toISOString(),
    pages,
    links: Array.from(allLinks),
    dataFiles: Array.from(allDataFiles),
  });
}
