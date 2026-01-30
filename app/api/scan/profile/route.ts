import { NextResponse } from 'next/server';
import { computeSharedLinksByActor, isSuspiciousDomain, linkDiversityScore, normalizeLinks, updateProfileAnomalyScore } from '../../../../lib/profile';
import { extractUrlsFromText, resolveUrlVariants } from '../../../../lib/urlResolvers';
import { handleStem, handleShape, isLikelyPhishingUrl } from '../../../../lib/scam';
import { rateLimit } from '../../../../lib/rateLimit';
import { safeFetchTextWithLimit } from '../../../../lib/safeFetch';

type ScanRequestBody = {
  urls?: unknown;
};

const MAX_BYTES = 1_500_000;
const MAX_LINKS = 250;

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

async function fetchTextWithLimit(url: string): Promise<{ contentType: string; text: string; finalUrl: string }> {
  return safeFetchTextWithLimit(url, { maxBytes: MAX_BYTES, timeoutMs: 12_000, userAgent: 'sybil-shield', allowHttp: true, maxRedirects: 3 });
}

function extractMetaContent(html: string, names: string[]): string | null {
  for (const name of names) {
    const re1 = new RegExp(`<meta[^>]+property=["']${name}["'][^>]+content=["']([^"']+)["'][^>]*>`, 'i');
    const re2 = new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']+)["'][^>]*>`, 'i');
    const m = re1.exec(html) || re2.exec(html);
    if (m?.[1]) return decodeHtmlEntities(m[1]).trim();
  }
  return null;
}

function extractTitle(html: string): string | null {
  const m = /<title[^>]*>([^<]+)<\/title>/i.exec(html);
  return m?.[1] ? decodeHtmlEntities(m[1]).trim() : null;
}

function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}

function extractLinksFromHtml(html: string, baseUrl: string): string[] {
  const links: string[] = [];
  const attr = /\bhref\s*=\s*["']([^"']+)["']/gi;
  for (let m = attr.exec(html); m; m = attr.exec(html)) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('#') || raw.startsWith('mailto:') || raw.startsWith('javascript:')) continue;
    try {
      const resolved = new URL(raw, baseUrl).toString();
      links.push(resolved);
      if (links.length >= MAX_LINKS) break;
    } catch {
      // ignore
    }
  }
  const rawUrls = extractUrlsFromText(html).slice(0, MAX_LINKS);
  links.push(...rawUrls);
  return links;
}

function inferActorIdFromUrl(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.replace(/^www\./, '').toLowerCase();
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'talent.app' && parts.length >= 1) return `talent:${parts[parts.length - 1]}`;
    if (host === 'github.com' && parts.length >= 1) return `github:${parts[0]}`;
    if (host === 'warpcast.com' && parts.length >= 1) return `farcaster:${parts[0]}`;
    if ((host === 'x.com' || host === 'twitter.com') && parts.length >= 1) return `twitter:${parts[0]}`;
    if ((host === 't.me' || host === 'telegram.me') && parts.length >= 1) return `telegram:${parts[0]}`;
    if (host === 'discord.gg' && parts.length >= 1) return `discord:${parts[0]}`;
    if (host === 'lenster.xyz' && parts.length >= 1) return `lens:${parts[0]}`;
    return `${host}:${parts.join('/') || ''}`.replace(/:$/g, '');
  } catch {
    return urlStr;
  }
}

export async function POST(req: Request) {
  const rl = rateLimit(req, { key: 'scan_profile', max: 15, windowMs: 60_000 });
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited. Try again later.' }, { status: 429 });

  const body = (await req.json().catch(() => ({}))) as ScanRequestBody;
  const inputs = Array.isArray(body.urls) ? body.urls.map(String) : [];
  const expanded = inputs.flatMap((t) => extractUrlsFromText(t));
  const baseUrls = (expanded.length > 0 ? expanded : inputs).map(normalizeHttpUrl).filter((u): u is string => Boolean(u));

  if (baseUrls.length === 0) {
    return NextResponse.json({ error: 'No valid URLs provided.' }, { status: 400 });
  }

  const profiles: Array<{
    inputUrl: string;
    url?: string;
    actorId?: string;
    ok: boolean;
    error?: string;
    title?: string;
    bio?: string;
    links?: string[];
    suspiciousLinks?: string[];
    phishingLinks?: string[];
    linkDiversity?: number;
    handleStem?: string;
    handleShape?: string;
    profileAnomalyScore?: number;
    riskScore?: number;
    reasons?: string[];
  }> = [];

  const linksByActor = new Map<string, string[]>();

  for (const inputUrl of baseUrls) {
    try {
      const candidates = resolveUrlVariants(inputUrl).map((v) => v.url);
      const { contentType, text, finalUrl } = await fetchTextWithLimit(candidates[0] || inputUrl);

      // If the first attempt isn't HTML, still try with the original/final URL.
      const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml') || contentType === '';
      if (!isHtml) {
        profiles.push({ inputUrl, url: finalUrl, ok: true, title: undefined, bio: undefined, links: [], riskScore: 0, reasons: [] });
        continue;
      }

      const title = extractTitle(text) || extractMetaContent(text, ['og:title', 'twitter:title']);
      const bio =
        extractMetaContent(text, ['og:description', 'twitter:description', 'description']) ||
        undefined;

      const actorId = inferActorIdFromUrl(finalUrl);

      const rawLinks = extractLinksFromHtml(text, finalUrl);
      const normalizedLinks = normalizeLinks(
        rawLinks
          .flatMap((u) => resolveUrlVariants(u).map((v) => v.url))
          .map((u) => normalizeHttpUrl(u))
          .filter((u): u is string => Boolean(u)),
      ).slice(0, MAX_LINKS);

      linksByActor.set(actorId, normalizedLinks);

      profiles.push({
        inputUrl,
        url: finalUrl,
        actorId,
        ok: true,
        title: title || undefined,
        bio,
        links: normalizedLinks,
        handleStem: handleStem(actorId),
        handleShape: handleShape(actorId),
      });
    } catch (e) {
      profiles.push({ inputUrl, ok: false, error: e instanceof Error ? e.message : 'Scan failed' });
    }
  }

  const sharedLinksByActor = computeSharedLinksByActor(linksByActor);

  const enriched = profiles.map((p) => {
    if (!p.ok || !p.actorId) return p;
    const links = linksByActor.get(p.actorId) ?? [];
    const suspiciousLinks = links.filter((l) => isSuspiciousDomain(l));
    const phishingLinks = links.filter((l) => isLikelyPhishingUrl(l));
    const sharedLinks = sharedLinksByActor.get(p.actorId) ?? [];
    const diversity = linkDiversityScore(links);
    const profileAnomalyScore = updateProfileAnomalyScore(p.actorId, links, undefined, undefined);

    const reasons: string[] = [];
    if (suspiciousLinks.length > 0) reasons.push(`Suspicious domains (${suspiciousLinks.length})`);
    if (phishingLinks.length > 0) reasons.push(`Phishing-like URLs (${phishingLinks.length})`);
    if (sharedLinks.length > 0) reasons.push(`Shared links (${sharedLinks.length})`);
    if (diversity < 0.5 && links.length >= 3) reasons.push(`Low link diversity (${diversity.toFixed(2)})`);
    if ((p.bio || '').length > 0 && (p.bio || '').length < 20) reasons.push('Very short bio');

    const riskScore = Math.min(
      (suspiciousLinks.length > 0 ? 0.4 : 0) +
        (phishingLinks.length > 0 ? 0.4 : 0) +
        (sharedLinks.length > 0 ? 0.2 : 0) +
        (diversity < 0.5 && links.length >= 3 ? 0.2 : 0) +
        0.3 * profileAnomalyScore,
      1,
    );

    return {
      ...p,
      links,
      suspiciousLinks,
      phishingLinks,
      linkDiversity: diversity,
      profileAnomalyScore,
      riskScore,
      reasons,
    };
  });

  return NextResponse.json({
    scannedAt: new Date().toISOString(),
    profiles: enriched,
  });
}
