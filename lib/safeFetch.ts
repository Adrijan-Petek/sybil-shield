type SafeFetchOptions = {
  maxBytes: number;
  timeoutMs: number;
  userAgent?: string;
  allowHttp?: boolean;
  maxRedirects?: number;
};

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

function assertAllowedUrl(u: URL, allowHttp: boolean) {
  if (u.protocol !== 'https:' && !(allowHttp && u.protocol === 'http:')) throw new Error('URL protocol not allowed');
  if (isBlockedHost(u.hostname)) throw new Error('Blocked host');
}

export async function safeFetchTextWithLimit(url: string, opts: SafeFetchOptions): Promise<{ contentType: string; text: string; finalUrl: string }> {
  const maxBytes = Math.max(1, opts.maxBytes);
  const timeoutMs = Math.max(1_000, opts.timeoutMs);
  const allowHttp = Boolean(opts.allowHttp);
  const maxRedirects = Math.min(Math.max(opts.maxRedirects ?? 3, 0), 10);

  let current = new URL(url);
  assertAllowedUrl(current, allowHttp);

  const headers: HeadersInit = {};
  if (opts.userAgent) headers['User-Agent'] = opts.userAgent;

  for (let i = 0; i <= maxRedirects; i++) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await fetch(current.toString(), {
        cache: 'no-store',
        redirect: 'manual',
        headers,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(t);
    }

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get('location');
      if (!location) throw new Error(`Redirect (${res.status}) missing Location header`);
      const next = new URL(location, current.toString());
      assertAllowedUrl(next, allowHttp);
      current = next;
      continue;
    }

    const finalUrl = current.toString();
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Fetch failed (${res.status}): ${text || res.statusText}`);
    }
    const contentType = res.headers.get('content-type') || '';
    const buf = await res.arrayBuffer();
    if (buf.byteLength > maxBytes) throw new Error(`Response too large (>${maxBytes} bytes)`);
    const text = new TextDecoder('utf-8').decode(buf);
    return { contentType, text, finalUrl };
  }

  throw new Error('Too many redirects');
}

