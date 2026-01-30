export type ResolvedUrl = {
  url: string;
  reason: string;
};

function stripTrailingPunctuation(value: string): string {
  return value.trim().replace(/[)\]}>,.]+$/g, '');
}

export function extractUrlsFromText(text: string): string[] {
  const matches = text.match(/\bhttps?:\/\/[^\s<>"']+/gi) || [];
  return Array.from(new Set(matches.map(stripTrailingPunctuation).filter(Boolean)));
}

function toUrl(input: string): URL | null {
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function withSearchParam(url: URL, key: string, value: string): URL {
  const next = new URL(url.toString());
  next.searchParams.set(key, value);
  return next;
}

function normalizeHostname(hostname: string): string {
  const h = hostname.toLowerCase();
  return h.startsWith('www.') ? h.slice(4) : h;
}

export function resolveUrlVariants(rawUrl: string): ResolvedUrl[] {
  const url = toUrl(rawUrl);
  if (!url) return [];

  const out: ResolvedUrl[] = [{ url: url.toString(), reason: 'original' }];
  const hostname = normalizeHostname(url.hostname);
  const path = url.pathname;

  // GitHub blob -> raw
  // https://github.com/{o}/{r}/blob/{ref}/{path} -> https://raw.githubusercontent.com/{o}/{r}/{ref}/{path}
  if (hostname === 'github.com') {
    const parts = path.split('/').filter(Boolean);
    if (parts.length >= 5 && parts[2] === 'blob') {
      const owner = parts[0];
      const repo = parts[1];
      const ref = parts[3];
      const rest = parts.slice(4).join('/');
      out.push({
        url: `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${rest}`,
        reason: 'github-blob-to-raw',
      });
    }
    // GitHub raw=1 (useful for some pages/assets)
    out.push({ url: withSearchParam(url, 'raw', '1').toString(), reason: 'github-raw-1' });
  }

  // GitHub Gist -> /raw (redirects to the raw content)
  if (hostname === 'gist.github.com') {
    const trimmed = url.toString().replace(/\/+$/, '');
    out.push({ url: `${trimmed}/raw`, reason: 'gist-raw' });
  }

  // GitLab blob -> raw
  // https://gitlab.com/{group}/{project}/-/blob/{ref}/{path} -> /-/raw/
  if (hostname === 'gitlab.com') {
    const replaced = url.toString().replace('/-/blob/', '/-/raw/');
    if (replaced !== url.toString()) out.push({ url: replaced, reason: 'gitlab-blob-to-raw' });
  }

  // Bitbucket src -> ?raw=1
  if (hostname === 'bitbucket.org') {
    out.push({ url: withSearchParam(url, 'raw', '1').toString(), reason: 'bitbucket-raw-1' });
  }

  // Dropbox share -> dl=1
  if (hostname === 'dropbox.com' || hostname.endsWith('.dropbox.com')) {
    out.push({ url: withSearchParam(url, 'dl', '1').toString(), reason: 'dropbox-dl-1' });
    out.push({ url: withSearchParam(url, 'raw', '1').toString(), reason: 'dropbox-raw-1' });
  }

  // Google Drive direct download
  // https://drive.google.com/file/d/{id}/view -> https://drive.google.com/uc?export=download&id={id}
  if (hostname === 'drive.google.com') {
    const m = path.match(/^\/file\/d\/([^/]+)\//);
    const id = m?.[1] || url.searchParams.get('id');
    if (id) {
      out.push({ url: `https://drive.google.com/uc?export=download&id=${encodeURIComponent(id)}`, reason: 'gdrive-uc-download' });
    }
  }

  // Google Sheets export (CSV)
  // https://docs.google.com/spreadsheets/d/{id}/edit#gid=0 -> /export?format=csv&gid=0
  if (hostname === 'docs.google.com') {
    const m = path.match(/^\/spreadsheets\/d\/([^/]+)\//);
    const id = m?.[1];
    if (id) {
      const gid = url.hash?.includes('gid=') ? url.hash.split('gid=')[1]?.split('&')[0] : url.searchParams.get('gid');
      const exportUrl = new URL(`https://docs.google.com/spreadsheets/d/${encodeURIComponent(id)}/export`);
      exportUrl.searchParams.set('format', 'csv');
      if (gid) exportUrl.searchParams.set('gid', gid);
      out.push({ url: exportUrl.toString(), reason: 'gsheets-export-csv' });
    }
  }

  // Pastebin raw
  // https://pastebin.com/{id} -> https://pastebin.com/raw/{id}
  if (hostname === 'pastebin.com') {
    const parts = path.split('/').filter(Boolean);
    if (parts.length === 1) {
      out.push({ url: `https://pastebin.com/raw/${encodeURIComponent(parts[0])}`, reason: 'pastebin-raw' });
    }
  }

  // OneDrive: add download=1 (many share links respect this, including 1drv.ms after redirect)
  if (hostname === '1drv.ms' || hostname.endsWith('onedrive.live.com')) {
    out.push({ url: withSearchParam(url, 'download', '1').toString(), reason: 'onedrive-download-1' });
  }

  // HuggingFace blob -> resolve
  // https://huggingface.co/.../blob/{rev}/file -> /resolve/{rev}/file
  if (hostname === 'huggingface.co') {
    const replaced = url.toString().replace('/blob/', '/resolve/');
    if (replaced !== url.toString()) out.push({ url: replaced, reason: 'hf-blob-to-resolve' });
  }

  // De-dupe while preserving order
  const seen = new Set<string>();
  const uniq: ResolvedUrl[] = [];
  for (const item of out) {
    if (seen.has(item.url)) continue;
    seen.add(item.url);
    uniq.push(item);
  }
  return uniq;
}
