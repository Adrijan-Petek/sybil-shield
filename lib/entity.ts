export type ControllerGroup = {
  controllerId: number;
  members: string[];
  score: number; // heuristic confidence 0..1
  evidence: string[]; // short human-readable reasons
};

type UnionFind = {
  parent: Map<string, string>;
  size: Map<string, number>;
  find: (x: string) => string;
  union: (a: string, b: string) => void;
};

function makeUnionFind(items: string[]): UnionFind {
  const parent = new Map<string, string>();
  const size = new Map<string, number>();
  for (const x of items) {
    parent.set(x, x);
    size.set(x, 1);
  }
  const find = (x: string): string => {
    const p = parent.get(x);
    if (!p) return x;
    if (p === x) return x;
    const r = find(p);
    parent.set(x, r);
    return r;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra === rb) return;
    const sa = size.get(ra) || 1;
    const sb = size.get(rb) || 1;
    if (sa < sb) {
      parent.set(ra, rb);
      size.set(rb, sa + sb);
    } else {
      parent.set(rb, ra);
      size.set(ra, sa + sb);
    }
  };
  return { parent, size, find, union };
}

function looksLikeEvmAddress(x: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(x);
}

function extractEvmAddressesFromText(text: string): string[] {
  if (!text) return [];
  const out: string[] = [];
  const re = /\b0x[a-fA-F0-9]{40}\b/g;
  for (let m = re.exec(text); m; m = re.exec(text)) out.push(m[0].toLowerCase());
  return out;
}

function extractDomains(links: string[]): string[] {
  const out: string[] = [];
  for (const l of links) {
    try {
      const u = new URL(l);
      out.push(u.hostname.replace(/^www\./, '').toLowerCase());
    } catch {
      // ignore
    }
  }
  return out;
}

const COMMON_DOMAINS = new Set([
  'github.com',
  'gist.github.com',
  'raw.githubusercontent.com',
  'twitter.com',
  'x.com',
  'talent.app',
  'warpcast.com',
  'farcaster.xyz',
  't.me',
  'telegram.me',
  'discord.gg',
  'discord.com',
  'linktr.ee',
  'medium.com',
  'youtube.com',
  'youtu.be',
]);

export function computeControllerGroups(input: {
  actors: string[];
  linksByActor: Map<string, string[]>;
  bioByActor: Map<string, string>;
  handleStemByActor: Map<string, string>;
  sharedFundersByWallet: Map<string, string[]>; // wallet -> list of funder wallets
  extraWalletsByActor?: Map<string, string[]>; // actor -> additional extracted wallets
  minGroupSize: number;
}): { groups: ControllerGroup[]; controllerIdByActor: Map<string, number> } {
  const {
    actors,
    linksByActor,
    bioByActor,
    handleStemByActor,
    sharedFundersByWallet,
    extraWalletsByActor,
    minGroupSize,
  } = input;

  const uf = makeUnionFind(actors);

  const evidenceByPair = new Map<string, Set<string>>();
  const addEvidence = (a: string, b: string, reason: string) => {
    const key = a < b ? `${a}||${b}` : `${b}||${a}`;
    if (!evidenceByPair.has(key)) evidenceByPair.set(key, new Set());
    evidenceByPair.get(key)!.add(reason);
  };

  const connectMany = (members: string[], reason: string) => {
    if (members.length < 2) return;
    const first = members[0];
    for (let i = 1; i < members.length; i++) {
      uf.union(first, members[i]);
      addEvidence(first, members[i], reason);
    }
  };

  // 1) Shared exact links (high signal)
  const linkToActors = new Map<string, Set<string>>();
  for (const a of actors) {
    const links = linksByActor.get(a) || [];
    for (const l of links) {
      if (!linkToActors.has(l)) linkToActors.set(l, new Set());
      linkToActors.get(l)!.add(a);
    }
  }
  linkToActors.forEach((set, link) => {
    if (set.size < 2) return;
    const members = Array.from(set);
    connectMany(members, `Shared link: ${link}`);
  });

  // 2) Shared uncommon domains (medium signal)
  const domainToActors = new Map<string, Set<string>>();
  for (const a of actors) {
    const links = linksByActor.get(a) || [];
    const domains = extractDomains(links).filter((d) => !COMMON_DOMAINS.has(d));
    const uniq = new Set(domains);
    uniq.forEach((d) => {
      if (!domainToActors.has(d)) domainToActors.set(d, new Set());
      domainToActors.get(d)!.add(a);
    });
  }
  domainToActors.forEach((set, domain) => {
    if (set.size < 3) return;
    connectMany(Array.from(set), `Shared domain: ${domain}`);
  });

  // 3) Shared handle stems (low/medium signal, needs size)
  const stemToActors = new Map<string, Set<string>>();
  handleStemByActor.forEach((stem, actor) => {
    if (!stem) return;
    if (!stemToActors.has(stem)) stemToActors.set(stem, new Set());
    stemToActors.get(stem)!.add(actor);
  });
  stemToActors.forEach((set, stem) => {
    if (set.size < 4) return;
    connectMany(Array.from(set), `Shared handle stem: ${stem}`);
  });

  // 3b) Exact base handle match across platforms (e.g., github:alice + twitter:alice)
  const baseHandleToActors = new Map<string, Set<string>>();
  for (const actor of actors) {
    const parts = actor.split(':');
    if (parts.length < 2) continue;
    const base = parts.slice(1).join(':').trim().toLowerCase();
    if (base.length < 3) continue;
    if (!baseHandleToActors.has(base)) baseHandleToActors.set(base, new Set());
    baseHandleToActors.get(base)!.add(actor);
  }
  baseHandleToActors.forEach((set, base) => {
    if (set.size < 2) return;
    connectMany(Array.from(set), `Same handle across platforms: ${base}`);
  });

  // 4) Wallet address reuse / disclosure (high signal)
  const walletToActors = new Map<string, Set<string>>();
  for (const a of actors) {
    const wallets: string[] = [];
    const bio = bioByActor.get(a) || '';
    wallets.push(...extractEvmAddressesFromText(bio));

    const links = linksByActor.get(a) || [];
    wallets.push(...extractEvmAddressesFromText(links.join('\n')));

    if (extraWalletsByActor?.get(a)) wallets.push(...extraWalletsByActor.get(a)!);

    // Also treat the actor itself as a wallet if it looks like one.
    if (looksLikeEvmAddress(a)) wallets.push(a.toLowerCase());

    const uniq = new Set(wallets.filter(looksLikeEvmAddress));
    uniq.forEach((w) => {
      if (!walletToActors.has(w)) walletToActors.set(w, new Set());
      walletToActors.get(w)!.add(a);
    });
  }
  walletToActors.forEach((set, wallet) => {
    if (set.size < 2) return;
    connectMany(Array.from(set), `Shared wallet: ${wallet}`);
  });

  // 5) Common funder across wallets (high signal onchain farms)
  const funderToWallets = new Map<string, Set<string>>();
  sharedFundersByWallet.forEach((funders, wallet) => {
    for (const f of funders) {
      if (!looksLikeEvmAddress(f)) continue;
      if (!funderToWallets.has(f)) funderToWallets.set(f, new Set());
      funderToWallets.get(f)!.add(wallet);
    }
  });
  funderToWallets.forEach((walletSet, funder) => {
    if (walletSet.size < 2) return;
    // connect the wallets to each other
    const wallets = Array.from(walletSet);
    connectMany(wallets, `Common funder: ${funder}`);
  });

  // Build groups
  const rootToMembers = new Map<string, string[]>();
  for (const a of actors) {
    const r = uf.find(a);
    if (!rootToMembers.has(r)) rootToMembers.set(r, []);
    rootToMembers.get(r)!.push(a);
  }

  const groups: ControllerGroup[] = [];
  const controllerIdByActor = new Map<string, number>();
  let controllerId = 0;

  rootToMembers.forEach((members) => {
    if (members.length < Math.max(2, minGroupSize)) return;
    members.sort();

    // Aggregate evidence from pairwise links (cap for display)
    const reasons = new Set<string>();
    for (let i = 0; i < members.length; i++) {
      for (let j = i + 1; j < members.length; j++) {
        const a = members[i];
        const b = members[j];
        const k = a < b ? `${a}||${b}` : `${b}||${a}`;
        evidenceByPair.get(k)?.forEach((r) => reasons.add(r));
        if (reasons.size >= 8) break;
      }
      if (reasons.size >= 8) break;
    }

    // Confidence score: size + high-signal indicators.
    const reasonsArr = Array.from(reasons);
    const hasWallet = reasonsArr.some((r) => r.startsWith('Shared wallet:'));
    const hasFunder = reasonsArr.some((r) => r.startsWith('Common funder:'));
    const hasExactLink = reasonsArr.some((r) => r.startsWith('Shared link:'));
    const hasDomain = reasonsArr.some((r) => r.startsWith('Shared domain:'));

    let score = 0.25;
    score += Math.min((members.length - 2) / 10, 0.25);
    if (hasWallet) score += 0.25;
    if (hasFunder) score += 0.25;
    if (hasExactLink) score += 0.15;
    if (hasDomain) score += 0.10;
    score = Math.min(score, 1);

    const group: ControllerGroup = {
      controllerId: controllerId++,
      members,
      score,
      evidence: reasonsArr.slice(0, 8),
    };
    groups.push(group);
    members.forEach((m) => controllerIdByActor.set(m, group.controllerId));
  });

  groups.sort((a, b) => b.score - a.score || b.members.length - a.members.length);
  return { groups, controllerIdByActor };
}
