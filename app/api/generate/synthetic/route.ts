import { NextResponse } from 'next/server';

type SyntheticRequest = {
  seed?: number;
  startTime?: string;
  minutes?: number;
  platforms?: string[];
  organicUsers?: number;
  organicActions?: number;
  targets?: number;
  sybilClusters?: number;
  sybilClusterSize?: number;
  sybilInternalEdgesPerActor?: number;
  burstTargetIndex?: number;
  burstActorsPerCluster?: number;
  burstActionsPerActor?: number;
  burstWindowSeconds?: number;
  includeProfiles?: boolean;
};

type LogEntry = {
  timestamp: string;
  platform: string;
  action: string;
  actor: string;
  target: string;
  bio?: string;
  links?: string[];
  followerCount?: number;
  followingCount?: number;
  actorCreatedAt?: string;
  verified?: boolean;
  location?: string;
  meta?: string;
};

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(rng: () => number, arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

function clampInt(value: number, min: number, max: number): number {
  return Math.min(Math.max(Math.floor(value), min), max);
}

function randInt(rng: () => number, min: number, max: number): number {
  return clampInt(min + rng() * (max - min + 1), min, max);
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function makeHandle(prefix: string, index: number, rng: () => number): string {
  const suffix = String(index).padStart(3, '0');
  const sep = rng() < 0.4 ? '_' : '';
  return `${prefix}${sep}${suffix}`;
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as SyntheticRequest;
  const seed = Number.isFinite(body.seed) ? (body.seed as number) : Date.now();
  const rng = mulberry32(seed);

  const startMs = body.startTime ? new Date(body.startTime).getTime() : Date.now() - 60 * 60 * 1000;
  const minutes = clampInt(body.minutes ?? 120, 5, 24 * 60);
  const endMs = startMs + minutes * 60 * 1000;

  const platforms = (body.platforms && body.platforms.length > 0 ? body.platforms : ['github', 'farcaster', 'base', 'talent']).slice(0, 6);
  const organicUsers = clampInt(body.organicUsers ?? 80, 5, 2000);
  const organicActions = clampInt(body.organicActions ?? 800, 10, 200000);
  const targets = clampInt(body.targets ?? 8, 1, 200);

  const sybilClusters = clampInt(body.sybilClusters ?? 2, 0, 50);
  const sybilClusterSize = clampInt(body.sybilClusterSize ?? 12, 3, 200);
  const sybilInternalEdgesPerActor = clampInt(body.sybilInternalEdgesPerActor ?? 3, 0, 50);

  const burstTargetIndex = clampInt(body.burstTargetIndex ?? 0, 0, targets - 1);
  const burstActorsPerCluster = clampInt(body.burstActorsPerCluster ?? Math.min(10, sybilClusterSize), 1, sybilClusterSize);
  const burstActionsPerActor = clampInt(body.burstActionsPerActor ?? 3, 1, 50);
  const burstWindowSeconds = clampInt(body.burstWindowSeconds ?? 120, 10, 3600);

  const includeProfiles = body.includeProfiles !== false;

  const organicActors = Array.from({ length: organicUsers }, (_, i) => `user${i + 1}`);
  const allTargets = Array.from({ length: targets }, (_, i) => `target${i + 1}`);

  const sybilActors: string[] = [];
  const clusters: Array<{ clusterId: number; members: string[]; prefix: string }> = [];
  for (let c = 0; c < sybilClusters; c++) {
    const prefix = `farm${c + 1}a`;
    const members = Array.from({ length: sybilClusterSize }, (_, i) => makeHandle(prefix, i + 1, rng));
    sybilActors.push(...members);
    clusters.push({ clusterId: c, members, prefix });
  }

  const allActors = [...organicActors, ...sybilActors];

  const logs: LogEntry[] = [];

  const profileByActor = new Map<string, Pick<LogEntry, 'bio' | 'links' | 'followerCount' | 'followingCount' | 'actorCreatedAt' | 'verified' | 'location'>>();
  if (includeProfiles) {
    const scamDomains = ['bit.ly', 't.co', 'tinyurl.com', 'talent.app', 'example.com'];
    const locations = ['NY, USA', 'SF, USA', 'Berlin', 'London', 'Remote', ''];

    const now = Date.now();
    for (const actor of allActors) {
      const isSybil = actor.startsWith('farm');
      const followerCount = isSybil ? randInt(rng, 0, 8) : randInt(rng, 10, 5000);
      const followingCount = isSybil ? randInt(rng, 50, 900) : randInt(rng, 10, 3000);
      const createdAtMs = now - (isSybil ? randInt(rng, 1, 10) : randInt(rng, 30, 2000)) * 24 * 60 * 60 * 1000;
      const verified = !isSybil && rng() < 0.08 ? true : undefined;
      const shared = isSybil && rng() < 0.85;
      const domain = shared ? pick(rng, scamDomains) : pick(rng, ['github.com', 'warpcast.com', 'example.org', 'site.dev']);
      const links = isSybil
        ? [`https://${domain}/invite/${actor}`]
        : rng() < 0.35
          ? [`https://${domain}/${actor}`]
          : [];
      const bio = isSybil ? `Builder • ${actor} • join my list` : rng() < 0.35 ? `Hi, I'm ${actor}` : '';
      profileByActor.set(actor, {
        bio: bio || undefined,
        links: links.length > 0 ? links : undefined,
        followerCount,
        followingCount,
        actorCreatedAt: iso(createdAtMs),
        verified,
        location: pick(rng, locations) || undefined,
      });
    }
  }

  function addLog(entry: Omit<LogEntry, 'timestamp'> & { timestampMs: number }) {
    const profile = includeProfiles ? profileByActor.get(entry.actor) : undefined;
    logs.push({
      timestamp: iso(entry.timestampMs),
      platform: entry.platform,
      action: entry.action,
      actor: entry.actor,
      target: entry.target,
      bio: profile?.bio,
      links: profile?.links,
      followerCount: profile?.followerCount,
      followingCount: profile?.followingCount,
      actorCreatedAt: profile?.actorCreatedAt,
      verified: profile?.verified,
      location: profile?.location,
      meta: entry.meta,
    });
  }

  // Organic activity
  const organicActionsList = ['follow', 'star', 'comment', 'issue', 'pr'];
  for (let i = 0; i < organicActions; i++) {
    const actor = pick(rng, organicActors);
    const target = pick(rng, allTargets);
    const platform = pick(rng, platforms);
    const action = pick(rng, organicActionsList);
    const ts = randInt(rng, startMs, endMs);
    addLog({ timestampMs: ts, platform, action, actor, target });
  }

  // Sybil internal edges (dense mutual follows/stars)
  for (const cluster of clusters) {
    for (const actor of cluster.members) {
      const internalTargets = cluster.members.filter((m) => m !== actor);
      const edges = Math.min(sybilInternalEdgesPerActor, internalTargets.length);
      for (let e = 0; e < edges; e++) {
        const target = pick(rng, internalTargets);
        const platform = pick(rng, platforms);
        const action = rng() < 0.7 ? 'follow' : 'star';
        const ts = randInt(rng, startMs, endMs);
        addLog({
          timestampMs: ts,
          platform,
          action,
          actor,
          target,
          meta: JSON.stringify({ synthetic: true, type: 'sybil-internal', clusterId: cluster.clusterId }),
        });
      }
    }
  }

  // Coordinated burst on a target (e.g., unfollow wave)
  const burstTarget = allTargets[burstTargetIndex] || allTargets[0];
  const burstStart = randInt(rng, startMs + 10 * 60 * 1000, endMs - 10 * 60 * 1000);

  for (const cluster of clusters) {
    const actors = cluster.members.slice(0, burstActorsPerCluster);
    for (const actor of actors) {
      for (let k = 0; k < burstActionsPerActor; k++) {
        const ts = burstStart + randInt(rng, 0, burstWindowSeconds * 1000);
        const platform = pick(rng, platforms);
        const action = rng() < 0.6 ? 'unfollow' : 'unstar';
        addLog({
          timestampMs: ts,
          platform,
          action,
          actor,
          target: burstTarget,
          meta: JSON.stringify({ synthetic: true, type: 'sybil-burst', clusterId: cluster.clusterId, burstTarget }),
        });
      }
    }
  }

  logs.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  return NextResponse.json({
    generatedAt: new Date().toISOString(),
    config: {
      seed,
      startTime: iso(startMs),
      minutes,
      platforms,
      organicUsers,
      organicActions,
      targets,
      sybilClusters,
      sybilClusterSize,
      sybilInternalEdgesPerActor,
      burstTarget,
      burstActorsPerCluster,
      burstActionsPerActor,
      burstWindowSeconds,
      includeProfiles,
    },
    groundTruth: {
      sybilActors,
      clusters: clusters.map((c) => ({ clusterId: c.clusterId, members: c.members })),
      burstTarget,
    },
    logs,
  });
}

