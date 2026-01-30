import type { EdgeDefinition, ElementDefinition, NodeDefinition } from 'cytoscape';
import { computeSharedLinksByActor, extractLinks, isSuspiciousDomain, linkDiversityScore, normalizeLinks, updateProfileAnomalyScore } from './profile';
import { computeHandlePatternScores, handleStem, isLikelyPhishingUrl } from './scam';
import { computeControllerGroups, type ControllerGroup } from './entity';

export type { ControllerGroup } from './entity';

export type LogEntry = {
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
  actorCreatedAt?: string;
  verified?: boolean;
  location?: string;
};

export type DetailedCluster = {
  clusterId: number;
  members: string[];
  density: number;
  conductance: number;
  externalEdges: number;
};

export type WaveResult = {
  windowStart: string;
  windowEnd: string;
  action: string;
  target: string;
  actors: string[];
  zScore: number;
  method?: 'bin' | 'window';
};

export type AnalysisSettings = {
  threshold: number;
  minClusterSize: number;
  timeBinMinutes: number;
  waveMinCount: number;
  waveMinActors: number;
  positiveActions: string[];
  churnActions: string[];
  rapidActionsPerMinuteThreshold: number;
  entropyMinTotalActions: number;
  burstWindowSeconds: number;
  burstMinCount: number;
  burstMinActors: number;
  velocityWindowSeconds: number;
  velocityMaxActionsInWindow: number;
  sessionGapMinutes: number;
  actionNgramSize: number;
  seedActors?: string[];
  seedInfluence: number; // 0..1 additive boost
  seedMaxHops: number; // 0..4
};

export type ActorScorecard = {
  actor: string;
  sybilScore: number;
  churnScore: number;
  coordinationScore: number;
  noveltyScore: number;
  clusterIsolationScore: number;
  lowDiversityScore: number;
  profileAnomalyScore: number;
  links: string[];
  suspiciousLinks: string[];
  sharedLinks: string[];
  linkDiversity: number;
  reciprocalRate: number;
  burstRate: number;
  newAccountScore: number;
  bioSimilarityScore: number;
  handlePatternScore: number;
  phishingLinkScore: number;
  pagerank: number;
  eigenCentrality: number;
  betweenness: number;
  maxActionsPerMinute: number;
  rapidActionScore: number;
  maxActionsPerVelocityWindow: number;
  maxActionsPerSecond: number;
  velocityScore: number;
  targetEntropy: number; // normalized [0,1]
  lowEntropyScore: number; // 1 - targetEntropy
  hourEntropy: number; // normalized [0,1]
  activeHours: number;
  circadianScore: number;
  actionSequenceRepeatScore: number;
  topActionNgram: string;
  topActionNgramCount: number;
  avgSessionMinutes: number;
  avgSessionGapMinutes: number;
  maxSessionGapMinutes: number;
  maxTargetJaccard: number;
  topTargetJaccardActor: string;
  seedProximityScore: number;
  sharedWallets: string[];
  crossAppPlatforms: string[];
  sessionCount: number;
  fraudTxScore: number;
  controllerId?: number;
  controllerGroupSize?: number;
  controllerScore?: number;
  controllerEvidence?: string[];
  reasons: string[];
};

export type AnalysisResult = {
  elements: ElementDefinition[];
  clusters: DetailedCluster[];
  waves: WaveResult[];
  scorecards: ActorScorecard[];
  controllers: ControllerGroup[];
};

export type AnalyzeProgress =
  | { stage: 'start'; pct: number }
  | { stage: 'profiles'; pct: number }
  | { stage: 'graph'; pct: number }
  | { stage: 'clusters'; pct: number }
  | { stage: 'waves'; pct: number }
  | { stage: 'scorecards'; pct: number }
  | { stage: 'done'; pct: number };

export function analyzeLogs(input: { logs: LogEntry[]; settings: AnalysisSettings; onProgress?: (p: AnalyzeProgress) => void }): AnalysisResult {
  const { logs, settings, onProgress } = input;
  const report = (p: AnalyzeProgress) => onProgress?.(p);
  report({ stage: 'start', pct: 0 });

  if (logs.length === 0) return { elements: [], clusters: [], waves: [], scorecards: [], controllers: [] };

  const allTimes = logs.map((l) => new Date(l.timestamp).getTime()).filter((t) => Number.isFinite(t));
  const datasetStartMs = allTimes.length > 0 ? Math.min(...allTimes) : Date.now();

  // Collect profile data
  const actorProfiles: Record<
    string,
    { bio?: string; links?: string[]; followerCount?: number; followingCount?: number; actorCreatedAt?: string; verified?: boolean; location?: string }
  > = {};
  logs.forEach((log) => {
    if (!actorProfiles[log.actor]) actorProfiles[log.actor] = {};
    if (log.bio) actorProfiles[log.actor].bio = log.bio;
    if (log.links) actorProfiles[log.actor].links = normalizeLinks(log.links);
    if (log.followerCount !== undefined) actorProfiles[log.actor].followerCount = log.followerCount;
    if (log.followingCount !== undefined) actorProfiles[log.actor].followingCount = log.followingCount;
    if (log.actorCreatedAt) actorProfiles[log.actor].actorCreatedAt = log.actorCreatedAt;
    if (log.verified !== undefined) actorProfiles[log.actor].verified = log.verified;
    if (log.location) actorProfiles[log.actor].location = log.location;
  });

  const linksByActor = new Map<string, string[]>();
  Object.entries(actorProfiles).forEach(([actor, profile]) => {
    const fromProfile = profile.links ?? [];
    const fromBio = profile.bio ? extractLinks(profile.bio) : [];
    linksByActor.set(actor, normalizeLinks([...fromProfile, ...fromBio]));
  });
  const sharedLinksByActor = computeSharedLinksByActor(linksByActor);

  const normalizedBioByActor = new Map<string, string>();
  const bioCount = new Map<string, number>();
  Object.entries(actorProfiles).forEach(([actor, profile]) => {
    const bio = (profile.bio || '').toLowerCase().replace(/\s+/g, ' ').trim();
    if (!bio) return;
    normalizedBioByActor.set(actor, bio);
    bioCount.set(bio, (bioCount.get(bio) || 0) + 1);
  });
  report({ stage: 'profiles', pct: 15 });

  // Build graph from positive actions
  const nodes = new Set<string>();
  const edges: EdgeDefinition[] = [];
  const positiveOut = new Map<string, Set<string>>();
  const positiveIn = new Map<string, Set<string>>();

  logs.forEach((log) => {
    nodes.add(log.actor);
    nodes.add(log.target);
    if (settings.positiveActions.includes(log.action)) {
      edges.push({ data: { source: log.actor, target: log.target, type: 'interaction' } });
      if (!positiveOut.has(log.actor)) positiveOut.set(log.actor, new Set());
      if (!positiveIn.has(log.target)) positiveIn.set(log.target, new Set());
      positiveOut.get(log.actor)!.add(log.target);
      positiveIn.get(log.target)!.add(log.actor);
    }
  });

  const nodeElements: NodeDefinition[] = Array.from(nodes).map((id) => ({ data: { id, label: id } }));
  const elements: ElementDefinition[] = [...nodeElements, ...edges];
  report({ stage: 'graph', pct: 30 });

  // Centrality measures (computed on the positive-action graph)
  const outNeighbors = new Map<string, string[]>();
  const inNeighbors = new Map<string, string[]>();
  const undirected = new Map<string, Set<string>>();
  nodes.forEach((n) => {
    outNeighbors.set(n, []);
    inNeighbors.set(n, []);
    undirected.set(n, new Set());
  });
  edges.forEach((e) => {
    const s = e.data?.source as string;
    const t = e.data?.target as string;
    if (!s || !t) return;
    outNeighbors.get(s)?.push(t);
    inNeighbors.get(t)?.push(s);
    undirected.get(s)?.add(t);
    undirected.get(t)?.add(s);
  });

  const pagerank = computePageRank(Array.from(nodes), outNeighbors, inNeighbors);
  const eigenCentrality = computeEigenCentrality(Array.from(nodes), undirected);
  const betweenness = computeApproxBetweenness(Array.from(nodes), undirected);
  report({ stage: 'clusters', pct: 38 });

  // Build adjacency for undirected connected components
  const graph: Record<string, string[]> = {};
  nodes.forEach((node) => (graph[node] = []));
  edges.forEach((edge) => {
    const s = edge.data?.source as string;
    const t = edge.data?.target as string;
    if (!s || !t) return;
    graph[s].push(t);
    graph[t].push(s);
  });

  const visited = new Set<string>();
  const clusters: DetailedCluster[] = [];
  let clusterId = 0;

  const dfs = (start: string, component: string[]) => {
    const stack = [start];
    visited.add(start);
    while (stack.length > 0) {
      const node = stack.pop()!;
      component.push(node);
      for (const neighbor of graph[node] || []) {
        if (visited.has(neighbor)) continue;
        visited.add(neighbor);
        stack.push(neighbor);
      }
    }
  };

  for (const node of nodes) {
    if (visited.has(node)) continue;
    const component: string[] = [];
    dfs(node, component);
    if (component.length < settings.minClusterSize) continue;

    const memberSet = new Set(component);
    const internalEdges = component.reduce((sum, n) => sum + (graph[n] || []).filter((neigh) => memberSet.has(neigh)).length, 0) / 2;
    const possibleEdges = (component.length * (component.length - 1)) / 2;
    const density = possibleEdges > 0 ? internalEdges / possibleEdges : 0;
    const externalEdges = component.reduce((sum, n) => sum + (graph[n] || []).filter((neigh) => !memberSet.has(neigh)).length, 0);
    const totalEdges = internalEdges + externalEdges;
    const conductance = totalEdges > 0 ? externalEdges / totalEdges : 0;

    clusters.push({
      clusterId: clusterId++,
      members: component,
      density,
      conductance,
      externalEdges,
    });
  }
  report({ stage: 'clusters', pct: 45 });

  // Timing coordination (bin -> action -> target -> {count, actors})
  const binSizeMs = Math.max(1, settings.timeBinMinutes) * 60 * 1000;
  const timeBins: Record<string, Record<string, Record<string, { count: number; actors: Set<string> }>>> = {};
  logs.forEach((log) => {
    const date = new Date(log.timestamp);
    const bin = Math.floor(date.getTime() / binSizeMs) * binSizeMs;
    const binKey = new Date(bin).toISOString();
    if (!timeBins[binKey]) timeBins[binKey] = {};
    if (!timeBins[binKey][log.action]) timeBins[binKey][log.action] = {};
    if (!timeBins[binKey][log.action][log.target]) timeBins[binKey][log.action][log.target] = { count: 0, actors: new Set() };
    timeBins[binKey][log.action][log.target].count++;
    timeBins[binKey][log.action][log.target].actors.add(log.actor);
  });

  const waves: WaveResult[] = [];
  Object.entries(timeBins).forEach(([time, actions]) => {
    Object.entries(actions).forEach(([action, targets]) => {
      Object.entries(targets).forEach(([target, info]) => {
        if (info.count >= settings.waveMinCount && info.actors.size >= settings.waveMinActors) {
          waves.push({
            windowStart: time,
            windowEnd: new Date(new Date(time).getTime() + binSizeMs).toISOString(),
            action,
            target,
            actors: Array.from(info.actors),
            zScore: info.count / Math.max(1, settings.waveMinCount),
            method: 'bin',
          });
        }
      });
    });
  });

  // Sliding-window bursts (avoids missing coordination when actors straddle fixed bins)
  const burstWindowMs = Math.max(1, settings.burstWindowSeconds) * 1000;
  const burstResult = detectWindowBursts({
    logs,
    windowMs: burstWindowMs,
    minCount: Math.max(1, settings.burstMinCount),
    minActors: Math.max(1, settings.burstMinActors),
  });
  burstResult.bursts.forEach((b) => waves.push(b));
  report({ stage: 'waves', pct: 60 });

  // Actor stats for scoring
  type ActorStats = {
    actor: string;
    totalActions: number;
    churnActions: number;
    burstActions: number;
    uniqueTargets: Set<string>;
    connections: number;
    clusterSize: number;
    positiveOut: number;
    positiveIn: number;
    mutualPositive: number;
    firstSeenMs?: number;
  };

  const actorStats: Record<string, ActorStats> = {};
  nodes.forEach((node) => {
    actorStats[node] = {
      actor: node,
      totalActions: 0,
      churnActions: 0,
      burstActions: 0,
      uniqueTargets: new Set(),
      connections: graph[node]?.length ?? 0,
      clusterSize: 0,
      positiveOut: positiveOut.get(node)?.size ?? 0,
      positiveIn: positiveIn.get(node)?.size ?? 0,
      mutualPositive: 0,
    };
  });

  logs.forEach((log) => {
    const s = actorStats[log.actor];
    if (!s) return;
    s.totalActions++;
    s.uniqueTargets.add(log.target);
    if (settings.churnActions.includes(log.action)) s.churnActions++;
    const ts = new Date(log.timestamp).getTime();
    if (Number.isFinite(ts)) s.firstSeenMs = s.firstSeenMs === undefined ? ts : Math.min(s.firstSeenMs, ts);
  });

  clusters.forEach((cluster) => {
    cluster.members.forEach((member) => {
      if (actorStats[member]) actorStats[member].clusterSize = cluster.members.length;
    });
  });

  // Mini-app style signals: rapid actions/minute and target entropy
  const perActorMinuteCounts = new Map<string, Map<number, number>>();
  logs.forEach((log) => {
    const t = new Date(log.timestamp).getTime();
    if (!Number.isFinite(t)) return;
    const minute = Math.floor(t / 60000);
    if (!perActorMinuteCounts.has(log.actor)) perActorMinuteCounts.set(log.actor, new Map());
    const m = perActorMinuteCounts.get(log.actor)!;
    m.set(minute, (m.get(minute) || 0) + 1);
  });

  const maxActionsPerMinute = new Map<string, number>();
  perActorMinuteCounts.forEach((m, actor) => {
    let max = 0;
    m.forEach((c) => {
      if (c > max) max = c;
    });
    maxActionsPerMinute.set(actor, max);
  });

  const targetEntropy = new Map<string, number>();
  Object.values(actorStats).forEach((s) => {
    const k = s.uniqueTargets.size;
    if (s.totalActions <= 0 || k <= 1) {
      targetEntropy.set(s.actor, 0);
      return;
    }
    // Recompute per-actor target counts from logs (streaming would be better, but OK for now)
    const counts = new Map<string, number>();
    logs.forEach((log) => {
      if (log.actor !== s.actor) return;
      counts.set(log.target, (counts.get(log.target) || 0) + 1);
    });
    const total = s.totalActions;
    let H = 0;
    counts.forEach((c) => {
      const p = c / total;
      H += -p * Math.log(p);
    });
    const Hmax = Math.log(k) || 1;
    targetEntropy.set(s.actor, Math.max(0, Math.min(H / Hmax, 1)));
  });

  // reciprocity
  nodes.forEach((actor) => {
    const outSet = positiveOut.get(actor) ?? new Set<string>();
    let mutual = 0;
    outSet.forEach((t) => {
      const back = positiveOut.get(t);
      if (back?.has(actor)) mutual++;
    });
    actorStats[actor].mutualPositive = mutual;
  });

  // wave bins by actor
  const waveBinsByActor = new Map<string, Set<string>>();
  Object.entries(timeBins).forEach(([binKey, actions]) => {
    Object.entries(actions).forEach(([action, targets]) => {
      Object.entries(targets).forEach(([target, info]) => {
        if (info.count >= settings.waveMinCount && info.actors.size >= settings.waveMinActors) {
          const waveKey = `${binKey}:${action}:${target}`;
          info.actors.forEach((actor) => {
            if (!waveBinsByActor.has(actor)) waveBinsByActor.set(actor, new Set());
            waveBinsByActor.get(actor)!.add(waveKey);
          });
        }
      });
    });
  });
  // include sliding window bursts in "burstActions"
  burstResult.burstKeysByActor.forEach((keys, actor) => {
    if (!waveBinsByActor.has(actor)) waveBinsByActor.set(actor, new Set());
    const s = waveBinsByActor.get(actor)!;
    keys.forEach((k) => s.add(k));
  });
  Object.keys(actorStats).forEach((actor) => {
    actorStats[actor].burstActions = waveBinsByActor.get(actor)?.size ?? 0;
  });

  const handlePatterns = computeHandlePatternScores(Array.from(nodes));

  // Additional mini-app detections
  const sharedFundersByWallet = detectSharedWallets(logs);
  const crossAppLinks = detectCrossAppLinking(logs);
  const sessionMetrics = detectSessionMetrics(logs, Math.max(1, settings.sessionGapMinutes) * 60 * 1000);
  const fraudulentTx = detectFraudulentTransactions(logs);
  const velocityByActor = computeVelocityByActor(
    logs,
    Math.max(1, settings.velocityWindowSeconds) * 1000,
    Math.max(1, settings.velocityMaxActionsInWindow),
  );
  const circadianByActor = computeCircadianByActor(logs);
  const ngramByActor = computeActionNgramByActor(logs, Math.min(Math.max(2, settings.actionNgramSize), 5));

  // Cross-actor similarity (same targets == coordinated ops / multi-account)
  const maxJaccardByActor = new Map<string, { score: number; peer: string }>();
  const targetToActors = new Map<string, string[]>();
  Object.values(actorStats).forEach((s) => {
    s.uniqueTargets.forEach((t) => {
      if (!targetToActors.has(t)) targetToActors.set(t, []);
      targetToActors.get(t)!.push(s.actor);
    });
  });
  Object.values(actorStats).forEach((s) => {
    const counts = new Map<string, number>();
    s.uniqueTargets.forEach((t) => {
      const co = targetToActors.get(t) || [];
      for (const other of co) {
        if (other === s.actor) continue;
        counts.set(other, (counts.get(other) || 0) + 1);
      }
    });
    let bestPeer = '';
    let best = 0;
    counts.forEach((intersect, peer) => {
      const aSize = s.uniqueTargets.size;
      const bSize = actorStats[peer].uniqueTargets.size;
      const union = aSize + bSize - intersect;
      if (union <= 0) return;
      const j = intersect / union;
      if (j > best) {
        best = j;
        bestPeer = peer;
      }
    });
    maxJaccardByActor.set(s.actor, { score: best, peer: bestPeer });
  });

  // Seed-based propagation: if you already confirmed some sybils, expand suspicion to nearby nodes
  const seedInfluence = Math.max(0, Math.min(settings.seedInfluence ?? 0, 1));
  const seedMaxHops = Math.min(Math.max(settings.seedMaxHops ?? 0, 0), 4);
  const seedProximity = new Map<string, number>();
  const seeds = Array.from(new Set((settings.seedActors || []).map((x) => String(x))));
  if (seeds.length > 0 && seedInfluence > 0 && seedMaxHops > 0) {
    const queue: Array<{ node: string; hop: number }> = [];
    const seenHop = new Map<string, number>();
    for (const s of seeds) {
      if (!nodes.has(s)) continue;
      queue.push({ node: s, hop: 0 });
      seenHop.set(s, 0);
      seedProximity.set(s, 1);
    }
    while (queue.length) {
      const { node, hop } = queue.shift()!;
      if (hop >= seedMaxHops) continue;
      const neighbors = graph[node] || [];
      for (const nb of neighbors) {
        const nextHop = hop + 1;
        const prevHop = seenHop.get(nb);
        if (prevHop !== undefined && prevHop <= nextHop) continue;
        seenHop.set(nb, nextHop);
        const proximity = Math.max(0, 1 - nextHop / (seedMaxHops + 0.0001));
        seedProximity.set(nb, Math.max(seedProximity.get(nb) || 0, proximity));
        queue.push({ node: nb, hop: nextHop });
      }
    }
  }

  // Controller / entity resolution (multi-account linking)
  const bioByActor = new Map<string, string>();
  const handleStemByActor = new Map<string, string>();
  const extraWalletsByActor = new Map<string, string[]>();

  Object.keys(actorStats).forEach((actor) => {
    const profile = actorProfiles[actor] || {};
    const existing = linksByActor.get(actor);
    if (!existing) {
      linksByActor.set(actor, normalizeLinks(profile.links || (profile.bio ? extractLinks(profile.bio) : [])));
    }
    const bio = (profile.bio || '').trim();
    if (bio) bioByActor.set(actor, bio);
    handleStemByActor.set(actor, handleStem(actor.includes(':') ? actor.split(':').slice(1).join(':') : actor));
  });

  // Map social actors -> wallets mentioned in links/bios/meta and onchain actors -> related wallets.
  logs.forEach((log) => {
    const candidates: string[] = [];
    if (typeof log.meta === 'string' && log.meta) candidates.push(log.meta);
    if (typeof log.txHash === 'string' && log.txHash) candidates.push(log.txHash);
    const joined = candidates.join('\n');
    if (!joined) return;
    const wallets = Array.from(new Set((joined.match(/\b0x[a-fA-F0-9]{40}\b/g) || []).map((x) => x.toLowerCase())));
    if (wallets.length === 0) return;
    const a = log.actor;
    if (!extraWalletsByActor.has(a)) extraWalletsByActor.set(a, []);
    extraWalletsByActor.get(a)!.push(...wallets);
  });
  extraWalletsByActor.forEach((ws, actor) => extraWalletsByActor.set(actor, Array.from(new Set(ws))));

  const controller = computeControllerGroups({
    actors: Object.keys(actorStats),
    linksByActor,
    bioByActor,
    handleStemByActor,
    sharedFundersByWallet,
    extraWalletsByActor,
    minGroupSize: 3,
  });

  const scorecards: ActorScorecard[] = Object.values(actorStats).map((stats) => {
    const coordinationScore = stats.totalActions > 0 ? Math.min(stats.burstActions / stats.totalActions, 1) : 0;
    const churnScore = stats.churnActions;
    const clusterIsolationScore = stats.clusterSize > 0 ? 1 - stats.connections / stats.clusterSize : 0;
    const createdAt = actorProfiles[stats.actor]?.actorCreatedAt;
    const createdMs = createdAt ? new Date(createdAt).getTime() : undefined;
    const firstSeenMs = stats.firstSeenMs ?? datasetStartMs;
    const ageDays = createdMs && Number.isFinite(createdMs) ? (firstSeenMs - createdMs) / (24 * 60 * 60 * 1000) : undefined;
    const newAccountScore = ageDays !== undefined && ageDays >= 0 && ageDays < 7 ? 1 : 0;
    const lowDiversityScore = stats.totalActions > 0 ? 1 - stats.uniqueTargets.size / stats.totalActions : 0;

    const profile = actorProfiles[stats.actor] || {};
    const links = linksByActor.get(stats.actor) ?? normalizeLinks(profile.links || (profile.bio ? extractLinks(profile.bio) : []));
    const suspiciousLinks = links.filter((link) => isSuspiciousDomain(link));
    const phishingLinks = links.filter((link) => isLikelyPhishingUrl(link));
    const sharedLinks = sharedLinksByActor.get(stats.actor) ?? [];
    const linkDiversity = linkDiversityScore(links);
    const reciprocalRate = stats.positiveOut > 0 ? stats.mutualPositive / stats.positiveOut : 0;
    const burstRate = stats.totalActions > 0 ? Math.min(stats.burstActions / stats.totalActions, 1) : 0;
    const bio = normalizedBioByActor.get(stats.actor);
    const bioSimilarityScore = bio ? Math.min(((bioCount.get(bio) || 1) - 1) / 5, 1) : 0;
    const handlePatternScore = handlePatterns.scoreByHandle.get(stats.actor) ?? 0;
    const phishingLinkScore = phishingLinks.length > 0 ? Math.min(phishingLinks.length / 2, 1) : 0;
    const profileAnomalyScore = updateProfileAnomalyScore(stats.actor, links, profile.followerCount, profile.followingCount);

    const baseSybilScore =
      0.30 * coordinationScore +
      0.20 * Math.min(churnScore / 10, 1) +
      0.15 * clusterIsolationScore +
      0.10 * newAccountScore +
      0.10 * lowDiversityScore +
      0.15 * profileAnomalyScore;

    const maxApm = maxActionsPerMinute.get(stats.actor) || 0;
    const rapidActionScore =
      maxApm >= Math.max(1, settings.rapidActionsPerMinuteThreshold)
        ? Math.min((maxApm - settings.rapidActionsPerMinuteThreshold) / settings.rapidActionsPerMinuteThreshold, 1)
        : 0;

    const ent = targetEntropy.get(stats.actor) ?? 0;
    const lowEntropyScore = 1 - ent;

    const velocity = velocityByActor.get(stats.actor) ?? { maxInWindow: 0, maxPerSecond: 0, velocityScore: 0 };
    const circadian = circadianByActor.get(stats.actor) ?? { hourEntropy: 0, activeHours: 0, circadianScore: 0 };
    const ngram = ngramByActor.get(stats.actor) ?? { repeatScore: 0, topNgram: '', topCount: 0 };

    const session = sessionMetrics.get(stats.actor) ?? {
      sessionCount: 0,
      avgSessionMinutes: 0,
      avgGapMinutes: 0,
      maxGapMinutes: 0,
      bottySessionScore: 0,
    };

    const jacc = maxJaccardByActor.get(stats.actor) ?? { score: 0, peer: '' };
    const seedProximityScore = seedProximity.get(stats.actor) ?? 0;

    // Extra mini-app style risk boosters (kept additive + clamped for backwards compatibility)
    const sharedWalletScore = (sharedFundersByWallet.get(stats.actor)?.length ?? 0) > 0 ? 1 : 0;
    const crossAppScore = (crossAppLinks.get(stats.actor)?.length ?? 0) > 1 ? 0.5 : 0;
    const sessionScore = session.bottySessionScore;
    const fraudScore = fraudulentTx.get(stats.actor) ?? 0;
    const sybilScore = Math.min(
      baseSybilScore +
        0.10 * rapidActionScore +
        0.05 * (stats.totalActions >= settings.entropyMinTotalActions ? lowEntropyScore : 0) +
        0.05 * velocity.velocityScore +
        0.03 * ngram.repeatScore +
        0.03 * circadian.circadianScore +
        0.05 * (jacc.score >= 0.85 && stats.uniqueTargets.size >= 3 ? Math.min((jacc.score - 0.85) / 0.15, 1) : 0) +
        seedInfluence * seedProximityScore +
        0.05 * sharedWalletScore +
        0.05 * crossAppScore +
        0.05 * sessionScore +
        0.05 * fraudScore,
      1,
    );

    const reasons: string[] = [];
    if (sybilScore > settings.threshold) reasons.push(`Score ${sybilScore.toFixed(2)} ≥ threshold ${settings.threshold.toFixed(2)}`);
    if (coordinationScore >= 0.5) reasons.push(`High coordination (${coordinationScore.toFixed(2)})`);
    if (churnScore >= 5) reasons.push(`High churn (${churnScore})`);
    if (clusterIsolationScore >= 0.5 && stats.clusterSize >= settings.minClusterSize) reasons.push(`Cluster isolation (${clusterIsolationScore.toFixed(2)}) in cluster size ${stats.clusterSize}`);
    if (lowDiversityScore >= 0.7) reasons.push(`Low target diversity (${lowDiversityScore.toFixed(2)})`);
    if (suspiciousLinks.length > 0) reasons.push(`Suspicious link domains (${suspiciousLinks.length})`);
    if (phishingLinks.length > 0) reasons.push(`Phishing-like URLs (${phishingLinks.length})`);
    if (sharedLinks.length > 0) reasons.push(`Shared links with others (${sharedLinks.length})`);
    if (bioSimilarityScore >= 0.4) reasons.push(`Repeated bio text (${bioSimilarityScore.toFixed(2)})`);
    if (handlePatternScore >= 0.4) reasons.push(`Handle pattern similarity (${handlePatternScore.toFixed(2)})`);
    if (newAccountScore === 1) reasons.push('New account (<7 days)');
    if ((pagerank.get(stats.actor) || 0) > 0.01) reasons.push(`High PageRank (${(pagerank.get(stats.actor) || 0).toFixed(3)})`);
    if ((betweenness.get(stats.actor) || 0) > 0.05) reasons.push(`Bridge-like betweenness (${(betweenness.get(stats.actor) || 0).toFixed(2)})`);
    if (maxApm >= settings.rapidActionsPerMinuteThreshold) reasons.push(`Rapid actions (${maxApm}/min)`);
    if (velocity.velocityScore >= 0.7) reasons.push(`High velocity (${velocity.maxInWindow} in ${Math.max(1, settings.velocityWindowSeconds)}s)`);
    if (ngram.repeatScore >= 0.7 && ngram.topNgram) reasons.push(`Script-like sequence (${ngram.topNgram})`);
    if (circadian.circadianScore >= 0.8) reasons.push(`Unnatural circadian pattern (active hours ${circadian.activeHours})`);
    if (jacc.score >= 0.85 && stats.uniqueTargets.size >= 3 && jacc.peer) reasons.push(`Very similar targets to ${jacc.peer} (Jaccard ${jacc.score.toFixed(2)})`);
    if (seedInfluence > 0 && seedProximityScore >= 0.5) reasons.push(`Near confirmed sybil(s) (seed proximity ${seedProximityScore.toFixed(2)})`);
    if (stats.totalActions >= settings.entropyMinTotalActions && lowEntropyScore >= 0.7) reasons.push(`Low target entropy (${ent.toFixed(2)})`);
    if (sharedFundersByWallet.get(stats.actor)?.length) reasons.push(`Shared funders (${sharedFundersByWallet.get(stats.actor)!.length})`);
    if (crossAppLinks.get(stats.actor)?.length) reasons.push(`Cross-app activity (${crossAppLinks.get(stats.actor)!.join(', ')})`);
    if (session.sessionCount > 5) reasons.push(`High session count (${session.sessionCount})`);
    if ((fraudulentTx.get(stats.actor) ?? 0) > 0.5) reasons.push(`Fraudulent transaction patterns (${(fraudulentTx.get(stats.actor) ?? 0).toFixed(2)})`);

    return {
      actor: stats.actor,
      sybilScore,
      churnScore,
      coordinationScore,
      noveltyScore: newAccountScore,
      clusterIsolationScore,
      lowDiversityScore,
      profileAnomalyScore,
      links,
      suspiciousLinks,
      sharedLinks,
      linkDiversity,
      reciprocalRate,
      burstRate,
      newAccountScore,
      bioSimilarityScore,
      handlePatternScore,
      phishingLinkScore,
      pagerank: pagerank.get(stats.actor) || 0,
      eigenCentrality: eigenCentrality.get(stats.actor) || 0,
      betweenness: betweenness.get(stats.actor) || 0,
      maxActionsPerMinute: maxApm,
      rapidActionScore,
      maxActionsPerVelocityWindow: velocity.maxInWindow,
      maxActionsPerSecond: velocity.maxPerSecond,
      velocityScore: velocity.velocityScore,
      targetEntropy: ent,
      lowEntropyScore,
      hourEntropy: circadian.hourEntropy,
      activeHours: circadian.activeHours,
      circadianScore: circadian.circadianScore,
      actionSequenceRepeatScore: ngram.repeatScore,
      topActionNgram: ngram.topNgram,
      topActionNgramCount: ngram.topCount,
      avgSessionMinutes: session.avgSessionMinutes,
      avgSessionGapMinutes: session.avgGapMinutes,
      maxSessionGapMinutes: session.maxGapMinutes,
      maxTargetJaccard: jacc.score,
      topTargetJaccardActor: jacc.peer,
      seedProximityScore,
      sharedWallets: sharedFundersByWallet.get(stats.actor) ?? [],
      crossAppPlatforms: crossAppLinks.get(stats.actor) ?? [],
      sessionCount: session.sessionCount,
      fraudTxScore: fraudulentTx.get(stats.actor) ?? 0,
      reasons,
    };
  });

  report({ stage: 'scorecards', pct: 90 });
  report({ stage: 'done', pct: 100 });
  // Attach controller/linking info to scorecards
  const controllerIdByActor = controller.controllerIdByActor;
  const controllerSizeById = new Map<number, number>();
  const controllerById = new Map<number, ControllerGroup>();
  controller.groups.forEach((g) => {
    controllerSizeById.set(g.controllerId, g.members.length);
    controllerById.set(g.controllerId, g);
  });
  scorecards.forEach((s) => {
    const id = controllerIdByActor.get(s.actor);
    if (id === undefined) return;
    const size = controllerSizeById.get(id) || 0;
    const g = controllerById.get(id);
    s.controllerId = id;
    s.controllerGroupSize = size;
    s.controllerScore = g?.score;
    s.controllerEvidence = g?.evidence;
    if (size >= 3) s.reasons.push(`Likely same controller (#${id}, size ${size})`);
  });

  return { elements, clusters, waves, scorecards, controllers: controller.groups };
}

export function detectSharedWallets(logs: LogEntry[]): Map<string, string[]> {
  // Detect "shared funders" across wallet actors (common funding sources used to seed multiple wallets).
  const isAddr = (x: string) => /^0x[a-fA-F0-9]{40}$/.test(x);

  const funderToTargets = new Map<string, Set<string>>();
  logs.forEach((log) => {
    if (log.action !== 'transfer') return;
    if (!isAddr(log.actor) || !isAddr(log.target)) return;
    const funder = log.actor.toLowerCase();
    const target = log.target.toLowerCase();
    if (!funderToTargets.has(funder)) funderToTargets.set(funder, new Set());
    funderToTargets.get(funder)!.add(target);
  });

  const walletToSharedFunders = new Map<string, string[]>();
  funderToTargets.forEach((targets, funder) => {
    if (targets.size < 2) return;
    targets.forEach((wallet) => {
      if (!walletToSharedFunders.has(wallet)) walletToSharedFunders.set(wallet, []);
      walletToSharedFunders.get(wallet)!.push(funder);
    });
  });
  return walletToSharedFunders;
}

export function detectCrossAppLinking(logs: LogEntry[]): Map<string, string[]> {
  const actorToPlatforms = new Map<string, Set<string>>();
  logs.forEach(log => {
    if (!actorToPlatforms.has(log.actor)) actorToPlatforms.set(log.actor, new Set());
    actorToPlatforms.get(log.actor)!.add(log.platform);
  });
  const crossAppActors = new Map<string, string[]>();
  actorToPlatforms.forEach((platforms, actor) => {
    if (platforms.size > 1) {
      crossAppActors.set(actor, Array.from(platforms));
    }
  });
  return crossAppActors;
}

export function detectSessionAnomalies(logs: LogEntry[], sessionThresholdMs: number = 300000): Map<string, number> {
  const metrics = detectSessionMetrics(logs, sessionThresholdMs);
  const out = new Map<string, number>();
  metrics.forEach((m, actor) => out.set(actor, m.sessionCount));
  return out;
}

export function detectSessionMetrics(
  logs: LogEntry[],
  sessionThresholdMs: number = 300000,
): Map<
  string,
  { sessionCount: number; avgSessionMinutes: number; avgGapMinutes: number; maxGapMinutes: number; bottySessionScore: number }
> {
  const actorTimes = new Map<string, number[]>();
  logs.forEach((log) => {
    const ts = new Date(log.timestamp).getTime();
    if (!Number.isFinite(ts)) return;
    if (!actorTimes.has(log.actor)) actorTimes.set(log.actor, []);
    actorTimes.get(log.actor)!.push(ts);
  });

  const out = new Map<
    string,
    { sessionCount: number; avgSessionMinutes: number; avgGapMinutes: number; maxGapMinutes: number; bottySessionScore: number }
  >();

  actorTimes.forEach((times, actor) => {
    if (times.length === 0) return;
    times.sort((a, b) => a - b);
    const sessionDurations: number[] = [];
    const gaps: number[] = [];

    let sessionStart = times[0];
    let sessionEnd = times[0];
    for (let i = 1; i < times.length; i++) {
      const gap = times[i] - times[i - 1];
      if (gap > sessionThresholdMs) {
        sessionDurations.push(sessionEnd - sessionStart);
        gaps.push(gap);
        sessionStart = times[i];
        sessionEnd = times[i];
      } else {
        sessionEnd = times[i];
      }
    }
    sessionDurations.push(sessionEnd - sessionStart);

    const sessionCount = sessionDurations.length;
    const avgSessionMs = sessionDurations.reduce((a, b) => a + b, 0) / Math.max(1, sessionDurations.length);
    const avgGapMs = gaps.length ? gaps.reduce((a, b) => a + b, 0) / gaps.length : 0;
    const maxGapMs = gaps.length ? Math.max(...gaps) : 0;

    // Botty if many sessions and sessions are very short (e.g., scripted “tap/claim” bursts).
    const shortSessionScore = avgSessionMs <= 60_000 ? 1 : avgSessionMs <= 5 * 60_000 ? 0.5 : 0;
    const manySessionScore = Math.min(sessionCount / 10, 1);
    const bottySessionScore = Math.min(shortSessionScore * manySessionScore, 1);

    out.set(actor, {
      sessionCount,
      avgSessionMinutes: avgSessionMs / 60_000,
      avgGapMinutes: avgGapMs / 60_000,
      maxGapMinutes: maxGapMs / 60_000,
      bottySessionScore,
    });
  });

  return out;
}

function computeVelocityByActor(
  logs: LogEntry[],
  windowMs: number,
  velocityMaxActionsInWindow: number,
): Map<string, { maxInWindow: number; maxPerSecond: number; velocityScore: number }> {
  const actorTimes = new Map<string, number[]>();
  logs.forEach((log) => {
    const ts = new Date(log.timestamp).getTime();
    if (!Number.isFinite(ts)) return;
    if (!actorTimes.has(log.actor)) actorTimes.set(log.actor, []);
    actorTimes.get(log.actor)!.push(ts);
  });

  const out = new Map<string, { maxInWindow: number; maxPerSecond: number; velocityScore: number }>();
  actorTimes.forEach((times, actor) => {
    times.sort((a, b) => a - b);
    let left = 0;
    let maxCount = 0;
    for (let right = 0; right < times.length; right++) {
      while (times[right] - times[left] > windowMs) left++;
      const count = right - left + 1;
      if (count > maxCount) maxCount = count;
    }
    const windowSeconds = Math.max(1, windowMs / 1000);
    const maxPerSecond = maxCount / windowSeconds;
    const threshold = Math.max(1, velocityMaxActionsInWindow);
    const velocityScore = maxCount >= threshold ? Math.min((maxCount - threshold) / threshold, 1) : 0;
    out.set(actor, { maxInWindow: maxCount, maxPerSecond, velocityScore });
  });
  return out;
}

function computeCircadianByActor(logs: LogEntry[]): Map<string, { hourEntropy: number; activeHours: number; circadianScore: number }> {
  const perActorHours = new Map<string, number[]>();
  logs.forEach((log) => {
    const ts = new Date(log.timestamp).getTime();
    if (!Number.isFinite(ts)) return;
    const h = new Date(ts).getUTCHours();
    if (!perActorHours.has(log.actor)) perActorHours.set(log.actor, []);
    perActorHours.get(log.actor)!.push(h);
  });

  const out = new Map<string, { hourEntropy: number; activeHours: number; circadianScore: number }>();
  perActorHours.forEach((hours, actor) => {
    const counts = new Array<number>(24).fill(0);
    for (const h of hours) counts[h] += 1;
    const activeHours = counts.filter((c) => c > 0).length;
    const total = hours.length;
    let H = 0;
    for (const c of counts) {
      if (c === 0) continue;
      const p = c / total;
      H += -p * Math.log(p);
    }
    const Hmax = Math.log(24) || 1;
    const hourEntropy = Math.max(0, Math.min(H / Hmax, 1));

    // Two “odd” regimes:
    // - very wide activity (near 24h) at high volume can indicate automation
    // - very narrow activity (1-2h) at high volume can indicate coordination farms
    const wide = activeHours >= 20 && total >= 200 ? 1 : 0;
    const narrow = activeHours <= 2 && total >= 100 ? 0.8 : 0;
    const circadianScore = Math.max(wide, narrow);

    out.set(actor, { hourEntropy, activeHours, circadianScore });
  });
  return out;
}

function computeActionNgramByActor(logs: LogEntry[], n: number): Map<string, { repeatScore: number; topNgram: string; topCount: number }> {
  const perActor = new Map<string, Array<{ ts: number; action: string }>>();
  logs.forEach((log) => {
    const ts = new Date(log.timestamp).getTime();
    if (!Number.isFinite(ts)) return;
    if (!perActor.has(log.actor)) perActor.set(log.actor, []);
    perActor.get(log.actor)!.push({ ts, action: String(log.action || '') });
  });

  const out = new Map<string, { repeatScore: number; topNgram: string; topCount: number }>();
  perActor.forEach((rows, actor) => {
    rows.sort((a, b) => a.ts - b.ts);
    const seq = rows.map((r) => r.action).filter(Boolean);
    if (seq.length < n + 2) {
      out.set(actor, { repeatScore: 0, topNgram: '', topCount: 0 });
      return;
    }
    const counts = new Map<string, number>();
    for (let i = 0; i <= seq.length - n; i++) {
      const gram = seq.slice(i, i + n).join('→');
      counts.set(gram, (counts.get(gram) || 0) + 1);
    }
    let topNgram = '';
    let topCount = 0;
    counts.forEach((c, g) => {
      if (c > topCount) {
        topCount = c;
        topNgram = g;
      }
    });
    const totalNgrams = Math.max(1, seq.length - n + 1);
    const repeatScore = Math.min(topCount / totalNgrams, 1);
    out.set(actor, { repeatScore, topNgram, topCount });
  });
  return out;
}

function detectWindowBursts(input: {
  logs: LogEntry[];
  windowMs: number;
  minCount: number;
  minActors: number;
}): { bursts: WaveResult[]; burstKeysByActor: Map<string, Set<string>> } {
  const { logs, windowMs, minCount, minActors } = input;
  const byKey = new Map<string, Array<{ ts: number; actor: string; action: string; target: string }>>();
  for (const log of logs) {
    const ts = new Date(log.timestamp).getTime();
    if (!Number.isFinite(ts)) continue;
    const action = String(log.action || '');
    const target = String(log.target || '');
    if (!action || !target) continue;
    const key = `${action}::${target}`;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key)!.push({ ts, actor: log.actor, action, target });
  }

  const bursts: WaveResult[] = [];
  const burstKeysByActor = new Map<string, Set<string>>();
  const durationMs = (() => {
    const times = logs.map((l) => new Date(l.timestamp).getTime()).filter((t) => Number.isFinite(t));
    if (times.length < 2) return windowMs;
    return Math.max(1, Math.max(...times) - Math.min(...times));
  })();

  byKey.forEach((events, key) => {
    if (events.length < minCount) return;
    events.sort((a, b) => a.ts - b.ts);

    let left = 0;
    const actorCounts = new Map<string, number>();
    let best = { start: events[0].ts, count: 0, actors: new Set<string>() as Set<string> };

    for (let right = 0; right < events.length; right++) {
      const ev = events[right];
      actorCounts.set(ev.actor, (actorCounts.get(ev.actor) || 0) + 1);

      while (events[right].ts - events[left].ts > windowMs) {
        const a = events[left].actor;
        const next = (actorCounts.get(a) || 0) - 1;
        if (next <= 0) actorCounts.delete(a);
        else actorCounts.set(a, next);
        left++;
      }

      const count = right - left + 1;
      const uniqueActors = actorCounts.size;
      if (count > best.count && count >= minCount && uniqueActors >= minActors) {
        best = { start: events[left].ts, count, actors: new Set(actorCounts.keys()) };
      }
    }

    if (best.count < minCount || best.actors.size < minActors) return;
    const [action, target] = key.split('::');

    const ratePerMs = events.length / durationMs;
    const expected = ratePerMs * windowMs;
    const z = (best.count - expected) / Math.sqrt(Math.max(1e-6, expected));
    if (!Number.isFinite(z) || z < 2.5) return;

    const windowStart = new Date(best.start).toISOString();
    const windowEnd = new Date(best.start + windowMs).toISOString();
    const burstKey = `${windowStart}:${action}:${target}:window`;

    bursts.push({
      windowStart,
      windowEnd,
      action,
      target,
      actors: Array.from(best.actors),
      zScore: z,
      method: 'window',
    });

    best.actors.forEach((actor) => {
      if (!burstKeysByActor.has(actor)) burstKeysByActor.set(actor, new Set());
      burstKeysByActor.get(actor)!.add(burstKey);
    });
  });

  // Keep top bursts (avoid UI overwhelm)
  bursts.sort((a, b) => b.zScore - a.zScore);
  const trimmed = bursts.slice(0, 250);

  // Trim actor burst keys to those within top bursts
  const allowed = new Set(trimmed.map((b) => `${b.windowStart}:${b.action}:${b.target}:window`));
  burstKeysByActor.forEach((keys, actor) => {
    const next = new Set<string>();
    keys.forEach((k) => {
      if (allowed.has(k)) next.add(k);
    });
    burstKeysByActor.set(actor, next);
  });

  return { bursts: trimmed, burstKeysByActor };
}

export function detectFraudulentTransactions(logs: LogEntry[]): Map<string, number> {
  const actorAmounts = new Map<string, number[]>();
  logs.forEach(log => {
    if (log.amount !== undefined) {
      if (!actorAmounts.has(log.actor)) actorAmounts.set(log.actor, []);
      actorAmounts.get(log.actor)!.push(log.amount);
    }
  });
  const fraudScores = new Map<string, number>();
  actorAmounts.forEach((amounts, actor) => {
    if (amounts.length < 2) return;
    const avg = amounts.reduce((a, b) => a + b, 0) / amounts.length;
    const variance = amounts.reduce((sum, a) => sum + (a - avg) ** 2, 0) / amounts.length;
    const std = Math.sqrt(variance);
    const score = std / (avg + 1); // normalized high variance
    fraudScores.set(actor, Math.min(score, 1));
  });
  return fraudScores;
}

function computePageRank(nodes: string[], out: Map<string, string[]>, incoming: Map<string, string[]>): Map<string, number> {
  const N = Math.max(nodes.length, 1);
  const damping = 0.85;
  let rank = new Map<string, number>();
  nodes.forEach((n) => rank.set(n, 1 / N));

  for (let iter = 0; iter < 20; iter++) {
    const next = new Map<string, number>();
    let danglingSum = 0;
    for (const n of nodes) {
      const outDeg = out.get(n)?.length ?? 0;
      if (outDeg === 0) danglingSum += rank.get(n) || 0;
    }
    const base = (1 - damping) / N;
    const danglingShare = damping * danglingSum / N;

    for (const n of nodes) {
      let sum = 0;
      const inc = incoming.get(n) ?? [];
      for (const src of inc) {
        const outDeg = out.get(src)?.length ?? 0;
        if (outDeg > 0) sum += (rank.get(src) || 0) / outDeg;
      }
      next.set(n, base + danglingShare + damping * sum);
    }
    rank = next;
  }
  return rank;
}

function computeEigenCentrality(nodes: string[], undirected: Map<string, Set<string>>): Map<string, number> {
  const v = new Map<string, number>();
  nodes.forEach((n) => v.set(n, 1));

  for (let iter = 0; iter < 20; iter++) {
    const next = new Map<string, number>();
    let norm = 0;
    for (const n of nodes) {
      let sum = 0;
      for (const nb of undirected.get(n) ?? []) sum += v.get(nb) || 0;
      next.set(n, sum);
      norm += sum * sum;
    }
    norm = Math.sqrt(norm) || 1;
    for (const n of nodes) next.set(n, (next.get(n) || 0) / norm);
    for (const n of nodes) v.set(n, next.get(n) || 0);
  }
  return v;
}

function computeApproxBetweenness(nodes: string[], undirected: Map<string, Set<string>>): Map<string, number> {
  const n = nodes.length;
  const out = new Map<string, number>();
  nodes.forEach((node) => out.set(node, 0));
  if (n <= 2) return out;

  // Sample sources to keep runtime reasonable on big graphs.
  const sampleSize = Math.min(50, n);
  const sampled = sampleDeterministic(nodes, sampleSize);

  for (const s of sampled) {
    const stack: string[] = [];
    const pred = new Map<string, string[]>();
    const sigma = new Map<string, number>();
    const dist = new Map<string, number>();

    nodes.forEach((v) => {
      pred.set(v, []);
      sigma.set(v, 0);
      dist.set(v, -1);
    });
    sigma.set(s, 1);
    dist.set(s, 0);

    const queue: string[] = [s];
    while (queue.length > 0) {
      const v = queue.shift()!;
      stack.push(v);
      const dv = dist.get(v) || 0;
      for (const w of undirected.get(v) ?? []) {
        if ((dist.get(w) ?? -1) < 0) {
          queue.push(w);
          dist.set(w, dv + 1);
        }
        if (dist.get(w) === dv + 1) {
          sigma.set(w, (sigma.get(w) || 0) + (sigma.get(v) || 0));
          pred.get(w)!.push(v);
        }
      }
    }

    const delta = new Map<string, number>();
    nodes.forEach((v) => delta.set(v, 0));
    while (stack.length > 0) {
      const w = stack.pop()!;
      for (const v of pred.get(w) ?? []) {
        const c = ((sigma.get(v) || 0) / (sigma.get(w) || 1)) * (1 + (delta.get(w) || 0));
        delta.set(v, (delta.get(v) || 0) + c);
      }
      if (w !== s) out.set(w, (out.get(w) || 0) + (delta.get(w) || 0));
    }
  }

  // Normalize to [0,1] approximately
  const scale = sampled.length > 0 ? 1 / sampled.length : 1;
  let max = 0;
  nodes.forEach((v) => {
    const val = (out.get(v) || 0) * scale;
    out.set(v, val);
    max = Math.max(max, val);
  });
  if (max > 0) nodes.forEach((v) => out.set(v, (out.get(v) || 0) / max));
  return out;
}

function sampleDeterministic(nodes: string[], k: number): string[] {
  // Deterministic pseudo-random sample based on a simple hash of node ids.
  const scored = nodes.map((n) => ({ n, h: fnv1a32(n) }));
  scored.sort((a, b) => a.h - b.h);
  return scored.slice(0, k).map((x) => x.n);
}

function fnv1a32(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}
