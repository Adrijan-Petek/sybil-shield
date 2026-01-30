'use client';

import dynamic from 'next/dynamic';
import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import Image from 'next/image';
import type { EdgeDefinition, ElementDefinition, NodeDefinition, NodeSingular } from 'cytoscape';
import { computeSharedLinksByActor, extractLinks, isSuspiciousDomain, linkDiversityScore, normalizeLinks, updateProfileAnomalyScore } from '../lib/profile';
import { extractUrlsFromText } from '../lib/urlResolvers';
import { computeHandlePatternScores, isLikelyPhishingUrl } from '../lib/scam';
import type { ReviewDecision } from '../lib/reviewStore';
import { deleteReview, getAllReviews, upsertReview } from '../lib/reviewStore';
import Papa from 'papaparse';

// Dynamically import CytoscapeComponent to avoid SSR issues
const CytoscapeComponent = dynamic(() => import('react-cytoscapejs'), { ssr: false });

interface LogEntry {
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
}

interface DetailedCluster {
  clusterId: number;
  members: string[];
  density: number;
  conductance: number;
  externalEdges: number;
}

interface WaveResult {
  windowStart: string;
  windowEnd: string;
  action: string;
  target: string;
  actors: string[];
  zScore: number;
}

interface ActorScorecard {
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
  reasons: string[];
}

interface ActorStats {
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
}

type CsvRow = Record<string, string | undefined>;

interface AnalysisSettings {
  threshold: number;
  minClusterSize: number;
  timeBinMinutes: number;
  waveMinCount: number;
  waveMinActors: number;
  positiveActions: string[];
  churnActions: string[];
}

type TabKey = 'dashboard' | 'data' | 'generator' | 'analysis' | 'graph' | 'results' | 'review' | 'evidence';

export default function Home() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [elements, setElements] = useState<ElementDefinition[]>([]);
  const [clusters, setClusters] = useState<DetailedCluster[]>([]);
  const [waves, setWaves] = useState<WaveResult[]>([]);
  const [scorecards, setScorecards] = useState<ActorScorecard[]>([]);
  const [settings, setSettings] = useState<AnalysisSettings>({
    threshold: 0.6,
    minClusterSize: 6,
    timeBinMinutes: 5,
    waveMinCount: 10,
    waveMinActors: 8,
    positiveActions: ['follow', 'star', 'transfer', 'fork'],
    churnActions: ['unfollow', 'unstar'],
  });
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [fileUploaded, setFileUploaded] = useState(false);
  const [showAllActors, setShowAllActors] = useState(false);
  const [githubRepo, setGithubRepo] = useState('');
  const [githubMaxPages, setGithubMaxPages] = useState(3);
  const [sourceStatus, setSourceStatus] = useState<string | null>(null);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [importUrlsText, setImportUrlsText] = useState('');
  const [farcasterId, setFarcasterId] = useState('');
  const [baseAddress, setBaseAddress] = useState('');
  const [talentId, setTalentId] = useState('');
  const [profileLinksText, setProfileLinksText] = useState('');
  const [scanFoundLinks, setScanFoundLinks] = useState<string[]>([]);
  const [scanFoundDataFiles, setScanFoundDataFiles] = useState<string[]>([]);
  const [scanDetails, setScanDetails] = useState<{ url: string; ok: boolean; error?: string; discoveredDataFiles?: string[] }[]>([]);
  const [actorSearch, setActorSearch] = useState('');
  const [profileScanText, setProfileScanText] = useState('');
  const [profileScanResults, setProfileScanResults] = useState<
    Array<{
      inputUrl: string;
      ok: boolean;
      error?: string;
      url?: string;
      actorId?: string;
      title?: string;
      bio?: string;
      links?: string[];
      suspiciousLinks?: string[];
      phishingLinks?: string[];
      linkDiversity?: number;
      profileAnomalyScore?: number;
      riskScore?: number;
      reasons?: string[];
    }>
  >([]);
  const [autoAddProfilesToDataset, setAutoAddProfilesToDataset] = useState(true);
  const [autoImportFromProfileLinks, setAutoImportFromProfileLinks] = useState(true);

  const [syntheticSeed, setSyntheticSeed] = useState<number>(() => Math.floor(Date.now() % 1_000_000));
  const [syntheticOrganicUsers, setSyntheticOrganicUsers] = useState(80);
  const [syntheticOrganicActions, setSyntheticOrganicActions] = useState(800);
  const [syntheticTargets, setSyntheticTargets] = useState(8);
  const [syntheticSybilClusters, setSyntheticSybilClusters] = useState(2);
  const [syntheticSybilClusterSize, setSyntheticSybilClusterSize] = useState(12);
  const [syntheticBurstTargetIndex, setSyntheticBurstTargetIndex] = useState(0);
  const [syntheticBurstActors, setSyntheticBurstActors] = useState(10);
  const [syntheticBurstActions, setSyntheticBurstActions] = useState(3);
  const [syntheticMinutes, setSyntheticMinutes] = useState(120);
  const [syntheticIncludeProfiles, setSyntheticIncludeProfiles] = useState(true);
  const [syntheticGroundTruth, setSyntheticGroundTruth] = useState<{ sybilActors: string[]; burstTarget: string } | null>(null);
  const [syntheticLastLogs, setSyntheticLastLogs] = useState<LogEntry[] | null>(null);

  const [reviews, setReviews] = useState<Record<string, { decision: ReviewDecision | ''; note?: string; updatedAt: string }>>({});

  const TabButton = ({ tab, label }: { tab: TabKey; label: string }) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={
        activeTab === tab
          ? 'px-3 py-2 rounded-md bg-slate-100 text-slate-950 text-sm shadow-sm'
          : 'px-3 py-2 rounded-md border border-slate-800 bg-slate-950/40 text-sm text-slate-200 hover:bg-slate-900/50'
      }
    >
      {label}
    </button>
  );

  const Card = ({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) => (
    <section className="bg-black/50 border border-slate-800 rounded-xl p-4 shadow-[0_0_0_1px_rgba(255,255,255,0.02)] backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold">{title}</h2>
          {subtitle && <p className="text-sm text-slate-300 mt-1">{subtitle}</p>}
        </div>
      </div>
      <div className="mt-4">{children}</div>
    </section>
  );

  const logSummary = useMemo(() => {
    const uniqueActors = new Set<string>();
    const uniqueTargets = new Set<string>();
    const byPlatform: Record<string, number> = {};
    const byAction: Record<string, number> = {};
    for (const l of logs) {
      uniqueActors.add(l.actor);
      uniqueTargets.add(l.target);
      byPlatform[l.platform] = (byPlatform[l.platform] || 0) + 1;
      byAction[l.action] = (byAction[l.action] || 0) + 1;
    }
    return {
      total: logs.length,
      uniqueActors: uniqueActors.size,
      uniqueTargets: uniqueTargets.size,
      byPlatform,
      byAction,
    };
  }, [logs]);

  const flaggedScorecards = useMemo(
    () => scorecards.filter((s) => s.sybilScore > settings.threshold).sort((a, b) => b.sybilScore - a.sybilScore),
    [scorecards, settings.threshold],
  );

  const insights = useMemo(() => {
    const top = (counts: Record<string, number>, limit: number) =>
      Object.entries(counts)
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);

    const targetCounts: Record<string, number> = {};
    const churnTargetCounts: Record<string, number> = {};
    const platformCounts: Record<string, number> = {};
    logs.forEach((l) => {
      targetCounts[l.target] = (targetCounts[l.target] || 0) + 1;
      platformCounts[l.platform] = (platformCounts[l.platform] || 0) + 1;
      if (settings.churnActions.includes(l.action)) {
        churnTargetCounts[l.target] = (churnTargetCounts[l.target] || 0) + 1;
      }
    });

    const suspiciousDomainCounts: Record<string, number> = {};
    const sharedLinkCounts: Record<string, number> = {};
    scorecards.forEach((s) => {
      s.suspiciousLinks.forEach((link) => {
        try {
          const host = new URL(link).hostname.replace(/^www\./, '').toLowerCase();
          suspiciousDomainCounts[host] = (suspiciousDomainCounts[host] || 0) + 1;
        } catch {
          // ignore
        }
      });
      s.sharedLinks.forEach((link) => {
        sharedLinkCounts[link] = (sharedLinkCounts[link] || 0) + 1;
      });
    });

    const handlePatterns = computeHandlePatternScores(scorecards.map((s) => s.actor));
    const topMap = (m: Map<string, number>, limit: number) =>
      Array.from(m.entries())
        .map(([key, count]) => ({ key, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);

    return {
      counts: {
        events: logs.length,
        actors: logSummary.uniqueActors,
        targets: logSummary.uniqueTargets,
        flaggedActors: flaggedScorecards.length,
        clusters: clusters.length,
        waves: waves.length,
      },
      topTargetsByActions: top(targetCounts, 8),
      topTargetsByChurn: top(churnTargetCounts, 8),
      topSuspiciousDomains: top(suspiciousDomainCounts, 8),
      topSharedLinks: top(sharedLinkCounts, 8),
      topHandleStems: topMap(handlePatterns.stemCounts, 8),
      topHandleShapes: topMap(handlePatterns.shapeCounts, 6),
      topWaves: waves
        .slice()
        .sort((a, b) => b.actors.length - a.actors.length)
        .slice(0, 8)
        .map((w) => ({ windowStart: w.windowStart, action: w.action, target: w.target, actors: w.actors.length, zScore: w.zScore })),
      platforms: top(platformCounts, 12),
    };
  }, [clusters.length, flaggedScorecards.length, logSummary.uniqueActors, logSummary.uniqueTargets, logs, scorecards, settings.churnActions, waves]);

  useEffect(() => {
    let cancelled = false;
    getAllReviews()
      .then((all) => {
        if (cancelled) return;
        const map: Record<string, { decision: ReviewDecision | ''; note?: string; updatedAt: string }> = {};
        all.forEach((r) => {
          map[r.actor] = { decision: r.decision, note: r.note, updatedAt: r.updatedAt };
        });
        setReviews(map);
      })
      .catch(() => {
        // ignore
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const evidenceObject = useMemo(() => {
    const profileLinks = Object.fromEntries(
      scorecards.map((s) => [
        s.actor,
        {
          links: s.links,
          suspiciousLinks: s.suspiciousLinks,
          sharedLinks: s.sharedLinks,
          linkDiversity: s.linkDiversity,
        },
      ]),
    );

    return {
      exportedAt: new Date().toISOString(),
      settings,
      insights,
      reviews,
      clusters,
      waves,
      scorecards: flaggedScorecards,
      profileLinks,
      syntheticGroundTruth: syntheticGroundTruth ?? undefined,
    };
  }, [clusters, insights, reviews, scorecards, flaggedScorecards, settings, syntheticGroundTruth, waves]);

  const evidenceJson = useMemo(() => JSON.stringify(evidenceObject, null, 2), [evidenceObject]);

  const parseLinksField = (value: unknown): string[] | undefined => {
    if (value === null || value === undefined) return undefined;
    if (Array.isArray(value)) return normalizeLinks(value.map(String));
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed) return undefined;
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) return normalizeLinks(parsed.map(String));
        if (typeof parsed === 'string') return normalizeLinks([parsed]);
      } catch {
        // ignore
      }
      const parts = trimmed.split(/[,\s]+/).filter(Boolean);
      return normalizeLinks(parts);
    }
    return undefined;
  };

  const parseBooleanField = (value: unknown): boolean | undefined => {
    if (value === null || value === undefined) return undefined;
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      const v = value.trim().toLowerCase();
      if (v === 'true' || v === '1' || v === 'yes') return true;
      if (v === 'false' || v === '0' || v === 'no') return false;
    }
    return undefined;
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSourceError(null);
      const fileType = file.name.split('.').pop()?.toLowerCase();
      if (fileType === 'csv') {
        Papa.parse(file, {
          header: true,
          complete: (results: Papa.ParseResult<CsvRow>) => {
            try {
              const data: LogEntry[] = results.data.flatMap((row) => {
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
                    links: parseLinksField(row.links),
                    followerCount: row.followerCount ? parseInt(row.followerCount) : undefined,
                    followingCount: row.followingCount ? parseInt(row.followingCount) : undefined,
                    actorCreatedAt: row.actorCreatedAt,
                    location: row.location,
                    verified: parseBooleanField(row.verified),
                  },
                ];
              });
              if (data.length === 0 || !data[0].timestamp) {
                alert('Invalid CSV format. Please ensure it has columns: timestamp, actor, target, action, platform');
                return;
              }
              setLogs(data);
              setFileUploaded(true);
              setSourceStatus(`Loaded ${data.length.toLocaleString()} rows from CSV`);
            } catch (error) {
              console.error('Error parsing CSV:', error);
              alert('Error parsing CSV. Check console for details.');
            }
          },
          error: (error) => {
            console.error('PapaParse error:', error);
            alert('Error reading CSV file.');
          },
        });
      } else if (fileType === 'json') {
        const reader = new FileReader();
        reader.onload = (e) => {
          try {
            const raw = JSON.parse(e.target?.result as string);
            const data: LogEntry[] = (Array.isArray(raw) ? raw : []).flatMap((row): LogEntry[] => {
              if (typeof row !== 'object' || row === null) return [];
              const record = row as Record<string, unknown>;
              const followerRaw = record.followerCount;
              const followingRaw = record.followingCount;
              return [
                {
                  timestamp: String(record.timestamp ?? ''),
                  actor: String(record.actor ?? ''),
                  target: String(record.target ?? ''),
                  action: String(record.action ?? ''),
                  platform: String(record.platform ?? ''),
                  bio: typeof record.bio === 'string' ? record.bio : undefined,
                  links: parseLinksField(record.links),
                  followerCount: typeof followerRaw === 'number' ? followerRaw : typeof followerRaw === 'string' ? parseInt(followerRaw) : undefined,
                  followingCount: typeof followingRaw === 'number' ? followingRaw : typeof followingRaw === 'string' ? parseInt(followingRaw) : undefined,
                  actorCreatedAt: typeof record.actorCreatedAt === 'string' ? record.actorCreatedAt : undefined,
                  location: typeof record.location === 'string' ? record.location : undefined,
                  verified: parseBooleanField(record.verified),
                },
              ];
            });
            if (!Array.isArray(data) || data.length === 0 || !data[0].timestamp) {
              alert('Invalid JSON format. Please ensure it is an array of objects with timestamp, actor, target, action, platform');
              return;
            }
            setLogs(data);
            setFileUploaded(true);
            setSourceStatus(`Loaded ${data.length.toLocaleString()} rows from JSON`);
          } catch (error) {
            console.error('Error parsing JSON:', error);
            alert('Error parsing JSON. Check console for details.');
          }
        };
        reader.readAsText(file);
      } else {
        alert('Please upload a CSV or JSON file.');
      }
    }
  };

  const startAnalysis = () => {
    processData(logs);
  };

  const appendLogs = (newLogs: LogEntry[], label: string) => {
    if (newLogs.length === 0) {
      setSourceStatus(`${label}: no events returned`);
      return;
    }
    setLogs((prev) => {
      const seen = new Set(prev.map((l) => `${l.timestamp}|${l.platform}|${l.action}|${l.actor}|${l.target}`));
      const merged = prev.slice();
      for (const l of newLogs) {
        const key = `${l.timestamp}|${l.platform}|${l.action}|${l.actor}|${l.target}`;
        if (seen.has(key)) continue;
        seen.add(key);
        merged.push(l);
      }
      return merged;
    });
    setFileUploaded(true);
    setSourceStatus(`${label}: added ${newLogs.length.toLocaleString()} events`);
  };

  const fetchGithubStargazers = async () => {
    try {
      setSourceError(null);
      setSourceStatus('Fetching GitHub stargazers...');
      const repo = githubRepo.trim();
      if (!repo || !repo.includes('/')) {
        setSourceError('GitHub repo must be in the format owner/name');
        setSourceStatus(null);
        return;
      }
      const url = new URL('/api/fetch/github', window.location.origin);
      url.searchParams.set('repo', repo);
      url.searchParams.set('maxPages', String(githubMaxPages));
      const res = await fetch(url.toString());
      const json = (await res.json()) as { logs?: LogEntry[]; error?: string };
      if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
      appendLogs(json.logs || [], `GitHub ${repo}`);
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : 'Failed to fetch GitHub data');
    }
  };

  const fetchSource = async (path: string, params: Record<string, string>, label: string) => {
    try {
      setSourceError(null);
      setSourceStatus(`Fetching ${label}...`);
      const url = new URL(path, window.location.origin);
      Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
      const res = await fetch(url.toString());
      const json = (await res.json()) as { logs?: LogEntry[]; error?: string; hint?: string };
      if (!res.ok) throw new Error([json.error, json.hint].filter(Boolean).join(' — ') || `Request failed (${res.status})`);
      appendLogs(json.logs || [], label);
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : `Failed to fetch ${label}`);
    }
  };

  const importFromUrls = async (overrideUrls?: string[]) => {
    try {
      setSourceError(null);
      setSourceStatus('Importing URLs...');
      const urls = overrideUrls ?? extractUrlsFromText(importUrlsText);
      if (urls.length === 0) {
        setSourceError('Paste one or more CSV/JSON URLs to import.');
        setSourceStatus(null);
        return;
      }
      const res = await fetch('/api/import/url', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ urls }),
      });
      const json = (await res.json()) as { logs?: LogEntry[]; error?: string; results?: { ok: boolean; count?: number }[] };
      if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
      appendLogs(json.logs || [], `Imported URLs (${urls.length})`);
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : 'Failed to import URLs');
    }
  };

  const scanProfileLinks = async () => {
    try {
      setSourceError(null);
      setSourceStatus('Scanning profile links...');
      setScanFoundLinks([]);
      setScanFoundDataFiles([]);
      setScanDetails([]);
      const urls = extractUrlsFromText(profileLinksText);
      if (urls.length === 0) {
        setSourceError('Paste one or more profile URLs to scan.');
        setSourceStatus(null);
        return;
      }
      const res = await fetch('/api/scan/links', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ urls }),
      });
      const json = (await res.json()) as {
        error?: string;
        links?: string[];
        dataFiles?: string[];
        pages?: { url: string; ok: boolean; error?: string; discoveredDataFiles?: string[] }[];
      };
      if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
      setScanFoundLinks(json.links || []);
      setScanFoundDataFiles(json.dataFiles || []);
      setScanDetails(json.pages || []);
      setSourceStatus(`Scan complete: found ${(json.dataFiles || []).length} CSV/JSON file link(s)`);
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : 'Failed to scan profile links');
    }
  };

  const importScannedDataFiles = async () => {
    setImportUrlsText(scanFoundDataFiles.join('\n'));
    await importFromUrls(scanFoundDataFiles);
  };

  const scanProfilesForAnomalies = async () => {
    try {
      setSourceError(null);
      setSourceStatus('Scanning profiles for anomalies...');
      setProfileScanResults([]);
      const urls = extractUrlsFromText(profileScanText);
      if (urls.length === 0) {
        setSourceError('Paste one or more profile URLs to scan.');
        setSourceStatus(null);
        return;
      }
      const res = await fetch('/api/scan/profile', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ urls }),
      });
      const json = (await res.json()) as { error?: string; profiles?: typeof profileScanResults };
      if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
      setProfileScanResults(json.profiles || []);
      const profiles = json.profiles || [];

      if (autoAddProfilesToDataset) {
        const now = new Date().toISOString();
        const profileLogs: LogEntry[] = profiles.flatMap((p) => {
          if (!p.ok || !p.actorId || !p.url) return [];
          const platform = p.actorId.includes(':') ? p.actorId.split(':')[0] : 'profile';
          return [
            {
              timestamp: now,
              platform,
              action: 'profile',
              actor: p.actorId,
              target: p.url,
              targetType: 'profile',
              bio: p.bio,
              links: p.links,
              meta: JSON.stringify({
                source: 'profile-scan',
                title: p.title,
                riskScore: p.riskScore,
                reasons: p.reasons,
                linkDiversity: p.linkDiversity,
              }),
            },
          ];
        });
        if (profileLogs.length > 0) appendLogs(profileLogs, 'Profile scan');
      }

      if (autoImportFromProfileLinks) {
        const candidateLinks = profiles
          .flatMap((p) => (p.ok ? p.links || [] : []))
          .slice(0, 50);
        if (candidateLinks.length > 0) {
          // Import API resolves share links to raw CSV/JSON when possible.
          await importFromUrls(candidateLinks);
        }
      }

      setSourceStatus(`Profile scan complete: ${profiles.length} scanned`);
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : 'Failed to scan profiles');
    }
  };

  const generateSynthetic = async () => {
    try {
      setSourceError(null);
      setSourceStatus('Generating synthetic dataset...');
      const res = await fetch('/api/generate/synthetic', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          seed: syntheticSeed,
          minutes: syntheticMinutes,
          organicUsers: syntheticOrganicUsers,
          organicActions: syntheticOrganicActions,
          targets: syntheticTargets,
          sybilClusters: syntheticSybilClusters,
          sybilClusterSize: syntheticSybilClusterSize,
          burstTargetIndex: syntheticBurstTargetIndex,
          burstActorsPerCluster: syntheticBurstActors,
          burstActionsPerActor: syntheticBurstActions,
          includeProfiles: syntheticIncludeProfiles,
        }),
      });
      const json = (await res.json()) as {
        error?: string;
        logs?: LogEntry[];
        groundTruth?: { sybilActors: string[]; burstTarget: string };
        config?: unknown;
      };
      if (!res.ok) throw new Error(json.error || `Request failed (${res.status})`);
      setSyntheticLastLogs(json.logs || []);
      setSyntheticGroundTruth(json.groundTruth || null);
      setSourceStatus(`Generated ${(json.logs || []).length.toLocaleString()} events`);
      setActiveTab('generator');
    } catch (e) {
      setSourceStatus(null);
      setSourceError(e instanceof Error ? e.message : 'Failed to generate synthetic dataset');
    }
  };

  const loadSyntheticIntoApp = () => {
    if (!syntheticLastLogs) return;
    setLogs(syntheticLastLogs);
    setFileUploaded(true);
    setSourceStatus(`Loaded synthetic dataset (${syntheticLastLogs.length.toLocaleString()} events)`);
    setActiveTab('analysis');
  };

  const downloadSyntheticCsv = () => {
    if (!syntheticLastLogs || syntheticLastLogs.length === 0) return;
    const csv = Papa.unparse(syntheticLastLogs as unknown as Record<string, unknown>[]);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `synthetic-${syntheticSeed}.csv`;
    a.click();
  };

  const downloadSyntheticJson = () => {
    if (!syntheticLastLogs) return;
    const blob = new Blob([JSON.stringify({ logs: syntheticLastLogs, groundTruth: syntheticGroundTruth }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `synthetic-${syntheticSeed}.json`;
    a.click();
  };

  const processData = (data: LogEntry[]) => {
    try {
      if (data.length === 0) {
        setElements([]);
        setClusters([]);
        setWaves([]);
        setScorecards([]);
        return;
      }

      const allTimes = data.map((l) => new Date(l.timestamp).getTime()).filter((t) => Number.isFinite(t));
      const datasetStartMs = allTimes.length > 0 ? Math.min(...allTimes) : Date.now();

      // Collect profile data
      const actorProfiles: {
        [actor: string]: { bio?: string; links?: string[]; followerCount?: number; followingCount?: number; actorCreatedAt?: string; verified?: boolean; location?: string };
      } = {};
      data.forEach((log) => {
        if (!actorProfiles[log.actor]) {
          actorProfiles[log.actor] = {};
        }
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

      // Build graph from positive actions
      const nodes = new Set<string>();
      const edges: EdgeDefinition[] = [];
      const positiveOut = new Map<string, Set<string>>();
      const positiveIn = new Map<string, Set<string>>();
      data.forEach((log) => {
        nodes.add(log.actor);
        nodes.add(log.target);
        if (settings.positiveActions.includes(log.action)) {
          edges.push({
            data: { source: log.actor, target: log.target, type: 'interaction' },
          });
          if (!positiveOut.has(log.actor)) positiveOut.set(log.actor, new Set());
          if (!positiveIn.has(log.target)) positiveIn.set(log.target, new Set());
          positiveOut.get(log.actor)!.add(log.target);
          positiveIn.get(log.target)!.add(log.actor);
        }
      });

      const nodeElements: NodeDefinition[] = Array.from(nodes).map((id) => ({
        data: { id, label: id },
      }));

      setElements([...nodeElements, ...edges]);

      // Detect clusters
      const graph: { [key: string]: string[] } = {};
      nodes.forEach((node) => (graph[node] = []));
      edges.forEach((edge) => {
        graph[edge.data.source].push(edge.data.target);
        graph[edge.data.target].push(edge.data.source);
      });

      const visited = new Set<string>();
      const clustersList: DetailedCluster[] = [];
      let clusterId = 0;
      for (const node of nodes) {
        if (!visited.has(node)) {
          const component: string[] = [];
          dfs(node, graph, visited, component);
          if (component.length >= settings.minClusterSize) {
            // Calculate density, conductance
            const internalEdges = component.reduce((sum, n) => sum + graph[n].filter(neigh => component.includes(neigh)).length, 0) / 2;
            const possibleEdges = (component.length * (component.length - 1)) / 2;
            const density = possibleEdges > 0 ? internalEdges / possibleEdges : 0;
            const externalEdges = component.reduce((sum, n) => sum + graph[n].filter(neigh => !component.includes(neigh)).length, 0);
            const totalEdges = internalEdges + externalEdges;
            const conductance = totalEdges > 0 ? externalEdges / totalEdges : 0;
            clustersList.push({
              clusterId: clusterId++,
              members: component,
              density,
              conductance,
              externalEdges,
            });
          }
        }
      }
      setClusters(clustersList);

      // Timing coordination (bin -> action -> target -> {count, actors})
      const timeBins: Record<string, Record<string, Record<string, { count: number; actors: Set<string> }>>> = {};
      const binSizeMs = Math.max(1, settings.timeBinMinutes) * 60 * 1000;
      data.forEach((log) => {
        const date = new Date(log.timestamp);
        const bin = Math.floor(date.getTime() / binSizeMs) * binSizeMs;
        const binKey = new Date(bin).toISOString();
        if (!timeBins[binKey]) timeBins[binKey] = {};
        if (!timeBins[binKey][log.action]) timeBins[binKey][log.action] = {};
        if (!timeBins[binKey][log.action][log.target]) timeBins[binKey][log.action][log.target] = { count: 0, actors: new Set() };
        timeBins[binKey][log.action][log.target].count++;
        timeBins[binKey][log.action][log.target].actors.add(log.actor);
      });

      const suspiciousWaves: WaveResult[] = [];
      Object.entries(timeBins).forEach(([time, actions]) => {
        Object.entries(actions).forEach(([action, targets]) => {
          Object.entries(targets).forEach(([target, info]) => {
            const actorCount = info.actors.size;
            if (info.count >= settings.waveMinCount && actorCount >= settings.waveMinActors) {
              const windowEnd = new Date(new Date(time).getTime() + binSizeMs).toISOString();
              suspiciousWaves.push({
                windowStart: time,
                windowEnd,
                action,
                target,
                actors: Array.from(info.actors),
                zScore: info.count / Math.max(1, settings.waveMinCount),
              });
            }
          });
        });
      });
      setWaves(suspiciousWaves);

      // Actor scorecards
      const actorStats: Record<string, ActorStats> = {};
      nodes.forEach((node) => {
        actorStats[node] = {
          actor: node,
          totalActions: 0,
          churnActions: 0,
          burstActions: 0,
          uniqueTargets: new Set(),
          connections: graph[node].length,
          clusterSize: 0,
          positiveOut: positiveOut.get(node)?.size ?? 0,
          positiveIn: positiveIn.get(node)?.size ?? 0,
          mutualPositive: 0,
        };
      });

      data.forEach((log) => {
        actorStats[log.actor].totalActions++;
        actorStats[log.actor].uniqueTargets.add(log.target);
        if (settings.churnActions.includes(log.action)) {
          actorStats[log.actor].churnActions++;
        }
        const ts = new Date(log.timestamp).getTime();
        if (Number.isFinite(ts)) {
          const current = actorStats[log.actor].firstSeenMs;
          actorStats[log.actor].firstSeenMs = current === undefined ? ts : Math.min(current, ts);
        }
      });

      // Assign cluster sizes
      clustersList.forEach((cluster) => {
        cluster.members.forEach((member) => {
          actorStats[member].clusterSize = cluster.members.length;
        });
      });

      // Mutual (reciprocal) positive interactions
      nodes.forEach((actor) => {
        const outSet = positiveOut.get(actor) ?? new Set<string>();
        let mutual = 0;
        outSet.forEach((t) => {
          const back = positiveOut.get(t);
          if (back?.has(actor)) mutual++;
        });
        actorStats[actor].mutualPositive = mutual;
      });

      // Coordination score: fraction of actions that occur in "wave" bins
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
      Object.keys(actorStats).forEach((actor) => {
        actorStats[actor].burstActions = waveBinsByActor.get(actor)?.size ?? 0;
      });

      const handlePatterns = computeHandlePatternScores(Array.from(nodes));

      const scorecardsList: ActorScorecard[] = Object.values(actorStats).map((stats) => {
        const coordinationScore = stats.totalActions > 0 ? Math.min(stats.burstActions / stats.totalActions, 1) : 0;
        const churnScore = stats.churnActions;
        const clusterIsolationScore = stats.clusterSize > 0 ? 1 - (stats.connections / stats.clusterSize) : 0;
        const createdAt = actorProfiles[stats.actor]?.actorCreatedAt;
        const createdMs = createdAt ? new Date(createdAt).getTime() : undefined;
        const firstSeenMs = stats.firstSeenMs ?? datasetStartMs;
        const ageDays = createdMs && Number.isFinite(createdMs) ? (firstSeenMs - createdMs) / (24 * 60 * 60 * 1000) : undefined;
        const newAccountScore = ageDays !== undefined && ageDays >= 0 && ageDays < 7 ? 1 : 0;
        const lowDiversityScore = stats.totalActions > 0 ? 1 - (stats.uniqueTargets.size / stats.totalActions) : 0;
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

        const sybilScore =
          0.30 * coordinationScore +
          0.20 * Math.min(churnScore / 10, 1) +
          0.15 * clusterIsolationScore +
          0.10 * newAccountScore +
          0.10 * lowDiversityScore +
          0.15 * profileAnomalyScore;

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
          reasons,
        };
      });
      setScorecards(scorecardsList);
      setActiveTab('results');
    } catch (error) {
      console.error('Error processing data:', error);
      alert('Error processing data. Check console for details.');
    }
  };

  const dfs = (node: string, graph: { [key: string]: string[] }, visited: Set<string>, component: string[]) => {
    visited.add(node);
    component.push(node);
    for (const neighbor of graph[node]) {
      if (!visited.has(neighbor)) {
        dfs(neighbor, graph, visited, component);
      }
    }
  };

  const exportEvidence = () => {
    const blob = new Blob([evidenceJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'evidence-pack.json';
    a.click();
  };

  return (
    <div className="min-h-screen bg-black text-slate-100">
      <header className="bg-black/60 border-b border-slate-800 backdrop-blur">
        <div className="mx-auto max-w-6xl px-4 py-4">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <Image src="/logo-mark.svg" alt="Sybil Shield" width={36} height={36} priority />
              <div>
                <h1 className="text-xl font-semibold tracking-tight">Sybil Shield</h1>
                <p className="text-sm text-slate-300">Coordinated clusters • timing waves • churn • profile anomalies</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <TabButton tab="dashboard" label="Dashboard" />
              <TabButton tab="data" label="Data" />
              <TabButton tab="generator" label="Generator" />
              <TabButton tab="analysis" label="Analysis" />
              <TabButton tab="graph" label="Graph" />
              <TabButton tab="results" label="Results" />
              <TabButton tab="review" label="Review" />
              <TabButton tab="evidence" label="Evidence" />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => {
                  setLogs([]);
                  setElements([]);
                  setClusters([]);
                  setWaves([]);
                  setScorecards([]);
                  setFileUploaded(false);
                  setSourceStatus(null);
                  setSourceError(null);
                  setActiveTab('dashboard');
                }}
                className="px-3 py-2 rounded-md border border-slate-800 bg-slate-950/40 text-sm text-slate-200 hover:bg-slate-900/50"
              >
                Reset
              </button>
              <button
                onClick={exportEvidence}
                disabled={logs.length === 0}
                className="px-3 py-2 rounded-md bg-gradient-to-r from-cyan-500 via-violet-500 to-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50"
              >
                Export evidence
              </button>
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-6 space-y-4">
        {(sourceStatus || sourceError) && (
          <div className="bg-black/50 border border-slate-800 rounded-xl p-3 backdrop-blur">
            {sourceStatus && <div className="text-sm text-slate-200">{sourceStatus}</div>}
            {sourceError && <div className="text-sm text-red-400">{sourceError}</div>}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card title="Dataset" subtitle="What you loaded so far">
                <div className="grid grid-cols-3 gap-3 text-sm">
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Events</div>
                    <div className="text-lg font-semibold">{logSummary.total.toLocaleString()}</div>
                  </div>
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Actors</div>
                    <div className="text-lg font-semibold">{logSummary.uniqueActors.toLocaleString()}</div>
                  </div>
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Targets</div>
                    <div className="text-lg font-semibold">{logSummary.uniqueTargets.toLocaleString()}</div>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => {
                      setActiveTab('data');
                    }}
                    className="px-3 py-2 rounded-md border border-slate-800 bg-slate-950/40 text-sm text-slate-200 hover:bg-slate-900/50"
                  >
                    Add data
                  </button>
                  <button
                    onClick={startAnalysis}
                    disabled={!fileUploaded || logs.length === 0}
                    className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
                  >
                    Run analysis
                  </button>
                </div>
              </Card>

              <Card title="Detections" subtitle="Outputs after analysis">
                <div className="grid grid-cols-3 gap-3 text-sm">
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Flagged</div>
                    <div className="text-lg font-semibold">{flaggedScorecards.length.toLocaleString()}</div>
                  </div>
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Clusters</div>
                    <div className="text-lg font-semibold">{clusters.length.toLocaleString()}</div>
                  </div>
                  <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                    <div className="text-slate-400">Waves</div>
                    <div className="text-lg font-semibold">{waves.length.toLocaleString()}</div>
                  </div>
                </div>
                <div className="mt-3 text-sm text-slate-300">
                  Threshold: <span className="font-medium text-slate-100">{settings.threshold.toFixed(2)}</span>
                </div>
              </Card>

              <Card title="What’s Included" subtitle="Signals we compute automatically">
                <ul className="text-sm text-slate-200 list-disc pl-4 space-y-1">
                  <li>Graph clusters (size, density, conductance)</li>
                  <li>Timing waves (binning + min actors/count)</li>
                  <li>Churn (unfollow/unstar counts)</li>
                  <li>Profile anomalies (ratio + suspicious/shared links)</li>
                  <li>Extra: reciprocity, repeated bios, new-account flag</li>
                </ul>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card title="Top Targets" subtitle="Who gets hit the most">
                <div className="text-sm text-slate-200">
                  <div className="font-medium text-slate-100">By actions</div>
                  <ul className="mt-1 space-y-1">
                    {insights.topTargetsByActions.length === 0 && <li className="text-slate-500">No data</li>}
                    {insights.topTargetsByActions.map((t) => (
                      <li key={t.key} className="flex items-center justify-between gap-3">
                        <span className="truncate">{t.key}</span>
                        <span className="text-slate-400">{t.count}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="mt-3 font-medium text-slate-100">By churn</div>
                  <ul className="mt-1 space-y-1">
                    {insights.topTargetsByChurn.length === 0 && <li className="text-slate-500">No churn targets</li>}
                    {insights.topTargetsByChurn.map((t) => (
                      <li key={t.key} className="flex items-center justify-between gap-3">
                        <span className="truncate">{t.key}</span>
                        <span className="text-slate-400">{t.count}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </Card>

              <Card title="Suspicious Domains" subtitle="Most common risky domains in bios">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topSuspiciousDomains.length === 0 && <li className="text-slate-500">No suspicious domains found</li>}
                  {insights.topSuspiciousDomains.map((d) => (
                    <li key={d.key} className="flex items-center justify-between gap-3">
                      <span className="truncate">{d.key}</span>
                      <span className="text-slate-400">{d.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>

              <Card title="Shared Links" subtitle="Links reused across profiles">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topSharedLinks.length === 0 && <li className="text-slate-500">No shared links detected</li>}
                  {insights.topSharedLinks.map((l) => (
                    <li key={l.key} className="flex items-center justify-between gap-3">
                      <a href={l.key} target="_blank" rel="noreferrer" className="truncate underline text-slate-200">
                        {l.key}
                      </a>
                      <span className="text-slate-400">{l.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card title="Handle Patterns" subtitle="Common naming stems/shapes (sybil farms often reuse)">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-slate-200">
                  <div>
                    <div className="font-medium text-slate-100">Top stems</div>
                    <ul className="mt-1 space-y-1">
                      {insights.topHandleStems.length === 0 && <li className="text-slate-500">No stems</li>}
                      {insights.topHandleStems.map((x) => (
                        <li key={x.key} className="flex items-center justify-between gap-3">
                          <span className="truncate">{x.key || '(empty)'}</span>
                          <span className="text-slate-400">{x.count}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <div className="font-medium text-slate-100">Top shapes</div>
                    <ul className="mt-1 space-y-1">
                      {insights.topHandleShapes.length === 0 && <li className="text-slate-500">No shapes</li>}
                      {insights.topHandleShapes.map((x) => (
                        <li key={x.key} className="flex items-center justify-between gap-3">
                          <span className="truncate">{x.key}</span>
                          <span className="text-slate-400">{x.count}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </Card>

              <Card title="Top Waves" subtitle="Largest coordinated bursts">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topWaves.length === 0 && <li className="text-slate-500">No waves</li>}
                  {insights.topWaves.map((w) => (
                    <li key={`${w.windowStart}:${w.action}:${w.target}`} className="flex items-center justify-between gap-3">
                      <span className="truncate">
                        {w.windowStart} · {w.action} · {w.target}
                      </span>
                      <span className="text-slate-400">{w.actors}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>
          </>
        )}

        {activeTab === 'data' && (
          <Card title="Data Sources" subtitle="Upload logs, fetch platform data, import or scan links">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Upload CSV/JSON</div>
                <div className="text-xs text-slate-400 mt-1">
                  Required: <code>timestamp, actor, target, action, platform</code>
                </div>
                <input type="file" accept=".csv,.json" onChange={handleFileUpload} className="mt-3 w-full text-sm" />
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">GitHub stargazers</div>
                <div className="text-xs text-slate-400 mt-1">
                  Pulls timestamped <code>star</code> events for a repo.
                </div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={githubRepo}
                    onChange={(e) => setGithubRepo(e.target.value)}
                    placeholder="owner/repo"
                    className="flex-1 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                  />
                  <input
                    type="number"
                    min={1}
                    max={20}
                    value={githubMaxPages}
                    onChange={(e) => setGithubMaxPages(Math.min(20, Math.max(1, Number.parseInt(e.target.value || '3', 10) || 3)))}
                    className="w-20 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100"
                    title="Max pages (100 per page)"
                  />
                  <button onClick={fetchGithubStargazers} className="px-3 py-1.5 rounded bg-cyan-500 text-slate-950 text-sm font-semibold hover:bg-cyan-400">
                    Fetch
                  </button>
                </div>
                <div className="text-xs text-slate-500 mt-2">
                  Optional: set <code>GITHUB_TOKEN</code> to raise rate limits.
                </div>
              </div>

              <div className="border rounded-lg p-3">
                <div className="text-sm font-medium">Farcaster (connector)</div>
                <div className="text-xs text-slate-400 mt-1">Requires a configured API backend (currently stubbed).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={farcasterId}
                    onChange={(e) => setFarcasterId(e.target.value)}
                    placeholder="fid or username"
                    className="flex-1 border rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={() => fetchSource('/api/fetch/farcaster', { id: farcasterId.trim() }, 'Farcaster')}
                    className="px-3 py-1.5 rounded bg-slate-700 text-white text-sm hover:bg-slate-800"
                  >
                    Fetch
                  </button>
                </div>
              </div>

              <div className="border rounded-lg p-3">
                <div className="text-sm font-medium">Base (connector)</div>
                <div className="text-xs text-slate-400 mt-1">Fetches ERC-20 Transfer logs via <code>BASE_RPC_URL</code> (native ETH not included).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={baseAddress}
                    onChange={(e) => setBaseAddress(e.target.value)}
                    placeholder="0x wallet address"
                    className="flex-1 border rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={() => fetchSource('/api/fetch/base', { address: baseAddress.trim(), maxBlocks: '5000', direction: 'both' }, 'Base')}
                    className="px-3 py-1.5 rounded bg-slate-700 text-white text-sm hover:bg-slate-800"
                  >
                    Fetch
                  </button>
                </div>
              </div>

              <div className="border rounded-lg p-3">
                <div className="text-sm font-medium">Talent Protocol (connector)</div>
                <div className="text-xs text-slate-400 mt-1">If you have exports, use Import/Scan (currently stubbed).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={talentId}
                    onChange={(e) => setTalentId(e.target.value)}
                    placeholder="handle / profile id"
                    className="flex-1 border rounded px-2 py-1 text-sm"
                  />
                  <button
                    onClick={() => fetchSource('/api/fetch/talent', { id: talentId.trim() }, 'Talent')}
                    className="px-3 py-1.5 rounded bg-slate-700 text-white text-sm hover:bg-slate-800"
                  >
                    Fetch
                  </button>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Import from URLs</div>
                <div className="text-xs text-slate-400 mt-1">Paste any text; we’ll extract URLs and try to resolve raw CSV/JSON.</div>
                <textarea
                  value={importUrlsText}
                  onChange={(e) => setImportUrlsText(e.target.value)}
                  placeholder="Paste links from GitHub/Gist/Drive/Dropbox/etc..."
                  className="mt-2 w-full border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500 h-24"
                />
                <div className="mt-2">
                  <button onClick={() => importFromUrls()} className="px-3 py-1.5 rounded bg-slate-100 text-slate-950 text-sm font-semibold hover:bg-white">
                    Import URLs
                  </button>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Scan profile links</div>
                <div className="text-xs text-slate-400 mt-1">Paste profile URLs (any site). We’ll scan and find CSV/JSON links.</div>
                <textarea
                  value={profileLinksText}
                  onChange={(e) => setProfileLinksText(e.target.value)}
                  placeholder="Paste profile URLs..."
                  className="mt-2 w-full border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500 h-24"
                />
                <div className="mt-2 flex flex-wrap gap-2">
                  <button onClick={scanProfileLinks} className="px-3 py-1.5 rounded bg-violet-500 text-slate-950 text-sm font-semibold hover:bg-violet-400">
                    Scan links
                  </button>
                  <button
                    onClick={importScannedDataFiles}
                    disabled={scanFoundDataFiles.length === 0}
                    className="px-3 py-1.5 rounded bg-slate-100 text-slate-950 text-sm font-semibold disabled:opacity-50"
                  >
                    Import found data files ({scanFoundDataFiles.length})
                  </button>
                </div>
                {scanDetails.length > 0 && (
                  <div className="mt-2 text-xs text-slate-200">
                    <div className="font-medium">Scan results</div>
                    <ul className="mt-1 list-disc pl-4">
                      {scanDetails.map((p) => (
                        <li key={p.url}>
                          {p.ok ? (
                            <>
                              {p.url} — data files: {(p.discoveredDataFiles || []).length}
                            </>
                          ) : (
                            <>
                              {p.url} — <span className="text-red-400">{p.error}</span>
                            </>
                          )}
                        </li>
                      ))}
                    </ul>
                    <div className="mt-2 text-slate-400">
                      Discovered links: {scanFoundLinks.length.toLocaleString()} · Data files: {scanFoundDataFiles.length.toLocaleString()}
                    </div>
                  </div>
                )}
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3 md:col-span-2">
                <div className="text-sm font-medium">Profile anomaly scan (no API)</div>
                <div className="text-xs text-slate-400 mt-1">
                  Paste profile URLs (e.g., Talent). We’ll fetch HTML, extract bio + links, and score anomalies.
                </div>
                <textarea
                  value={profileScanText}
                  onChange={(e) => setProfileScanText(e.target.value)}
                  placeholder="https://talent.app/...\nhttps://github.com/..."
                  className="mt-2 w-full border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500 h-24"
                />
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <button onClick={scanProfilesForAnomalies} className="px-3 py-1.5 rounded bg-cyan-500 text-slate-950 text-sm font-semibold hover:bg-cyan-400">
                    Scan profiles
                  </button>
                  <label className="text-xs text-slate-300 flex items-center gap-2">
                    <input type="checkbox" checked={autoAddProfilesToDataset} onChange={(e) => setAutoAddProfilesToDataset(e.target.checked)} />
                    Auto-add profiles to dataset
                  </label>
                  <label className="text-xs text-slate-300 flex items-center gap-2">
                    <input type="checkbox" checked={autoImportFromProfileLinks} onChange={(e) => setAutoImportFromProfileLinks(e.target.checked)} />
                    Auto-import datasets from profile links
                  </label>
                  <div className="text-xs text-slate-400">Scanned: {profileScanResults.length}</div>
                </div>
                {profileScanResults.length > 0 && (
                  <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                    {profileScanResults.slice(0, 8).map((p) => (
                      <div key={p.inputUrl} className="border border-slate-800 bg-black/40 rounded-lg p-3">
                        <div className="text-sm font-medium truncate">{p.actorId || p.inputUrl}</div>
                        {!p.ok && <div className="text-xs text-red-400 mt-1">{p.error}</div>}
                        {p.ok && (
                          <>
                            {p.title && <div className="text-xs text-slate-300 mt-1 truncate">{p.title}</div>}
                            {p.riskScore !== undefined && (
                              <div className="text-xs text-slate-300 mt-1">
                                Risk <span className="font-semibold">{p.riskScore.toFixed(2)}</span> · Links {p.links?.length || 0} · Diversity{' '}
                                {(p.linkDiversity ?? 0).toFixed(2)}
                              </div>
                            )}
                            {p.reasons && p.reasons.length > 0 && (
                              <ul className="mt-2 text-xs text-slate-200 list-disc pl-4">
                                {p.reasons.slice(0, 4).map((r) => (
                                  <li key={r}>{r}</li>
                                ))}
                              </ul>
                            )}
                            {p.suspiciousLinks && p.suspiciousLinks.length > 0 && (
                              <div className="mt-2 text-xs">
                                <div className="text-slate-400">Suspicious links</div>
                                <div className="mt-1 flex flex-wrap gap-2">
                                  {p.suspiciousLinks.slice(0, 4).map((u) => (
                                    <a key={u} href={u} target="_blank" rel="noreferrer" className="underline text-red-300">
                                      {u}
                                    </a>
                                  ))}
                                </div>
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2">
              <button
                onClick={startAnalysis}
                disabled={!fileUploaded || logs.length === 0}
                className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
              >
                Run analysis
              </button>
              <div className="text-sm text-slate-300">
                Loaded events: <span className="font-medium text-slate-100">{logs.length.toLocaleString()}</span>
              </div>
            </div>
          </Card>
        )}

        {activeTab === 'generator' && (
          <Card title="Synthetic Attack Generator" subtitle="Create safe, labeled Sybil scenarios for testing (no real data required)">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <label className="text-sm text-slate-200 block">
                    Seed
                    <input
                      type="number"
                      value={syntheticSeed}
                      onChange={(e) => setSyntheticSeed(Number.parseInt(e.target.value || '0', 10) || 0)}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Minutes
                    <input
                      type="number"
                      min={5}
                      max={1440}
                      value={syntheticMinutes}
                      onChange={(e) => setSyntheticMinutes(Math.max(5, Number.parseInt(e.target.value || '120', 10) || 120))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Organic users
                    <input
                      type="number"
                      min={5}
                      value={syntheticOrganicUsers}
                      onChange={(e) => setSyntheticOrganicUsers(Math.max(5, Number.parseInt(e.target.value || '80', 10) || 80))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Organic actions
                    <input
                      type="number"
                      min={10}
                      value={syntheticOrganicActions}
                      onChange={(e) => setSyntheticOrganicActions(Math.max(10, Number.parseInt(e.target.value || '800', 10) || 800))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Targets
                    <input
                      type="number"
                      min={1}
                      value={syntheticTargets}
                      onChange={(e) => setSyntheticTargets(Math.max(1, Number.parseInt(e.target.value || '8', 10) || 8))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Sybil clusters
                    <input
                      type="number"
                      min={0}
                      value={syntheticSybilClusters}
                      onChange={(e) => setSyntheticSybilClusters(Math.max(0, Number.parseInt(e.target.value || '2', 10) || 2))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Cluster size
                    <input
                      type="number"
                      min={3}
                      value={syntheticSybilClusterSize}
                      onChange={(e) => setSyntheticSybilClusterSize(Math.max(3, Number.parseInt(e.target.value || '12', 10) || 12))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Burst target index
                    <input
                      type="number"
                      min={0}
                      value={syntheticBurstTargetIndex}
                      onChange={(e) => setSyntheticBurstTargetIndex(Math.max(0, Number.parseInt(e.target.value || '0', 10) || 0))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Burst actors/cluster
                    <input
                      type="number"
                      min={1}
                      value={syntheticBurstActors}
                      onChange={(e) => setSyntheticBurstActors(Math.max(1, Number.parseInt(e.target.value || '10', 10) || 10))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                  <label className="text-sm text-slate-200 block">
                    Burst actions/actor
                    <input
                      type="number"
                      min={1}
                      value={syntheticBurstActions}
                      onChange={(e) => setSyntheticBurstActions(Math.max(1, Number.parseInt(e.target.value || '3', 10) || 3))}
                      className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                    />
                  </label>
                </div>

                <label className="text-sm text-slate-200 flex items-center gap-2">
                  <input type="checkbox" checked={syntheticIncludeProfiles} onChange={(e) => setSyntheticIncludeProfiles(e.target.checked)} />
                  Include profile fields (bio/links/createdAt)
                </label>

                <div className="flex flex-wrap gap-2">
                  <button onClick={generateSynthetic} className="px-3 py-2 rounded-md bg-violet-500 text-slate-950 text-sm font-semibold hover:bg-violet-400">
                    Generate
                  </button>
                  <button
                    onClick={loadSyntheticIntoApp}
                    disabled={!syntheticLastLogs || syntheticLastLogs.length === 0}
                    className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50"
                  >
                    Load into app
                  </button>
                  <button
                    onClick={downloadSyntheticCsv}
                    disabled={!syntheticLastLogs || syntheticLastLogs.length === 0}
                    className="px-3 py-2 rounded-md border border-slate-800 bg-black/50 text-sm text-slate-200 disabled:opacity-50"
                  >
                    Download CSV
                  </button>
                  <button
                    onClick={downloadSyntheticJson}
                    disabled={!syntheticLastLogs || syntheticLastLogs.length === 0}
                    className="px-3 py-2 rounded-md border border-slate-800 bg-black/50 text-sm text-slate-200 disabled:opacity-50"
                  >
                    Download JSON
                  </button>
                </div>
              </div>

              <div className="border border-slate-800 bg-black/40 rounded-lg p-3">
                <div className="text-sm font-medium">Last generation</div>
                <div className="mt-2 text-sm text-slate-300">
                  Events: <span className="text-slate-100 font-semibold">{(syntheticLastLogs?.length || 0).toLocaleString()}</span>
                </div>
                {syntheticGroundTruth && (
                  <div className="mt-2 text-sm text-slate-300">
                    Ground truth sybils: <span className="text-slate-100 font-semibold">{syntheticGroundTruth.sybilActors.length.toLocaleString()}</span>
                    <div className="text-xs text-slate-400 mt-1">Burst target: {syntheticGroundTruth.burstTarget}</div>
                  </div>
                )}
                <div className="mt-3 text-xs text-slate-400">
                  Tip: after loading, go to Analysis tab, tune thresholds, run analysis, then compare flagged actors to ground truth.
                </div>
              </div>
            </div>
          </Card>
        )}

        {activeTab === 'analysis' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card title="Settings" subtitle="Tune detection without changing code">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="text-sm text-slate-200 block">
                  Threshold (0–1)
                  <input
                    type="number"
                    min={0}
                    max={1}
                    step={0.05}
                    value={settings.threshold}
                    onChange={(e) => setSettings((s) => ({ ...s, threshold: Number.parseFloat(e.target.value) }))}
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block">
                  Min cluster size
                  <input
                    type="number"
                    min={2}
                    step={1}
                    value={settings.minClusterSize}
                    onChange={(e) => setSettings((s) => ({ ...s, minClusterSize: Math.max(2, Number.parseInt(e.target.value || '0')) }))}
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block">
                  Time bin (minutes)
                  <input
                    type="number"
                    min={1}
                    step={1}
                    value={settings.timeBinMinutes}
                    onChange={(e) => setSettings((s) => ({ ...s, timeBinMinutes: Math.max(1, Number.parseInt(e.target.value || '0')) }))}
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block">
                  Wave min count
                  <input
                    type="number"
                    min={1}
                    step={1}
                    value={settings.waveMinCount}
                    onChange={(e) => setSettings((s) => ({ ...s, waveMinCount: Math.max(1, Number.parseInt(e.target.value || '0')) }))}
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block">
                  Wave min actors
                  <input
                    type="number"
                    min={1}
                    step={1}
                    value={settings.waveMinActors}
                    onChange={(e) => setSettings((s) => ({ ...s, waveMinActors: Math.max(1, Number.parseInt(e.target.value || '0')) }))}
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block md:col-span-2">
                  Positive actions (graph edges)
                  <input
                    type="text"
                    value={settings.positiveActions.join(', ')}
                    onChange={(e) =>
                      setSettings((s) => ({
                        ...s,
                        positiveActions: e.target.value
                          .split(',')
                          .map((v) => v.trim())
                          .filter(Boolean),
                      }))
                    }
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block md:col-span-2">
                  Churn actions
                  <input
                    type="text"
                    value={settings.churnActions.join(', ')}
                    onChange={(e) =>
                      setSettings((s) => ({
                        ...s,
                        churnActions: e.target.value
                          .split(',')
                          .map((v) => v.trim())
                          .filter(Boolean),
                      }))
                    }
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
              </div>
              <div className="mt-4">
                <button
                  onClick={startAnalysis}
                  disabled={!fileUploaded || logs.length === 0}
                  className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
                >
                  Run analysis
                </button>
              </div>
            </Card>

            <Card title="How scoring works" subtitle="Explainable, human-readable signals">
              <ul className="text-sm text-slate-200 list-disc pl-4 space-y-1">
                <li>Coordination: actor activity in detected “wave” bins</li>
                <li>Churn: unfollow/unstar counts</li>
                <li>Cluster isolation: low external connections within components</li>
                <li>Low diversity: many actions on few targets</li>
                <li>Profile: suspicious/shared links + follower/following ratio</li>
                <li>Extra: reciprocity, repeated bios, new-account flag</li>
              </ul>
              <p className="text-xs text-slate-400 mt-3">
                Tip: start with a higher threshold (e.g. 0.7) while tuning to reduce false positives.
              </p>
            </Card>
          </div>
        )}

        {activeTab === 'graph' && (
          <Card title="Graph" subtitle="Red nodes are above your threshold">
            <div style={{ width: '100%', height: '640px' }}>
              <CytoscapeComponent
                elements={elements}
                style={{ width: '100%', height: '100%' }}
                stylesheet={[
                  {
                    selector: 'node',
                    style: {
                      'background-color': (ele: NodeSingular) => {
                        const scorecard = scorecards.find(s => s.actor === ele.data('id'));
                        return scorecard && scorecard.sybilScore > settings.threshold ? 'rgb(220 38 38)' : 'rgb(37 99 235)';
                      },
                      label: 'data(label)',
                      'text-valign': 'center',
                      'text-halign': 'center',
                      'font-size': '10px',
                      color: 'rgb(226 232 240)',
                      'text-outline-color': 'rgb(2 6 23)',
                      'text-outline-width': 1,
                    },
                  },
                  {
                    selector: 'edge[type="interaction"]',
                    style: {
                      width: 2,
                      'line-color': 'rgb(52 211 153)',
                    },
                  },
                ]}
                layout={{ name: 'cose' }}
              />
            </div>
          </Card>
        )}

        {activeTab === 'results' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card title="Clusters" subtitle="Connected components above your minimum size">
              <ul className="text-sm text-slate-200 list-disc pl-4 space-y-1">
                {clusters.length === 0 && <li className="list-none text-slate-500">No clusters yet.</li>}
                {clusters.map((c) => (
                  <li key={c.clusterId}>
                    #{c.clusterId}: {c.members.length} members · density {c.density.toFixed(2)} · conductance {c.conductance.toFixed(2)} · external edges {c.externalEdges}
                  </li>
                ))}
              </ul>
            </Card>

            <Card title="Waves" subtitle="Bursts in fixed time bins">
              <ul className="text-sm text-slate-200 list-disc pl-4 space-y-1">
                {waves.length === 0 && <li className="list-none text-slate-500">No waves yet.</li>}
                {waves.map((w, i) => (
                  <li key={i}>
                    {w.windowStart}: {w.action} on {w.target} · {w.actors.length} actors · z {w.zScore.toFixed(2)}
                  </li>
                ))}
              </ul>
            </Card>

            <Card title="Actor scorecards" subtitle="Searchable, explainable reasons">
              <div className="flex flex-col md:flex-row md:items-center gap-2 md:justify-between">
                <label className="text-sm text-slate-200">
                  <input type="checkbox" className="mr-2" checked={showAllActors} onChange={(e) => setShowAllActors(e.target.checked)} />
                  Show all actors
                </label>
                <input
                  value={actorSearch}
                  onChange={(e) => setActorSearch(e.target.value)}
                  placeholder="Search actor..."
                  className="border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                />
              </div>
              <ul className="mt-3 space-y-3 max-h-[720px] overflow-y-auto">
                {(showAllActors ? scorecards : flaggedScorecards)
                  .filter((s) => (actorSearch.trim() ? s.actor.toLowerCase().includes(actorSearch.trim().toLowerCase()) : true))
                  .slice()
                  .sort((a, b) => b.sybilScore - a.sybilScore)
                  .map((s) => (
                    <li key={s.actor} className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="font-medium flex items-center gap-2">
                          <span>{s.actor}</span>
                          {reviews[s.actor]?.decision && (
                            <span className="text-[10px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300">
                              {reviews[s.actor].decision}
                            </span>
                          )}
                        </div>
                        <div className="text-sm">
                          Score <span className="font-semibold">{s.sybilScore.toFixed(2)}</span>
                        </div>
                      </div>
                      <div className="mt-1 text-xs text-slate-400">
                        Churn {s.churnScore} · Coord {s.coordinationScore.toFixed(2)} · Burst {s.burstRate.toFixed(2)} · Reciprocity {s.reciprocalRate.toFixed(2)} · Bio {s.bioSimilarityScore.toFixed(2)} · Handle {s.handlePatternScore.toFixed(2)} · Phish {s.phishingLinkScore.toFixed(2)} · New {s.newAccountScore}
                      </div>
                      {s.reasons.length > 0 && (
                        <div className="mt-2 text-xs text-slate-200">
                          <div className="font-medium">Why flagged</div>
                          <ul className="mt-1 list-disc pl-4">
                            {s.reasons.slice(0, 6).map((r) => (
                              <li key={r}>{r}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {s.links.length > 0 && (
                        <div className="mt-2 text-xs text-slate-200">
                          Links ({s.links.length}, diversity {s.linkDiversity.toFixed(2)}):{' '}
                          {s.links.slice(0, 10).map((link) => (
                            <a
                              key={link}
                              href={link}
                              target="_blank"
                              rel="noreferrer"
                              className={s.suspiciousLinks.includes(link) ? 'text-red-700 underline mr-2' : 'text-blue-700 underline mr-2'}
                            >
                              {link}
                            </a>
                          ))}
                          {s.links.length > 10 && <span className="text-slate-500">(+{s.links.length - 10} more)</span>}
                        </div>
                      )}
                    </li>
                  ))}
                {scorecards.length === 0 && <li className="text-slate-500">Run analysis to generate scorecards.</li>}
              </ul>
            </Card>
          </div>
        )}

        {activeTab === 'evidence' && (
          <Card title="Evidence pack" subtitle="Copy/paste or download JSON for review/reporting">
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={exportEvidence} disabled={logs.length === 0} className="px-3 py-2 rounded-md bg-slate-100 text-slate-950 text-sm font-semibold disabled:opacity-50">
                Download JSON
              </button>
              <button
                onClick={async () => {
                  await navigator.clipboard.writeText(evidenceJson);
                  setSourceStatus('Copied evidence JSON to clipboard');
                }}
                disabled={logs.length === 0}
                className="px-3 py-2 rounded-md border border-slate-800 bg-slate-950/40 text-sm text-slate-200 disabled:opacity-50"
              >
                Copy JSON
              </button>
              <div className="text-sm text-slate-300">
                Flagged: <span className="font-medium text-slate-100">{flaggedScorecards.length.toLocaleString()}</span>
              </div>
            </div>
            <pre className="mt-4 bg-black/50 text-slate-100 border border-slate-800 rounded-lg p-3 overflow-auto text-xs max-h-[720px]">{evidenceJson}</pre>
          </Card>
        )}

        {activeTab === 'review' && (
          <Card title="Human Review" subtitle="Confirm / dismiss / escalate flagged actors with notes (stored locally in IndexedDB)">
            <div className="text-sm text-slate-300">
              Flagged actors: <span className="font-semibold text-slate-100">{flaggedScorecards.length.toLocaleString()}</span>
            </div>
            <div className="mt-3 space-y-3">
              {flaggedScorecards.length === 0 && <div className="text-slate-500">Run analysis to populate flagged actors.</div>}
              {flaggedScorecards.slice(0, 100).map((s) => (
                <div key={s.actor} className="border border-slate-800 bg-black/40 rounded-lg p-3">
                  <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                    <div className="font-medium">{s.actor}</div>
                    <div className="text-sm text-slate-300">
                      Score <span className="font-semibold text-slate-100">{s.sybilScore.toFixed(2)}</span>
                    </div>
                  </div>
                  {s.reasons.length > 0 && (
                    <div className="mt-2 text-xs text-slate-300">
                      <div className="text-slate-400">Signals</div>
                      <ul className="mt-1 list-disc pl-4">
                        {s.reasons.slice(0, 5).map((r) => (
                          <li key={r}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div className="mt-3 flex flex-wrap items-center gap-2">
                    {(['confirm_sybil', 'dismiss', 'escalate'] as const).map((decision) => (
                      <button
                        key={decision}
                        onClick={async () => {
                          const note = reviews[s.actor]?.note || '';
                          const updatedAt = new Date().toISOString();
                          await upsertReview({ actor: s.actor, decision, note, updatedAt });
                          setReviews((prev) => ({ ...prev, [s.actor]: { decision, note, updatedAt } }));
                          setSourceStatus(`Saved review for ${s.actor}`);
                        }}
                        className={
                          reviews[s.actor]?.decision === decision
                            ? 'px-3 py-1.5 rounded-md bg-slate-100 text-slate-950 text-xs font-semibold'
                            : 'px-3 py-1.5 rounded-md border border-slate-800 bg-black/40 text-xs text-slate-200 hover:bg-slate-900/40'
                        }
                      >
                        {decision}
                      </button>
                    ))}
                    <button
                      onClick={async () => {
                        await deleteReview(s.actor);
                        setReviews((prev) => {
                          const next = { ...prev };
                          delete next[s.actor];
                          return next;
                        });
                        setSourceStatus(`Cleared review for ${s.actor}`);
                      }}
                      className="px-3 py-1.5 rounded-md border border-slate-800 bg-black/40 text-xs text-slate-200 hover:bg-slate-900/40"
                    >
                      Clear
                    </button>
                  </div>
                  <div className="mt-2">
                    <textarea
                      value={reviews[s.actor]?.note || ''}
                      onChange={(e) => setReviews((prev) => ({ ...prev, [s.actor]: { decision: prev[s.actor]?.decision || '', note: e.target.value, updatedAt: prev[s.actor]?.updatedAt || new Date().toISOString() } }))}
                      placeholder="Add review notes..."
                      className="w-full border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500 h-16"
                    />
                    <div className="mt-1 flex items-center gap-2">
                      <button
                        onClick={async () => {
                          const decision = reviews[s.actor]?.decision;
                          if (!decision) {
                            setSourceError('Select a decision before saving notes.');
                            return;
                          }
                          const note = reviews[s.actor]?.note || '';
                          const updatedAt = new Date().toISOString();
                          await upsertReview({ actor: s.actor, decision, note, updatedAt });
                          setReviews((prev) => ({ ...prev, [s.actor]: { decision, note, updatedAt } }));
                          setSourceStatus(`Saved notes for ${s.actor}`);
                        }}
                        className="px-3 py-1.5 rounded-md bg-emerald-500 text-slate-950 text-xs font-semibold"
                      >
                        Save notes
                      </button>
                      {reviews[s.actor]?.updatedAt && <span className="text-xs text-slate-500">Updated {reviews[s.actor].updatedAt}</span>}
                    </div>
                  </div>
                </div>
              ))}
              {flaggedScorecards.length > 100 && <div className="text-xs text-slate-500">Showing first 100 flagged actors.</div>}
            </div>
          </Card>
        )}
      </main>
    </div>
  );
}
