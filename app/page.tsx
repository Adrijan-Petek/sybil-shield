'use client';

import dynamic from 'next/dynamic';
import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import Image from 'next/image';
import type { ElementDefinition, NodeSingular } from 'cytoscape';
import { normalizeLinks } from '../lib/profile';
import { extractUrlsFromText } from '../lib/urlResolvers';
import { computeHandlePatternScores } from '../lib/scam';
import type { AnalysisSettings, ActorScorecard, ControllerGroup, DetailedCluster, LogEntry, WaveResult } from '../lib/analyze';
import type { ReviewDecision } from '../lib/reviewStore';
import { deleteReview, getAllReviews, upsertReview } from '../lib/reviewStore';
import { addAuditEvent, clearAuditEvents, getRecentAuditEvents } from '../lib/auditStore';
import Papa from 'papaparse';

// Dynamically import CytoscapeComponent to avoid SSR issues
const CytoscapeComponent = dynamic(() => import('react-cytoscapejs'), { ssr: false });

type CsvRow = Record<string, string | undefined>;

type TabKey = 'dashboard' | 'data' | 'generator' | 'analysis' | 'assistant' | 'graph' | 'results' | 'review' | 'evidence' | 'miniapp' | 'history';

export default function Home() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [elements, setElements] = useState<ElementDefinition[]>([]);
  const [clusters, setClusters] = useState<DetailedCluster[]>([]);
  const [waves, setWaves] = useState<WaveResult[]>([]);
  const [scorecards, setScorecards] = useState<ActorScorecard[]>([]);
  const [controllers, setControllers] = useState<ControllerGroup[]>([]);
  const [settings, setSettings] = useState<AnalysisSettings>({
    threshold: 0.6,
    minClusterSize: 6,
    timeBinMinutes: 5,
    waveMinCount: 10,
    waveMinActors: 8,
    positiveActions: ['follow', 'star', 'transfer', 'fork'],
    churnActions: ['unfollow', 'unstar'],
    rapidActionsPerMinuteThreshold: 50,
    entropyMinTotalActions: 20,
    burstWindowSeconds: 60,
    burstMinCount: 20,
    burstMinActors: 10,
    velocityWindowSeconds: 10,
    velocityMaxActionsInWindow: 20,
    sessionGapMinutes: 5,
    actionNgramSize: 3,
    seedInfluence: 0.15,
    seedMaxHops: 2,
    trustInfluence: 0.15,
    trustMaxHops: 2,
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
  const [baseRpcUrl, setBaseRpcUrl] = useState('');
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
  const [reviewsLoading, setReviewsLoading] = useState(true);
  const [useReviewSeeds, setUseReviewSeeds] = useState(true);
  const [useDismissAsTrustedSeeds, setUseDismissAsTrustedSeeds] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState<{ stage: string; pct: number } | null>(null);
  const [analysisRequestId, setAnalysisRequestId] = useState<string | null>(null);
  const [analysisWorker, setAnalysisWorker] = useState<Worker | null>(null);
  const analysisListenerRef = useRef<((ev: MessageEvent) => void) | null>(null);
  const cyRef = useRef<unknown>(null);
  const [resultsPage, setResultsPage] = useState(1);
  const resultsPageSize = 50;
  const [auditEvents, setAuditEvents] = useState<Array<{ id: string; type: string; at: string; summary: string }>>([]);

  type AssistantMessage = { role: 'user' | 'assistant'; text: string; at: string };
  const [assistantMessages, setAssistantMessages] = useState<AssistantMessage[]>([]);
  const [assistantInput, setAssistantInput] = useState('');

  useEffect(() => {
    const saved = window.localStorage.getItem('sybilShieldTheme');
    if (saved === 'light' || saved === 'dark') setTheme(saved);
  }, []);

  useEffect(() => {
    const saved = window.localStorage.getItem('sybilShieldBaseRpcUrl');
    if (typeof saved === 'string' && saved.trim()) setBaseRpcUrl(saved);
  }, []);

  const refreshAudit = async () => {
    try {
      const items = await getRecentAuditEvents(500);
      setAuditEvents(items.map((x) => ({ id: x.id, type: x.type, at: x.at, summary: x.summary })));
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    void refreshAudit();
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    window.localStorage.setItem('sybilShieldTheme', theme);
  }, [theme]);

  useEffect(() => {
    window.localStorage.setItem('sybilShieldBaseRpcUrl', baseRpcUrl.trim());
  }, [baseRpcUrl]);

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
      topPageRank: scorecards
        .slice()
        .sort((a, b) => (b.pagerank || 0) - (a.pagerank || 0))
        .slice(0, 8)
        .map((s) => ({ key: s.actor, count: Number((s.pagerank || 0).toFixed(6)) })),
      topBetweenness: scorecards
        .slice()
        .sort((a, b) => (b.betweenness || 0) - (a.betweenness || 0))
        .slice(0, 8)
        .map((s) => ({ key: s.actor, count: Number((s.betweenness || 0).toFixed(4)) })),
      topEigen: scorecards
        .slice()
        .sort((a, b) => (b.eigenCentrality || 0) - (a.eigenCentrality || 0))
        .slice(0, 8)
        .map((s) => ({ key: s.actor, count: Number((s.eigenCentrality || 0).toFixed(4)) })),
      topRapidActors: scorecards
        .slice()
        .sort((a, b) => (b.maxActionsPerMinute || 0) - (a.maxActionsPerMinute || 0))
        .slice(0, 8)
        .map((s) => ({ key: s.actor, count: s.maxActionsPerMinute || 0 })),
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
    setReviewsLoading(true);
    getAllReviews()
      .then((all) => {
        if (cancelled) return;
        const map: Record<string, { decision: ReviewDecision | ''; note?: string; updatedAt: string }> = {};
        all.forEach((r) => {
          map[r.actor] = { decision: r.decision, note: r.note, updatedAt: r.updatedAt };
        });
        setReviews(map);
        setReviewsLoading(false);
      })
      .catch(() => {
        setReviewsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const worker = new Worker(new URL('./workers/analyzeWorker.ts', import.meta.url), { type: 'module' });
    setAnalysisWorker(worker);
    return () => {
      if (analysisListenerRef.current) {
        worker.removeEventListener('message', analysisListenerRef.current);
        analysisListenerRef.current = null;
      }
      worker.terminate();
      setAnalysisWorker(null);
    };
  }, []);

  // Prevent Cytoscape from calling renderer.notify() after unmount when layouts/animations are still running.
  useEffect(() => {
    if (activeTab === 'graph') return;
    try {
      const cy = cyRef.current as { stop?: () => void } | null;
      cy?.stop?.();
    } catch {
      // ignore
    }
  }, [activeTab]);

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
      auditTrail: auditEvents,
      reviews,
      clusters,
      waves,
      controllers,
      scorecards: flaggedScorecards,
      profileLinks,
      syntheticGroundTruth: syntheticGroundTruth ?? undefined,
    };
  }, [auditEvents, clusters, controllers, insights, reviews, scorecards, flaggedScorecards, settings, syntheticGroundTruth, waves]);

  const evidenceJson = useMemo(() => JSON.stringify(evidenceObject, null, 2), [evidenceObject]);
  const evidenceSummary = useMemo(() => {
    const flagged = flaggedScorecards.length;
    const clustersN = clusters.length;
    const wavesN = waves.length;
    const topWave = insights.topWaves[0];
    const topChurnTarget = insights.topTargetsByChurn[0];
    const topSuspDomain = insights.topSuspiciousDomains[0];

    const lines: string[] = [];
    lines.push(`Sybil Shield Summary`);
	    lines.push(`- Events: ${logSummary.total.toLocaleString()} · Actors: ${logSummary.uniqueActors.toLocaleString()} · Targets: ${logSummary.uniqueTargets.toLocaleString()}`);
	    lines.push(`- Flagged actors: ${flagged.toLocaleString()} (threshold ${settings.threshold.toFixed(2)})`);
	    lines.push(`- Clusters: ${clustersN.toLocaleString()} · Waves: ${wavesN.toLocaleString()} (bin ${settings.timeBinMinutes}m, minActors ${settings.waveMinActors}, minCount ${settings.waveMinCount})`);
	    lines.push(`- Likely controllers: ${controllers.length.toLocaleString()} group(s) (min size 3)`);
	    if (topWave) lines.push(`- Largest wave: ${topWave.action} on ${topWave.target} @ ${topWave.windowStart} (${topWave.actors} actors)`);
    if (topChurnTarget) lines.push(`- Top churn target: ${topChurnTarget.key} (${topChurnTarget.count} churn events)`);
    if (topSuspDomain) lines.push(`- Top suspicious domain: ${topSuspDomain.key} (seen in ${topSuspDomain.count} profiles)`);
    lines.push('');
    lines.push('Recommended next steps:');
    lines.push('- Review the top flagged actors in Results and confirm/dismiss in Review tab.');
    lines.push('- Check Graph for tight clusters and verify whether they have low external edges.');
    lines.push('- Export the evidence pack once reviewed (includes reviews + insights).');
    return lines.join('\n');
	  }, [
	    clusters.length,
	    controllers.length,
	    flaggedScorecards.length,
    insights.topSuspiciousDomains,
    insights.topTargetsByChurn,
    insights.topWaves,
    logSummary.total,
    logSummary.uniqueActors,
    logSummary.uniqueTargets,
    settings.threshold,
    settings.timeBinMinutes,
    settings.waveMinActors,
    settings.waveMinCount,
	    waves.length,
	  ]);

  const syntheticMetrics = useMemo(() => {
    if (!syntheticGroundTruth || syntheticGroundTruth.sybilActors.length === 0) return null;
    const truth = new Set(syntheticGroundTruth.sybilActors);
    const flagged = new Set(flaggedScorecards.map((s) => s.actor));
    let tp = 0;
    flagged.forEach((a) => {
      if (truth.has(a)) tp++;
    });
    const fp = Math.max(0, flagged.size - tp);
    let fn = 0;
    truth.forEach((a) => {
      if (!flagged.has(a)) fn++;
    });
    const precision = flagged.size > 0 ? tp / flagged.size : 0;
    const recall = truth.size > 0 ? tp / truth.size : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    return { tp, fp, fn, precision, recall, f1, truth: truth.size, flagged: flagged.size };
  }, [flaggedScorecards, syntheticGroundTruth]);

  const assistantKnowledge = useMemo(() => {
    const entries: Array<{ title: string; patterns: string[]; answer: () => string }> = [
      {
        title: 'What does SybilScore mean?',
        patterns: ['sybilscore', 'score', 'confidence'],
        answer: () =>
          [
            'SybilScore is an explainable heuristic score (0–1) that aggregates multiple signals:',
            '- coordinationScore: activity concentrated inside detected “wave” bins',
            '- churnScore: unfollow/unstar volume',
            '- clusterIsolationScore: low external connections relative to cluster size',
            '- lowDiversityScore: many actions on few targets',
            '- profileAnomalyScore: suspicious/shared links and follower/following ratio (if provided)',
            '',
            'Use it as a review prioritization signal, not an accusation.',
          ].join('\n'),
      },
      {
        title: 'Why was an actor flagged?',
        patterns: ['why flagged', 'reason', 'reasons', 'flagged'],
        answer: () =>
          [
            'Open the Results tab and expand an actor: “Why flagged” lists the strongest signals.',
            'Common reasons:',
            '- High coordination (burst actions in wave bins)',
            '- High churn (unfollow/unstar)',
            '- Cluster isolation (farm topology)',
            '- Shared/suspicious links and repeated bios',
            '- Handle pattern similarity (template reuse)',
          ].join('\n'),
      },
      {
        title: 'How should I set thresholds?',
        patterns: ['threshold', 'tune', 'settings'],
        answer: () => {
          const flagged = flaggedScorecards.length;
          const total = scorecards.length;
          const ratio = total > 0 ? flagged / total : 0;
          const lines = [
            `Current threshold: ${settings.threshold.toFixed(2)}`,
            `Flagged actors: ${flagged.toLocaleString()} / ${total.toLocaleString()}`,
          ];
          if (total === 0) {
            lines.push('Load data and run analysis first.');
            return lines.join('\n');
          }
          if (flagged === 0) {
            lines.push('Suggestion: lower threshold (e.g. 0.6 → 0.5) or lower waveMinActors/waveMinCount to detect smaller coordinated waves.');
          } else if (ratio > 0.25) {
            lines.push('Suggestion: raise threshold (e.g. +0.05 to +0.15) and/or increase waveMinActors to reduce false positives.');
          } else {
            lines.push('Suggestion: keep threshold, then confirm/dismiss in Review tab to calibrate.');
          }
          return lines.join('\n');
        },
      },
      {
        title: 'What should I look at first?',
        patterns: ['first', 'start', 'where', 'what next', 'triage'],
        answer: () =>
          [
            'Triage order (fast → deep):',
            '1) Dashboard insights: top targets, top waves, suspicious domains, shared links',
            '2) Results: highest SybilScore actors and “Why flagged”',
            '3) Graph: verify clusters (do the red nodes form tight components?)',
            '4) Review: confirm/dismiss/escalate and export evidence',
          ].join('\n'),
      },
      {
        title: 'What does a wave mean?',
        patterns: ['wave', 'burst', 'timing'],
        answer: () =>
          [
            'A wave is a burst of the same action on the same target within a fixed time bin.',
            'It’s useful for detecting coordinated campaigns (e.g., mass unfollow/unstar).',
            'Tune it with:',
            '- timeBinMinutes',
            '- waveMinCount',
            '- waveMinActors',
          ].join('\n'),
      },
      {
        title: 'How do link signals catch scammers?',
        patterns: ['link', 'domain', 'phishing', 'scam'],
        answer: () =>
          [
            'Scam campaigns often reuse the same domains/URLs across many accounts.',
            'Sybil Shield flags:',
            '- suspicious domains (shorteners + punycode/IP hosts)',
            '- phishing-like URL structure (user@host, excessive subdomains, etc.)',
            '- shared links across profiles',
            '- low link diversity',
          ].join('\n'),
      },
    ];
    return entries;
  }, [flaggedScorecards.length, scorecards.length, settings.threshold]);

  const assistantAnswer = (question: string): string => {
    const q = question.trim().toLowerCase();
    if (!q) return 'Ask a question like: “Why was an actor flagged?” or “How should I set thresholds?”';

    const tokens = new Set(q.split(/[^a-z0-9]+/g).filter(Boolean));
    const scored = assistantKnowledge
      .map((e) => {
        const patternHits = e.patterns.reduce((sum, p) => sum + (q.includes(p) ? 3 : 0), 0);
        const tokenHits = e.patterns.reduce((sum, p) => sum + (tokens.has(p) ? 1 : 0), 0);
        return { e, score: patternHits + tokenHits };
      })
      .sort((a, b) => b.score - a.score);

    const best = scored[0];
    if (best && best.score > 0) return best.e.answer();

    const summary = [
      'I can help with:',
      ...assistantKnowledge.map((e) => `- ${e.title}`),
      '',
      'Tip: If you paste a specific actor ID, I’ll tell you how to interpret their signals (use Results tab for exact “Why flagged”).',
    ];
    return summary.join('\n');
  };

  const assistantExplainCurrent = (): string => {
    const lines: string[] = [];
    lines.push('Current run summary:');
    lines.push(`- Events: ${logSummary.total.toLocaleString()}`);
    lines.push(`- Actors: ${logSummary.uniqueActors.toLocaleString()}`);
    lines.push(`- Targets: ${logSummary.uniqueTargets.toLocaleString()}`);
    lines.push(`- Flagged: ${flaggedScorecards.length.toLocaleString()} (threshold ${settings.threshold.toFixed(2)})`);
    lines.push(`- Clusters: ${clusters.length.toLocaleString()}`);
    lines.push(`- Waves: ${waves.length.toLocaleString()} (bin ${settings.timeBinMinutes}m, minActors ${settings.waveMinActors}, minCount ${settings.waveMinCount})`);

    if (insights.topTargetsByChurn.length > 0) {
      lines.push('');
      lines.push('Top churn targets:');
      insights.topTargetsByChurn.slice(0, 5).forEach((t) => lines.push(`- ${t.key} (${t.count})`));
    }
    if (insights.topSuspiciousDomains.length > 0) {
      lines.push('');
      lines.push('Top suspicious domains:');
      insights.topSuspiciousDomains.slice(0, 5).forEach((d) => lines.push(`- ${d.key} (${d.count})`));
    }
    if (insights.topSharedLinks.length > 0) {
      lines.push('');
      lines.push('Top shared links:');
      insights.topSharedLinks.slice(0, 3).forEach((l) => lines.push(`- ${l.key} (${l.count})`));
    }
    lines.push('');
    lines.push('Next steps:');
    lines.push('- Open Results to inspect top actors and “Why flagged”');
    lines.push('- Use Review tab to confirm/dismiss and export evidence');
    return lines.join('\n');
  };

  const temporalHeatmap = useMemo(() => {
    // Top actions by frequency -> counts by UTC hour (0-23)
    const actionCounts: Record<string, number> = {};
    logs.forEach((l) => {
      actionCounts[l.action] = (actionCounts[l.action] || 0) + 1;
    });
    const topActions = Object.entries(actionCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([action]) => action);

    const matrix: Record<string, number[]> = {};
    topActions.forEach((a) => (matrix[a] = Array.from({ length: 24 }, () => 0)));

    for (const l of logs) {
      if (!matrix[l.action]) continue;
      const t = new Date(l.timestamp);
      const h = Number.isFinite(t.getTime()) ? t.getUTCHours() : 0;
      matrix[l.action][h] += 1;
    }

    const max = Math.max(
      1,
      ...Object.values(matrix).flatMap((arr) => arr),
    );
    return { topActions, matrix, max };
  }, [logs]);

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
      // Guard: large files can freeze the browser when parsing client-side.
      const maxBytes = 50 * 1024 * 1024; // 50MB
      if (file.size > maxBytes) {
        alert(`File is too large (${Math.round(file.size / (1024 * 1024))}MB). Please upload a file smaller than 50MB or split it into chunks.`);
        event.target.value = '';
        return;
      }
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
    if (isAnalyzing) return;
    runAnalysis(logs);
  };

  const runAnalysis = (data: LogEntry[]) => {
    if (!analysisWorker) {
      setSourceError('Analysis worker is not ready yet. Try again in a moment.');
      return;
    }
    if (analysisRequestId) {
      analysisWorker.postMessage({ type: 'cancel', requestId: analysisRequestId });
    }
    if (analysisListenerRef.current) {
      analysisWorker.removeEventListener('message', analysisListenerRef.current);
      analysisListenerRef.current = null;
    }

    const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    setAnalysisRequestId(requestId);
    setIsAnalyzing(true);
    setAnalysisProgress({ stage: 'start', pct: 0 });
    setSourceError(null);
    setSourceStatus('Analyzing…');
    setResultsPage(1);

    const seedActors = useReviewSeeds
      ? Object.entries(reviews)
          .filter(([, r]) => r.decision === 'confirm_sybil')
          .map(([actor]) => actor)
      : [];
    const trustedActors = useDismissAsTrustedSeeds
      ? Object.entries(reviews)
          .filter(([, r]) => r.decision === 'dismiss')
          .map(([actor]) => actor)
      : [];
    const settingsToSend: AnalysisSettings = { ...settings, seedActors, trustedActors };

    void addAuditEvent({
      type: 'analysis_run',
      at: new Date().toISOString(),
      summary: `Analysis run: ${data.length.toLocaleString()} events, threshold ${settings.threshold.toFixed(2)}`,
      meta: { count: data.length, settings, seedActorsCount: seedActors.length },
    }).then(refreshAudit);

    type WorkerProgress = { type: 'progress'; requestId: string; stage: string; pct: number };
    type WorkerResult = {
      type: 'result';
      requestId: string;
      result: { elements: ElementDefinition[]; clusters: DetailedCluster[]; waves: WaveResult[]; scorecards: ActorScorecard[]; controllers: ControllerGroup[] };
    };
    type WorkerError = { type: 'error'; requestId: string; error: string };
    type WorkerMsg = WorkerProgress | WorkerResult | WorkerError;

    const onMessage = (ev: MessageEvent<WorkerMsg>) => {
      const msg = ev.data;
      if (!msg || msg.requestId !== requestId) return;

      if (msg.type === 'progress') {
        setAnalysisProgress({ stage: msg.stage || 'progress', pct: msg.pct ?? 0 });
        return;
      }

      if (msg.type === 'result') {
        setElements(msg.result.elements || []);
        setClusters(msg.result.clusters || []);
        setWaves(msg.result.waves || []);
        setScorecards(msg.result.scorecards || []);
        setControllers(msg.result.controllers || []);
        setIsAnalyzing(false);
        setAnalysisProgress({ stage: 'done', pct: 100 });
        setSourceStatus('Analysis complete');
        analysisWorker.removeEventListener('message', onMessage);
        analysisListenerRef.current = null;
        setActiveTab('results');
        return;
      }

      if (msg.type === 'error') {
        setIsAnalyzing(false);
        setSourceStatus(null);
        setSourceError(msg.error || 'Analysis failed');
        analysisWorker.removeEventListener('message', onMessage);
        analysisListenerRef.current = null;
      }
    };

    analysisWorker.addEventListener('message', onMessage);
    analysisListenerRef.current = onMessage;
    analysisWorker.postMessage({ type: 'analyze', requestId, logs: data, settings: settingsToSend });
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
      void addAuditEvent({ type: 'fetch_source', at: new Date().toISOString(), summary: `Fetched GitHub stargazers: ${repo}` }).then(refreshAudit);
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
      void addAuditEvent({ type: 'fetch_source', at: new Date().toISOString(), summary: `Fetched source: ${label}` }).then(refreshAudit);
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
      void addAuditEvent({ type: 'import_urls', at: new Date().toISOString(), summary: `Imported URLs: ${urls.length} url(s)` }).then(refreshAudit);
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
      void addAuditEvent({ type: 'scan_profile_links', at: new Date().toISOString(), summary: `Scanned profile links: ${urls.length} url(s)` }).then(refreshAudit);
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
      setActiveTab('analysis');
      void addAuditEvent({ type: 'scan_profile', at: new Date().toISOString(), summary: `Profile anomaly scan: ${profiles.length} profile(s)` }).then(refreshAudit);
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

  // Worker-based analysis replaces the previous in-component implementation.

  const exportEvidence = () => {
    const blob = new Blob([evidenceJson], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'evidence-pack.json';
    a.click();
    void addAuditEvent({
      type: 'export_evidence',
      at: new Date().toISOString(),
      summary: `Exported evidence pack (${flaggedScorecards.length.toLocaleString()} flagged)`,
    }).then(refreshAudit);
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
              <TabButton tab="assistant" label="Assistant" />
              <TabButton tab="graph" label="Graph" />
              <TabButton tab="results" label="Results" />
              <TabButton tab="review" label="Review" />
              <TabButton tab="evidence" label="Evidence" />
              <TabButton tab="miniapp" label="Mini-App" />
              <TabButton tab="history" label="History" />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
                className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 hover:bg-slate-900/40"
                title="Toggle theme"
              >
                {theme === 'dark' ? 'Black' : 'Dim'}
              </button>
              <button
	                onClick={() => {
	                  setLogs([]);
	                  setElements([]);
	                  setClusters([]);
	                  setWaves([]);
	                  setScorecards([]);
	                  setControllers([]);
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
            {isAnalyzing && analysisProgress && (
              <div className="mt-2">
                <div className="text-xs text-slate-400">
                  {analysisProgress.stage} · {Math.round(analysisProgress.pct)}%
                </div>
                <div className="mt-1 h-2 w-full bg-slate-900 rounded">
                  <div className="h-2 rounded bg-gradient-to-r from-cyan-500 via-violet-500 to-emerald-500" style={{ width: `${analysisProgress.pct}%` }} />
                </div>
              </div>
            )}
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
	                    disabled={!fileUploaded || logs.length === 0 || isAnalyzing}
	                    className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
	                  >
	                    {isAnalyzing ? 'Analyzing…' : 'Run analysis'}
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
                {syntheticMetrics && (
                  <div className="mt-3 border border-slate-800 bg-black/40 rounded-lg p-3">
                    <div className="text-sm font-medium">Synthetic validation</div>
                    <div className="mt-1 text-xs text-slate-300">
                      Precision {syntheticMetrics.precision.toFixed(2)} · Recall {syntheticMetrics.recall.toFixed(2)} · F1 {syntheticMetrics.f1.toFixed(2)}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      TP {syntheticMetrics.tp} · FP {syntheticMetrics.fp} · FN {syntheticMetrics.fn} · Truth {syntheticMetrics.truth} · Flagged {syntheticMetrics.flagged}
                    </div>
                  </div>
                )}
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

            <Card title="Temporal Heatmap" subtitle="Event intensity by UTC hour (top actions)">
              <div className="overflow-auto">
                <div className="min-w-[760px]">
                  <div className="grid grid-cols-[140px_repeat(24,minmax(18px,1fr))] gap-1 text-xs text-slate-400">
                    <div />
                    {Array.from({ length: 24 }, (_, h) => (
                      <div key={h} className="text-center">
                        {h}
                      </div>
                    ))}
                  </div>
                  <div className="mt-2 space-y-1">
                    {temporalHeatmap.topActions.length === 0 && <div className="text-sm text-slate-500">No events loaded.</div>}
                    {temporalHeatmap.topActions.map((action) => (
                      <div key={action} className="grid grid-cols-[140px_repeat(24,minmax(18px,1fr))] gap-1 items-center">
                        <div className="truncate text-xs text-slate-200 pr-2">{action}</div>
                        {temporalHeatmap.matrix[action].map((count, h) => {
                          const intensity = count / temporalHeatmap.max;
                          const bg = `rgba(34, 211, 238, ${Math.max(0.05, intensity * 0.9)})`;
                          return (
                            <div
                              key={`${action}-${h}`}
                              title={`${action} @ ${h}:00 UTC — ${count}`}
                              className="h-5 rounded border border-slate-800"
                              style={{ background: count === 0 ? 'rgba(0,0,0,0.25)' : bg }}
                            />
                          );
                        })}
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 text-xs text-slate-500">Tip: spikes often reveal scheduled farms or coordinated campaigns.</div>
                </div>
              </div>
            </Card>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <Card title="Top PageRank" subtitle="Influential nodes in the interaction graph">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topPageRank.length === 0 && <li className="text-slate-500">No graph yet</li>}
                  {insights.topPageRank.map((x) => (
                    <li key={x.key} className="flex items-center justify-between gap-3">
                      <span className="truncate">{x.key}</span>
                      <span className="text-slate-400">{x.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>
              <Card title="Top Betweenness" subtitle="Bridge-like nodes that connect groups">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topBetweenness.length === 0 && <li className="text-slate-500">No graph yet</li>}
                  {insights.topBetweenness.map((x) => (
                    <li key={x.key} className="flex items-center justify-between gap-3">
                      <span className="truncate">{x.key}</span>
                      <span className="text-slate-400">{x.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>
              <Card title="Top Eigenvector" subtitle="Highly-connected within highly-connected neighborhoods">
                <ul className="text-sm text-slate-200 space-y-1">
                  {insights.topEigen.length === 0 && <li className="text-slate-500">No graph yet</li>}
                  {insights.topEigen.map((x) => (
                    <li key={x.key} className="flex items-center justify-between gap-3">
                      <span className="truncate">{x.key}</span>
                      <span className="text-slate-400">{x.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>

            <Card title="Rapid Interaction" subtitle="Mini-app / bot-like behavior: max actions per minute">
              <ul className="text-sm text-slate-200 space-y-1">
                {insights.topRapidActors.length === 0 && <li className="text-slate-500">No events yet</li>}
                {insights.topRapidActors.map((x) => (
                  <li key={x.key} className="flex items-center justify-between gap-3">
                    <span className="truncate">{x.key}</span>
                    <span className="text-slate-400">{x.count}/min</span>
                  </li>
                ))}
              </ul>
              <div className="mt-2 text-xs text-slate-500">
                Threshold: {settings.rapidActionsPerMinuteThreshold}/min · Consider lowering time bin to 1 minute for mini-app logs.
              </div>
            </Card>
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

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Farcaster (connector)</div>
                <div className="text-xs text-slate-400 mt-1">Requires a configured API backend (currently stubbed).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={farcasterId}
                    onChange={(e) => setFarcasterId(e.target.value)}
                    placeholder="fid or username"
                    className="flex-1 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                  />
                  <button
                    onClick={() => fetchSource('/api/fetch/farcaster', { id: farcasterId.trim() }, 'Farcaster')}
                    className="px-3 py-1.5 rounded border border-slate-800 bg-black/40 text-slate-200 text-sm hover:bg-slate-900/50"
                  >
                    Fetch
                  </button>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Base (connector)</div>
                <div className="text-xs text-slate-400 mt-1">Fetches ERC-20 Transfer logs (native ETH not included).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={baseAddress}
                    onChange={(e) => setBaseAddress(e.target.value)}
                    placeholder="0x wallet address"
                    className="flex-1 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                  />
                  <button
                    onClick={() =>
                      fetchSource(
                        '/api/fetch/base',
                        { address: baseAddress.trim(), maxBlocks: '5000', direction: 'both', ...(baseRpcUrl.trim() ? { rpcUrl: baseRpcUrl.trim() } : {}) },
                        'Base',
                      )
                    }
                    className="px-3 py-1.5 rounded border border-slate-800 bg-black/40 text-slate-200 text-sm hover:bg-slate-900/50"
                  >
                    Fetch
                  </button>
                </div>
                <div className="mt-2">
                  <input
                    value={baseRpcUrl}
                    onChange={(e) => setBaseRpcUrl(e.target.value)}
                    placeholder="Optional: https://… Base JSON-RPC URL (uses BASE_RPC_URL if set)"
                    className="w-full border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                  />
                  <div className="text-xs text-slate-500 mt-1">
                    Tip: set <code>BASE_RPC_URL</code> in <code>.env.local</code> for private/local RPC endpoints.
                  </div>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                <div className="text-sm font-medium">Talent Protocol (connector)</div>
                <div className="text-xs text-slate-400 mt-1">If you have exports, use Import/Scan (currently stubbed).</div>
                <div className="mt-2 flex gap-2">
                  <input
                    value={talentId}
                    onChange={(e) => setTalentId(e.target.value)}
                    placeholder="handle / profile id"
                    className="flex-1 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
                  />
                  <button
                    onClick={() => fetchSource('/api/fetch/talent', { id: talentId.trim() }, 'Talent')}
                    className="px-3 py-1.5 rounded border border-slate-800 bg-black/40 text-slate-200 text-sm hover:bg-slate-900/50"
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
	                disabled={!fileUploaded || logs.length === 0 || isAnalyzing}
	                className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
	              >
	                {isAnalyzing ? 'Analyzing…' : 'Run analysis'}
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
              <div className="flex flex-wrap gap-2 mb-3">
                <button
                  onClick={() =>
	                    setSettings((s) => ({
	                      ...s,
	                      timeBinMinutes: 1,
	                      waveMinCount: 50,
	                      waveMinActors: 10,
	                      rapidActionsPerMinuteThreshold: 50,
	                      entropyMinTotalActions: 20,
	                      burstWindowSeconds: 60,
	                      burstMinCount: 50,
	                      burstMinActors: 10,
	                      velocityWindowSeconds: 10,
	                      velocityMaxActionsInWindow: 25,
	                      sessionGapMinutes: 5,
	                      actionNgramSize: 3,
	                      seedInfluence: 0.15,
	                      seedMaxHops: 2,
	                      trustInfluence: 0.15,
	                      trustMaxHops: 2,
	                      positiveActions: Array.from(
	                        new Set([
	                          ...s.positiveActions,
	                          'tap',
                          'claim',
                          'reward',
                          'mint',
                          'swap',
                          'follow',
                          'star',
                          'transfer',
                        ]),
                      ),
	                      churnActions: Array.from(new Set([...s.churnActions, 'unclaim', 'unlike', 'revoke'])),
	                    }))
	                  }
                  className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 hover:bg-slate-900/50"
                  title="Good defaults for high-volume mini-app/bot logs (1-minute bins + rapid/entropy signals)"
                >
                  Apply mini-app preset
                </button>
              </div>
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
                <label className="text-sm text-slate-200 block">
                  Rapid actions threshold (/min)
                  <input
                    type="number"
                    min={1}
                    step={1}
                    value={settings.rapidActionsPerMinuteThreshold}
                    onChange={(e) =>
                      setSettings((s) => ({ ...s, rapidActionsPerMinuteThreshold: Math.max(1, Number.parseInt(e.target.value || '0', 10) || 1) }))
                    }
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <label className="text-sm text-slate-200 block">
                  Entropy min actions
                  <input
                    type="number"
                    min={0}
                    step={1}
                    value={settings.entropyMinTotalActions}
                    onChange={(e) =>
                      setSettings((s) => ({ ...s, entropyMinTotalActions: Math.max(0, Number.parseInt(e.target.value || '0', 10) || 0) }))
                    }
                    className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                  />
                </label>
                <div className="md:col-span-2">
                  <details className="border border-slate-800 bg-black/30 rounded-lg p-3">
                    <summary className="cursor-pointer text-sm text-slate-200">Advanced detection settings</summary>
                    <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
                      <label className="text-sm text-slate-200 block">
                        Burst window (seconds)
                        <input
                          type="number"
                          min={10}
                          step={10}
                          value={settings.burstWindowSeconds}
                          onChange={(e) => setSettings((s) => ({ ...s, burstWindowSeconds: Math.max(10, Number.parseInt(e.target.value || '60', 10) || 60) }))}
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Burst min count
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={settings.burstMinCount}
                          onChange={(e) => setSettings((s) => ({ ...s, burstMinCount: Math.max(1, Number.parseInt(e.target.value || '20', 10) || 20) }))}
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Burst min actors
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={settings.burstMinActors}
                          onChange={(e) => setSettings((s) => ({ ...s, burstMinActors: Math.max(1, Number.parseInt(e.target.value || '10', 10) || 10) }))}
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Velocity window (seconds)
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={settings.velocityWindowSeconds}
                          onChange={(e) =>
                            setSettings((s) => ({ ...s, velocityWindowSeconds: Math.max(1, Number.parseInt(e.target.value || '10', 10) || 10) }))
                          }
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Velocity max actions/window
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={settings.velocityMaxActionsInWindow}
                          onChange={(e) =>
                            setSettings((s) => ({
                              ...s,
                              velocityMaxActionsInWindow: Math.max(1, Number.parseInt(e.target.value || '20', 10) || 20),
                            }))
                          }
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Session gap (minutes)
                        <input
                          type="number"
                          min={1}
                          step={1}
                          value={settings.sessionGapMinutes}
                          onChange={(e) => setSettings((s) => ({ ...s, sessionGapMinutes: Math.max(1, Number.parseInt(e.target.value || '5', 10) || 5) }))}
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <label className="text-sm text-slate-200 block">
                        Action n-gram size
                        <input
                          type="number"
                          min={2}
                          max={5}
                          step={1}
                          value={settings.actionNgramSize}
                          onChange={(e) =>
                            setSettings((s) => ({ ...s, actionNgramSize: Math.min(5, Math.max(2, Number.parseInt(e.target.value || '3', 10) || 3)) }))
                          }
                          className="mt-1 block border border-slate-800 bg-slate-950/60 rounded px-2 py-1 w-full text-sm text-slate-100"
                        />
                      </label>
                      <div className="md:col-span-2 border-t border-slate-800 pt-3">
                        <div className="text-sm text-slate-200 font-medium">Use confirmed sybils as seeds</div>
                        <div className="mt-2 flex flex-wrap items-center gap-3">
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            <input type="checkbox" checked={useReviewSeeds} onChange={(e) => setUseReviewSeeds(e.target.checked)} />
                            Enable seed propagation (from Review tab)
                          </label>
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            Influence
                            <input
                              type="number"
                              min={0}
                              max={1}
                              step={0.05}
                              value={settings.seedInfluence}
                              onChange={(e) => setSettings((s) => ({ ...s, seedInfluence: Math.max(0, Math.min(1, Number.parseFloat(e.target.value || '0') || 0)) }))}
                              className="w-20 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-xs text-slate-100"
                            />
                          </label>
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            Max hops
                            <input
                              type="number"
                              min={0}
                              max={4}
                              step={1}
                              value={settings.seedMaxHops}
                              onChange={(e) => setSettings((s) => ({ ...s, seedMaxHops: Math.max(0, Math.min(4, Number.parseInt(e.target.value || '0', 10) || 0)) }))}
                              className="w-16 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-xs text-slate-100"
                            />
                          </label>
                          <div className="text-xs text-slate-500">
                            Tip: mark a few accounts as <code>confirm_sybil</code>, rerun analysis, and we’ll boost nearby accounts in the interaction graph.
                          </div>
                        </div>
                      </div>
                      <div className="md:col-span-2 border-t border-slate-800 pt-3">
                        <div className="text-sm text-slate-200 font-medium">Trusted damping (reduce false positives)</div>
                        <div className="mt-2 flex flex-wrap items-center gap-3">
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            <input type="checkbox" checked={useDismissAsTrustedSeeds} onChange={(e) => setUseDismissAsTrustedSeeds(e.target.checked)} />
                            Use <code>dismiss</code> as trusted seeds
                          </label>
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            Influence
                            <input
                              type="number"
                              min={0}
                              max={1}
                              step={0.05}
                              value={settings.trustInfluence}
                              onChange={(e) => setSettings((s) => ({ ...s, trustInfluence: Math.max(0, Math.min(1, Number.parseFloat(e.target.value || '0') || 0)) }))}
                              className="w-20 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-xs text-slate-100"
                            />
                          </label>
                          <label className="text-xs text-slate-300 flex items-center gap-2">
                            Max hops
                            <input
                              type="number"
                              min={0}
                              max={4}
                              step={1}
                              value={settings.trustMaxHops}
                              onChange={(e) => setSettings((s) => ({ ...s, trustMaxHops: Math.max(0, Math.min(4, Number.parseInt(e.target.value || '0', 10) || 0)) }))}
                              className="w-16 border border-slate-800 bg-slate-950/60 rounded px-2 py-1 text-xs text-slate-100"
                            />
                          </label>
                          <div className="text-xs text-slate-500">
                            Tip: if you know some accounts are legitimate, mark them <code>dismiss</code> and rerun analysis to dampen nearby accounts.
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="mt-2 text-xs text-slate-500">
                      Tip: burst/velocity/sequences help detect bots and coordinated mini-app farms even when they avoid fixed time bins.
                    </div>
                  </details>
                </div>
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
                  disabled={!fileUploaded || logs.length === 0 || isAnalyzing}
                  className="px-3 py-2 rounded-md bg-emerald-500 text-slate-950 text-sm font-semibold disabled:opacity-50 hover:bg-emerald-400"
                >
                  {isAnalyzing ? 'Analyzing…' : 'Run analysis'}
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
                <li>Mini-app: rapid actions/min + low target entropy</li>
                <li>Extra: reciprocity, repeated bios, new-account flag</li>
              </ul>
              <p className="text-xs text-slate-400 mt-3">
                Tip: start with a higher threshold (e.g. 0.7) while tuning to reduce false positives.
              </p>
            </Card>
          </div>
        )}

        {activeTab === 'assistant' && (
          <Card title="Local Assistant" subtitle="Local-first help and recommendations (no external APIs)">
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  const now = new Date().toISOString();
                  setAssistantMessages((prev) => [...prev, { role: 'assistant', text: assistantExplainCurrent(), at: now }]);
                }}
                className="px-3 py-2 rounded-md bg-slate-100 text-slate-950 text-sm font-semibold"
              >
                Explain current results
              </button>
              <button
                onClick={() => setAssistantMessages([])}
                className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200"
              >
                Clear
              </button>
            </div>

            <div className="mt-4 border border-slate-800 bg-black/40 rounded-lg p-3 max-h-[520px] overflow-y-auto">
              {assistantMessages.length === 0 ? (
                <div className="text-sm text-slate-400">
                  Ask questions like:
                  <ul className="mt-2 list-disc pl-4">
                    <li>Why was an actor flagged?</li>
                    <li>How should I set thresholds?</li>
                    <li>What does a wave mean?</li>
                    <li>How do link signals catch scammers?</li>
                  </ul>
                </div>
              ) : (
                <div className="space-y-3">
                  {assistantMessages.map((m, idx) => (
                    <div key={`${m.at}-${idx}`} className={m.role === 'assistant' ? 'text-slate-100' : 'text-slate-200'}>
                      <div className="text-xs text-slate-500">{m.role} · {m.at}</div>
                      <pre className="whitespace-pre-wrap text-sm leading-5 mt-1">{m.text}</pre>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="mt-3 flex gap-2">
              <input
                value={assistantInput}
                onChange={(e) => setAssistantInput(e.target.value)}
                placeholder="Ask a question…"
                className="flex-1 border border-slate-800 bg-slate-950/60 rounded px-2 py-2 text-sm text-slate-100 placeholder:text-slate-500"
                onKeyDown={(e) => {
                  if (e.key !== 'Enter') return;
                  const q = assistantInput.trim();
                  if (!q) return;
                  const now = new Date().toISOString();
                  setAssistantMessages((prev) => [...prev, { role: 'user', text: q, at: now }, { role: 'assistant', text: assistantAnswer(q), at: new Date().toISOString() }]);
                  setAssistantInput('');
                }}
              />
              <button
                onClick={() => {
                  const q = assistantInput.trim();
                  if (!q) return;
                  const now = new Date().toISOString();
                  setAssistantMessages((prev) => [...prev, { role: 'user', text: q, at: now }, { role: 'assistant', text: assistantAnswer(q), at: new Date().toISOString() }]);
                  setAssistantInput('');
                }}
                className="px-4 py-2 rounded-md bg-gradient-to-r from-cyan-500 via-violet-500 to-emerald-500 text-slate-950 text-sm font-semibold"
              >
                Ask
              </button>
            </div>
          </Card>
        )}

        {activeTab === 'graph' && (
          <Card title="Graph" subtitle="Red nodes are above your threshold">
            <div style={{ width: '100%', height: '640px' }}>
              <CytoscapeComponent
                elements={elements}
                cy={(cy: unknown) => {
                  cyRef.current = cy;
                }}
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
                      color: 'rgb(248 250 252)',
                      'text-outline-color': 'rgb(2 6 23)',
                      'text-outline-width': 1,
                    },
                  },
                  {
                    selector: 'edge[type="interaction"]',
                    style: {
                      width: 2,
                      'line-color': 'rgb(52 211 153)',
                      'target-arrow-color': 'rgb(52 211 153)',
                      'target-arrow-shape': 'triangle',
                      'curve-style': 'bezier',
                    },
                  },
                ]}
                layout={{ name: 'cose', animate: false, fit: true, randomize: true }}
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

	            <Card title="Waves" subtitle="Fixed bins + sliding-window bursts">
              <ul className="text-sm text-slate-200 list-disc pl-4 space-y-1">
                {waves.length === 0 && <li className="list-none text-slate-500">No waves yet.</li>}
                {waves
                  .slice()
                  .sort((a, b) => b.zScore - a.zScore)
                  .slice(0, 80)
                  .map((w, i) => (
                  <li key={i}>
                    {w.windowStart}: {w.action} on {w.target} · {w.actors.length} actors · z {w.zScore.toFixed(2)}{' '}
                    <span className="text-slate-500">({w.method || 'bin'})</span>
                  </li>
                ))}
                {waves.length > 80 && <li className="list-none text-xs text-slate-500">Showing top 80 waves by z-score.</li>}
              </ul>
	            </Card>

              <Card title="Likely controllers" subtitle="Multiple accounts likely controlled by the same operator">
                <div className="text-xs text-slate-400">
                  Groups: <span className="text-slate-200">{controllers.length.toLocaleString()}</span> · min size 3
                </div>
                <ul className="mt-3 space-y-2 max-h-[360px] overflow-y-auto">
                  {controllers.length === 0 && <li className="text-slate-500">Run analysis to generate controller groups.</li>}
                  {controllers.slice(0, 20).map((g) => (
                    <li key={g.controllerId} className="border border-slate-800 bg-black/40 rounded-lg p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="text-sm font-medium text-slate-100">#{g.controllerId}</div>
                        <div className="text-xs text-slate-300">
                          score {g.score.toFixed(2)} · members {g.members.length}
                        </div>
                      </div>
                      {g.evidence.length > 0 && (
                        <ul className="mt-2 text-xs text-slate-300 list-disc pl-4">
                          {g.evidence.slice(0, 4).map((e) => (
                            <li key={e}>{e}</li>
                          ))}
                        </ul>
                      )}
                      <div className="mt-2 flex flex-wrap gap-2">
                        <button
                          onClick={async () => {
                            await navigator.clipboard.writeText(g.members.join('\n'));
                            setSourceStatus(`Copied controller #${g.controllerId} members`);
                          }}
                          className="px-2 py-1 rounded border border-slate-800 bg-black/40 text-xs text-slate-200"
                        >
                          Copy members
                        </button>
                      </div>
                    </li>
                  ))}
                  {controllers.length > 20 && <li className="text-xs text-slate-500">Showing top 20 groups.</li>}
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
              <div className="mt-2 flex items-center justify-between gap-2 text-xs text-slate-400">
                <div>
                  Showing page <span className="text-slate-200">{resultsPage}</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setResultsPage((p) => Math.max(1, p - 1))}
                    className="px-2 py-1 rounded border border-slate-800 bg-black/40 text-slate-200"
                  >
                    Prev
                  </button>
                  <button
                    onClick={() => setResultsPage((p) => p + 1)}
                    className="px-2 py-1 rounded border border-slate-800 bg-black/40 text-slate-200"
                  >
                    Next
                  </button>
                </div>
              </div>
              <ul className="mt-3 space-y-3 max-h-[720px] overflow-y-auto">
                {(showAllActors ? scorecards : flaggedScorecards)
                  .filter((s) => (actorSearch.trim() ? s.actor.toLowerCase().includes(actorSearch.trim().toLowerCase()) : true))
                  .slice()
                  .sort((a, b) => b.sybilScore - a.sybilScore)
                  .slice((resultsPage - 1) * resultsPageSize, resultsPage * resultsPageSize)
                  .map((s) => (
                    <li key={s.actor} className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                      <div className="flex items-start justify-between gap-3">
	                        <div className="font-medium flex items-center gap-2">
	                          <span>{s.actor}</span>
                          {s.controllerId !== undefined && (s.controllerGroupSize || 0) >= 3 && (
                            <span className="text-[10px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300">
                              ctrl #{s.controllerId} · {s.controllerGroupSize}
                            </span>
                          )}
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
                      <div className="mt-1 text-xs text-slate-400 space-y-0.5">
                        <div>
                          Core: churn {s.churnScore} · coord {s.coordinationScore.toFixed(2)} · burst {s.burstRate.toFixed(2)} · diversity {s.lowDiversityScore.toFixed(2)} · cluster {s.clusterIsolationScore.toFixed(2)}
                        </div>
	                        <div>
	                          Mini-app: rapid {s.maxActionsPerMinute}/min · velocity {s.maxActionsPerVelocityWindow} in {settings.velocityWindowSeconds}s · seq {s.actionSequenceRepeatScore.toFixed(2)} · sessions {s.sessionCount} · hours {s.activeHours}
	                        </div>
	                        <div>
	                          Linking: ctrl {s.controllerId ?? '-'} · jacc {s.maxTargetJaccard.toFixed(2)}{s.topTargetJaccardActor ? ` (${s.topTargetJaccardActor})` : ''} · seed {s.seedProximityScore.toFixed(2)}
	                        </div>
	                        <div>
	                          Trust: proximity {s.trustProximityScore.toFixed(2)}
	                        </div>
	                        <div>
	                          Profile/graph: links {s.links.length} · bio {s.bioSimilarityScore.toFixed(2)} · handle {s.handlePatternScore.toFixed(2)} · phish {s.phishingLinkScore.toFixed(2)} · PR {s.pagerank.toFixed(4)} · betw {s.betweenness.toFixed(2)}
	                        </div>
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
                      {s.controllerEvidence && s.controllerEvidence.length > 0 && (
                        <div className="mt-2 text-xs text-slate-300">
                          <div className="text-slate-400">Controller evidence</div>
                          <ul className="mt-1 list-disc pl-4">
                            {s.controllerEvidence.slice(0, 2).map((e) => (
                              <li key={e}>{e}</li>
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
              <button
                onClick={async () => {
                  await navigator.clipboard.writeText(evidenceSummary);
                  setSourceStatus('Copied summary to clipboard');
                }}
                disabled={logs.length === 0}
                className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 disabled:opacity-50"
              >
                Copy summary
              </button>
              <div className="text-sm text-slate-300">
                Flagged: <span className="font-medium text-slate-100">{flaggedScorecards.length.toLocaleString()}</span>
              </div>
            </div>
            <pre className="mt-4 bg-black/50 text-slate-100 border border-slate-800 rounded-lg p-3 overflow-auto text-sm max-h-[220px]">{evidenceSummary}</pre>
            <pre className="mt-4 bg-black/50 text-slate-100 border border-slate-800 rounded-lg p-3 overflow-auto text-xs max-h-[720px]">{evidenceJson}</pre>
          </Card>
        )}

        {activeTab === 'miniapp' && (
          <div className="space-y-6">
            <Card title="Mini-App Protection" subtitle="Enhanced detection for mini-app Sybil attacks (rapid interactions, wallet clusters, cross-app linking)">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">Shared Funders</h3>
                  <p className="text-xs text-slate-300 mt-1">Wallets funded by the same source</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {scorecards.filter(s => s.sharedWallets.length > 0).length}
                  </div>
                </div>
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">Cross-App Activity</h3>
                  <p className="text-xs text-slate-300 mt-1">Actors active on multiple platforms</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {scorecards.filter(s => s.crossAppPlatforms.length > 1).length}
                  </div>
                </div>
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">High Session Count</h3>
                  <p className="text-xs text-slate-300 mt-1">Actors with many short sessions</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {scorecards.filter(s => s.sessionCount > 5).length}
                  </div>
                </div>
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">Fraudulent Transactions</h3>
                  <p className="text-xs text-slate-300 mt-1">Unusual amount patterns</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {scorecards.filter(s => s.fraudTxScore > 0.5).length}
                  </div>
                </div>
	                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
	                  <h3 className="text-sm font-semibold text-slate-100">Rapid Interactions</h3>
	                  <p className="text-xs text-slate-300 mt-1">High actions per minute</p>
	                  <div className="mt-2 text-lg font-bold text-slate-100">
	                    {scorecards.filter(s => s.maxActionsPerMinute > settings.rapidActionsPerMinuteThreshold).length}
	                  </div>
	                </div>
	                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
	                  <h3 className="text-sm font-semibold text-slate-100">High Velocity</h3>
	                  <p className="text-xs text-slate-300 mt-1">Many actions in a few seconds</p>
	                  <div className="mt-2 text-lg font-bold text-slate-100">
	                    {scorecards.filter(s => s.velocityScore > 0.7).length}
	                  </div>
	                </div>
	                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
	                  <h3 className="text-sm font-semibold text-slate-100">Script Sequences</h3>
	                  <p className="text-xs text-slate-300 mt-1">Repeated action n-grams</p>
	                  <div className="mt-2 text-lg font-bold text-slate-100">
	                    {scorecards.filter(s => s.actionSequenceRepeatScore > 0.7).length}
	                  </div>
	                </div>
	                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
	                  <h3 className="text-sm font-semibold text-slate-100">Circadian Anomalies</h3>
	                  <p className="text-xs text-slate-300 mt-1">Unnatural active-hour patterns</p>
	                  <div className="mt-2 text-lg font-bold text-slate-100">
	                    {scorecards.filter(s => s.circadianScore >= 0.8).length}
	                  </div>
	                </div>
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">Low Target Entropy</h3>
                  <p className="text-xs text-slate-300 mt-1">Focused on few targets</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {scorecards.filter(s => s.lowEntropyScore > 0.7).length}
                  </div>
                </div>
                <div className="bg-black/50 border border-slate-800 rounded-lg p-3">
                  <h3 className="text-sm font-semibold text-slate-100">Likely Controllers</h3>
                  <p className="text-xs text-slate-300 mt-1">Merged multi-account groups</p>
                  <div className="mt-2 text-lg font-bold text-slate-100">
                    {controllers.length}
                  </div>
                </div>
              </div>
            </Card>
            <Card title="Top Mini-App Risks" subtitle="Actors with highest mini-app specific scores">
              <ul className="space-y-2">
                {scorecards
                  .filter(
                    (s) =>
                      s.sharedWallets.length > 0 ||
                      s.crossAppPlatforms.length > 1 ||
                      s.sessionCount > 5 ||
                      s.fraudTxScore > 0.5 ||
                      s.maxActionsPerMinute > settings.rapidActionsPerMinuteThreshold ||
                      s.velocityScore > 0.7 ||
                      s.actionSequenceRepeatScore > 0.7 ||
                      s.circadianScore >= 0.8 ||
                      s.lowEntropyScore > 0.7,
                  )
                  .sort((a, b) => b.sybilScore - a.sybilScore)
                  .slice(0, 10)
                  .map((s) => (
                    <li key={s.actor} className="flex items-center justify-between p-2 bg-black/30 border border-slate-800 rounded-lg">
                      <div>
                        <div className="text-sm font-medium text-slate-100">{s.actor}</div>
                        <div className="text-xs text-slate-300">
                          Score: {s.sybilScore.toFixed(2)} | Shared: {s.sharedWallets.length} | Cross: {s.crossAppPlatforms.length} | Sessions: {s.sessionCount} | Fraud: {s.fraudTxScore.toFixed(2)}
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm font-bold text-red-400">{s.sybilScore > settings.threshold ? 'FLAGGED' : 'OK'}</div>
                      </div>
                    </li>
                  ))}
                {scorecards.length === 0 && <li className="text-slate-500">Run analysis to see mini-app risks.</li>}
              </ul>
            </Card>
          </div>
        )}

        {activeTab === 'review' && (
          <Card title="Human Review" subtitle="Confirm / dismiss / escalate flagged actors with notes (stored locally in IndexedDB)">
            <div className="text-sm text-slate-300">
              Flagged actors: <span className="font-semibold text-slate-100">{flaggedScorecards.length.toLocaleString()}</span>
            </div>
            <div className="mt-3 space-y-3">
              {reviewsLoading && <div className="text-slate-500">Loading saved reviews…</div>}
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

        {activeTab === 'history' && (
          <Card title="History" subtitle="Local audit trail (stored in IndexedDB)">
            <div className="flex flex-wrap gap-2">
              <button onClick={refreshAudit} className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 hover:bg-slate-900/50">
                Refresh
              </button>
              <button
                onClick={async () => {
                  await clearAuditEvents();
                  await refreshAudit();
                  setSourceStatus('Cleared audit history');
                }}
                className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 hover:bg-slate-900/50"
              >
                Clear history
              </button>
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(auditEvents, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'audit-history.json';
                  a.click();
                }}
                disabled={auditEvents.length === 0}
                className="px-3 py-2 rounded-md bg-slate-100 text-slate-950 text-sm font-semibold disabled:opacity-50"
              >
                Download JSON
              </button>
              <button
                onClick={() => {
                  const lines = ['at,type,summary'];
                  auditEvents.forEach((e) => {
                    const esc = (v: string) => `"${v.replaceAll('"', '""')}"`;
                    lines.push([esc(e.at), esc(e.type), esc(e.summary)].join(','));
                  });
                  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = 'audit-history.csv';
                  a.click();
                }}
                disabled={auditEvents.length === 0}
                className="px-3 py-2 rounded-md border border-slate-800 bg-black/40 text-sm text-slate-200 disabled:opacity-50"
              >
                Download CSV
              </button>
            </div>

            <div className="mt-4 border border-slate-800 bg-black/40 rounded-lg p-3 max-h-[720px] overflow-y-auto">
              {auditEvents.length === 0 ? (
                <div className="text-sm text-slate-500">No history yet. Run analysis, imports, scans, or exports to populate.</div>
              ) : (
                <ul className="space-y-2">
                  {auditEvents.map((e) => (
                    <li key={e.id} className="border border-slate-800 bg-slate-950/30 rounded-lg p-3">
                      <div className="text-xs text-slate-500">
                        {e.at} · {e.type}
                      </div>
                      <div className="text-sm text-slate-200 mt-1">{e.summary}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Card>
        )}
      </main>
    </div>
  );
}
