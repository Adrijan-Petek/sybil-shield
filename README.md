# Sybil Shield (Sybil Attack Detection)

Sybil Shield is a **local-first** Next.js app that helps you detect **coordinated farms** (Sybil clusters), **scammer patterns**, and **mini-app attacks** across social, onchain, and mini-app systems using explainable graph + timing + profile + behavioral signals.

It’s designed for **human review**: you get an evidence pack with "why flagged" reasons, not automatic bans. Now includes enhanced protection for mini-apps, where most Sybil attacks occur via rapid interactions, wallet clusters, and cross-platform coordination.

## What this catches (and why it works)

Sybil attackers typically optimize for scale and coordination:

- **Dense internal graphs** with limited external connectivity (farms)
- **Bursty, synchronized actions** (waves) to manipulate rankings, airdrops, or reputation
- **Low diversity** (many actions against few targets) and repetitive behavior
- **Reusable templates**: similar handles, repeated bios, shared links, same domains
- **Mini-app specific**: shared wallets, cross-app linking, session anomalies, fraudulent transaction patterns, rapid interactions, low target entropy

This project focuses on signals that are **harder to fake** without losing the attacker’s operational efficiency, now extended to mini-app ecosystems.

## UI (Tabs)

- **Dashboard**: key counts + cheat-catching insights (top targets, suspicious domains, shared links, handle patterns)
- **Data**: upload logs, fetch GitHub, import URLs, scan profile pages for data files
- **Generator**: create synthetic attack data for testing
- **Analysis**: settings + scoring explanation
- **Assistant**: local-first Q&A for interpreting signals (no external APIs)
- **Graph**: interaction visualization
- **Results**: clusters, waves, searchable actor scorecards with "why flagged"
- **Review**: human review mode with confirm/dismiss and notes (IndexedDB storage)
- **Evidence**: copy/download the full JSON evidence pack
- **Mini-App**: dedicated stats and top risks for mini-app Sybil detection (shared wallets, cross-app activity, sessions, fraud, rapid actions, entropy)
- **History**: local audit trail of runs/imports/scans/exports (IndexedDB)

## Quickstart

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

Optional environment variables:

- `GITHUB_TOKEN` – increases GitHub API rate limits for fetching stargazers

## Getting data into the system

### 1) Upload CSV or JSON

Upload a file with events. The app parses and analyzes locally in the browser.

### 2) Import from URLs (works with “everything”)

Paste any text containing links (chat messages, docs, issues). The server:

- extracts URLs
- resolves common “share” links into raw download URLs
- downloads `.csv` / `.json` (size-limited) and ingests as events

Resolvers include GitHub (blob→raw), Gist (→/raw), GitLab (blob→raw), Bitbucket (`raw=1`), Google Drive (direct download), Dropbox (`dl=1`), OneDrive (`download=1`), HuggingFace (blob→resolve).
Also supports Google Sheets export (CSV) and Pastebin raw links.

### 3) Scan profile links (auto-find CSV/JSON)

Paste profile URLs (GitHub, Talent, Farcaster pages, etc.). The server fetches HTML, extracts links, applies resolvers, and lists any `.csv` / `.json` data files it discovers.

### 4) GitHub: Fetch stargazers

Fetch timestamped `star` events for `owner/repo` via the GitHub API:

- API: `app/api/fetch/github/route.ts`
- Output: normalized log entries for analysis

## Event schema (CSV/JSON)

Required:

- `timestamp` (ISO8601)
- `platform` (e.g. `github`, `farcaster`, `base`, `talent`, `binance`, `custom`)
- `action` (e.g. `follow`, `unfollow`, `star`, `unstar`, `transfer`, `fork`, `comment`, `issue`, `pr`)
- `actor` (handle or wallet)
- `target` (user/repo/wallet/etc.)

Optional (used by extra signals if provided):

- `actorCreatedAt` (ISO8601) – enables new-account scoring
- `bio` – enables bio similarity + link extraction
- `links` (array of URLs, or JSON string in CSV) – enables link signals
- `followerCount`, `followingCount`
- `verified` (boolean-ish)
- `location` (string)
- `amount`, `txHash`, `blockNumber`, `meta`, `targetType`

## How to Use Sybil Shield

### Step-by-Step Guide

1. **Install and Run**:
   ```bash
   npm install
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

2. **Prepare Your Data**:
   - Ensure your logs are in CSV or JSON format with the required fields: `timestamp`, `platform`, `action`, `actor`, `target`.
   - Optional fields like `bio`, `links`, `amount` enhance detection.

3. **Upload Data**:
   - Go to the **Data** tab.
   - Upload your CSV/JSON file, or paste URLs to import, or scan profile pages.
   - For GitHub repos, use the fetch feature with `owner/repo`.

4. **Configure Analysis**:
   - Switch to the **Analysis** tab.
   - Adjust settings: threshold (e.g., 0.6), min cluster size (e.g., 5), time bin minutes (e.g., 5), rapid actions threshold (e.g., 10/min).
   - Click "Start Analysis" to run the detection pipeline.

5. **Review Results**:
   - **Dashboard**: Overview of actors, actions, suspicious domains.
   - **Graph**: Visualize interactions and clusters.
   - **Results**: Search and filter flagged actors, see "why flagged" reasons.
   - **Mini-App**: Specific stats for mini-app risks.
   - **Review**: Confirm/dismiss flags with notes.

6. **Export Evidence**:
   - Go to **Evidence** tab.
   - Download JSON or copy summary for reporting.

### Interpreting Signals

- **Sybil Score > Threshold**: Actor is flagged. Reasons include high coordination, churn, isolation, etc.
- **Clusters**: Groups of densely connected actors (farms).
- **Waves**: Coordinated bursts of actions.
- **Mini-App Signals**: Shared wallets indicate farms; high sessions suggest bots.

### Advanced Usage

- Use the **Generator** tab to create synthetic data for testing.
- The **Assistant** tab answers questions about signals without external calls.
- **History** tab tracks your analysis runs locally.

## Detection outputs

The Evidence pack includes:

- `clusters`: connected components + density/conductance metrics
- `waves`: burst events per **action + target** in fixed bins **and** sliding-window bursts (harder to evade)
- `controllers`: multi-account "likely same operator" groups (entity resolution across platforms/wallets/links)
- `scorecards`: per-actor scores + link stats + "why flagged" reasons (now includes velocity, action-sequence repetition, circadian anomalies, controller id/evidence)
- `profileLinks`: all scanned links per actor (suspicious/shared)
- `insights`: top targets, top suspicious domains, shared links, handle patterns, top waves

## Built-in scammer / cheater signals

In practice, Sybil farms and scammers overlap (phishing, link-farming, impersonation, fake endorsements). Sybil Shield includes:

### Link + domain risk

- **Suspicious domains** (shorteners, known risky domains, and heuristics like punycode / IP literals, mini-app scams)
- **Shared links** across actors (common "farm destination" or phishing destination)
- **Low link diversity** (same domain repeated)
- **Phishing-like URL heuristics**: punycode (`xn--`), IP-literal hosts, excessive subdomains, userinfo in URL, mini-app specific patterns

These help catch campaigns where many accounts drive traffic to the same scam endpoint.

### Identity template reuse

- **Handle pattern score**: repeated stems (e.g. `alice001`, `alice002`, …) and repeated "shapes"
- **Repeated bio score**: identical bios across multiple actors (template reuse)

### Coordination and manipulation

Sybil attackers often avoid fixed bins by spreading actions right over the boundary. Sybil Shield includes:

- **Fixed-bin waves** (fast baseline)
- **Sliding-window bursts** (catches boundary-straddling coordination)
- **Velocity** (N actions within N seconds)
- **Action sequence repetition** (script-like n-grams)
- **Circadian anomalies** (sustained 24/7 activity or tight high-volume windows)

### Controller / entity resolution (multi-account linking)

To uncover “many accounts / many wallets” controlled by one operator, the analyzer builds **controller groups** using high-signal overlaps:

- Same wallet disclosed/used across profiles
- Common funder patterns onchain (seed wallet → many wallets)
- Shared links and uncommon shared domains across profiles
- Same handle across platforms (e.g., `github:alice`, `twitter:alice`)
- Large handle-stem clusters (template reuse)

These groups are **not accusations** — they’re ranked leads for human review and evidence export.

### Semi-supervised “seed” expansion (human-in-the-loop)

If you confirm a handful of accounts as Sybil in **Review** (set decision to `confirm_sybil`) and rerun analysis, Sybil Shield can **propagate suspicion** to nearby accounts in the interaction graph with a configurable hop limit and influence. This helps uncover “support” accounts around a core farm without relying on paid APIs.

### Cross-actor similarity (same-target overlap)

Sybil farms often reuse the same playbook and hit the same targets. Sybil Shield computes per-actor **max target-set Jaccard similarity** to surface accounts that behave like duplicates (useful for ranking manipulation and mini-app reward farming).

### Research notes (why these signals)

- **SybilGuard (2006)**: social-network trust graphs can limit Sybils by leveraging fast-mixing honest regions.
- **SybilLimit (2008)**: improves scalability/guarantees over SybilGuard for large networks.
- **SybilRank (2012)**: ranking-based approach that propagates trust from seeds via random walks.

Sybil Shield uses pragmatic, local-first versions of these ideas:
- graph + clustering for structure
- seed-based propagation (from your reviews) for human-in-the-loop trust/suspicion diffusion
- explainable timing + behavior signals for coordination farms

## Security hardening

- API routes use **rate limiting** and **SSRF protections** (blocks localhost/private IPs for URL imports/scans).
- The app ships common **security headers** (CSP, COOP/CORP, HSTS, etc.) via `next.config.ts`.

- **Waves**: many actions in the same time bin, on the same target
- **Churn**: heavy `unfollow/unstar` behavior
- **Low target diversity**: actions concentrated on a small number of targets
- **Rapid actions per minute**: bot-like behavior in mini-apps
- **Low target entropy**: focused interactions

### Graph structure

- **Cluster isolation**: components with low external connections (farm topology)
- **Reciprocity**: mutual positive interactions (can indicate collusive boosting)

### Mini-app specific signals

- **Shared wallets**: actors using the same wallet addresses (common in Sybil farms)
- **Cross-app linking**: actors active across multiple platforms
- **Session anomalies**: high number of short sessions (bursts)
- **Fraudulent transactions**: unusual amount patterns (high variance or uniform small amounts)

### Added Detection Functions

The following functions have been added to `lib/analyze.ts` for enhanced detection, particularly for mini-app ecosystems:

- `detectSharedWallets(logs: LogEntry[])`: Scans the `meta` field for wallet addresses (e.g., starting with '0x'). Groups actors sharing the same wallets, indicating coordinated farms. Returns a map of actors to their shared wallets.

- `detectCrossAppLinking(logs: LogEntry[])`: Groups actors by platform activity. Actors active on multiple platforms are flagged for potential cross-app coordination. Returns a map of actors to their active platforms.

- `detectSessionAnomalies(logs: LogEntry[], thresholdMs: number = 300000)`: Analyzes action timestamps to detect sessions (groups of actions within time gaps). High session counts suggest bot-like behavior. Returns a map of actors to session counts.

- `detectFraudulentTransactions(logs: LogEntry[])`: For logs with `amount`, calculates variance in transaction amounts per actor. High variance or uniform small amounts indicate fraudulent patterns. Returns a map of actors to fraud scores (0-1).

These functions are called during analysis and their results are integrated into the scoring model with weights: sharedWalletScore (0.05), crossAppScore (0.05), sessionScore (0.05), fraudScore (0.05). They contribute to "why flagged" reasons in the evidence pack.

## Threat model and boundaries

### In scope

- Coordinated follow/star/unfollow/unstar waves (ranking manipulation)
- Dense identity clusters with low external edges (farms)
- Link-farming campaigns (shared domains/URLs)
- Airdrop-style farms *when you provide onchain event logs*
- **Mini-app attacks**: rapid interactions, wallet clusters, cross-app coordination, session bursts, fraudulent transactions

### Out of scope (by default)

- IP/device fingerprinting (unless you import such logs yourself)
- Private chat evidence (WhatsApp/Telegram) — only inferred via timing + behavior

### Safety & ethics

- No automatic bans/blocks. Outputs are **decision-support** for maintainers/analysts.
- Prefer reviewing evidence packs before reporting or enforcement.

## Project structure

- `app/page.tsx` – UI + analysis pipeline (tabs, scoring, evidence)
- `lib/analyze.ts` – core analysis engine (clustering, waves, scoring, mini-app detections: detectSharedWallets, detectCrossAppLinking, detectSessionAnomalies, detectFraudulentTransactions)
- `lib/profile.ts` – profile link extraction + anomaly scoring (expanded suspicious domains)
- `lib/urlResolvers.ts` – URL extraction + share-link → raw download resolver
- `lib/scam.ts` – handle pattern signals + phishing-like URL heuristics (enhanced for mini-apps)
- `lib/reviewStore.ts` – IndexedDB-based human review storage
- `lib/auditStore.ts` – local audit trail for runs/imports/scans/exports
- `lib/rateLimit.ts` – rate limiting utilities for API routes
- `app/workers/analyzeWorker.ts` – Web Worker for offloading analysis
- `app/api/import/url/route.ts` – import CSV/JSON from URLs (SSRF-safe, size limited)
- `app/api/scan/links/route.ts` – scan pages to discover CSV/JSON links
- `app/api/fetch/github/route.ts` – GitHub stargazer fetcher
- `app/api/fetch/{base,farcaster,talent}/route.ts` – connector stubs (implement with keys/indexers)
- `app/api/generate/synthetic/route.ts` – synthetic data generator

## Roadmap (high impact next)

- Base transfers via `BASE_RPC_URL` (or an indexer), funding-tree/common-funder signals
- Farcaster fetch via `NEYNAR_API_KEY` (or hub), follow/cast graphs
- Stronger scam detection: brand-impersonation domain lists, redirect-chain analysis, optional allowlist mode for imports

## License

MIT

Only positive edges contribute to cluster topology.
Negative edges are used exclusively for churn and wave detection.

Expand with ML: Centrality measures, DBSCAN on features.

### Open-Source Inspirations

- [ArbitrumFoundation/sybil-detection](https://github.com/ArbitrumFoundation/sybil-detection): On-chain graph partitioning.
- [TrustaLabs/Airdrop-Sybil-Identification](https://github.com/TrustaLabs/Airdrop-Sybil-Identification): Python ML for sybil clusters.
- [forkoooor/Sybil-Defender](https://github.com/forkoooor/Sybil-Defender): EVM chain monitoring.
- Farcaster-specific: Graph ML papers and Optimism grants.

## CSV/JSON Schema

### Required Fields

- `timestamp` (ISO8601 string, e.g., `2023-01-01T10:00:00Z`)
- `platform` (string: `github`, `farcaster`, `base`, `binance`, or custom)
- `action` (string: `follow`, `unfollow`, `star`, `unstar`, `transfer`, `swap`, `comment`, `fork`, `pr`, `issue`, `endorse`, `score`)
- `actor` (string: user handle or wallet address)
- `target` (string: user/repo/wallet/contract)

### Optional Fields

- `amount` (number: for weighting edges, e.g., transfer amount or star value)
- `txHash` (string: blockchain transaction hash)
- `blockNumber` (number: for onchain ordering)
- `meta` (JSON string: extra data like `{"repo": "owner/repo", "chainId": 8453, "token": "ETH"}`)
- `actorCreatedAt` (ISO8601: account creation time for age analysis)
- `followerCount` (number: current follower count for ratio analysis)
- `followingCount` (number: current following count for ratio analysis)
- `bio` (string: user bio text for pattern analysis)
- `location` (string: user location for geographic clustering)
- `verified` (boolean: if account is verified)
- `links` (array of strings: URLs from bio or profile)
- `targetType` (string: `repo`, `user`, `wallet`, etc.)

### Example CSV Snippet

```csv
timestamp,platform,action,actor,target,amount,meta
2023-01-01T10:00:00Z,github,follow,user1,user2,,{"repo": "example/repo"}
2023-01-01T10:01:00Z,github,star,user2,example/repo,,
2023-01-01T10:02:00Z,base,transfer,0x123...,0x456...,1000,{"chainId": 8453, "token": "ETH"}
2023-01-01T10:03:00Z,talent,endorse,user3,user4,,{"score": 85}
2023-01-01T10:04:00Z,farcaster,follow,user5,user6,,
```

### Example JSON Array

```json
[
  {
    "timestamp": "2023-01-01T10:00:00Z",
    "platform": "github",
    "action": "follow",
    "actor": "user1",
    "target": "user2",
    "meta": "{\"repo\": \"example/repo\"}"
  },
  {
    "timestamp": "2023-01-01T10:01:00Z",
    "platform": "github",
    "action": "star",
    "actor": "user2",
    "target": "example/repo"
  },
  {
    "timestamp": "2023-01-01T10:02:00Z",
    "platform": "talent",
    "action": "endorse",
    "actor": "user3",
    "target": "user4",
    "meta": "{\"score\": 85}"
  }
]
```

Weighting edges (e.g., by amount) improves detection quality.

## Data Ingestion

### CSV / JSON Upload

Minimum required fields: timestamp, platform, action, actor, target

Parser rules:

- Normalize timestamps to UTC
- Lowercase platform + action
- Deduplicate identical rows
- Reject files > configurable limit

### GitHub Ingestion

What GitHub allows: Stars (who starred + when), Follows (current list), Events (received activity)

What GitHub does NOT allow: Unstar events, Unfollow events, Historical removal logs

Use snapshots + diffs to prove unfollow/unstar waves.

Snapshot scripts provided in `/scripts`.

## Detection Pipeline

Order matters for accuracy:

1. **Build interaction graph**: Nodes (actor, target), Edges (actor → target), Weight (count or amount)
2. **Cluster detection**: Connected components, Size ≥ 5 → candidate cluster. Later: Louvain/Leiden modularity
3. **Timing coordination**: Bin events into 5-minute windows, Count actions per (target, action), Compute z-score vs baseline, Flag zScore > 3 AND actors ≥ 5
4. **Churn signals**: Heuristics (many actions toward same target, follow → unfollow patterns, star → unstar via diffs)
5. **Behavioral anomalies**: Low unique targets, New accounts, High repetition

## Evidence Generation

Every flag must generate:

```json
{
  "actor": "user123",
  "sybilScore": 0.71,
  "signals": [
    "Part of 9-node cluster",
    "7 unfollows in 1h",
    "Actions within 120s window",
    "Account age < 3 days"
  ],
  "linkedActors": ["userA", "userB", "userC"]
}
```

No evidence → no claim.

## Frontend Flow

Upload file OR connect GitHub → Click "Analyze" → Show: Graph, Clusters, Waves, Actor scorecards → Export: CSV, JSON, ZIP evidence pack

## Storage Choices

Best MVP stack:

- **Blob Storage** (Vercel/Cloudflare): CSV uploads & reports
- **Postgres** (Neon/Supabase): Entities, runs, scores, audit trail
- **Redis** (Upstash): Queues, rate limits, caching
- **Edge Config** (Vercel): Thresholds ONLY (never data)

Do NOT use: Redis as primary DB, Edge Config for logs, Mongo for graph analysis

## What to Add Next (Ordered)

1. Enhanced mini-app API integrations (e.g., Telegram Mini Apps data fetching)
2. GitHub App integration for private repos
3. Onchain funding tree detection
4. Advanced ML-based clustering (Louvain/Leiden)
5. Cross-platform correlation for broader detection

## What NOT to Claim

Never say: "We detected Sybil attackers", "These accounts are fake"

Always say: "Activity consistent with coordinated behavior", "Risk indicators exceeded thresholds"

This keeps the project legally safe, scientifically credible, and taken seriously by platforms.

## Detection Outputs

The app returns structured results for transparency and defensibility:

- **Cluster Results**: `clusterId`, `members` (list), `density` (internal edges / possible edges), `conductance` (external edges / internal edges), `externalEdges`.
- **Wave Results**: `windowStart`, `windowEnd`, `action`, `target`, `actors` (list), `zScore` (deviation from expected).
- **Actor Scorecard**: `sybilScore` (0-1), `churnScore`, `coordinationScore`, `noveltyScore`.
- **Evidence Pack**: "Why flagged" summary with top signals (e.g., "High churn: 8 unfollows in 1 hour; Part of cluster with 10 members").

### Confidence Levels

Each flagged entity is assigned a confidence tier:

- **Low**: Anomalous behavior detected, weak coordination evidence
- **Medium**: Multiple signals align (timing + churn or clustering)
- **High**: Dense clusters + strong temporal coordination

Confidence is derived from signal agreement, not score magnitude alone.

Outputs are risk flags, not accusations, to avoid doxxing.

## Scoring Model

Even heuristic-based, the model is explicit and configurable:

**SybilScore(actor) = 0.30 * coordinationScore + 0.20 * churnScore + 0.15 * clusterIsolationScore + 0.10 * newAccountScore + 0.10 * lowDiversityScore + 0.15 * profileAnomalyScore + 0.05 * sharedWalletScore + 0.05 * crossAppScore + 0.05 * sessionScore + 0.05 * fraudScore**

- **coordinationScore**: Fraction of actions in bursts (>10 in 5-min window).
- **churnScore**: Number of unfollow/unstar actions.
- **clusterIsolationScore**: 1 - (external connections / total connections).
- **newAccountScore**: 1 if account age < 7 days, else 0.
- **lowDiversityScore**: 1 - (unique targets / total actions).
- **profileAnomalyScore**: 1 if follower/following ratio < 0.1 or bio matches common spam patterns, or links to suspicious domains/shared links, else 0.
- **sharedWalletScore**: 1 if actor shares wallets with others, else 0.
- **crossAppScore**: 0.5 if actor active on multiple platforms, else 0.
- **sessionScore**: Min(sessionCount / 10, 1) for high session frequency.
- **fraudScore**: Transaction pattern anomaly score (0-1).

Thresholds (e.g., SybilScore > 0.6) are configurable per platform. Tune via environment variables.

## False Positive Mitigations

The system explicitly reduces false positives by:

- Ignoring clusters smaller than configurable thresholds
- Discounting long-lived accounts with diverse activity
- Down-weighting actions spread over long time windows
- Separating organic growth spikes from coordinated bursts
- Allowing per-platform threshold tuning

## Adversarial Considerations

Attackers may attempt to evade detection by:

- Spreading actions over longer windows
- Introducing noise via organic interactions
- Mixing real and fake accounts
- Reusing compromised aged accounts

Mitigations include adaptive windows, entropy measures, and cross-platform correlation.

## Graph Methods

Concrete algorithms for cluster and timing detection:

- **Cluster Discovery**: Connected components (for dense groups) or Louvain/Leiden modularity (for hierarchical clusters).
- **Group Tightness**: Triangle count or clustering coefficient (measures mutual connections).
- **Isolation**: Conductance or cut ratio (low external edges indicate farms).
- **Reciprocity**: Fraction of mutual follows/stars.
- **Temporal Bursts**: 5-min binning + z-score (deviation) or Poisson burst detection for waves.

Start with connected components + heuristics; expand to ML later.

## Evaluation & Benchmarks

To build trust and iterate:

- **Synthetic Generator**: Create fake Sybil clusters (e.g., 10 accounts mutually following, bursting on a target) + organic users.
- **Metrics**: Precision/recall on synthetic ground truth; false positive review rate (<5%).
- **Scenario Configs**: Save seeds for reproducibility (e.g., clusterSize=10, burstWindow=300s).

This enables fast iteration without real data risks.

## Privacy & Safety

- Data uploaded stays local (no server storage unless opted-in).
- No IP collection unless user provides logs.
- Outputs are "risk flags" for personal defense/reporting, not public accusations.
- Anonymized reporting to platforms (e.g., Base/Farcaster) via aggregated stats.

Protects users and the project.

## Integrations (Roadmap)

Planned concrete endpoints for real data:

- **GitHub**: REST API (stargazers, followers, events, user profiles for age/bio/follower counts). Rate limit handling. Optional GitHub App for private repos.
- **Base/Onchain**: RPC via Alchemy/QuickNode. Transfer graphs from ERC20 events. Funding-tree detection ("common funder" chains). Wallet profiles via ENS or onchain data.
- **Talent Protocol**: API for talent scores, endorsements, and builder networks. Sybil detection for decentralized talent verification.
- **Farcaster**: Hub API or Neynar. Follow/cast graphs. User profiles (bio, followers, created_at).

## Deployment & Storage

Suggested MVP architecture:

- **Blob Storage** (Vercel/Cloudflare): For CSV uploads and generated reports.
- **Postgres** (Neon/Supabase): Entities, runs, scores, audit trail.
- **Redis** (Upstash): Rate limits, job queues, caching.
- **Edge Config** (Vercel): Feature flags, thresholds (not data).

Deployable on Vercel for simplicity.

## Abuse Response Playbook

Since Sybil attacks are common:

- **Lock Repo Interactions**: Enable branch protection, require approvals.
- **Export Evidence**: CSV + JSON summary of flagged actors/clusters.
- **Report to Platform**: Anonymized patterns to GitHub/Base/Farcaster teams.
- **Evidence Pack Format**: Structured for platform reports.

## Screenshots / Demo

- Graph view: Interactive Cytoscape graph of interactions.
- Cluster report: List of suspicious clusters with members (see Sample Reports).
- Wave/timing chart: Bursts highlighted.
- Export evidence: Downloadable pack (JSON example above).

(Sample outputs provided above; add actual screenshots later.)

## Project Structure

- `/app`: Next.js routes (upload, results, API endpoints)
  - `page.tsx`: Landing / upload
  - `analyze/page.tsx`: Analysis results
  - `api/analyze/route.ts`: Main analysis endpoint
  - `api/github/route.ts`: GitHub fetcher
- `/lib`: Core logic
  - `ingest/`: Data ingestion (CSV, JSON, GitHub)
  - `graph/`: Graph building and clustering
  - `signals/`: Detection signals (timing, churn, etc.)
  - `scoring/`: Sybil score calculation
  - `evidence/`: Evidence generation
- `/components`: React components (Upload, GraphView, etc.)
- `/datasets`: Sample and synthetic data
- `/scripts`: Shell scripts for GitHub snapshots

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

### Running the App

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the app.

### Building for Production

```bash
npm run build
npm start
```

## Usage

1. Upload a CSV or JSON file with the required fields: timestamp, actor, target, action, platform.
   - Actions: follow, star, unfollow, unstar, etc.
   - Platforms: github, farcaster, binance, etc.
2. Click "Start Analysis" to process the data.
3. View the interaction graph.
4. See detected suspicious clusters, coordinated waves, and high-churn actors.
5. Export evidence pack as JSON.

A sample CSV file `sample_logs.csv` is provided for testing.

## Sample Reports

The app generates structured JSON reports for clusters, waves, actor scorecards, and evidence packs. Below are examples based on the sample data.

### Example Cluster Results

```json
[
  {
    "clusterId": 1,
    "members": ["user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9", "user10"],
    "density": 0.2,
    "conductance": 0.8,
    "externalEdges": 2
  }
]
```

### Example Wave Results

```json
[
  {
    "windowStart": "2023-01-01T10:19:00Z",
    "windowEnd": "2023-01-01T10:27:00Z",
    "action": "unfollow",
    "target": "user3",
    "actors": ["user1", "user2", "user4", "user5", "user6", "user7", "user8", "user9", "user10"],
    "zScore": 3.5
  }
]
```

### Example Actor Scorecard

```json
{
  "user1": {
    "sybilScore": 0.75,
    "churnScore": 0.8,
    "coordinationScore": 0.9,
    "noveltyScore": 0.1,
    "sharedWallets": ["0x123...", "0x456..."],
    "crossAppPlatforms": ["telegram", "twitter"],
    "sessionCount": 12,
    "fraudTxScore": 0.3,
    "confidence": "High"
  }
}
```

### Example Evidence Pack (JSON Export)

```json
{
  "summary": "High-confidence Sybil cluster detected with coordinated unfollow wave.",
  "clusters": [...],
  "waves": [...],
  "scorecards": {...},
  "exportedAt": "2023-01-01T12:00:00Z"
}
```

These reports can be exported as JSON for further analysis or reporting to platforms.

## Technologies Used

- Next.js 16.1.6
- React 19.2.3
- TypeScript
- Tailwind CSS
- Cytoscape.js for graph visualization
- PapaParse for CSV parsing
- Web Workers for performance
- IndexedDB for local storage

## Future Improvements

- Integrate Python backend for advanced analysis (networkx, pandas).
- Add ML models (LightGBM on subgraphs).
- Support real API integrations (GitHub, Base, Binance).
- Enhance mini-app integrations (Telegram, Discord bots).
- Anonymized reporting to platforms.

## References

- [Sybil Attack - Wikipedia](https://en.wikipedia.org/wiki/Sybil_attack)
- Yu et al. (2008). SybilGuard: defending against sybil attacks via social networks.
- Cao et al. (2012). Aiding the detection of fake accounts in large scale social online services.
- Arbitrum Sybil Detection
- TrustaLabs Airdrop Sybil Identification

## Future Enhancements

Based on ongoing development, here are prioritized suggestions for expanding Sybil Shield's capabilities:

### Advanced Analytics
- **Time-Series Anomaly Detection**: Statistical models (e.g., ARIMA) for unusual activity spikes.
- **Action Sequence Mining**: Markov chains for detecting scripted bot patterns.
- **Graph Embeddings**: node2vec for similarity-based clustering.
- **Community Detection**: Louvain/Leiden algorithms for hierarchical Sybil structures.

### Machine Learning
- **Unsupervised Anomaly Scoring**: Autoencoders for deviation detection.
- **Supervised Classification**: User-labeled datasets for custom models.
- **Explainable AI**: LIME/SHAP for ML prediction explanations.

### Onchain Features
- **Funding Tree Analysis**: Trace common funders in blockchain logs.
- **Token Flow Graphs**: Directed graphs for transfer patterns.
- **Gas Fee Anomalies**: Detect bots via transaction costs.

### Cross-Platform
- **Fuzzy Identity Matching**: Link similar handles across platforms.
- **Multi-Platform Waves**: Coordinated attacks spanning services.

### Performance & UX
- **Incremental Analysis**: Re-analyze new data without full recomputation.
- **Real-Time Alerts**: Notifications for high-risk detections.
- **Custom Dashboards**: Personalized metric views.

### Integrations
- **API Connectors**: Real endpoints for Base, Farcaster, Talent.
- **Plugin System**: Custom signal extensions.
- **Webhook Notifications**: External alerts.

For implementation, follow the Suggestion Workflow: design, implement, test, document, deploy.

## License

MIT
