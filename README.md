# Sybil Shield

[![Build Status](https://github.com/yourusername/sybil-attack-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/sybil-attack-detection/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Next.js](https://img.shields.io/badge/Next.js-16.1.6-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)

## Demo Video

<img src="promo.gif" width="1200" alt="Sybil Shield Demo">

Full video available for download: [promo.mp4](promo.mp4)

Sybil Shield is a powerful, local-first Next.js application designed for detecting coordinated Sybil attacks, scammer patterns, and mini-app exploits across social, onchain, and mini-app ecosystems. Built for human review, it provides explainable evidence packs with "why flagged" reasons, empowering analysts to make informed decisions without automatic bans.

This tool excels at identifying hard-to-fake signals such as dense internal graphs, synchronized bursts (waves), low diversity behaviors, and reusable identity templates. Enhanced with mini-app specific detections, it uncovers shared wallets, cross-platform coordination, session anomalies, and fraudulent transaction patterns.

## Table of Contents

- [Features](#features)
- [Supported Platforms](#supported-platforms)
- [Quick Start](#quick-start)
- [Data Ingestion](#data-ingestion)
- [Usage Guide](#usage-guide)
- [Detection Signals](#detection-signals)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Local-First Architecture**: All analysis runs in the browser with IndexedDB storage for reviews and audit trails.
- **Explainable AI**: Every flag includes detailed "why flagged" reasons, avoiding black-box decisions.
- **Graph Visualization**: Interactive Cytoscape.js graphs for interaction networks and clusters.
- **Multi-Platform Support**: Handles GitHub, Farcaster, Talent Protocol, Base (onchain), Binance, X (Twitter), and custom platforms.
- **Mini-App Protections**: Specialized detections for shared wallets, cross-app linking, session anomalies, and fraudulent transactions.
- **Human-in-the-Loop**: Review mode for confirming/dismissing flags with notes and semi-supervised seed expansion.
- **Evidence Export**: Downloadable JSON packs for reporting and auditing.
- **Synthetic Data Generation**: Create test datasets for validation.
- **Rate-Limited APIs**: Secure URL imports and profile scans with SSRF protections.

## Supported Platforms

Sybil Shield supports detection across multiple platforms, with specific mappings for optimal results:

- **GitHub**: Stars, follows, forks, issues, PRs.
- **Farcaster**: Follows, likes, recasts, replies.
- **Talent Protocol**: Endorsements, scores.
- **Base (Onchain)**: Transfers, swaps, mints, approvals.
- **Binance**: Trades, buys, sells, transfers (crypto exchange activities).
- **X (Twitter)**: Follows, unfollows, likes, retweets, replies.
- **Mini-Apps**: Taps, claims, rewards, invites, purchases.
- **Custom**: Any platform normalized to the schema.

### Platform-Specific Data Fetching

- **GitHub**: Fetch stargazers via API (`app/api/fetch/github/route.ts`).
- **Farcaster**: Stub for Neynar API integration.
- **Talent Protocol**: Stub for talent scores.
- **Base**: Stub for RPC-based transfers.
- **Binance**: Planned API integration for trade logs (requires API key).
- **X (Twitter)**: Planned API integration for activity logs (requires API key).

## Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
git clone https://github.com/yourusername/sybil-attack-detection.git
cd sybil-attack-detection
npm install
```

### Running Locally

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to access the app.

### Optional Environment Variables

- `GITHUB_TOKEN`: Increases GitHub API rate limits.
- `BASE_RPC_URL`: For onchain data fetching.
- `BINANCE_API_KEY`: For Binance trade data (future).
- `TWITTER_BEARER_TOKEN`: For X (Twitter) data (future).

## Data Ingestion

### Upload CSV/JSON

Upload files with events. Required fields: `timestamp`, `platform`, `action`, `actor`, `target`.

### Import from URLs

Paste links containing data. Supports resolvers for GitHub, Gist, GitLab, Bitbucket, Google Drive, Dropbox, OneDrive, HuggingFace, Google Sheets, Pastebin.

### Scan Profile Pages

Provide profile URLs to auto-discover and ingest CSV/JSON data files.

### Fetch from Platforms

- GitHub: Enter `owner/repo` to fetch stargazers.
- Future: Binance and X integrations for direct API pulls.

## Event Schema

### Required Fields

- `timestamp` (ISO8601)
- `platform` (e.g., `github`, `farcaster`, `base`, `talent`, `binance`, `x`)
- `action` (e.g., `follow`, `star`, `transfer`, `trade`, `like`)
- `actor` (handle or wallet)
- `target` (user/repo/wallet/etc.)

### Optional Fields

- `amount`, `txHash`, `blockNumber`, `meta`, `actorCreatedAt`, `bio`, `links`, `followerCount`, `followingCount`, `verified`, `location`, `targetType`

## Usage Guide

1. **Ingest Data**: Upload files, import URLs, scan profiles, or fetch from platforms.
2. **Configure Analysis**: Adjust thresholds and settings.
3. **Run Analysis**: Process data with clustering, waves, and scoring.
4. **Review Results**: Explore graphs, clusters, waves, and actor scorecards.
5. **Export Evidence**: Download JSON packs for reporting.

## Detection Signals

### Core Signals

- **Clusters**: Dense groups with low external connectivity.
- **Waves**: Coordinated bursts in time bins.
- **Churn**: High unfollow/unstar rates.
- **Low Diversity**: Concentrated actions on few targets.
- **Profile Anomalies**: Suspicious domains, shared links, handle patterns.

### Mini-App Specific

- **Shared Wallets**: Actors using common addresses.
- **Cross-App Linking**: Multi-platform activity.
- **Session Anomalies**: Frequent short sessions.
- **Fraudulent Transactions**: Unusual amount patterns.

### Platform Additions

- **Binance**: Wash trading detection via repeated counterparty patterns.
- **X (Twitter)**: Brigading and astroturfing via synchronized likes/retweets.

## API Endpoints

- `/api/fetch/github`: GitHub stargazer fetch.
- `/api/fetch/base`: Base transfer fetch (stub).
- `/api/fetch/farcaster`: Farcaster data (stub).
- `/api/fetch/talent`: Talent scores (stub).
- `/api/fetch/binance`: Binance trades (planned).
- `/api/fetch/x`: X activity (planned).
- `/api/import/url`: URL-based imports.
- `/api/scan/profile`: Profile scanning.
- `/api/generate/synthetic`: Synthetic data creation.

## Project Structure

- `app/`: Next.js pages and API routes.
- `lib/`: Core logic (analyze.ts, profile.ts, scam.ts, etc.).
- `public/`: Static assets.
- `scripts/`: Utility scripts for snapshots.

## Contributing

Contributions welcome! See issues for roadmap items like ML enhancements, new platform integrations, and performance optimizations.

## License

MIT License. See LICENSE for details.

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
- Same handle across platforms (e.g., `github:alice`, `x:alice` — `twitter:*` is treated as alias)
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

## Related coordinated abuse (beyond “Sybil”)

In the wild, “Sybil” often overlaps with other coordinated abuse. Sybil Shield is built to surface these patterns as **signals**, not to auto-ban.

- **Sockpuppeting / multi-accounting**: one operator runs many accounts for influence. Signals: controller groups, shared links/domains, shared funders, same-target similarity.
- **Brigading / coordinated harassment**: many accounts target one user/repo in a short time. Signals: waves (bin + sliding window), high churn against a target, low diversity.
- **Astroturfing / fake engagement**: staged “organic” activity. Signals: repeated sequences, low entropy, unnatural circadian patterns, reciprocity anomalies.
- **Airdrop farming / wallet farms**: clusters of wallets farming rewards. Signals: common funders, transfer bursts, identical behavior patterns.
- **Wash trading / fake volume** (marketplace contexts): repeated counterparty patterns and bursts. Signals: tight clusters, repeated sequences, rapid velocity, target overlap.
- **Phishing / wallet drainer campaigns**: many accounts promote the same malicious endpoints. Signals: suspicious/typosquat domains, shared links, phishing-like URL heuristics.

## Platform-specific mapping (how to model your logs)

You get best results when you normalize actions per platform into the same schema:

- **GitHub**: `star`, `unstar`, `follow`, `unfollow`, `fork`, `issue`, `pr`
- **Farcaster / social**: `follow`, `unfollow`, `like`, `recast`, `reply`
- **Mini-apps (Telegram/Web3 games)**: `tap`, `claim`, `reward`, `invite`, `join`, `purchase`
- **Onchain (Base/EVM)**: `transfer`, `swap`, `mint`, `approve` (include `txHash`, `amount`, `meta.chainId` when possible)

If your action names differ, update **Analysis → Positive actions / Churn actions** so the graph and churn signals align.

## Security hardening

- API routes use **rate limiting** and **SSRF protections** (blocks localhost/private IPs for URL imports/scans).
- The app ships common **security headers** (CSP, COOP/CORP, HSTS, etc.) via `next.config.ts`.

## CI (GitHub Actions)

This repo includes a basic CI workflow that runs `npm ci`, `npm run lint`, and `npm run build` on PRs and pushes to `main`.

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


