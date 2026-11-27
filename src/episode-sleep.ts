/**
 * Non-REM Episodic Memory & Pitfall Consolidation Engine (Zero-ORM).
 *
 * Implements offline sleep consolidation:
 * - Decays stale low-salience episodes reversibly
 * - Consolidates recurring failure patterns into learned semantic invariants
 * - Synthesizes invariant rule proposals while strictly forbidding protected gate weakening
 */

import { createHash } from 'node:crypto';

export type EpisodeKind = 'failure' | 'fix' | 'learned' | 'pitfall';

export interface Episode {
  readonly id: string;
  readonly kind: EpisodeKind;
  readonly summary: string;
  readonly failurePattern: string;
  readonly ownerFiles: readonly string[];
  readonly importanceBps: number; // 0..10000 (basis points)
  readonly accessCount: number;
  readonly status: 'active' | 'decayed' | 'consolidated';
  readonly createdAt: string;
  readonly lastAccessedAt?: string;
}

export interface InvariantProposal {
  readonly ruleId: string;
  readonly ruleText: string;
  readonly derivedFromEpisodes: readonly string[];
  readonly confidence: number;
  readonly automatedPromotionAllowed: false;
  readonly status: 'proposed';
}

export interface ConsolidationReport {
  readonly processedEpisodes: number;
  readonly decayedCount: number;
  readonly consolidatedClusters: number;
  readonly synthesizedInvariants: readonly InvariantProposal[];
}

export interface SleepConsolidationOptions {
  readonly decayThresholdBps?: number;
  readonly minClusterSize?: number;
  readonly protectedGateKeywords?: readonly string[];
}

const DEFAULT_DECAY_THRESHOLD_BPS = 3000;
const DEFAULT_MIN_CLUSTER_SIZE = 2;
const DEFAULT_PROTECTED_GATES = [
  'R0', 'R1', 'R2', 'R3', 'R4', 'zero-orm', 'air-gap', 'bypass', 'disable'
] as const;

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

export class EpisodeSleepEngine {
  private readonly episodes: Map<string, Episode> = new Map();
  private readonly decayThreshold: number;
  private readonly minClusterSize: number;
  private readonly protectedKeywords: readonly string[];

  constructor(options?: SleepConsolidationOptions) {
    this.decayThreshold = options?.decayThresholdBps ?? DEFAULT_DECAY_THRESHOLD_BPS;
    this.minClusterSize = options?.minClusterSize ?? DEFAULT_MIN_CLUSTER_SIZE;
    this.protectedKeywords = options?.protectedGateKeywords ?? DEFAULT_PROTECTED_GATES;
  }

  public recordEpisode(params: {
    readonly kind: EpisodeKind;
    readonly summary: string;
    readonly failurePattern: string;
    readonly ownerFiles?: readonly string[];
    readonly importanceBps?: number;
  }): Episode {
    const id = sha256(`${params.kind}:${params.failurePattern}:${params.summary}`).slice(0, 16);
    const episode: Episode = {
      id,
      kind: params.kind,
      summary: params.summary.trim(),
      failurePattern: params.failurePattern.trim().toLowerCase(),
      ownerFiles: params.ownerFiles ? Object.freeze([...params.ownerFiles]) : Object.freeze([]),
      importanceBps: Math.max(0, Math.min(10000, params.importanceBps ?? 5000)),
      accessCount: 1,
      status: 'active',
      createdAt: new Date().toISOString(),
    };
    this.episodes.set(id, episode);
    return episode;
  }

  public getEpisode(id: string): Episode | undefined {
    return this.episodes.get(id);
  }

  public listEpisodes(status?: Episode['status']): readonly Episode[] {
    const all = Array.from(this.episodes.values());
    if (!status) return all;
    return all.filter((e) => e.status === status);
  }

  /**
   * Run Non-REM sleep consolidation over stored episodes.
   */
  public runSleepConsolidation(): ConsolidationReport {
    let decayedCount = 0;
    const activeEpisodes: Episode[] = [];

    // 1. Decay pass
    for (const [id, ep] of this.episodes.entries()) {
      if (ep.status === 'decayed') continue;
      if (ep.importanceBps < this.decayThreshold && ep.accessCount <= 1) {
        this.episodes.set(id, { ...ep, status: 'decayed' });
        decayedCount++;
      } else {
        activeEpisodes.push(ep);
      }
    }

    // 2. Pattern clustering pass
    const clusters: Map<string, Episode[]> = new Map();
    for (const ep of activeEpisodes) {
      if (!ep.failurePattern) continue;
      const group = clusters.get(ep.failurePattern) ?? [];
      group.push(ep);
      clusters.set(ep.failurePattern, group);
    }

    const proposals: InvariantProposal[] = [];
    let consolidatedClusters = 0;

    for (const [pattern, group] of clusters.entries()) {
      if (group.length < this.minClusterSize) continue;

      // Fail-closed protection: check if proposal attempts to weaken protected surfaces
      const isWeakening = this.protectedKeywords.some((kw) => pattern.toLowerCase().includes(kw.toLowerCase()));
      if (isWeakening) {
        continue; // Disallow invariant proposal that weakens protected policies
      }

      consolidatedClusters++;
      const ruleId = `inv_${sha256(pattern).slice(0, 12)}`;
      const proposal: InvariantProposal = Object.freeze({
        ruleId,
        ruleText: `Never recur failure pattern: ${pattern} (observed across ${group.length} episodes)`,
        derivedFromEpisodes: Object.freeze(group.map((e) => e.id)),
        confidence: Math.min(1.0, 0.5 + group.length * 0.15),
        automatedPromotionAllowed: false as const,
        status: 'proposed' as const,
      });
      proposals.push(proposal);

      // Mark episodes as consolidated
      for (const member of group) {
        this.episodes.set(member.id, { ...member, status: 'consolidated' });
      }
    }

    return {
      processedEpisodes: this.episodes.size,
      decayedCount,
      consolidatedClusters,
      synthesizedInvariants: Object.freeze(proposals),
    };
  }
}
