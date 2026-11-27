import { describe, expect, it } from 'bun:test';
import { EpisodeSleepEngine } from '../src/episode-sleep.js';

describe('EpisodeSleepEngine (Non-REM Sleep Consolidation)', () => {
  it('records episodes and persists active state', () => {
    const engine = new EpisodeSleepEngine();
    const ep = engine.recordEpisode({
      kind: 'pitfall',
      summary: 'Race condition when closing socket without flush',
      failurePattern: 'socket_unflushed_close',
      importanceBps: 7000,
      ownerFiles: ['src/net.ts'],
    });

    expect(ep.id).toBeDefined();
    expect(ep.status).toBe('active');
    expect(ep.importanceBps).toBe(7000);
    expect(engine.getEpisode(ep.id)).toEqual(ep);
  });

  it('decays low-importance, low-access episodes during sleep', () => {
    const engine = new EpisodeSleepEngine({ decayThresholdBps: 4000 });
    const epLow = engine.recordEpisode({
      kind: 'failure',
      summary: 'Minor typo in comment',
      failurePattern: 'comment_typo',
      importanceBps: 2000,
    });
    const epHigh = engine.recordEpisode({
      kind: 'failure',
      summary: 'Database connection pool starvation',
      failurePattern: 'pool_starvation',
      importanceBps: 8000,
    });

    const report = engine.runSleepConsolidation();
    expect(report.decayedCount).toBe(1);
    expect(engine.getEpisode(epLow.id)?.status).toBe('decayed');
    expect(engine.getEpisode(epHigh.id)?.status).toBe('active');
  });

  it('consolidates recurring failure patterns into invariants without weakening protected gates', () => {
    const engine = new EpisodeSleepEngine({ minClusterSize: 2 });
    engine.recordEpisode({
      kind: 'failure',
      summary: 'Uncaught rejection in async event loop',
      failurePattern: 'unhandled_async_rejection',
      importanceBps: 6000,
    });
    engine.recordEpisode({
      kind: 'failure',
      summary: 'Worker crashed on unhandled promise',
      failurePattern: 'unhandled_async_rejection',
      importanceBps: 6500,
    });

    // Episode with protected keyword must be guarded
    engine.recordEpisode({
      kind: 'failure',
      summary: 'Bypass R3 gate for performance',
      failurePattern: 'bypass_r3_gate',
      importanceBps: 9000,
    });
    engine.recordEpisode({
      kind: 'failure',
      summary: 'Disable R3 gate in test',
      failurePattern: 'bypass_r3_gate',
      importanceBps: 9000,
    });

    const report = engine.runSleepConsolidation();
    expect(report.consolidatedClusters).toBe(1);
    expect(report.synthesizedInvariants.length).toBe(1);
    expect(report.synthesizedInvariants[0].ruleText).toContain('unhandled_async_rejection');
    expect(report.synthesizedInvariants.some((inv) => inv.ruleText.includes('bypass_r3_gate'))).toBe(false);
  });
});
