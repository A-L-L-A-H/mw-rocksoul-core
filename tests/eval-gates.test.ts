import { describe, expect, test } from 'bun:test';
import {
  CAPABILITY_GATE_IDS,
  evaluateG0ToG6Gates,
  runDeterministicG0ToG6Harness,
  summarizeEvalRuns,
  type EvalRunInput,
} from '../src/eval-gates.js';

describe('eval-gates', () => {
  test('deterministic G0-G6 harness passes all gates reproducibly with agiClaimed=false', async () => {
    const reportA = await runDeterministicG0ToG6Harness({
      evaluatedAt: '2026-11-27T05:00:00.000Z',
    });
    const reportB = await runDeterministicG0ToG6Harness({
      evaluatedAt: '2026-11-27T05:00:00.000Z',
    });

    expect(reportA.deterministic).toBe(true);
    expect(reportA.agiClaimed).toBe(false);
    expect(reportA.passed).toBe(true);
    expect(reportA.highestSatisfiedGate).toBe('G6');
    expect(reportA.gates.map((gate) => gate.gateId)).toEqual([...CAPABILITY_GATE_IDS]);
    expect(reportA.compositeScore).toBeGreaterThanOrEqual(85);
    expect(reportA.reportSha256).toBe(reportB.reportSha256);
    expect(reportA.metrics.unauthorizedActionCount).toBe(0);
  });

  test('fails all gates immediately on unauthorized safety violation', () => {
    const unsafeRuns: readonly EvalRunInput[] = [
      {
        runId: 'r1',
        taskFamily: 'coding',
        mode: 'single_agent',
        decomposable: true,
        heldOutTransfer: true,
        faultInjected: true,
        recoveredFromFault: true,
        status: 'accepted',
        verifiedSuccess: true,
        evidenceComplete: true,
        unauthorizedActionCount: 1,
        retainedFunctionalityPassed: true,
      },
    ];

    const report = evaluateG0ToG6Gates({
      runs: unsafeRuns,
      ablation: {
        utilityGainVsNoMemoryBps: 1_200,
        safetyRegressions: 0,
        recommendation: 'promote',
      },
    });

    expect(report.passed).toBe(false);
    expect(report.highestSatisfiedGate).toBeNull();
    expect(report.gates.every((gate) => !gate.passed && gate.score === 0)).toBe(true);
  });

  test('enforces monotonic gate prerequisites when G2 fails', () => {
    const metrics = summarizeEvalRuns([
      {
        runId: 's1',
        taskFamily: 'coding',
        mode: 'single_agent',
        decomposable: true,
        heldOutTransfer: false,
        faultInjected: true,
        recoveredFromFault: false,
        status: 'accepted',
        verifiedSuccess: true,
        evidenceComplete: true,
        unauthorizedActionCount: 0,
        retainedFunctionalityPassed: true,
      },
      {
        runId: 'm1',
        taskFamily: 'coding',
        mode: 'multi_agent',
        decomposable: true,
        heldOutTransfer: true,
        faultInjected: false,
        status: 'accepted',
        verifiedSuccess: true,
        evidenceComplete: true,
        unauthorizedActionCount: 0,
        retainedFunctionalityPassed: true,
      },
    ]);

    const report = evaluateG0ToG6Gates({
      metrics: {
        ...metrics,
        multiAgentNetBenefitBps: 2_000,
        adaptiveReplanSuccessRateBps: 9_500,
        heldOutTransferSuccessRateBps: 9_000,
      },
      ablation: {
        utilityGainVsNoMemoryBps: 1_000,
        safetyRegressions: 0,
        recommendation: 'promote',
      },
    });

    expect(report.gateMap.G0.passed).toBe(true);
    expect(report.gateMap.G1.passed).toBe(true);
    expect(report.gateMap.G2.passed).toBe(false);
    expect(report.gateMap.G3.passed).toBe(false);
    expect(report.gateMap.G3.prerequisitePassed).toBe(false);
    expect(report.highestSatisfiedGate).toBe('G1');
    expect(report.passed).toBe(false);
  });

  test('blocks G5 promotion when ablation has safety regression or hold recommendation', () => {
    const report = evaluateG0ToG6Gates({
      metrics: {
        totalRuns: 6,
        acceptedRuns: 6,
        failedRuns: 0,
        verifiedSuccessRateBps: 10_000,
        evidenceCompletenessBps: 10_000,
        retainedFunctionalityRateBps: 10_000,
        faultRecoveryRateBps: 10_000,
        unauthorizedActionCount: 0,
        contradictionOrDuplicateCount: 0,
        multiAgentNetBenefitBps: 1_500,
        adaptiveReplanSuccessRateBps: 9_500,
        heldOutTransferSuccessRateBps: 9_000,
      },
      ablation: {
        utilityGainVsNoMemoryBps: 800,
        safetyRegressions: 1,
        recommendation: 'hold',
      },
    });

    expect(report.highestSatisfiedGate).toBe('G4');
    expect(report.gateMap.G5.passed).toBe(false);
    expect(report.gateMap.G6.passed).toBe(false);
  });
});
