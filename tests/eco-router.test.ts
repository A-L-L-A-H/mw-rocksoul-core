import { describe, expect, it } from 'bun:test';
import {
  escalateModelTier,
  ESCALATION_LADDER,
  selectEcoModel,
  type BudgetConfig,
  type RouteClassification,
  type TaskProfile,
} from '../src/eco-router.js';

describe('Eco-Quota Model Router', () => {
  const healthyBudgets: BudgetConfig = {
    dailyTokenLimit: 1_000_000,
    dailyTokensUsed: 50_000,
    maxTokensPerRequest: 16_000,
  };

  const exhaustedBudgets: BudgetConfig = {
    dailyTokenLimit: 100_000,
    dailyTokensUsed: 100_000,
    maxTokensPerRequest: 8_000,
  };

  it('strictly enforces local_only air-gap regardless of budget or complexity', () => {
    const localClass: RouteClassification = { dataClassification: 'local_only', airGapped: true };

    const task: TaskProfile = {
      complexity: 'architecture',
      estimatedTokens: 5000,
      requiresReasoning: true,
    };

    const decision = selectEcoModel(task, healthyBudgets, localClass);
    expect(decision.isLocal).toBe(true);
    expect(decision.provider).toBe('local');
    expect(decision.modelId).toBe('ollama/llama3.2:3b');
    expect(decision.tier).toBe('free_local');
    expect(decision.reason).toContain('air-gap');
  });

  it('routes boilerplate, grep, and lint to free fast tier (groq)', () => {
    const classification: RouteClassification = { dataClassification: 'cloud_eligible', airGapped: false };

    const boilerplateTask: TaskProfile = { complexity: 'boilerplate', estimatedTokens: 500 };
    const grepTask: TaskProfile = { complexity: 'grep', estimatedTokens: 300 };
    const lintTask: TaskProfile = { complexity: 'lint', estimatedTokens: 400 };

    for (const task of [boilerplateTask, grepTask, lintTask]) {
      const decision = selectEcoModel(task, healthyBudgets, classification);
      expect(decision.isLocal).toBe(false);
      expect(decision.tier).toBe('free_cloud');
      expect(decision.provider).toBe('groq');
      expect(decision.modelId).toBe('groq/llama-3.1-8b-instant');
      expect(decision.fallbackApplied).toBe(false);
    }
  });

  it('routes balanced work to Gemini free tier', () => {
    const classification: RouteClassification = { dataClassification: 'cloud_eligible', airGapped: false };
    const balancedTask: TaskProfile = { complexity: 'balanced', estimatedTokens: 2000 };

    const decision = selectEcoModel(balancedTask, healthyBudgets, classification);
    expect(decision.tier).toBe('free_cloud');
    expect(decision.provider).toBe('google');
    expect(decision.modelId).toBe('google/gemini-2.0-flash-exp:free');
    expect(decision.budgetExceeded).toBe(false);
  });

  it('routes complex architecture and security tasks to top-tier premium models', () => {
    const classification: RouteClassification = { dataClassification: 'cloud_eligible', airGapped: false };

    const archTask: TaskProfile = { complexity: 'architecture', estimatedTokens: 4000 };
    const secTask: TaskProfile = { complexity: 'security', estimatedTokens: 3500 };
    const complexTask: TaskProfile = { complexity: 'complex', estimatedTokens: 4500 };

    for (const task of [archTask, secTask, complexTask]) {
      const decision = selectEcoModel(task, healthyBudgets, classification);
      expect(decision.tier).toBe('premium');
      expect(decision.provider).toBe('anthropic');
      expect(decision.modelId).toBe('anthropic/claude-3-5-sonnet');
      expect(decision.budgetExceeded).toBe(false);
    }
  });

  it('enforces daily token ceilings with deterministic fallback when budget is exhausted', () => {
    const classification: RouteClassification = { dataClassification: 'cloud_eligible', airGapped: false };

    // Complex task when budget exhausted -> fallback to Gemini Free
    const archTask: TaskProfile = { complexity: 'architecture', estimatedTokens: 4000 };
    const decisionArch = selectEcoModel(archTask, exhaustedBudgets, classification);
    expect(decisionArch.budgetExceeded).toBe(true);
    expect(decisionArch.fallbackApplied).toBe(true);
    expect(decisionArch.modelId).toBe('google/gemini-2.0-flash-exp:free');

    // Standard task when budget exhausted -> fallback to Groq Free
    const simpleTask: TaskProfile = { complexity: 'boilerplate', estimatedTokens: 500 };
    const decisionSimple = selectEcoModel(simpleTask, exhaustedBudgets, classification);
    expect(decisionSimple.budgetExceeded).toBe(true);
    expect(decisionSimple.fallbackApplied).toBe(true);
    expect(decisionSimple.modelId).toBe('groq/llama-3.1-8b-instant');
  });
});

describe('V40 Episode-Driven Model Tier Escalator (flash -> neon -> argon)', () => {
  it('stays on flash when no failure or complexity escalation triggers are met', () => {
    expect(ESCALATION_LADDER).toEqual(['flash', 'neon', 'argon']);
    const decision = escalateModelTier({ recentFailures: 0, complexity: 'boilerplate', riskLevel: 'low' });
    expect(decision.previousTier).toBe('flash');
    expect(decision.targetTier).toBe('flash');
    expect(decision.escalated).toBe(false);
    expect(decision.stepsEscalated).toBe(0);
    expect(decision.modelHint).toBe('gemini-3.8-flash-low');
  });

  it('escalates flash -> neon on initial episode failure or complex/high-risk task', () => {
    const byFailure = escalateModelTier({ recentFailures: 1, complexity: 'balanced' });
    expect(byFailure.targetTier).toBe('neon');
    expect(byFailure.escalated).toBe(true);
    expect(byFailure.stepsEscalated).toBe(1);
    expect(byFailure.modelHint).toBe('gemini-4-neon-low');

    const byComplexity = escalateModelTier({ recentFailures: 0, complexity: 'complex' });
    expect(byComplexity.targetTier).toBe('neon');
    expect(byComplexity.escalated).toBe(true);
  });

  it('escalates neon -> argon on repeated failure or starting from neon with a failure', () => {
    const fromNeon = escalateModelTier({ recentFailures: 1 }, { startingTier: 'neon' });
    expect(fromNeon.previousTier).toBe('neon');
    expect(fromNeon.targetTier).toBe('argon');
    expect(fromNeon.escalated).toBe(true);
    expect(fromNeon.stepsEscalated).toBe(1);
    expect(fromNeon.modelHint).toBe('gemini-4-argon-low');

    const byThreshold = escalateModelTier({ recentFailures: 3, complexity: 'balanced' });
    expect(byThreshold.previousTier).toBe('flash');
    expect(byThreshold.targetTier).toBe('argon');
    expect(byThreshold.stepsEscalated).toBe(2);
  });

  it('escalates directly to argon for architecture, security, or critical risk', () => {
    const bySecurity = escalateModelTier({ recentFailures: 0, complexity: 'security' });
    expect(bySecurity.targetTier).toBe('argon');
    expect(bySecurity.escalated).toBe(true);

    const byCriticalRisk = escalateModelTier({ recentFailures: 0, riskLevel: 'critical' });
    expect(byCriticalRisk.targetTier).toBe('argon');
    expect(byCriticalRisk.escalated).toBe(true);
  });

  it('escalates based on recurring episodic pitfalls and never downgrades from argon', () => {
    const pitfallOnly = escalateModelTier({ recentFailures: 0, recurringPitfallCount: 2 });
    expect(pitfallOnly.targetTier).toBe('neon');

    const pitfallAndFailure = escalateModelTier({ recentFailures: 1, recurringPitfallCount: 2 });
    expect(pitfallAndFailure.targetTier).toBe('argon');

    const stayArgon = escalateModelTier({ recentFailures: 0, complexity: 'lint' }, { startingTier: 'argon' });
    expect(stayArgon.targetTier).toBe('argon');
    expect(stayArgon.escalated).toBe(false);
    expect(stayArgon.stepsEscalated).toBe(0);
  });
});
