import { describe, expect, it } from 'bun:test';
import { selectEcoModel, type BudgetConfig, type RouteClassification, type TaskProfile } from '../src/eco-router.js';

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
