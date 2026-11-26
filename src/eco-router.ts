import { type DataClassification } from './risk-policy.js';

export type TaskComplexity = 'boilerplate' | 'grep' | 'lint' | 'balanced' | 'complex' | 'architecture' | 'security';

export interface TaskProfile {
  readonly complexity?: TaskComplexity | string;
  readonly taskFamily?: string;
  readonly estimatedTokens?: number;
  readonly requiresReasoning?: boolean;
}

export interface BudgetConfig {
  readonly dailyTokenLimit: number;
  readonly dailyTokensUsed: number;
  readonly maxTokensPerRequest?: number;
}

export interface RouteClassification {
  readonly dataClassification: DataClassification;
  readonly airGapped?: boolean;
}

export interface ModelTier {
  readonly id: string;
  readonly name: string;
  readonly provider: 'local' | 'groq' | 'google' | 'openrouter' | 'anthropic' | 'openai';
  readonly tier: 'free_local' | 'free_cloud' | 'balanced' | 'premium';
  readonly costPer1kInputTokensUsd: number;
  readonly isLocal: boolean;
}

export const KNOWN_MODELS: readonly ModelTier[] = Object.freeze([
  // Local / Free air-gapped
  {
    id: 'ollama/llama3.2:3b',
    name: 'Ollama LLaMA 3.2 3B (Local)',
    provider: 'local',
    tier: 'free_local',
    costPer1kInputTokensUsd: 0,
    isLocal: true,
  },
  {
    id: 'groq/llama-3.1-8b-instant',
    name: 'Groq LLaMA 3.1 8B Instant (Free Tier)',
    provider: 'groq',
    tier: 'free_cloud',
    costPer1kInputTokensUsd: 0,
    isLocal: false,
  },
  {
    id: 'google/gemini-2.0-flash-exp:free',
    name: 'Google Gemini 2.0 Flash (Free)',
    provider: 'google',
    tier: 'free_cloud',
    costPer1kInputTokensUsd: 0,
    isLocal: false,
  },
  {
    id: 'openrouter/auto:free',
    name: 'OpenRouter Free Gateway',
    provider: 'openrouter',
    tier: 'free_cloud',
    costPer1kInputTokensUsd: 0,
    isLocal: false,
  },
  {
    id: 'google/gemini-1.5-pro',
    name: 'Google Gemini 1.5 Pro',
    provider: 'google',
    tier: 'balanced',
    costPer1kInputTokensUsd: 0.00125,
    isLocal: false,
  },
  {
    id: 'anthropic/claude-3-5-sonnet',
    name: 'Claude 3.5 Sonnet',
    provider: 'anthropic',
    tier: 'premium',
    costPer1kInputTokensUsd: 0.003,
    isLocal: false,
  },
  {
    id: 'openai/o3-mini',
    name: 'OpenAI o3-mini',
    provider: 'openai',
    tier: 'premium',
    costPer1kInputTokensUsd: 0.0011,
    isLocal: false,
  },
]);

export interface EcoRouteDecision {
  readonly modelId: string;
  readonly provider: string;
  readonly tier: 'free_local' | 'free_cloud' | 'balanced' | 'premium';
  readonly isLocal: boolean;
  readonly quotaRemainingTokens: number;
  readonly budgetExceeded: boolean;
  readonly fallbackApplied: boolean;
  readonly reason: string;
}

export function selectEcoModel(
  taskProfile: TaskProfile,
  budgets: BudgetConfig,
  classification: RouteClassification
): EcoRouteDecision {
  const isLocalOnly =
    classification.dataClassification === 'local_only' || Boolean(classification.airGapped);

  const estimatedTokens = Math.max(0, taskProfile.estimatedTokens ?? 1000);
  const remainingBudget = Math.max(0, budgets.dailyTokenLimit - budgets.dailyTokensUsed);
  const budgetExceeded = budgets.dailyTokensUsed + estimatedTokens > budgets.dailyTokenLimit;

  // Rule 1: local_only air-gap MUST ONLY route to isLocal models
  if (isLocalOnly) {
    return {
      modelId: 'ollama/llama3.2:3b',
      provider: 'local',
      tier: 'free_local',
      isLocal: true,
      quotaRemainingTokens: remainingBudget,
      budgetExceeded,
      fallbackApplied: false,
      reason: 'Enforced local_only air-gap: routed to local Ollama runtime.',
    };
  }

  // Rule 2: If daily budget is exhausted or exceeded, fallback to free tier models
  if (budgetExceeded || remainingBudget <= 0) {
    // If complex/architecture or requires reasoning, route to Gemini Free / OpenRouter Free
    const complexity = (taskProfile.complexity ?? '').toLowerCase();
    const needsReasoning =
      taskProfile.requiresReasoning ||
      complexity === 'complex' ||
      complexity === 'architecture' ||
      complexity === 'security';

    if (needsReasoning) {
      return {
        modelId: 'google/gemini-2.0-flash-exp:free',
        provider: 'google',
        tier: 'free_cloud',
        isLocal: false,
        quotaRemainingTokens: 0,
        budgetExceeded: true,
        fallbackApplied: true,
        reason: 'Daily token ceiling reached: falling back to Gemini Free for reasoning task.',
      };
    }

    return {
      modelId: 'groq/llama-3.1-8b-instant',
      provider: 'groq',
      tier: 'free_cloud',
      isLocal: false,
      quotaRemainingTokens: 0,
      budgetExceeded: true,
      fallbackApplied: true,
      reason: 'Daily token ceiling reached: falling back to free Groq fast tier.',
    };
  }

  // Rule 3: Routing according to task complexity
  const rawComplexity = (taskProfile.complexity ?? 'balanced').toLowerCase();

  // Tier A: Boilerplate, grep, lint -> local Ollama or free Groq
  if (rawComplexity === 'boilerplate' || rawComplexity === 'grep' || rawComplexity === 'lint') {
    return {
      modelId: 'groq/llama-3.1-8b-instant',
      provider: 'groq',
      tier: 'free_cloud',
      isLocal: false,
      quotaRemainingTokens: remainingBudget - estimatedTokens,
      budgetExceeded: false,
      fallbackApplied: false,
      reason: `Low complexity (${rawComplexity}): routed to high-throughput free Groq tier.`,
    };
  }

  // Tier B: Complex architecture or security -> top-tier premium models
  if (
    rawComplexity === 'complex' ||
    rawComplexity === 'architecture' ||
    rawComplexity === 'security'
  ) {
    return {
      modelId: 'anthropic/claude-3-5-sonnet',
      provider: 'anthropic',
      tier: 'premium',
      isLocal: false,
      quotaRemainingTokens: remainingBudget - estimatedTokens,
      budgetExceeded: false,
      fallbackApplied: false,
      reason: `High complexity (${rawComplexity}): routed to Claude 3.5 Sonnet.`,
    };
  }

  // Tier C: Balanced work -> Gemini Free or OpenRouter :free or balanced tier
  return {
    modelId: 'google/gemini-2.0-flash-exp:free',
    provider: 'google',
    tier: 'free_cloud',
    isLocal: false,
    quotaRemainingTokens: remainingBudget - estimatedTokens,
    budgetExceeded: false,
    fallbackApplied: false,
    reason: 'Balanced task profile: routed to Gemini Free tier.',
  };
}
