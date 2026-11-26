export type DagNodeStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

export type DagRiskTier = 'R0' | 'R1' | 'R2' | 'R3' | 'R4';

export interface DagNodeDefinition<TData = unknown> {
  readonly id: string;
  readonly dependencies?: readonly string[];
  readonly owner?: string;
  readonly ownedPaths?: readonly string[];
  readonly riskTier?: DagRiskTier;
  readonly data?: TData;
}

export interface DagNodeState<TData = unknown> {
  readonly id: string;
  readonly status: DagNodeStatus;
  readonly dependencies: readonly string[];
  readonly owner?: string;
  readonly ownedPaths?: readonly string[];
  readonly riskTier?: DagRiskTier;
  readonly data?: TData;
  readonly output?: unknown;
  readonly error?: string;
  readonly startedAt?: string;
  readonly completedAt?: string;
}

export interface DagExecutionState<TData = unknown> {
  readonly nodes: Readonly<Record<string, DagNodeState<TData>>>;
  readonly order: readonly string[];
}

export type DagValidationErrorCode =
  | 'CYCLE_DETECTED'
  | 'MISSING_DEPENDENCY'
  | 'DUPLICATE_NODE'
  | 'EMPTY_DAG'
  | 'INVALID_NODE_ID'
  | 'SELF_DEPENDENCY'
  | 'INVALID_TRANSITION';

export interface DagPlanError {
  readonly code: DagValidationErrorCode;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export interface DagPlanValidationResult {
  readonly valid: boolean;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly topologicalOrder: readonly string[];
  readonly waves: readonly (readonly string[])[];
  readonly criticalPathLength: number;
  readonly cycles: readonly (readonly string[])[];
  readonly errors: readonly DagPlanError[];
}

export class DagValidationError extends Error {
  readonly code: DagValidationErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: DagValidationErrorCode,
    message: string,
    details?: Readonly<Record<string, unknown>>
  ) {
    super(message);
    this.name = 'DagValidationError';
    this.code = code;
    this.details = details;
  }
}

function compareAscii(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function uniqueSortedDeps(deps: readonly string[] | undefined): string[] {
  if (!deps || deps.length === 0) return [];
  return [...new Set(deps)].sort(compareAscii);
}

export function detectDagCycles(nodes: readonly DagNodeDefinition[]): string[][] {
  const adjacency = new Map<string, string[]>();
  const nodeIds = new Set<string>();

  for (const node of nodes) {
    nodeIds.add(node.id);
    if (!adjacency.has(node.id)) {
      adjacency.set(node.id, []);
    }
  }

  for (const node of nodes) {
    for (const dep of uniqueSortedDeps(node.dependencies)) {
      if (nodeIds.has(dep)) {
        const list = adjacency.get(dep);
        if (list) {
          list.push(node.id);
        }
      }
    }
  }

  const visitState = new Map<string, 'unvisited' | 'visiting' | 'visited'>();
  for (const id of nodeIds) {
    visitState.set(id, 'unvisited');
  }

  const cycles: string[][] = [];
  const stack: string[] = [];

  const dfs = (id: string): void => {
    visitState.set(id, 'visiting');
    stack.push(id);
    const neighbors = [...(adjacency.get(id) ?? [])].sort(compareAscii);
    for (const next of neighbors) {
      const nextState = visitState.get(next);
      if (nextState === 'visiting') {
        const startIdx = stack.indexOf(next);
        if (startIdx >= 0) {
          cycles.push([...stack.slice(startIdx), next]);
        }
      } else if (nextState === 'unvisited') {
        dfs(next);
      }
    }
    stack.pop();
    visitState.set(id, 'visited');
  };

  for (const id of [...nodeIds].sort(compareAscii)) {
    if (visitState.get(id) === 'unvisited') {
      dfs(id);
    }
  }

  return cycles;
}

export function topologicalSortDag(nodes: readonly DagNodeDefinition[]): string[] {
  if (nodes.length === 0) {
    throw new DagValidationError('EMPTY_DAG', 'DAG must contain at least one node.');
  }

  const nodeMap = new Map<string, DagNodeDefinition>();
  for (const node of nodes) {
    if (typeof node.id !== 'string' || node.id.trim().length === 0) {
      throw new DagValidationError('INVALID_NODE_ID', 'DAG node id must be a non-empty string.');
    }
    if (nodeMap.has(node.id)) {
      throw new DagValidationError('DUPLICATE_NODE', `Duplicate DAG node id: ${node.id}`, {
        nodeId: node.id,
      });
    }
    nodeMap.set(node.id, node);
  }

  const inDegree = new Map<string, number>();
  const dependents = new Map<string, string[]>();
  for (const node of nodes) {
    inDegree.set(node.id, 0);
    dependents.set(node.id, []);
  }

  for (const node of nodes) {
    const deps = uniqueSortedDeps(node.dependencies);
    for (const dep of deps) {
      if (dep === node.id) {
        throw new DagValidationError(
          'SELF_DEPENDENCY',
          `Node "${node.id}" cannot depend on itself.`,
          { nodeId: node.id }
        );
      }
      if (!nodeMap.has(dep)) {
        throw new DagValidationError(
          'MISSING_DEPENDENCY',
          `Node "${node.id}" depends on unknown node "${dep}".`,
          { nodeId: node.id, dependencyId: dep }
        );
      }
      const depList = dependents.get(dep);
      if (depList) {
        depList.push(node.id);
      }
      inDegree.set(node.id, (inDegree.get(node.id) ?? 0) + 1);
    }
  }

  const ready: string[] = [];
  for (const [id, degree] of inDegree.entries()) {
    if (degree === 0) {
      ready.push(id);
    }
  }
  ready.sort(compareAscii);

  const order: string[] = [];
  while (ready.length > 0) {
    const current = ready.shift();
    if (current === undefined) {
      break;
    }
    order.push(current);
    const nextNodes = dependents.get(current) ?? [];
    for (const dependentId of nextNodes) {
      const nextDegree = (inDegree.get(dependentId) ?? 0) - 1;
      inDegree.set(dependentId, nextDegree);
      if (nextDegree === 0) {
        ready.push(dependentId);
      }
    }
    ready.sort(compareAscii);
  }

  if (order.length !== nodes.length) {
    const cycles = detectDagCycles(nodes);
    throw new DagValidationError('CYCLE_DETECTED', 'Cycle detected in DAG workflow.', {
      cycles,
    });
  }

  return order;
}

export function computeExecutionWaves(nodes: readonly DagNodeDefinition[]): string[][] {
  const order = topologicalSortDag(nodes);
  const nodeMap = new Map<string, DagNodeDefinition>();
  for (const node of nodes) {
    nodeMap.set(node.id, node);
  }

  const depthByNode = new Map<string, number>();
  let maxDepth = 0;

  for (const id of order) {
    const node = nodeMap.get(id);
    const deps = uniqueSortedDeps(node?.dependencies);
    let depth = 0;
    for (const dep of deps) {
      const depDepth = depthByNode.get(dep) ?? 0;
      if (depDepth + 1 > depth) {
        depth = depDepth + 1;
      }
    }
    depthByNode.set(id, depth);
    if (depth > maxDepth) {
      maxDepth = depth;
    }
  }

  const waves: string[][] = Array.from({ length: maxDepth + 1 }, () => []);
  for (const id of order) {
    const depth = depthByNode.get(id) ?? 0;
    const wave = waves[depth];
    if (wave) {
      wave.push(id);
    }
  }

  for (const wave of waves) {
    wave.sort(compareAscii);
  }

  return waves;
}

export function validateDagPlan(nodes: readonly DagNodeDefinition[]): DagPlanValidationResult {
  const errors: DagPlanError[] = [];

  if (nodes.length === 0) {
    errors.push({
      code: 'EMPTY_DAG',
      message: 'DAG must contain at least one node.',
    });
    return {
      valid: false,
      nodeCount: 0,
      edgeCount: 0,
      topologicalOrder: [],
      waves: [],
      criticalPathLength: 0,
      cycles: [],
      errors,
    };
  }

  const seenIds = new Set<string>();
  let edgeCount = 0;

  for (const node of nodes) {
    if (typeof node.id !== 'string' || node.id.trim().length === 0) {
      errors.push({
        code: 'INVALID_NODE_ID',
        message: 'DAG node id must be a non-empty string.',
      });
      continue;
    }
    if (seenIds.has(node.id)) {
      errors.push({
        code: 'DUPLICATE_NODE',
        message: `Duplicate DAG node id: ${node.id}`,
        details: { nodeId: node.id },
      });
    } else {
      seenIds.add(node.id);
    }
  }

  for (const node of nodes) {
    const deps = uniqueSortedDeps(node.dependencies);
    edgeCount += deps.length;
    for (const dep of deps) {
      if (dep === node.id) {
        errors.push({
          code: 'SELF_DEPENDENCY',
          message: `Node "${node.id}" cannot depend on itself.`,
          details: { nodeId: node.id },
        });
      } else if (!seenIds.has(dep)) {
        errors.push({
          code: 'MISSING_DEPENDENCY',
          message: `Node "${node.id}" depends on unknown node "${dep}".`,
          details: { nodeId: node.id, dependencyId: dep },
        });
      }
    }
  }

  const cycles = detectDagCycles(nodes);
  if (cycles.length > 0) {
    errors.push({
      code: 'CYCLE_DETECTED',
      message: `Cycle detected in DAG workflow (${cycles.length} cycle(s)).`,
      details: { cycles },
    });
  }

  if (errors.length > 0) {
    return {
      valid: false,
      nodeCount: nodes.length,
      edgeCount,
      topologicalOrder: [],
      waves: [],
      criticalPathLength: 0,
      cycles,
      errors,
    };
  }

  const topologicalOrder = topologicalSortDag(nodes);
  const waves = computeExecutionWaves(nodes);

  return {
    valid: true,
    nodeCount: nodes.length,
    edgeCount,
    topologicalOrder,
    waves,
    criticalPathLength: waves.length,
    cycles: [],
    errors: [],
  };
}

export function createDagExecutionState<TData = unknown>(
  nodes: readonly DagNodeDefinition<TData>[]
): DagExecutionState<TData> {
  const order = topologicalSortDag(nodes);
  const nodeStates: Record<string, DagNodeState<TData>> = {};

  for (const node of nodes) {
    nodeStates[node.id] = {
      id: node.id,
      status: 'pending',
      dependencies: uniqueSortedDeps(node.dependencies),
      ...(node.owner !== undefined ? { owner: node.owner } : {}),
      ...(node.ownedPaths !== undefined ? { ownedPaths: [...node.ownedPaths] } : {}),
      ...(node.riskTier !== undefined ? { riskTier: node.riskTier } : {}),
      ...(node.data !== undefined ? { data: node.data } : {}),
    };
  }

  return { nodes: nodeStates, order };
}

export function getReadyDagNodes<TData = unknown>(state: DagExecutionState<TData>): string[] {
  const ready: string[] = [];
  for (const id of state.order) {
    const node = state.nodes[id];
    if (!node || node.status !== 'pending') {
      continue;
    }
    const allDepsCompleted = node.dependencies.every(
      (depId) => state.nodes[depId]?.status === 'completed'
    );
    if (allDepsCompleted) {
      ready.push(id);
    }
  }
  return ready.sort(compareAscii);
}

const ALLOWED_TRANSITIONS: Readonly<Record<DagNodeStatus, readonly DagNodeStatus[]>> = {
  pending: ['running', 'skipped'],
  running: ['completed', 'failed'],
  completed: [],
  failed: [],
  skipped: [],
};

export function transitionDagNode<TData = unknown>(
  state: DagExecutionState<TData>,
  nodeId: string,
  nextStatus: DagNodeStatus,
  options?: { readonly output?: unknown; readonly error?: string; readonly timestamp?: string }
): DagExecutionState<TData> {
  const current = state.nodes[nodeId];
  if (!current) {
    throw new DagValidationError('MISSING_DEPENDENCY', `Unknown DAG node "${nodeId}".`, {
      nodeId,
    });
  }

  const allowed = ALLOWED_TRANSITIONS[current.status];
  if (!allowed.includes(nextStatus)) {
    throw new DagValidationError(
      'INVALID_TRANSITION',
      `Invalid transition for node "${nodeId}": ${current.status} -> ${nextStatus}.`,
      { nodeId, from: current.status, to: nextStatus }
    );
  }

  const timestamp = options?.timestamp ?? new Date().toISOString();
  const updatedNode: DagNodeState<TData> = {
    ...current,
    status: nextStatus,
    ...(nextStatus === 'running' ? { startedAt: timestamp } : {}),
    ...(nextStatus === 'completed' || nextStatus === 'failed' || nextStatus === 'skipped'
      ? { completedAt: timestamp }
      : {}),
    ...(options?.output !== undefined ? { output: options.output } : {}),
    ...(options?.error !== undefined ? { error: options.error } : {}),
  };

  return {
    ...state,
    nodes: {
      ...state.nodes,
      [nodeId]: updatedNode,
    },
  };
}

export interface DagExecutionOptions {
  readonly maxConcurrency?: number;
  readonly failFast?: boolean;
  readonly now?: () => string;
}

export interface DagExecutionResult<TData = unknown, TResult = unknown> {
  readonly state: DagExecutionState<TData>;
  readonly outputs: Readonly<Record<string, TResult>>;
  readonly completed: boolean;
  readonly wavesExecuted: number;
}

export async function executeDagWorkflow<TData = unknown, TResult = unknown>(
  nodes: readonly DagNodeDefinition<TData>[],
  executor: (
    node: DagNodeDefinition<TData>,
    context: { readonly outputs: Readonly<Record<string, TResult>> }
  ) => Promise<TResult>,
  options?: DagExecutionOptions
): Promise<DagExecutionResult<TData, TResult>> {
  const maxConcurrency = Math.max(1, options?.maxConcurrency ?? Number.POSITIVE_INFINITY);
  const failFast = options?.failFast ?? true;
  const now = options?.now ?? (() => new Date().toISOString());

  let state = createDagExecutionState(nodes);
  const nodeMap = new Map<string, DagNodeDefinition<TData>>();
  for (const node of nodes) {
    nodeMap.set(node.id, node);
  }

  const outputs: Record<string, TResult> = {};
  let hasFailure = false;
  let wavesExecuted = 0;

  while (true) {
    if (hasFailure && failFast) {
      for (const id of state.order) {
        if (state.nodes[id]?.status === 'pending') {
          state = transitionDagNode(state, id, 'skipped', { timestamp: now() });
        }
      }
      break;
    }

    if (!failFast && hasFailure) {
      for (const id of state.order) {
        const nodeState = state.nodes[id];
        if (!nodeState || nodeState.status !== 'pending') continue;
        const blockedByFailedDep = nodeState.dependencies.some((depId) => {
          const depStatus = state.nodes[depId]?.status;
          return depStatus === 'failed' || depStatus === 'skipped';
        });
        if (blockedByFailedDep) {
          state = transitionDagNode(state, id, 'skipped', {
            error: 'Skipped because upstream dependency failed.',
            timestamp: now(),
          });
        }
      }
    }

    const readyIds = getReadyDagNodes(state);
    if (readyIds.length === 0) {
      break;
    }

    const batch = readyIds.slice(0, maxConcurrency);
    wavesExecuted += 1;

    for (const id of batch) {
      state = transitionDagNode(state, id, 'running', { timestamp: now() });
    }

    const batchResults = await Promise.all(
      batch.map(async (id) => {
        const definition = nodeMap.get(id);
        if (!definition) {
          return { id, ok: false as const, error: `Missing node definition for "${id}"` };
        }
        try {
          const output = await executor(definition, { outputs: { ...outputs } });
          return { id, ok: true as const, output };
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          return { id, ok: false as const, error: message };
        }
      })
    );

    for (const outcome of batchResults) {
      if (outcome.ok) {
        outputs[outcome.id] = outcome.output;
        state = transitionDagNode(state, outcome.id, 'completed', {
          output: outcome.output,
          timestamp: now(),
        });
      } else {
        hasFailure = true;
        state = transitionDagNode(state, outcome.id, 'failed', {
          error: outcome.error,
          timestamp: now(),
        });
      }
    }
  }

  const completed = state.order.every((id) => state.nodes[id]?.status === 'completed');
  return { state, outputs, completed, wavesExecuted };
}
