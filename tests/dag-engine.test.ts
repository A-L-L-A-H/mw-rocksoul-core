import { describe, expect, test } from 'bun:test';
import {
  computeExecutionWaves,
  createDagExecutionState,
  DagValidationError,
  detectDagCycles,
  executeDagWorkflow,
  getReadyDagNodes,
  topologicalSortDag,
  transitionDagNode,
  validateDagPlan,
  type DagNodeDefinition,
} from '../src/dag-engine.js';

describe('dag-engine', () => {
  test('produces identical deterministic topological order and waves regardless of input order', () => {
    const nodesA: readonly DagNodeDefinition[] = [
      { id: 'deploy', dependencies: ['test-api', 'test-ui'] },
      { id: 'test-ui', dependencies: ['build'] },
      { id: 'test-api', dependencies: ['build'] },
      { id: 'build', dependencies: ['lint'] },
      { id: 'lint', dependencies: [] },
    ];
    const nodesB: readonly DagNodeDefinition[] = [...nodesA].reverse();

    const orderA = topologicalSortDag(nodesA);
    const orderB = topologicalSortDag(nodesB);

    expect(orderA).toEqual(['lint', 'build', 'test-api', 'test-ui', 'deploy']);
    expect(orderB).toEqual(orderA);

    const waves = computeExecutionWaves(nodesA);
    expect(waves).toEqual([['lint'], ['build'], ['test-api', 'test-ui'], ['deploy']]);

    const validation = validateDagPlan(nodesA);
    expect(validation.valid).toBe(true);
    expect(validation.nodeCount).toBe(5);
    expect(validation.edgeCount).toBe(5);
    expect(validation.criticalPathLength).toBe(4);
    expect(validation.cycles).toEqual([]);
    expect(validation.errors).toEqual([]);
  });

  test('detects multi-node cycles and self-dependencies deterministically', () => {
    const cyclicNodes: readonly DagNodeDefinition[] = [
      { id: 'a', dependencies: ['c'] },
      { id: 'b', dependencies: ['a'] },
      { id: 'c', dependencies: ['b'] },
    ];

    const cycles = detectDagCycles(cyclicNodes);
    expect(cycles.length).toBeGreaterThanOrEqual(1);
    expect(cycles[0]).toEqual(['a', 'b', 'c', 'a']);

    expect(() => topologicalSortDag(cyclicNodes)).toThrow(DagValidationError);

    const validation = validateDagPlan(cyclicNodes);
    expect(validation.valid).toBe(false);
    expect(validation.errors.some((err) => err.code === 'CYCLE_DETECTED')).toBe(true);

    const selfDepValidation = validateDagPlan([{ id: 'self', dependencies: ['self'] }]);
    expect(selfDepValidation.valid).toBe(false);
    expect(selfDepValidation.errors.some((err) => err.code === 'SELF_DEPENDENCY')).toBe(true);
  });

  test('rejects empty DAG, duplicate nodes, blank ids, and missing dependencies', () => {
    expect(validateDagPlan([]).errors[0]?.code).toBe('EMPTY_DAG');
    expect(
      validateDagPlan([
        { id: 'a' },
        { id: 'a' },
      ]).errors.some((err) => err.code === 'DUPLICATE_NODE')
    ).toBe(true);
    expect(
      validateDagPlan([{ id: '  ' }]).errors.some((err) => err.code === 'INVALID_NODE_ID')
    ).toBe(true);
    expect(
      validateDagPlan([{ id: 'a', dependencies: ['missing'] }]).errors.some(
        (err) => err.code === 'MISSING_DEPENDENCY'
      )
    ).toBe(true);
  });

  test('executes ready DAG nodes in parallel waves and enforces maxConcurrency', async () => {
    const nodes: readonly DagNodeDefinition<{ readonly weight: number }>[] = [
      { id: 'root', dependencies: [], data: { weight: 1 } },
      { id: 'branch-a', dependencies: ['root'], data: { weight: 2 } },
      { id: 'branch-b', dependencies: ['root'], data: { weight: 3 } },
      { id: 'branch-c', dependencies: ['root'], data: { weight: 4 } },
      { id: 'join', dependencies: ['branch-a', 'branch-b', 'branch-c'], data: { weight: 5 } },
    ];

    let activeCount = 0;
    let peakConcurrency = 0;
    const result = await executeDagWorkflow<{ readonly weight: number }, number>(
      nodes,
      async (node, ctx) => {
        activeCount += 1;
        if (activeCount > peakConcurrency) {
          peakConcurrency = activeCount;
        }
        await Bun.sleep(5);
        activeCount -= 1;
        const depSum = (node.dependencies ?? []).reduce(
          (sum, depId) => sum + (ctx.outputs[depId] ?? 0),
          0
        );
        return depSum + (node.data?.weight ?? 0);
      },
      { maxConcurrency: 2, now: () => '2026-11-27T00:00:00.000Z' }
    );

    expect(result.completed).toBe(true);
    expect(peakConcurrency).toBe(2);
    expect(result.outputs['root']).toBe(1);
    expect(result.outputs['branch-a']).toBe(3);
    expect(result.outputs['branch-b']).toBe(4);
    expect(result.outputs['branch-c']).toBe(5);
    expect(result.outputs['join']).toBe(17);
    expect(result.wavesExecuted).toBe(4);
  });

  test('handles failFast=true and failFast=false failure propagation cleanly', async () => {
    const nodes: readonly DagNodeDefinition[] = [
      { id: 'root', dependencies: [] },
      { id: 'bad', dependencies: ['root'] },
      { id: 'good', dependencies: ['root'] },
      { id: 'bad-child', dependencies: ['bad'] },
      { id: 'good-child', dependencies: ['good'] },
    ];

    const failFastResult = await executeDagWorkflow(
      nodes,
      async (node) => {
        if (node.id === 'bad') throw new Error('boom');
        return node.id;
      },
      { failFast: true }
    );

    expect(failFastResult.completed).toBe(false);
    expect(failFastResult.state.nodes['bad']?.status).toBe('failed');
    expect(failFastResult.state.nodes['bad-child']?.status).toBe('skipped');
    expect(failFastResult.state.nodes['good-child']?.status).toBe('skipped');

    const continueResult = await executeDagWorkflow(
      nodes,
      async (node) => {
        if (node.id === 'bad') throw new Error('boom');
        return node.id;
      },
      { failFast: false }
    );

    expect(continueResult.completed).toBe(false);
    expect(continueResult.state.nodes['bad']?.status).toBe('failed');
    expect(continueResult.state.nodes['bad-child']?.status).toBe('skipped');
    expect(continueResult.state.nodes['good']?.status).toBe('completed');
    expect(continueResult.state.nodes['good-child']?.status).toBe('completed');
  });

  test('enforces strict node state transitions', () => {
    let state = createDagExecutionState([{ id: 'n1' }]);
    expect(getReadyDagNodes(state)).toEqual(['n1']);

    state = transitionDagNode(state, 'n1', 'running', { timestamp: '2026-11-27T00:00:00.000Z' });
    state = transitionDagNode(state, 'n1', 'completed', {
      output: 'done',
      timestamp: '2026-11-27T00:00:01.000Z',
    });

    expect(() => transitionDagNode(state, 'n1', 'running')).toThrow(DagValidationError);
  });
});
