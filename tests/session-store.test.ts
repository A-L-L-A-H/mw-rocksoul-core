import { afterEach, beforeEach, describe, expect, it } from 'bun:test';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import { PersistentSessionStore } from '../src/session-store.js';

describe('PersistentSessionStore', () => {
  const testStorePath = path.resolve('.tmp/test-sessions.json');

  beforeEach(async () => {
    await rm(testStorePath, { force: true });
  });

  afterEach(async () => {
    await rm(testStorePath, { force: true });
  });

  it('creates sessions and lists them sorted by updatedAt', async () => {
    const store = new PersistentSessionStore(testStorePath);
    const session1 = await store.createSession({ title: 'Task 1', project: 'mw' });
    const session2 = await store.createSession({ title: 'Task 2', project: 'mw' });

    const list = await store.listSessions();
    expect(list.length).toBe(2);
    expect(list.map((s) => s.id)).toContain(session1.id);
    expect(list.map((s) => s.id)).toContain(session2.id);
  });

  it('appends turns and tracks token telemetry deterministically', async () => {
    const store = new PersistentSessionStore(testStorePath);
    const session = await store.createSession({ title: 'Turn Test' });

    const turn1 = await store.appendTurn(session.id, {
      role: 'user',
      content: 'Fix the bug in server.ts',
    });
    expect(turn1.seq).toBe(1);
    expect(turn1.role).toBe('user');

    const turn2 = await store.appendTurn(session.id, {
      role: 'assistant',
      content: 'Found the issue, executing edit.',
      meta: { tokensIn: 100, tokensOut: 50, rtkTokensSaved: 20 },
    });
    expect(turn2.seq).toBe(2);

    const loaded = await store.getSession(session.id);
    expect(loaded).not.toBeNull();
    expect(loaded?.turns.length).toBe(2);
    expect(loaded?.session.totalTokensIn).toBe(100);
    expect(loaded?.session.totalTokensOut).toBe(50);
    expect(loaded?.session.rtkTokensSaved).toBe(20);
  });

  it('persists and restores from disk across store instances (atomic writes)', async () => {
    const storeA = new PersistentSessionStore(testStorePath);
    const session = await storeA.createSession({ title: 'Persistent Session', project: 'rocksoul' });
    await storeA.appendTurn(session.id, {
      role: 'user',
      content: 'Hello persistent world',
    });

    // Create fresh instance reading same file
    const storeB = new PersistentSessionStore(testStorePath);
    const loaded = await storeB.getSession(session.id);
    expect(loaded).not.toBeNull();
    expect(loaded?.session.title).toBe('Persistent Session');
    expect(loaded?.turns.length).toBe(1);
    expect(loaded?.turns[0].content).toBe('Hello persistent world');
  });

  it('forks a session up to a specific turn sequence', async () => {
    const store = new PersistentSessionStore(testStorePath);
    const origin = await store.createSession({ title: 'Base Session' });
    await store.appendTurn(origin.id, { role: 'user', content: 'Step 1' });
    await store.appendTurn(origin.id, { role: 'assistant', content: 'Reply 1' });
    await store.appendTurn(origin.id, { role: 'user', content: 'Step 2' });

    const forked = await store.forkSession(origin.id, {
      newTitle: 'Forked Branch',
      upToSeq: 2,
    });

    expect(forked.parentSessionId).toBe(origin.id);
    expect(forked.title).toBe('Forked Branch');

    const forkedLoaded = await store.getSession(forked.id);
    expect(forkedLoaded?.turns.length).toBe(2);
    expect(forkedLoaded?.turns[0].content).toBe('Step 1');
    expect(forkedLoaded?.turns[1].content).toBe('Reply 1');
  });
});
