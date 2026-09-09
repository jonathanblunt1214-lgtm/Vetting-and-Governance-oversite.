import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { mergeWorkerState, sha } from './worker-export.mjs';

const project = 'github:jonathanblunt1214-lgtm/The-Crucible';
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oversight-worker-'));
  const workerRoot = path.join(root, 'worker');
  const vettedRoot = path.join(root, 'vetted');
  fs.mkdirSync(path.join(workerRoot, 'sources'), { recursive: true });
  fs.mkdirSync(vettedRoot);
  const contentHash = digest('independently vetted content');
  const source = { id: 'source-1', url: 'https://example.edu/a', durablePath: `sources/${contentHash}.html`, contentSha256: contentHash, state: 'claim-extraction-forced-pending' };
  const vettedQueue = { schemaVersion: 1, projectId: project, documents: [], links: [source] };
  const workerQueue = structuredClone(vettedQueue);
  workerQueue.links[0].durablePath = 'D:\\runner\\temporary\\source.html';
  workerQueue.links[0].state = 'claim-extraction-complete';
  workerQueue.links[0].claimExtraction = { candidateIds: ['candidate-1'], windows: [] };
  fs.writeFileSync(path.join(vettedRoot, 'source-queue.json'), JSON.stringify(vettedQueue));
  fs.writeFileSync(path.join(workerRoot, 'sources', 'source-queue.json'), JSON.stringify(workerQueue));
  const candidate = { schemaVersion: 1, id: 'candidate-1', projectId: project, claim: 'bounded claim', claimBoundary: 'bounded', generalizationBoundary: 'bounded', kind: 'retrieval', provenance: { sourceType: 'web', sourceId: source.id, retrievedAt: '2026-09-05T00:00:00.000Z', author: 'author', license: 'unknown', contentSha256: contentHash }, classification: 'Insufficient Evidence', createdAt: '2026-09-05T00:00:00.000Z' };
  const record = { schemaVersion: 1, candidate, recordRevision: 0, claimScope: null, state: 'candidate', hypothesis: null, gates: { falsifiableHypothesis: false, controlledReproduction: false, causalIsolation: false, controlTesting: false, independentVerification: false, negativeTesting: false, regressionTesting: false, deterministicScopeProof: false, claimBoundaryCheck: false, generalizationCheck: false, contradictionAnalysis: false }, experimentalProof: null, independentVerification: null, proof: null, history: [{ from: null, to: 'candidate', at: candidate.createdAt, reason: 'ingested' }] };
  const payload = { schemaVersion: 1, projectId: project, revision: 1, candidateRecords: [record], knowledgeVersions: [], activeVersion: null, auditLog: [] };
  const envelope = { schemaVersion: 1, payload, payloadSha256: sha(payload) };
  fs.writeFileSync(path.join(workerRoot, 'learning.learning.json'), JSON.stringify(envelope));
  fs.writeFileSync(path.join(vettedRoot, 'old.learning.json'), '{}');
  const reportFile = path.join(root, 'report.json');
  fs.writeFileSync(reportFile, JSON.stringify({ schemaVersion: 1, projectId: project }));
  const manifest = { schemaVersion: 1, stage: 'worker-candidate-export', projectId: project, repository: 'jonathanblunt1214-lgtm/Learning-Worker', ref: 'refs/heads/main', workerSha: 'a'.repeat(40), vettedStateSha: 'b'.repeat(40), generatedAt: '2026-09-05T00:00:00.000Z', plaintextSha256: 'c'.repeat(64) };
  return { root, workerRoot, vettedRoot, reportFile, manifest, contentHash };
}

test('merges only candidate state and preserves independently vetted source custody', () => {
  const item = fixture();
  const result = mergeWorkerState({ workerRoot: item.workerRoot, vettedRoot: item.vettedRoot, manifest: item.manifest, expectedWorkerSha: item.manifest.workerSha, expectedVettedStateSha: item.manifest.vettedStateSha, reportFile: item.reportFile });
  const queue = JSON.parse(fs.readFileSync(path.join(item.vettedRoot, 'source-queue.json')));
  assert.equal(queue.links[0].durablePath, `sources/${item.contentHash}.html`);
  assert.equal(queue.links[0].state, 'claim-extraction-complete');
  assert.equal(result.candidateCount, 1);
  assert.equal(result.independentlyValidated, true);
  assert.deepEqual(fs.readdirSync(item.vettedRoot).filter((name) => name.endsWith('.learning.json')), ['learning.learning.json']);
});

test('accepts legacy candidate records with an omitted revision as revision zero', () => {
  const item = fixture();
  const learningFile = path.join(item.workerRoot, 'learning.learning.json');
  const envelope = JSON.parse(fs.readFileSync(learningFile));
  delete envelope.payload.candidateRecords[0].recordRevision;
  envelope.payloadSha256 = sha(envelope.payload);
  fs.writeFileSync(learningFile, JSON.stringify(envelope));

  const result = mergeWorkerState({ workerRoot: item.workerRoot, vettedRoot: item.vettedRoot, manifest: item.manifest, expectedWorkerSha: item.manifest.workerSha, expectedVettedStateSha: item.manifest.vettedStateSha, reportFile: item.reportFile });
  assert.equal(result.candidateCount, 1);
  assert.equal(result.independentlyValidated, true);
});

test('rejects promoted worker knowledge and stale vetted-state lineage', () => {
  const item = fixture();
  const learningFile = path.join(item.workerRoot, 'learning.learning.json');
  const envelope = JSON.parse(fs.readFileSync(learningFile));
  envelope.payload.knowledgeVersions.push({ version: 1 });
  envelope.payloadSha256 = sha(envelope.payload);
  fs.writeFileSync(learningFile, JSON.stringify(envelope));
  assert.throws(() => mergeWorkerState({ workerRoot: item.workerRoot, vettedRoot: item.vettedRoot, manifest: item.manifest, expectedWorkerSha: item.manifest.workerSha, expectedVettedStateSha: item.manifest.vettedStateSha, reportFile: item.reportFile }), /promoted learning state/);

  const clean = fixture();
  assert.throws(() => mergeWorkerState({ workerRoot: clean.workerRoot, vettedRoot: clean.vettedRoot, manifest: clean.manifest, expectedWorkerSha: clean.manifest.workerSha, expectedVettedStateSha: 'd'.repeat(40), reportFile: clean.reportFile }), /current vetted-state commit/);
});
