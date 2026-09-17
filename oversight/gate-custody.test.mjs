import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import {
  GateCustodyError,
  appendCustody,
  emptyLedger,
  gateEvidenceRegistration,
  verifyGateEvidence,
} from './gate-custody.mjs';
import { sha } from './worker-export.mjs';

const organism = JSON.parse(fs.readFileSync(new URL('../CRUCIBLE-ORGANISM.json', import.meta.url), 'utf8'));
const registration = gateEvidenceRegistration(organism);
const digest = (value) => crypto.createHash('sha256').update(value).digest('hex');
const seal = (payload) => ({ payload, sha256: sha(payload) });

function payloadFor({ revision = 7, gates, history, sourceSha = digest('R5 experimental record') } = {}) {
  const named = [{ id: 'proof/r5.json', sha256: sourceSha }];
  return {
    schemaVersion: 1,
    projectId: registration.projectId,
    revision,
    revisionSha: 'a'.repeat(40),
    fingerprintAlgorithm: 'sha256-canonical-sources',
    sources: named,
    gates: gates ?? {
      R4: { state: 'unproven', fingerprint: null, sources: [] },
      R5: { state: 'satisfied', fingerprint: sha(named), sources: named },
      R6: { state: 'unsatisfied' },
      R7: { state: 'manual-evidence-required' },
      R8: { state: 'pending' },
    },
    history: history ?? [{ gate: 'R5', from: 'unproven', to: 'satisfied', at: '2026-09-10T00:00:00.000Z' }],
  };
}

const runSource = (overrides = {}) => ({
  repository: registration.repository,
  ref: registration.ref,
  workflow: registration.workflow,
  file: registration.file,
  runId: 4242,
  runAttempt: 1,
  artifactName: `${registration.artifactPrefix}4242-1`,
  // The runs worth holding custody of are the failing ones, so that is the default.
  conclusion: 'failure',
  headSha: 'a'.repeat(40),
  completedAt: '2026-09-10T00:05:00.000Z',
  ...overrides,
});

const admit = (envelope, { held = null, source = runSource() } = {}) =>
  verifyGateEvidence({ envelope, registration, held, source, receivedAt: '2026-09-10T01:00:00.000Z' });

function rejects(code, run) {
  assert.throws(run, (error) => error instanceof GateCustodyError && error.code === code);
}

test('admits a sealed envelope and copies every gate verdict verbatim', () => {
  const payload = payloadFor();
  const record = admit(seal(payload));
  assert.deepEqual(record.gateStates, {
    R4: 'unproven', R5: 'satisfied', R6: 'unsatisfied', R7: 'manual-evidence-required', R8: 'pending',
  });
  assert.deepEqual(record.satisfiedGates, ['R5']);
  assert.equal(record.fingerprintsRecomputed, 1);
  assert.equal(record.payloadSha256, sha(payload));
});

test('custody of a red run leaves the run red and claims no proof', () => {
  const record = admit(seal(payloadFor()));
  assert.equal(record.sourceRun.conclusion, 'failure');
  assert.equal(record.conveysNoScientificProof, true);
  assert.equal(record.custodyOnly, true);
  assert.equal(record.archivalIsAdditive, true);
});

test('rejects an envelope whose seal does not recompute over its payload', () => {
  const envelope = seal(payloadFor());
  envelope.payload.revision = 8;
  rejects('envelope-hash', () => admit(envelope));
});

test('rejects evidence from another project', () => {
  const payload = payloadFor();
  payload.projectId = 'github:someone-else/Not-The-Crucible';
  rejects('payload-identity', () => admit(seal(payload)));
});

test('rejects a rewound revision', () => {
  const held = admit(seal(payloadFor({ revision: 9 })));
  rejects('revision-rewound', () => admit(seal(payloadFor({ revision: 8 })), { held }));
});

test('rejects the same revision reissued with different contents', () => {
  const held = admit(seal(payloadFor({ revision: 9 })));
  const reissued = payloadFor({ revision: 9, sourceSha: digest('swapped record') });
  rejects('revision-replayed', () => admit(seal(reissued), { held }));
});

test('treats an unchanged revision as nothing to store rather than a new copy', () => {
  const payload = payloadFor({ revision: 9 });
  const held = admit(seal(payload));
  rejects('revision-not-advanced', () => admit(seal(payload), { held }));
});

test('rejects a gate set that is not exactly R4 R5 R6 R7 R8', () => {
  const payload = payloadFor();
  delete payload.gates.R8;
  rejects('gate-set', () => admit(seal(payload)));
  const extra = payloadFor();
  extra.gates.R9 = { state: 'pending' };
  rejects('gate-set', () => admit(seal(extra)));
});

test('rejects a gate state outside the vocabulary', () => {
  const payload = payloadFor();
  payload.gates.R6 = { state: 'passed' };
  rejects('gate-state', () => admit(seal(payload)));
});

test('rejects a satisfied gate with no fingerprint or no named source', () => {
  const bare = payloadFor();
  bare.gates.R6 = { state: 'satisfied' };
  rejects('gate-binding', () => admit(seal(bare)));
  const unbound = payloadFor();
  unbound.gates.R6 = { state: 'satisfied', fingerprint: 'b'.repeat(64), sources: [] };
  rejects('gate-binding', () => admit(seal(unbound)));
});

test('rejects a satisfied gate whose fingerprint does not match the sources it names', () => {
  const payload = payloadFor();
  payload.gates.R5.fingerprint = 'f'.repeat(64);
  rejects('gate-binding', () => admit(seal(payload)));
});

test('rejects a satisfied gate naming a source the payload does not carry', () => {
  const payload = payloadFor();
  payload.gates.R5.sources = [{ id: 'proof/ghost.json', sha256: digest('ghost') }];
  rejects('gate-binding', () => admit(seal(payload)));
});

test('rejects a verdict that kept its fingerprint although its source moved', () => {
  const held = admit(seal(payloadFor({ revision: 9 })));
  const moved = payloadFor({ revision: 10, sourceSha: digest('the source moved') });
  moved.gates.R5.fingerprint = held.gates.R5.fingerprint;
  rejects('gate-stale', () => admit(seal(moved), { held }));
});

test('rejects a shortened or rewritten history', () => {
  const held = admit(seal(payloadFor({ revision: 9 })));
  rejects('history-invalid', () => admit(seal(payloadFor({ revision: 10, history: [] })), { held }));
  const rewritten = payloadFor({
    revision: 10,
    history: [{ gate: 'R5', from: 'unproven', to: 'satisfied', at: '2026-09-11T00:00:00.000Z' }],
  });
  rejects('history-invalid', () => admit(seal(rewritten), { held }));
});

test('rejects history naming an unregistered gate or an unknown state', () => {
  rejects('history-invalid', () => admit(seal(payloadFor({ history: [{ gate: 'R9', to: 'satisfied' }] }))));
  rejects('history-invalid', () => admit(seal(payloadFor({ history: [{ gate: 'R5', to: 'passed' }] }))));
});

test('rejects evidence that did not come from the registered run and artifact', () => {
  const envelope = seal(payloadFor());
  rejects('source-mismatch', () => admit(envelope, { source: runSource({ repository: 'attacker/The-Crucible' }) }));
  rejects('source-mismatch', () => admit(envelope, { source: runSource({ ref: 'main' }) }));
  rejects('source-mismatch', () => admit(envelope, { source: runSource({ artifactName: 'hosted-learning-proof-1-1' }) }));
  rejects('source-mismatch', () => admit(envelope, { source: runSource({ conclusion: '' }) }));
});

test('the ledger keeps full bindings only for the newest copy', () => {
  const first = admit(seal(payloadFor({ revision: 9 })));
  const ledger = appendCustody(emptyLedger(registration), first);
  const second = admit(seal(payloadFor({ revision: 10 })), { held: ledger.latest });
  const next = appendCustody(ledger, second);
  assert.equal(next.entries.length, 2);
  assert.equal(next.latest.revision, 10);
  assert.equal(next.entries[0].revision, 9);
  assert.equal(next.entries[0].gates, undefined);
  assert.equal(next.entries[0].conclusion, 'failure');
});

test('an inventory without a gate-evidence registration is not usable', () => {
  rejects('registration', () => gateEvidenceRegistration({ schemaVersion: 1, organismId: registration.projectId }));
});
