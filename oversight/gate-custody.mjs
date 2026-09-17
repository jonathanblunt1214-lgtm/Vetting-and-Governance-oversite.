import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha } from './worker-export.mjs';

// Independent custody of The Crucible's durable gate evidence.
//
// Oversight takes a copy of the sealed gate-evidence envelope that Crucible's
// hosted-learning-proof workflow uploads with `if: always()`, so the red runs -
// the ones worth holding evidence for - are retained too. Holding a copy is a
// safety and custody act only: a record that R5 is `satisfied` never makes R5
// satisfied, and archival is additive and can never convert a failing gate,
// or a failing source run, into a pass.

const HEX64 = /^[a-f0-9]{64}$/;
const SATISFIED = 'satisfied';

// Crucible seals the envelope as { payload, sha256 } with sha256 over the
// canonicalised payload, the same canonical form the worker learning envelope
// already uses, so oversight reuses its single canonicalisation rather than
// keeping a second copy that could drift.
const RECOGNISED_FINGERPRINT_ALGORITHMS = new Set(['sha256-canonical-sources']);

export class GateCustodyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'GateCustodyError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new GateCustodyError(code, message);
}

function text(value) {
  return typeof value === 'string' && value.length > 0;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function wholeNumber(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

/**
 * The inventory is oversight-owned. Crucible does not get to name the workflow,
 * artifact or gate vocabulary that oversight will accept, so the expected shape
 * is read from CRUCIBLE-ORGANISM.json and never from the envelope itself.
 */
export function gateEvidenceRegistration(organism) {
  const registration = organism?.gateEvidence;
  if (!plainObject(registration)) fail('registration', 'Oversight holds no gate-evidence registration.');
  if (organism.schemaVersion !== 1 || !text(organism.organismId)) {
    fail('registration', 'Oversight organism inventory identity is invalid.');
  }
  for (const field of ['componentId', 'repository', 'ref', 'workflow', 'artifactPrefix', 'file']) {
    if (!text(registration[field])) fail('registration', `Gate-evidence registration field is invalid: ${field}`);
  }
  if (registration.schemaVersion !== 1 || registration.custodyOnly !== true) {
    fail('registration', 'Gate-evidence registration must declare schemaVersion 1 and custody-only intake.');
  }
  const gates = registration.gates;
  const states = registration.states;
  if (!Array.isArray(gates) || gates.length === 0 || !gates.every(text) || new Set(gates).size !== gates.length) {
    fail('registration', 'Gate-evidence registration gate set is invalid.');
  }
  if (!Array.isArray(states) || states.length === 0 || !states.every(text) || new Set(states).size !== states.length) {
    fail('registration', 'Gate-evidence registration state vocabulary is invalid.');
  }
  if (!states.includes(SATISFIED)) {
    fail('registration', 'Gate-evidence state vocabulary must include the satisfied verdict.');
  }
  return { ...registration, projectId: organism.organismId, gates: [...gates].sort(), states: [...states] };
}

function normaliseSources(value) {
  const list = value == null ? [] : Array.isArray(value) ? value : [value];
  const sources = list.map((item) => {
    if (text(item)) return { id: item, sha256: null };
    if (!plainObject(item)) fail('gate-binding', 'Gate source declaration is neither an identifier nor a record.');
    const id = item.id ?? item.path ?? item.name ?? item.sourceId;
    if (!text(id)) fail('gate-binding', 'Gate source record names no source.');
    const sha256 = item.sha256 ?? item.contentSha256 ?? null;
    if (sha256 !== null && !HEX64.test(sha256)) fail('gate-binding', `Gate source digest is invalid: ${id}`);
    return { id, sha256 };
  });
  if (new Set(sources.map((source) => source.id)).size !== sources.length) {
    fail('gate-binding', 'Gate names the same source twice.');
  }
  return sources.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
}

/**
 * Crucible records one source fingerprint per gate; `invalidateStaleGates`
 * clears a verdict whose source moved. Oversight cannot recompute Crucible's
 * fingerprint unless the payload names a recipe it recognises, so the binding
 * that is always enforced is structural and cross-copy: a satisfied gate must
 * name resolvable sources and carry a digest-shaped fingerprint, and a
 * fingerprint that stayed still while its named sources moved is a stale
 * verdict and is rejected.
 */
function readGate(id, gate, states) {
  if (!plainObject(gate)) fail('gate-state', `Gate ${id} is not a record.`);
  const state = gate.state;
  if (!text(state) || !states.includes(state)) fail('gate-state', `Gate ${id} carries a state outside the vocabulary.`);
  const fingerprint = gate.fingerprint ?? gate.sourceFingerprint ?? gate.sourcesSha256 ?? null;
  if (fingerprint !== null && !HEX64.test(fingerprint)) {
    fail('gate-binding', `Gate ${id} fingerprint is not a sha256 digest.`);
  }
  const sources = normaliseSources(gate.sources ?? gate.sourceIds ?? gate.source ?? null);
  return { id, state, fingerprint, sources };
}

function sourceTable(payload) {
  const declared = payload.sources;
  const list = Array.isArray(declared) ? declared : plainObject(declared)
    ? Object.entries(declared).map(([id, value]) => (plainObject(value) ? { id, ...value } : { id, sha256: value }))
    : null;
  if (list === null) return null;
  const table = new Map();
  for (const entry of normaliseSources(list)) table.set(entry.id, entry.sha256);
  return table;
}

function checkSatisfiedBinding(gate, payload, table) {
  if (gate.state !== SATISFIED) return false;
  if (!gate.fingerprint) fail('gate-binding', `Gate ${gate.id} claims ${SATISFIED} without a source fingerprint.`);
  if (gate.sources.length === 0) {
    fail('gate-binding', `Gate ${gate.id} claims ${SATISFIED} but names no source to bind the fingerprint to.`);
  }
  if (table) {
    for (const source of gate.sources) {
      if (!table.has(source.id)) {
        fail('gate-binding', `Gate ${gate.id} names a source the payload does not carry: ${source.id}`);
      }
      const declared = table.get(source.id);
      if (source.sha256 && declared && source.sha256 !== declared) {
        fail('gate-binding', `Gate ${gate.id} disagrees with the payload digest for source ${source.id}`);
      }
    }
  }
  if (!RECOGNISED_FINGERPRINT_ALGORITHMS.has(payload.fingerprintAlgorithm)) return false;
  const digests = gate.sources.map((source) => ({
    id: source.id,
    sha256: source.sha256 ?? (table ? table.get(source.id) : null) ?? null,
  }));
  if (digests.some((entry) => entry.sha256 === null)) {
    fail('gate-binding', `Gate ${gate.id} names a source with no digest to recompute its fingerprint from.`);
  }
  if (sha(digests) !== gate.fingerprint) {
    fail('gate-binding', `Gate ${gate.id} fingerprint does not match the sources it names.`);
  }
  return true;
}

function sourceSignature(sources) {
  return sha(sources.map((source) => ({ id: source.id, sha256: source.sha256 })));
}

/**
 * A verdict is stale when the fingerprint stood still while the sources it
 * names moved. Comparing against the copy oversight already holds catches that
 * without needing Crucible's fingerprint recipe.
 */
function checkAgainstHeld(gate, held) {
  const previous = held?.gates?.[gate.id];
  if (!plainObject(previous)) return;
  if (!previous.fingerprint || !gate.fingerprint || previous.fingerprint !== gate.fingerprint) return;
  if (previous.sourceSignature && previous.sourceSignature !== sourceSignature(gate.sources)) {
    fail('gate-stale', `Gate ${gate.id} kept its fingerprint although the sources it names moved.`);
  }
}

function checkHistory(history, registration, held) {
  if (!Array.isArray(history)) fail('history-invalid', 'Gate evidence history is not a list.');
  for (const entry of history) {
    if (!plainObject(entry)) fail('history-invalid', 'Gate evidence history contains a non-record entry.');
    const gate = entry.gate ?? entry.gateId ?? null;
    if (gate !== null && !registration.gates.includes(gate)) {
      fail('history-invalid', `Gate evidence history names an unregistered gate: ${gate}`);
    }
    for (const field of ['from', 'to', 'state']) {
      const value = entry[field];
      if (value !== undefined && value !== null && !registration.states.includes(value)) {
        fail('history-invalid', `Gate evidence history carries a state outside the vocabulary: ${value}`);
      }
    }
  }
  // History is append-only. A shortened history, or a rewritten prefix, is a
  // rewind dressed up as a new revision.
  if (held && wholeNumber(held.historyLength)) {
    if (history.length < held.historyLength) {
      fail('history-invalid', 'Gate evidence history is shorter than the copy oversight already holds.');
    }
    if (text(held.historySha256) && sha(history.slice(0, held.historyLength)) !== held.historySha256) {
      fail('history-invalid', 'Gate evidence history no longer matches the prefix oversight already holds.');
    }
  }
}

function checkSource(source, registration) {
  if (!plainObject(source)) fail('source-mismatch', 'Gate evidence source run was not described.');
  if (source.repository !== registration.repository || source.ref !== registration.ref) {
    fail('source-mismatch', 'Gate evidence did not come from the registered component and ref.');
  }
  if (source.workflow !== registration.workflow || source.file !== registration.file) {
    fail('source-mismatch', 'Gate evidence did not come from the registered workflow and file.');
  }
  if (!wholeNumber(source.runId) || source.runId === 0 || !wholeNumber(source.runAttempt) || source.runAttempt === 0) {
    fail('source-mismatch', 'Gate evidence run identity is invalid.');
  }
  const expected = `${registration.artifactPrefix}${source.runId}-${source.runAttempt}`;
  if (source.artifactName !== expected) fail('source-mismatch', `Gate evidence artifact name is not ${expected}.`);
  if (!text(source.conclusion)) fail('source-mismatch', 'Gate evidence source run conclusion is unknown.');
  return {
    repository: source.repository,
    ref: source.ref,
    workflow: source.workflow,
    file: source.file,
    runId: source.runId,
    runAttempt: source.runAttempt,
    artifactName: source.artifactName,
    // Preserved verbatim. Taking custody of a red run's evidence must leave the
    // run red; the record says so rather than quietly dropping it.
    conclusion: source.conclusion,
    headSha: text(source.headSha) ? source.headSha : null,
    completedAt: text(source.completedAt) ? source.completedAt : null,
  };
}

export function verifyGateEvidence({ envelope, registration, held = null, source, receivedAt = new Date().toISOString() }) {
  if (!plainObject(envelope) || !plainObject(envelope.payload) || !text(envelope.sha256)) {
    fail('envelope-shape', 'Gate evidence is not a sealed { payload, sha256 } envelope.');
  }
  if (!HEX64.test(envelope.sha256)) fail('envelope-shape', 'Gate evidence envelope seal is not a sha256 digest.');
  const payload = envelope.payload;
  if (sha(payload) !== envelope.sha256) {
    fail('envelope-hash', 'Gate evidence envelope seal does not recompute over its payload.');
  }
  if (payload.schemaVersion !== 1) fail('payload-identity', 'Gate evidence schema version is not 1.');
  if (payload.projectId !== registration.projectId) {
    fail('payload-identity', 'Gate evidence is not from the Crucible project oversight registered.');
  }
  if (!wholeNumber(payload.revision)) fail('payload-identity', 'Gate evidence revision is not a whole number.');

  const custodySource = checkSource(source, registration);

  if (held) {
    if (!wholeNumber(held.revision)) fail('revision-rewound', 'Held gate evidence revision is unreadable.');
    if (payload.revision < held.revision) {
      fail('revision-rewound', `Gate evidence revision ${payload.revision} is behind the held revision ${held.revision}.`);
    }
    if (payload.revision === held.revision) {
      // Same revision, same bytes, is the ordinary case for a scheduled pull
      // that found nothing new. Same revision with different bytes is the
      // attack, and is never stored.
      if (held.payloadSha256 !== envelope.sha256) {
        fail('revision-replayed', `Gate evidence revision ${payload.revision} was reissued with different contents.`);
      }
      fail('revision-not-advanced', `Gate evidence revision ${payload.revision} is already held.`);
    }
  }

  const gates = payload.gates;
  if (!plainObject(gates)) fail('gate-set', 'Gate evidence carries no gate record.');
  const present = Object.keys(gates).sort();
  if (present.length !== registration.gates.length || present.some((id, index) => id !== registration.gates[index])) {
    fail('gate-set', `Gate evidence gate set is not exactly ${registration.gates.join(' ')}.`);
  }

  const table = sourceTable(payload);
  const custodyGates = {};
  const gateStates = {};
  let recomputed = 0;
  for (const id of registration.gates) {
    const gate = readGate(id, gates[id], registration.states);
    if (checkSatisfiedBinding(gate, payload, table)) recomputed += 1;
    checkAgainstHeld(gate, held);
    gateStates[id] = gate.state;
    custodyGates[id] = {
      // Copied verbatim from the payload. Custody never restates a verdict.
      state: gate.state,
      fingerprint: gate.fingerprint,
      sources: gate.sources,
      sourceSignature: sourceSignature(gate.sources),
    };
  }

  const history = payload.history ?? [];
  checkHistory(history, registration, held);

  return {
    schemaVersion: 1,
    custodian: 'independent-oversight',
    custodyOnly: true,
    archivalIsAdditive: true,
    // Standing rule: holding evidence that a gate is satisfied does not make it
    // satisfied. This record is never scientific proof.
    conveysNoScientificProof: true,
    projectId: payload.projectId,
    revision: payload.revision,
    payloadSha256: envelope.sha256,
    envelopeSha256: sha(envelope),
    gateStates,
    gates: custodyGates,
    satisfiedGates: registration.gates.filter((id) => gateStates[id] === SATISFIED),
    fingerprintsRecomputed: recomputed,
    fingerprintAlgorithm: text(payload.fingerprintAlgorithm) ? payload.fingerprintAlgorithm : null,
    historyLength: history.length,
    historySha256: sha(history),
    crucibleRevisionSha: text(payload.revisionSha) ? payload.revisionSha : null,
    sourceRun: custodySource,
    receivedAt,
    verifier: 'oversight/gate-custody.mjs',
  };
}

export function emptyLedger(registration) {
  return {
    schemaVersion: 1,
    custodian: 'independent-oversight',
    custodyOnly: true,
    projectId: registration.projectId,
    latest: null,
    entries: [],
  };
}

export function readLedger(file, registration) {
  if (!file || !fs.existsSync(file)) return emptyLedger(registration);
  const ledger = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (ledger?.schemaVersion !== 1 || ledger.projectId !== registration.projectId || !Array.isArray(ledger.entries)) {
    fail('ledger-invalid', 'Held gate-evidence ledger identity is invalid.');
  }
  if (ledger.latest !== null && !plainObject(ledger.latest)) {
    fail('ledger-invalid', 'Held gate-evidence ledger latest entry is invalid.');
  }
  return ledger;
}

/**
 * The ledger keeps every revision oversight has taken custody of. Only the
 * newest entry carries the full gate bindings, because only the newest is
 * needed to prove the next copy moved forward; older entries stay compact so a
 * recurring pull does not re-read a growing history.
 */
export function appendCustody(ledger, record) {
  if (ledger.projectId !== record.projectId) fail('ledger-invalid', 'Custody record does not belong to this ledger.');
  return {
    ...ledger,
    latest: record,
    entries: [...ledger.entries, {
      revision: record.revision,
      payloadSha256: record.payloadSha256,
      envelopeSha256: record.envelopeSha256,
      gateStates: record.gateStates,
      runId: record.sourceRun.runId,
      runAttempt: record.sourceRun.runAttempt,
      conclusion: record.sourceRun.conclusion,
      receivedAt: record.receivedAt,
    }],
  };
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  const value = (name, fallback) => {
    const index = args.indexOf(name);
    if (index < 0 || !args[index + 1]) {
      if (fallback !== undefined) return fallback;
      throw new GateCustodyError('usage', `${name} is required.`);
    }
    return args[index + 1];
  };
  if (command !== 'admit') {
    throw new GateCustodyError('usage', 'Usage: gate-custody.mjs admit --envelope <file> --organism <file> --source <file> --record <file> [--ledger <file>] [--ledger-output <file>]');
  }
  const registration = gateEvidenceRegistration(JSON.parse(fs.readFileSync(value('--organism'), 'utf8')));
  const envelope = JSON.parse(fs.readFileSync(value('--envelope'), 'utf8'));
  const source = JSON.parse(fs.readFileSync(value('--source'), 'utf8'));
  const ledger = readLedger(value('--ledger', ''), registration);
  const record = verifyGateEvidence({ envelope, registration, held: ledger.latest, source });
  fs.writeFileSync(value('--record'), `${JSON.stringify(record, null, 2)}\n`);
  const ledgerOutput = value('--ledger-output', '');
  if (ledgerOutput) fs.writeFileSync(ledgerOutput, `${JSON.stringify(appendCustody(ledger, record), null, 2)}\n`);
  console.log(JSON.stringify({
    revision: record.revision,
    payloadSha256: record.payloadSha256,
    gateStates: record.gateStates,
    conclusion: record.sourceRun.conclusion,
    conveysNoScientificProof: true,
  }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    // A scheduled pull that found no newer revision is a quiet no-op, not a
    // custody failure. Every other rejection is a failure and stores nothing.
    process.exitCode = error instanceof GateCustodyError && error.code === 'revision-not-advanced' ? 3 : 1;
  }
}

export { HEX64, SATISFIED, sourceSignature };
