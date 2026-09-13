import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const MAGIC = 'CRUCIBLE-WORKER-EXPORT-V1';
const PROJECT = 'github:jonathanblunt1214-lgtm/The-Crucible';
const REPOSITORY = 'jonathanblunt1214-lgtm/Learning-Worker';
const REF = 'refs/heads/main';
const CUSTODY_REPOSITORY = 'jonathanblunt1214-lgtm/The-Crucible';
const CUSTODY_REF = 'refs/heads/development';
const TAG_BYTES = 16;
const CANDIDATE_KEYS = new Set([
  'schemaVersion',
  'id',
  'projectId',
  'claim',
  'claimBoundary',
  'generalizationBoundary',
  'kind',
  'provenance',
  'classification',
  'createdAt',
]);

function shaFile(file) {
  const hash = crypto.createHash('sha256');
  const descriptor = fs.openSync(file, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let bytes;
    while ((bytes = fs.readSync(descriptor, buffer, 0, buffer.length, null)) > 0) {
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha(value) {
  return crypto.createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
}

function digest(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function commit(value, label) {
  if (!/^[a-f0-9]{40}$/.test(value || '')) throw new Error(`${label} is not an exact Git commit.`);
  return value;
}

function key() {
  const value = Buffer.from(process.env.OVERSIGHT_WORKER_BUNDLE_KEY || '', 'base64');
  if (value.length !== 32) throw new Error('Worker export decryption key is unavailable.');
  return value;
}

function validateIdentity(value) {
  if (
    value.schemaVersion !== 1 ||
    value.stage !== 'worker-candidate-export' ||
    value.projectId !== PROJECT ||
    value.repository !== REPOSITORY ||
    value.ref !== REF
  ) {
    throw new Error('Worker export is outside the governed repository boundary.');
  }
  commit(value.workerSha, 'workerSha');
  commit(value.vettedStateSha, 'vettedStateSha');
}

export function joinWorkerChunks(root, output) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'worker-export-manifest.json'), 'utf8'));
  validateIdentity(manifest);
  if (manifest.format !== MAGIC || !digest(manifest.plaintextSha256) || !digest(manifest.encryptedSha256)) {
    throw new Error('Worker export manifest is invalid.');
  }
  const descriptor = fs.openSync(output, 'wx', 0o600);
  try {
    for (const item of manifest.chunks || []) {
      if (!/^worker-state\.part-\d{4}\.enc$/.test(item.name) || !digest(item.sha256)) {
        throw new Error('Worker export chunk declaration is invalid.');
      }
      const file = path.join(root, item.name);
      if (fs.statSync(file).size !== item.bytes || shaFile(file) !== item.sha256) {
        throw new Error(`Worker export chunk failed custody: ${item.name}`);
      }
      fs.writeSync(descriptor, fs.readFileSync(file));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  if (fs.statSync(output).size !== manifest.encryptedBytes || shaFile(output) !== manifest.encryptedSha256) {
    throw new Error('Joined worker ciphertext does not match its manifest.');
  }
  return manifest;
}

export async function decryptWorkerExport(input, output, manifest) {
  const descriptor = fs.openSync(input, 'r');
  const probe = Buffer.alloc(8192);
  const count = fs.readSync(descriptor, probe, 0, probe.length, 0);
  fs.closeSync(descriptor);
  const newline = probe.subarray(0, count).indexOf(10);
  if (newline < 0) throw new Error('Worker export header is missing.');
  const encoded = probe.subarray(0, newline + 1);
  const header = JSON.parse(encoded.toString('utf8'));
  if (header.magic !== MAGIC || header.algorithm !== 'aes-256-gcm') {
    throw new Error('Worker export encryption format is invalid.');
  }
  validateIdentity(header);
  for (const field of ['workerSha', 'vettedStateSha', 'plaintextSha256', 'plaintextBytes']) {
    if (header[field] !== manifest[field]) throw new Error(`Worker export ${field} binding mismatch.`);
  }
  const size = fs.statSync(input).size;
  const tag = Buffer.alloc(TAG_BYTES);
  const tagDescriptor = fs.openSync(input, 'r');
  fs.readSync(tagDescriptor, tag, 0, TAG_BYTES, size - TAG_BYTES);
  fs.closeSync(tagDescriptor);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key(), Buffer.from(header.iv, 'base64'));
  decipher.setAAD(encoded);
  decipher.setAuthTag(tag);
  await pipeline(
    fs.createReadStream(input, { start: encoded.length, end: size - TAG_BYTES - 1 }),
    decipher,
    fs.createWriteStream(output, { flags: 'wx', mode: 0o600 }),
  );
  if (fs.statSync(output).size !== header.plaintextBytes || shaFile(output) !== header.plaintextSha256) {
    throw new Error('Worker export plaintext custody failed.');
  }
  return header;
}

function queueSources(queue) {
  if (queue?.schemaVersion !== 1 || queue?.projectId !== PROJECT) {
    throw new Error('Worker or vetted queue identity is invalid.');
  }
  if (!Array.isArray(queue.documents) || !Array.isArray(queue.links)) {
    throw new Error('Worker or vetted queue source collections are invalid.');
  }
  return [...queue.documents, ...queue.links];
}

function validateCandidateRecord(record, sourceById, candidateIds) {
  if (
    (record?.schemaVersion ?? 1) !== 1 ||
    record.state !== 'candidate' ||
    (record.recordRevision ?? 0) !== 0 ||
    record.claimScope != null ||
    record.hypothesis != null ||
    record.experimentalProof != null ||
    record.independentVerification != null ||
    record.proof != null
  ) {
    throw new Error('Worker export contains non-candidate or advanced learning state.');
  }
  if (record.gates !== undefined && (!record.gates || Object.values(record.gates).some((value) => value !== false))) {
    throw new Error('Worker candidate export contains a satisfied scientific gate.');
  }
  const candidate = record.candidate;
  if (
    !candidate ||
    Object.keys(candidate).some((field) => !CANDIDATE_KEYS.has(field)) ||
    candidate.schemaVersion !== 1 ||
    candidate.projectId !== PROJECT ||
    candidate.classification !== 'Insufficient Evidence' ||
    typeof candidate.id !== 'string' ||
    candidateIds.has(candidate.id)
  ) {
    throw new Error('Worker candidate identity or classification is invalid.');
  }
  candidateIds.add(candidate.id);
  const source = sourceById.get(String(candidate.provenance?.sourceId));
  if (!source || candidate.provenance?.contentSha256 !== source.contentSha256) {
    throw new Error(`Worker candidate ${candidate.id} is not bound to a vetted source hash.`);
  }
  if (record.history !== undefined && (!Array.isArray(record.history) || record.history.length !== 1 || record.history[0]?.to !== 'candidate')) {
    throw new Error('Worker candidate history contains an unauthorized transition.');
  }
}

function refreshCustodyManifest(vettedRoot, learningFileName) {
  const manifestFile = path.join(vettedRoot, 'manifest.json');
  const queueFile = path.join(vettedRoot, 'source-queue.json');
  const learningFile = path.join(vettedRoot, learningFileName);
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (
    manifest?.schemaVersion !== 1 ||
    manifest.projectId !== PROJECT ||
    manifest.repository !== CUSTODY_REPOSITORY ||
    manifest.ref !== CUSTODY_REF ||
    !Array.isArray(manifest.sourceFiles) ||
    !digest(manifest.queueSha256) ||
    !digest(manifest.learningSha256)
  ) {
    throw new Error('Vetted custody manifest identity or commitments are invalid.');
  }
  if (!fs.existsSync(queueFile) || !fs.existsSync(learningFile)) {
    throw new Error('Merged queue or learning envelope is missing before custody commitment.');
  }

  // mergeWorkerState changes both files. The manifest came from raw intake and therefore
  // commits to their pre-merge bytes; publishing it unchanged creates an authenticated bundle
  // whose own manifest rejects the queue it contains. Refresh all mutable commitments inside
  // the same unpublished staging directory, then re-read them before encryption.
  const next = {
    ...manifest,
    learningFile: learningFileName,
    queueSha256: shaFile(queueFile),
    learningSha256: shaFile(learningFile),
    updatedAt: new Date().toISOString(),
  };
  const temporary = `${manifestFile}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  fs.renameSync(temporary, manifestFile);
  const committed = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  if (committed.queueSha256 !== shaFile(queueFile) || committed.learningSha256 !== shaFile(learningFile)) {
    throw new Error('Post-merge custody commitments do not match the files that would be encrypted.');
  }
  return committed;
}

export function mergeWorkerState({ workerRoot, vettedRoot, manifest, expectedWorkerSha, expectedVettedStateSha, reportFile }) {
  validateIdentity(manifest);
  if (manifest.workerSha !== commit(expectedWorkerSha, 'expectedWorkerSha')) {
    throw new Error('Worker export does not match the checked-out worker commit.');
  }
  if (manifest.vettedStateSha !== commit(expectedVettedStateSha, 'expectedVettedStateSha')) {
    throw new Error('Worker export was not derived from the current vetted-state commit.');
  }
  const vettedQueueFile = path.join(vettedRoot, 'source-queue.json');
  const workerQueueFile = path.join(workerRoot, 'sources', 'source-queue.json');
  const vettedQueue = JSON.parse(fs.readFileSync(vettedQueueFile, 'utf8'));
  const workerQueue = JSON.parse(fs.readFileSync(workerQueueFile, 'utf8'));
  const vettedSources = queueSources(vettedQueue);
  const workerSources = queueSources(workerQueue);
  const workerById = new Map(workerSources.map((source) => [String(source.id), source]));
  if (workerById.size !== workerSources.length || workerSources.length !== vettedSources.length) {
    throw new Error('Worker queue membership differs from independently vetted custody.');
  }
  const mergedQueue = structuredClone(vettedQueue);
  for (const source of queueSources(mergedQueue)) {
    const worker = workerById.get(String(source.id));
    if (!worker || worker.contentSha256 !== source.contentSha256) {
      throw new Error(`Worker queue source custody mismatch: ${source.id}`);
    }
    if (typeof worker.state !== 'string' || !worker.state) throw new Error(`Worker source state is invalid: ${source.id}`);
    source.state = worker.state;
    if (worker.claimExtraction === undefined) delete source.claimExtraction;
    else source.claimExtraction = structuredClone(worker.claimExtraction);
  }

  const learningFiles = fs.readdirSync(workerRoot).filter((name) => name.endsWith('.learning.json'));
  if (learningFiles.length !== 1) throw new Error('Worker export must contain exactly one learning envelope.');
  const learningFile = path.join(workerRoot, learningFiles[0]);
  const envelope = JSON.parse(fs.readFileSync(learningFile, 'utf8'));
  if (envelope?.schemaVersion !== 1 || envelope.payloadSha256 !== sha(envelope.payload)) {
    throw new Error('Worker learning envelope integrity check failed.');
  }
  const payload = envelope.payload;
  if (
    payload?.schemaVersion !== 1 ||
    payload.projectId !== PROJECT ||
    !Array.isArray(payload.candidateRecords) ||
    !Array.isArray(payload.knowledgeVersions) ||
    payload.knowledgeVersions.length !== 0 ||
    payload.activeVersion !== null ||
    !Array.isArray(payload.auditLog)
  ) {
    throw new Error('Worker export contains invalid or promoted learning state.');
  }
  const sourceById = new Map(vettedSources.map((source) => [String(source.id), source]));
  const candidateIds = new Set();
  for (const record of payload.candidateRecords) validateCandidateRecord(record, sourceById, candidateIds);

  const temporaryQueue = `${vettedQueueFile}.${process.pid}.tmp`;
  fs.writeFileSync(temporaryQueue, `${JSON.stringify(mergedQueue, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  fs.renameSync(temporaryQueue, vettedQueueFile);
  for (const name of fs.readdirSync(vettedRoot).filter((entry) => entry.endsWith('.learning.json'))) {
    fs.rmSync(path.join(vettedRoot, name));
  }
  fs.copyFileSync(learningFile, path.join(vettedRoot, learningFiles[0]), fs.constants.COPYFILE_EXCL);
  const custody = refreshCustodyManifest(vettedRoot, learningFiles[0]);

  const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
  report.queueSha256 = custody.queueSha256;
  report.learningSha256 = custody.learningSha256;
  report.workerCandidateExport = {
    workerSha: manifest.workerSha,
    priorVettedStateSha: manifest.vettedStateSha,
    generatedAt: manifest.generatedAt,
    plaintextSha256: manifest.plaintextSha256,
    candidateCount: payload.candidateRecords.length,
    queueSourceCount: workerSources.length,
    candidateOnly: true,
    independentlyValidated: true,
  };
  fs.writeFileSync(reportFile, `${JSON.stringify(report, null, 2)}\n`);
  return report.workerCandidateExport;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const value = (name) => {
    const index = args.indexOf(name);
    if (index < 0 || !args[index + 1]) throw new Error(`${name} is required.`);
    return args[index + 1];
  };
  if (command === 'join') {
    console.log(JSON.stringify(joinWorkerChunks(value('--root'), value('--output'))));
  } else if (command === 'decrypt') {
    const manifest = JSON.parse(fs.readFileSync(value('--manifest'), 'utf8'));
    console.log(JSON.stringify(await decryptWorkerExport(value('--input'), value('--output'), manifest)));
  } else if (command === 'merge') {
    const manifest = JSON.parse(fs.readFileSync(value('--manifest'), 'utf8'));
    console.log(JSON.stringify(mergeWorkerState({
      workerRoot: value('--worker-root'),
      vettedRoot: value('--vetted-root'),
      manifest,
      expectedWorkerSha: value('--worker-sha'),
      expectedVettedStateSha: value('--vetted-state-sha'),
      reportFile: value('--report'),
    })));
  } else {
    throw new Error('Usage: worker-export.mjs join|decrypt|merge');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

export { MAGIC, PROJECT, REF, REPOSITORY, refreshCustodyManifest, sha, shaFile };
