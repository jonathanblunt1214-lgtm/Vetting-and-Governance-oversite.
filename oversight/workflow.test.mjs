import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflow = fs.readFileSync(path.join(root, '.github', 'workflows', 'independent-oversight.yml'), 'utf8');

test('custody publication does not depend on Actions artifact quota', () => {
  assert.doesNotMatch(workflow, /actions\/(?:upload|download)-artifact/);
  assert.match(workflow, /archive-oversight-report:[\s\S]*?if: always\(\)/);
  assert.match(workflow, /return-vetted-data:[\s\S]*?needs\.oversight\.result == 'success'/);
});

test('additive report preservation occurs before the original oversight failure', () => {
  const preserve = workflow.indexOf('Preserve the original oversight report as an additive job output');
  const fail = workflow.indexOf('Fail after preserving independent evidence');
  assert.ok(preserve > 0 && fail > preserve);
  assert.match(workflow, /steps\.audit\.outcome == 'failure'[\s\S]*?run: exit 1/);
});

test('worker custody is exact-tip and stale-lineage bound before publication', () => {
  assert.match(workflow, /ref: oversight-export/);
  assert.match(workflow, /normalized_entry=\$\{entry\/\/\\\\\/\/\}/);
  assert.match(workflow, /duplicate queue entry/);
  assert.match(workflow, /invalid or duplicate learning entry/);
  assert.match(workflow, /unzip -p[^\r\n]+"\$queue_entry"[^\r\n]+source-queue\.json/);
  assert.match(workflow, /unzip -p[^\r\n]+"\$learning_entry"[^\r\n]+"\$RUNNER_TEMP\/custody\/worker-root\/\$learning_name"/);
  assert.doesNotMatch(workflow, /unzip -q[^\r\n]+worker-state\.zip/);
  assert.match(workflow, /worker_sha=\$\(git -C learning-worker rev-parse HEAD\)/);
  assert.match(workflow, /vetted_state_sha=\$\(git -C "\$RUNNER_TEMP\/vetted-state" rev-parse HEAD\)/);
  assert.match(workflow, /worker-export\.mjs merge[^\r\n]+--worker-sha "\$worker_sha"[^\r\n]+--vetted-state-sha "\$vetted_state_sha"/);
});

test('worker archive failures report only structural entry names', () => {
  assert.match(workflow, /Worker archive structural entries/);
  assert.match(workflow, /printf '%s\\n' "\$\{worker_entries\[@\]\}"/);
});
