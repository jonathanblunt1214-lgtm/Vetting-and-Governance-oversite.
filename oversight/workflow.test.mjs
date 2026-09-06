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
  assert.match(workflow, /worker_sha=\$\(git -C learning-worker rev-parse HEAD\)/);
  assert.match(workflow, /vetted_state_sha=\$\(git -C "\$RUNNER_TEMP\/vetted-state" rev-parse HEAD\)/);
  assert.match(workflow, /worker-export\.mjs merge[^\r\n]+--worker-sha "\$worker_sha"[^\r\n]+--vetted-state-sha "\$vetted_state_sha"/);
});
