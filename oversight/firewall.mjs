import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ALLOWED_MODULES = new Set(['encrypted-custody.mjs', 'encrypted-custody.test.mjs', 'firewall.mjs', 'firewall.test.mjs', 'verify.mjs', 'verify.test.mjs']);
const FORBIDDEN_RUNTIME_PATTERNS = [
  /from\s+['"](?:\.\.\/)*target/i,
  /require\s*\([^)]*target/i,
  /node:child_process/i,
  /process\.env\.(?:GITHUB_TOKEN|GH_TOKEN)/i,
  /secrets\./i,
  /https?:\/\/(?!github\.com\/jonathanblunt1214-lgtm\/The-Crucible)/i,
];

export function enforce(oversightRoot, targetRoot, workerRoot = null) {
  const workflow = fs.readFileSync(path.join(oversightRoot, '.github', 'workflows', 'independent-oversight.yml'), 'utf8');
  const writePermissions = workflow.match(/contents:\s*write/g) || [];
  if (!/^permissions:\s*\r?\n\s*contents:\s*read/m.test(workflow)
      || writePermissions.length !== 1
      || !/return-vetted-data:[\s\S]*?environment:\s*vetted-return[\s\S]*?permissions:\s*\r?\n\s*contents:\s*write/.test(workflow)
      || /issues:\s*write|actions:\s*write/.test(workflow)) {
    throw new Error('Oversight workflow permissions exceed read-only.');
  }
  if (!/repository:\s*jonathanblunt1214-lgtm\/The-Crucible/.test(workflow)
      || !/repository:\s*jonathanblunt1214-lgtm\/Learning-Worker/.test(workflow)
      || (workflow.match(/persist-credentials:\s*false/g) || []).length < 3) {
    throw new Error('Oversight checkout identity or credential isolation failed.');
  }
  const moduleNames = fs.readdirSync(path.join(oversightRoot, 'oversight')).filter((item) => /\.(?:mjs|js)$/.test(item));
  const unexpected = moduleNames.filter((item) => !ALLOWED_MODULES.has(item));
  if (unexpected.length > 0) throw new Error(`Oversight firewall rejected unauthorized modules: ${unexpected.join(', ')}.`);
  for (const moduleName of moduleNames.filter((item) => !item.includes('.test.'))) {
    const source = fs.readFileSync(path.join(oversightRoot, 'oversight', moduleName), 'utf8');
    for (const pattern of FORBIDDEN_RUNTIME_PATTERNS) if (pattern.test(source)) throw new Error(`Oversight firewall rejected ${moduleName} capability: ${pattern}.`);
  }
  if (!fs.existsSync(path.join(targetRoot, 'src', 'scientificLearning.js'))) throw new Error('Exact Crucible target checkout is unavailable.');
  if (workerRoot && !fs.existsSync(workerRoot)) throw new Error('Exact Learning Worker checkout is unavailable.');
  return { state: 'isolated', assimilatesData: false, sharedRuntimeImports: 0, writePermissions: 0, persistedCredentials: 0, targetMutationAuthorized: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(enforce(path.resolve(process.argv[2]), path.resolve(process.argv[3]), process.argv[4] ? path.resolve(process.argv[4]) : null)));
}
