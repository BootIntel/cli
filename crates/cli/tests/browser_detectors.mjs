// Browser-parity harness: run the browser detector library (the source of
// truth) over a directory of boot logs and print its findings as JSON.
//
// Usage: node browser_detectors.mjs <path/to/detectors.ts> <logs-dir>
//
// Output: { "<file>": { "raw": [ { label, value, detail }, … ], "prefixed": [ … ] }, … }
//
// The `prefixed` variant is every line behind `[12:34:56.123] `. It is not
// padding: line-prefix normalization is the one place the two
// implementations could agree on a bare log and still disagree on a real
// capture, and the browser exempts two policy detectors from it.
//
// `detectors.ts` is TypeScript living in the website repo, so it is
// transpiled in-process with the `typescript` package resolved from that
// repo's own node_modules (found by walking up from the file) and evaluated
// in a fresh vm context — the same trick cli/test-parity.mjs uses, so both
// parity harnesses agree on what "the browser implementation" means.
import fs from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { createRequire } from 'node:module'

const [detectorsPath, logsDir] = process.argv.slice(2)
if (!detectorsPath || !logsDir) {
  console.error('usage: browser_detectors.mjs <detectors.ts> <logs-dir>')
  process.exit(2)
}

function findTypescript(from) {
  let dir = path.resolve(path.dirname(from))
  for (;;) {
    const candidate = path.join(dir, 'node_modules', 'typescript', 'package.json')
    if (fs.existsSync(candidate)) return createRequire(candidate)('typescript')
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  // Last resort: whatever `typescript` resolves to for this script.
  return createRequire(import.meta.url)('typescript')
}

const ts = findTypescript(detectorsPath)
const source = fs.readFileSync(detectorsPath, 'utf8')
const context = { exports: {} }
vm.runInNewContext(
  ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText,
  context,
)

const rows = (log) =>
  context.exports.analyze(log).map((f) => ({
    label: f.label,
    value: f.value,
    detail: f.detail === undefined ? null : f.detail,
  }))

const out = {}
for (const file of fs.readdirSync(logsDir).filter((f) => f.endsWith('.txt')).sort()) {
  const log = fs.readFileSync(path.join(logsDir, file), 'utf8')
  out[file] = {
    raw: rows(log),
    prefixed: rows(log.split(/\r\n|\n|\r/).map((line) => `[12:34:56.123] ${line}`).join('\n')),
  }
}
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
