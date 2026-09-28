import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

// What the current UI at / showed for each parity case, recorded before Phase 30
// removed it, so /beta stays checked against it. With PARITY_RECORD=1 a case
// reads the current UI and writes its recording under e2e/recorded/; otherwise it
// reads the recording. A case whose ceremony is live keeps the stored records the
// ceremony wrote beside the words, so the new UI is read for that very credential.
//
// A recording is what the current UI showed at the cutover: it is never edited. A
// later, intended change of what the new UI shows is an expected difference, with
// its reason, in the spec that compares it.

export const RECORDING = process.env.PARITY_RECORD === '1';

const ROOT = join(import.meta.dirname, 'recorded');
const written = new Set<string>();

// A file name for a case: its label with anything but letters, digits, dots and
// dashes as a dash.
function fileFor(spec: string, key: string) {
  const name = key.replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
  return join(ROOT, spec, `${name}.json`);
}

export async function recorded<T>(spec: string, key: string, read: () => Promise<T>): Promise<T> {
  const file = fileFor(spec, key);
  if (RECORDING) {
    if (written.has(file)) throw new Error(`Two cases record ${file}`);
    written.add(file);
    const value = await read();
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
    return value;
  }
  if (!existsSync(file)) {
    throw new Error(`No recording at ${file}: the current UI's side of each case was recorded with PARITY_RECORD=1 before Phase 30A removed it`);
  }
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}
