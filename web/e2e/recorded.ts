import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// What the current UI at / showed for each parity case, recorded before Phase 30
// removed it, so the new UI stays checked against it. The readers that recorded
// it (with PARITY_RECORD=1) went with the current UI; they are in the commit that
// added e2e/recorded/. A case whose ceremony was live keeps the stored records the
// ceremony wrote beside the words, so the new UI is read for that very credential.
//
// A recording is what the current UI showed at the cutover: it is never edited. A
// later, intended change of what the new UI shows is an expected difference, with
// its reason, in the spec that compares it.

const ROOT = join(import.meta.dirname, 'recorded');

// A case's file: its label with anything but letters, digits, dots and dashes as a dash.
export function recorded<T>(spec: string, key: string): T {
  const name = key.replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
  return JSON.parse(readFileSync(join(ROOT, spec, `${name}.json`), 'utf8')) as T;
}
