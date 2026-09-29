import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// What a page showed, recorded for each case of the *-recorded specs, so the pages
// stay checked against it. A case whose ceremony was live keeps the stored records
// the ceremony wrote beside the words, so the page is read for that very
// credential.
//
// A recording is never edited. A later, intended change of what a page shows is
// an expected difference, with its reason, in the spec that compares it.

const ROOT = join(import.meta.dirname, 'recorded');

// A case's file: its label with anything but letters, digits, dots and dashes as a dash.
export function recorded<T>(spec: string, key: string): T {
  const name = key.replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
  return JSON.parse(readFileSync(join(ROOT, spec, `${name}.json`), 'utf8')) as T;
}
