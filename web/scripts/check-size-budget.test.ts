import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { BUDGET, main, measureExport, overBudget } from './check-size-budget.mjs';

const page = (scripts: string) => `<!DOCTYPE html><html><head>${scripts}</head><body></body></html>`;
const sized = (text: string) => ({ raw: text.length, gzip: gzipSync(text, { level: 9 }).length });
const MAIN = 'console.log("main");\n'.repeat(40);
const POLYFILLS = 'var polyfill = 1;\n'.repeat(50);

let dir = '';

function exportWith(files: Record<string, string>) {
  dir = mkdtempSync(join(tmpdir(), 'size-budget-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

// An export as Next writes one: three pages naming the same first-load scripts,
// the noModule polyfills, each named chunk and a shared one no page names.
function anExport(extra: Record<string, string> = {}) {
  const head = '<script defer nomodule src="/_next/static/chunks/polyfills-1.js"></script><script defer src="/_next/static/chunks/main-1.js"></script>';
  return exportWith({
    'index.html': page(head + '<script defer src="/_next/static/chunks/pages/index-1.js"></script>'),
    '404.html': page(head),
    '500.html': page(head),
    '_next/static/chunks/polyfills-1.js': POLYFILLS,
    '_next/static/chunks/main-1.js': MAIN,
    '_next/static/chunks/pages/index-1.js': 'index();',
    '_next/static/chunks/section-advanced.0a1b.js': 'advanced();',
    '_next/static/chunks/section-codec.0a1b.js': 'codec();',
    '_next/static/chunks/section-mds.0a1b.js': 'mds();',
    '_next/static/chunks/credential-details.0a1b.js': 'details();',
    '_next/static/chunks/analyze-browser.0a1b.js': 'analyze();',
    '_next/static/chunks/546.0a1b.js': 'shared();',
    '_next/static/chunks/pages/_error-1.js': 'error();',
    ...extra,
  });
}

afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = '';
  vi.restoreAllMocks();
});

describe('the size budget', () => {
  it('counts what each page loads first, but the noModule polyfills a modern browser skips', () => {
    const measured = measureExport(anExport());

    const first = sized(MAIN);
    expect(measured.pages['404.html']).toEqual(first);
    expect(measured.pages['index.html']).toEqual({ raw: first.raw + 'index();'.length, gzip: first.gzip + sized('index();').gzip });
  });

  it('counts each named chunk, and every chunk no page names together', () => {
    const measured = measureExport(anExport());

    expect(measured.chunks['section-mds']).toEqual(sized('mds();'));
    expect(Object.keys(measured.chunks).sort()).toEqual(Object.keys(BUDGET.chunks).sort());
    expect(measured.unnamed).toEqual({
      raw: 'shared();'.length + 'error();'.length,
      gzip: sized('shared();').gzip + sized('error();').gzip,
    });
  });

  it('names each figure over its budget, raw or gzipped, and a budgeted chunk the export lost', () => {
    const measured = measureExport(anExport());
    const budget = structuredClone(BUDGET);
    budget.pages['index.html'].raw = 10;
    budget.unnamed.gzip = 1;
    delete measured.chunks['analyze-browser'];

    expect(overBudget(measured, budget)).toEqual([
      `first load of index.html: ${measured.pages['index.html'].raw} bytes raw, over its 10`,
      'chunk analyze-browser: not in the export',
      `chunks no page names: ${measured.unnamed.gzip} bytes gzip, over its 1`,
    ]);
    expect(overBudget(measureExport(dir))).toEqual([]);
  });

  it('exits 0 within the budget, and 1 over it or without an export', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(main([anExport()])).toBe(0);
    expect(log).toHaveBeenCalledWith(`chunk section-mds: ${'mds();'.length} bytes, ${sized('mds();').gzip} gzipped`);

    writeFileSync(join(dir, '_next/static/chunks/section-mds.0a1b.js'), 'x'.repeat(BUDGET.chunks['section-mds'].raw + 1));
    expect(main([dir])).toBe(1);
    expect(error).toHaveBeenCalledWith(`chunk section-mds: ${BUDGET.chunks['section-mds'].raw + 1} bytes raw, over its ${BUDGET.chunks['section-mds'].raw}`);

    expect(main([join(dir, 'missing')])).toBe(1);
    expect(error.mock.lastCall?.[0]).toMatch(/^Cannot read the export in .*missing: .* Run `npm run build` first\.$/);
  });
});
