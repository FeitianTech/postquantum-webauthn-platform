#!/usr/bin/env node
// How much JavaScript the export makes a browser load, held to a budget so the
// loading work stays done: each page's first load (every <script src> its HTML
// names, but the noModule polyfills modern browsers skip), each chunk the page
// loads by name (a section, the credential details, the Analyze Browser panel),
// and all the chunks no page names, the shared ones among them; raw and gzipped
// (level 9, as tools/build_static_assets.py serves them). Run after the build,
// beside the CSP scan: the export exists only then.
//
//   node scripts/check-size-budget.mjs out

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

import { parse } from 'parse5';

// Bytes: each the figure the export measured when it was set (2026-10-02),
// plus a kilobyte, rounded up to the next kilobyte. Raise one only for a change
// that is worth its bytes.
export const BUDGET = {
  pages: {
    'index.html': { raw: 458752, gzip: 142336 },
    '404.html': { raw: 355328, gzip: 110592 },
    '500.html': { raw: 355328, gzip: 110592 },
  },
  chunks: {
    'section-advanced': { raw: 94208, gzip: 27648 },
    'section-codec': { raw: 28672, gzip: 10240 },
    'section-mds': { raw: 66560, gzip: 21504 },
    'credential-details': { raw: 27648, gzip: 9216 },
    'analyze-browser': { raw: 21504, gzip: 8192 },
  },
  unnamed: { raw: 33792, gzip: 12288 },
};

const CHUNKS = join('_next', 'static', 'chunks');

function size(data) {
  return { raw: data.length, gzip: gzipSync(data, { level: 9 }).length };
}

function add(total, more) {
  return { raw: total.raw + more.raw, gzip: total.gzip + more.gzip };
}

// The scripts a page's HTML names: those a modern browser loads, and the
// noModule ones it skips.
function pageScripts(html) {
  const scripts = { loaded: [], skipped: [] };
  const visit = (node) => {
    if (node.tagName === 'script') {
      const attrs = new Map((node.attrs ?? []).map((attr) => [attr.name, attr.value]));
      if (attrs.has('src')) scripts[attrs.has('nomodule') ? 'skipped' : 'loaded'].push(attrs.get('src'));
    }
    for (const child of node.childNodes ?? []) visit(child);
  };
  visit(parse(html));
  return scripts;
}

const exportPath = (source) => join(...source.replace(/^\//, '').split('/'));

function chunkFiles(dir) {
  return readdirSync(join(dir, CHUNKS), { recursive: true })
    .map(String)
    .filter((name) => name.endsWith('.js'))
    .map((name) => join(CHUNKS, name));
}

/** @typedef {{ raw: number, gzip: number }} Size */

/**
 * What the export at `dir` makes a browser load: by page, by named chunk, and the chunks no page names.
 * @param {string} dir
 * @returns {{ pages: Record<string, Size>, chunks: Record<string, Size>, unnamed: Size }}
 */
export function measureExport(dir) {
  /** @type {Record<string, Size>} */
  const pages = {};
  const named = new Set();
  for (const page of Object.keys(BUDGET.pages)) {
    const { loaded, skipped } = pageScripts(readFileSync(join(dir, page), 'utf8'));
    [...loaded, ...skipped].forEach((source) => named.add(exportPath(source)));
    pages[page] = loaded.reduce((total, source) => add(total, size(readFileSync(join(dir, exportPath(source))))), { raw: 0, gzip: 0 });
  }
  /** @type {Record<string, Size>} */
  const chunks = {};
  let unnamed = { raw: 0, gzip: 0 };
  for (const file of chunkFiles(dir)) {
    if (named.has(file)) continue;
    const chunk = Object.keys(BUDGET.chunks).find((name) => file === join(CHUNKS, `${name}.${file.split('.').at(-2)}.js`));
    if (chunk) chunks[chunk] = size(readFileSync(join(dir, file)));
    else unnamed = add(unnamed, size(readFileSync(join(dir, file))));
  }
  return { pages, chunks, unnamed };
}

/** Each figure over its budget, and each budgeted chunk the export no longer has (renamed or gone). */
export function overBudget(measured, budget = BUDGET) {
  const findings = [];
  const check = (label, figure, limit) => {
    for (const kind of ['raw', 'gzip']) {
      if (figure[kind] > limit[kind]) findings.push(`${label}: ${figure[kind]} bytes ${kind}, over its ${limit[kind]}`);
    }
  };
  for (const [page, limit] of Object.entries(budget.pages)) check(`first load of ${page}`, measured.pages[page], limit);
  for (const [chunk, limit] of Object.entries(budget.chunks)) {
    if (measured.chunks[chunk]) check(`chunk ${chunk}`, measured.chunks[chunk], limit);
    else findings.push(`chunk ${chunk}: not in the export`);
  }
  check('chunks no page names', measured.unnamed, budget.unnamed);
  return findings;
}

export function main(argv) {
  const dir = argv[0] ?? 'out';
  let measured;
  try {
    measured = measureExport(dir);
  } catch (error) {
    console.error(`Cannot read the export in ${dir}: ${error.message}. Run \`npm run build\` first.`);
    return 1;
  }
  const rows = [
    ...Object.entries(measured.pages).map(([page, figure]) => [`first load of ${page}`, figure]),
    ...Object.entries(measured.chunks).map(([chunk, figure]) => [`chunk ${chunk}`, figure]),
    ['chunks no page names', measured.unnamed],
  ];
  for (const [label, figure] of rows) console.log(`${label}: ${figure.raw} bytes, ${figure.gzip} gzipped`);
  const findings = overBudget(measured);
  for (const finding of findings) console.error(finding);
  return findings.length === 0 ? 0 : 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exit(main(process.argv.slice(2)));
}
