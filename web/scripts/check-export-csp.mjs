#!/usr/bin/env node
// The static export must hold nothing the strict Content-Security-Policy refuses
// (server/app/config/security_headers.py: script-src 'self', style-src 'self',
// no 'unsafe-inline'). Every HTML file under the export is parsed and fails on:
// an inline <script> that would run (anything but type="application/json"), a
// <style> element, a style attribute, an on* handler attribute, a javascript:
// URL, an srcdoc, or a script or stylesheet from outside the base path.
//
//   node scripts/check-export-csp.mjs out

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';

import { parse } from 'parse5';

export const BASE_PATH = '/beta';
const URL_ATTRIBUTES = new Set(['href', 'src', 'action', 'formaction', 'xlink:href']);

function attributes(node) {
  return new Map((node.attrs ?? []).map((attr) => [attr.prefix ? `${attr.prefix}:${attr.name}` : attr.name, attr.value]));
}

function isOwn(url) {
  return typeof url === 'string' && url.startsWith(`${BASE_PATH}/`);
}

function inspect(node, findings, counts) {
  const tag = node.tagName;
  if (tag) {
    const attrs = attributes(node);
    if (tag === 'script') {
      counts.scripts += 1;
      if (attrs.has('src')) {
        if (!isOwn(attrs.get('src'))) findings.push({ kind: 'script from elsewhere', detail: attrs.get('src') });
      } else if ((attrs.get('type') ?? '').trim().toLowerCase() !== 'application/json') {
        const text = (node.childNodes ?? []).map((child) => child.value ?? '').join('');
        findings.push({ kind: 'inline script', detail: text.slice(0, 80) });
      }
    }
    if (tag === 'style') findings.push({ kind: 'style element', detail: '' });
    if (tag === 'link' && (attrs.get('rel') ?? '').toLowerCase().split(/\s+/).includes('stylesheet')) {
      if (!isOwn(attrs.get('href'))) findings.push({ kind: 'stylesheet from elsewhere', detail: attrs.get('href') ?? '' });
    }
    for (const [name, value] of attrs) {
      const lowered = name.toLowerCase();
      if (lowered === 'style') findings.push({ kind: 'style attribute', detail: `<${tag} style="${value}">` });
      if (lowered.startsWith('on')) findings.push({ kind: 'event handler attribute', detail: `<${tag} ${name}>` });
      if (lowered === 'srcdoc') findings.push({ kind: 'srcdoc attribute', detail: `<${tag}>` });
      if (URL_ATTRIBUTES.has(lowered) && /^\s*javascript:/i.test(value)) {
        findings.push({ kind: 'javascript: URL', detail: `<${tag} ${name}>` });
      }
    }
  }
  for (const child of node.childNodes ?? []) inspect(child, findings, counts);
  if (node.content) inspect(node.content, findings, counts);
}

// What one HTML document holds that the policy refuses.
export function scanHtml(html) {
  const findings = [];
  const counts = { scripts: 0 };
  // Parsed as a browser without scripting would, so <noscript> content is
  // checked as markup too.
  inspect(parse(html, { scriptingEnabled: false }), findings, counts);
  return { findings, scripts: counts.scripts };
}

function htmlFiles(dir) {
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.html'))
    .map((entry) => join(entry.parentPath, entry.name))
    .sort();
}

export function scanExport(dir) {
  const files = htmlFiles(dir);
  const findings = [];
  let scripts = 0;
  for (const file of files) {
    const result = scanHtml(readFileSync(file, 'utf8'));
    scripts += result.scripts;
    for (const finding of result.findings) findings.push({ file: relative(dir, file), ...finding });
  }
  return { files: files.length, scripts, findings };
}

export function main(argv) {
  const dir = argv[0] ?? 'out';
  let result;
  try {
    result = scanExport(dir);
  } catch (error) {
    console.error(`Cannot read the export in ${dir}: ${error.message}. Run \`npm run build\` first.`);
    return 1;
  }
  if (result.files === 0) {
    console.error(`No HTML files in ${dir}. Run \`npm run build\` first.`);
    return 1;
  }
  for (const finding of result.findings) {
    console.error(`${finding.file}: ${finding.kind}${finding.detail ? `: ${finding.detail}` : ''}`);
  }
  console.log(
    `CSP scan: ${result.files} HTML files, ${result.scripts} script elements, ${result.findings.length} violations.`,
  );
  return result.findings.length === 0 ? 0 : 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exit(main(process.argv.slice(2)));
}
