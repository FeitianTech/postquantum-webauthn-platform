// The page's markup as the server renders it, for tests that need the real
// templates: frontend/templates/index.html with its includes inlined. Only the
// template syntax index.html uses is understood; anything else throws, so a new
// construct in a template cannot slip past the tests unrendered.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const TEMPLATES = resolve(process.cwd(), 'frontend/templates');

function render(name) {
  return readFileSync(resolve(TEMPLATES, name), 'utf8')
    .replace(/\{%\s*include\s+'([^']+)'\s*%\}/g, (_match, included) => render(included))
    .replace(/\{\{\s*asset_url\('([^']+)'\)\s*\}\}/g, (_match, path) => `/assets/test/${path}`)
    .replace(/\{\{\s*initial_mds_info\s*\|\s*tojson\s*\}\}/g, '{}');
}

/** The rendered body: its class and its markup, scripts left out. */
export function renderPageBody() {
  const html = render('index.html');
  const leftover = html.match(/\{[{%][\s\S]*?[}%]\}/);
  if (leftover) {
    throw new Error(`page-template.js does not render ${leftover[0]}`);
  }
  const body = html.match(/<body([^>]*)>([\s\S]*)<\/body>/);
  if (!body) {
    throw new Error('index.html has no <body>');
  }
  const className = (body[1].match(/class="([^"]*)"/) || [])[1] || '';
  return {
    className,
    markup: body[2].replace(/<script\b[\s\S]*?<\/script>/g, ''),
  };
}
