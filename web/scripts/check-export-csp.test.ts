import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { main, scanExport, scanHtml } from './check-export-csp.mjs';

const page = (head: string, body = '') => `<!DOCTYPE html><html><head>${head}</head><body>${body}</body></html>`;
const kinds = (html: string) => scanHtml(html).findings.map((finding: { kind: string }) => finding.kind);

describe('the export CSP scan', () => {
  it('accepts what a Pages Router export holds', () => {
    const html = page(
      '<link rel="stylesheet" href="/beta/_next/static/css/a.css"><noscript data-n-css=""></noscript>' +
        '<script defer nomodule src="/beta/_next/static/chunks/polyfills.js"></script>',
      '<div id="__next"><svg viewBox="0 0 16 16"><path d="M0 0"/></svg></div>' +
        '<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>',
    );
    expect(scanHtml(html)).toEqual({ findings: [], scripts: 2 });
  });

  it('refuses an inline script that would run, whatever its type says', () => {
    expect(kinds(page('<script>alert(1)</script>'))).toEqual(['inline script']);
    expect(kinds(page('<script type="module">import "x"</script>'))).toEqual(['inline script']);
    expect(kinds(page('<script type="text/javascript">1</script>'))).toEqual(['inline script']);
    expect(scanHtml(page('<script>self.__next_f.push(1)</script>')).findings[0].detail).toBe('self.__next_f.push(1)');
  });

  it('refuses style elements and style attributes, in HTML and SVG and inside noscript', () => {
    expect(kinds(page('<style>body{}</style>'))).toEqual(['style element']);
    expect(kinds(page('', '<p style="color:red">x</p>'))).toEqual(['style attribute']);
    expect(kinds(page('', '<svg><rect style="fill:red"/></svg>'))).toEqual(['style attribute']);
    expect(kinds(page('<noscript><style>p{}</style></noscript>'))).toEqual(['style element']);
    expect(kinds(page('', '<template><b style="x"></b></template>'))).toEqual(['style attribute']);
  });

  it('refuses handlers, javascript: URLs and srcdoc', () => {
    expect(kinds(page('', '<img src="/beta/a.png" onerror="x()">'))).toEqual(['event handler attribute']);
    expect(kinds(page('', '<a href=" JavaScript:alert(1)">x</a>'))).toEqual(['javascript: URL']);
    expect(kinds(page('', '<iframe srcdoc="<p>x</p>"></iframe>'))).toEqual(['srcdoc attribute']);
  });

  it('refuses scripts and stylesheets from outside the base path', () => {
    expect(kinds(page('<script src="https://cdn.example/x.js"></script>'))).toEqual(['script from elsewhere']);
    expect(kinds(page('<script src="/_next/static/x.js"></script>'))).toEqual(['script from elsewhere']);
    expect(kinds(page('<link rel="preload stylesheet" href="https://fonts.googleapis.com/css">'))).toEqual([
      'stylesheet from elsewhere',
    ]);
    expect(kinds(page('<link rel="stylesheet">'))).toEqual(['stylesheet from elsewhere']);
  });

  describe('over an export directory', () => {
    let dir: string;
    afterEach(() => {
      rmSync(dir, { recursive: true, force: true });
      vi.restoreAllMocks();
    });

    function exportWith(files: Record<string, string>) {
      dir = mkdtempSync(join(tmpdir(), 'csp-scan-'));
      for (const [name, content] of Object.entries(files)) {
        mkdirSync(join(dir, name, '..'), { recursive: true });
        writeFileSync(join(dir, name), content);
      }
      return dir;
    }

    it('scans every HTML file, in subdirectories too, and names the file of each finding', () => {
      exportWith({
        'index.html': page('<script src="/beta/a.js"></script>'),
        'nested/design.html': page('', '<p style="x"></p>'),
        '_next/static/a.js': 'console.log(1)',
      });
      expect(scanExport(dir)).toEqual({
        files: 2,
        scripts: 1,
        findings: [{ file: join('nested', 'design.html'), kind: 'style attribute', detail: '<p style="x">' }],
      });
    });

    it('exits 0 on a clean export and 1 on a violation, an empty export or a missing one', () => {
      const log = vi.spyOn(console, 'log').mockImplementation(() => {});
      const error = vi.spyOn(console, 'error').mockImplementation(() => {});

      exportWith({ 'index.html': page('') });
      expect(main([dir])).toBe(0);
      expect(log).toHaveBeenLastCalledWith('CSP scan: 1 HTML files, 0 script elements, 0 violations.');

      writeFileSync(join(dir, 'bad.html'), page('<style></style>'));
      expect(main([dir])).toBe(1);
      expect(error).toHaveBeenCalledWith('bad.html: style element');

      rmSync(join(dir, 'bad.html'));
      rmSync(join(dir, 'index.html'));
      expect(main([dir])).toBe(1);
      expect(error).toHaveBeenLastCalledWith(`No HTML files in ${dir}. Run \`npm run build\` first.`);

      expect(main([join(dir, 'missing')])).toBe(1);
      expect(error.mock.lastCall?.[0]).toMatch(/^Cannot read the export in .*missing: .* Run `npm run build` first\.$/);
    });
  });
});
