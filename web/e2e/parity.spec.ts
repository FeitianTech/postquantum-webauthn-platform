import { expect, test } from '@playwright/test';

import { compareShownText, describeDifferences, readShownRows, readShownText } from './parity';

// The parity check itself: it must see a missing, an extra and a doubled word,
// and read a region as the comparison expects.

test('finds a missing, an extra and a doubled word, section by section', () => {
  const legacy = [
    { heading: '', lines: ['Codec Output', 'offset 8 · ${1} — map key 1 appears twice'] },
    { heading: 'EDN (exact bytes)', lines: ['{1: "a", 1: "c"}'] },
  ];
  expect(compareShownText(legacy, [{ heading: '', lines: ['Codec Output', 'offset 8', '${1}', 'map key 1 appears twice'] }, { heading: 'EDN (exact bytes)', lines: ['{1: "a",', '1: "c"}'] }])).toEqual([]);

  const differences = compareShownText(legacy, [
    { heading: '', lines: ['Codec Output', 'Codec', 'offset ${1} map key 1 appears twice', 'canonical'] },
  ], [{ only: 'beta', token: /^canonical$/, reason: 'a new chip' }]);
  // "8" is missing, "Codec" doubled, the chip explained, and the EDN section gone.
  expect(differences.map(({ section, only, token, count, reason }) => [section, only, token, count, reason ?? null])).toEqual([
    ['', 'legacy', '8', 1, null],
    ['', 'beta', 'Codec', 1, null],
    ['', 'beta', 'canonical', 1, 'a new chip'],
    ['EDN (exact bytes)', 'legacy', 'EDN', 1, null],
    ['EDN (exact bytes)', 'legacy', '(exact', 1, null],
    ['EDN (exact bytes)', 'legacy', 'bytes)', 1, null],
    ['EDN (exact bytes)', 'legacy', '{1', 1, null],
    ['EDN (exact bytes)', 'legacy', '"a"', 1, null],
    ['EDN (exact bytes)', 'legacy', '1', 1, null],
    ['EDN (exact bytes)', 'legacy', '"c"}', 1, null],
  ]);
  expect(describeDifferences(differences).slice(0, 3)).toEqual([
    '[header] only in the recording: "8" (in "offset 8 · ${1} — map key 1 appears twice") — UNEXPLAINED',
    '[header] only in /beta: "Codec" (in "Codec") — UNEXPLAINED',
    '[header] only in /beta: "canonical" (in "canonical") — a new chip',
  ]);
});

test('explains a difference only in the section an expected difference names', () => {
  const legacy = [{ heading: 'Details', lines: ['Base: 10'] }, { heading: 'Other', lines: ['Base: 10'] }];
  const beta = [{ heading: 'Details', lines: ['Base: 10', 'FAR: 0.1'] }, { heading: 'Other', lines: ['Base: 10', 'FAR: 0.1'] }];
  const differences = compareShownText(legacy, beta, [{ only: 'beta', token: /^(FAR|0\.1)$/, section: 'Details', reason: 'new' }]);
  expect(differences.map(({ section, token, reason }) => [section, token, reason ?? null])).toEqual([
    ['Details', 'FAR', 'new'],
    ['Details', '0.1', 'new'],
    ['Other', 'FAR', null],
    ['Other', '0.1', null],
  ]);
});

test('reads text by section, skipping controls and what is hidden, with closed details and text areas', async ({ page }) => {
  await page.setContent(`
    <div id="region">
      <h3>Codec Output</h3><button>Raw</button><span>Success</span><span aria-hidden="true">✓</span>
      <div class="section"><h4>Decoded value</h4><dl><dt>1</dt><dd>c</dd></dl></div>
      <details class="section"><summary><h4>EDN (exact bytes)</h4></summary><pre>{1: "a",\n 1: "c"}</pre></details>
      <div class="section"><h4>Expanded JSON</h4><textarea>{"decoded json": 1}</textarea><span class="sr-only">copied</span></div>
    </div>`);
  expect(await readShownText(page.locator('#region'), '.section h4')).toEqual([
    { heading: '', lines: ['Codec Output', 'Success'] },
    { heading: 'Decoded value', lines: ['1', 'c'] },
    { heading: 'EDN (exact bytes)', lines: ['{1: "a",', '1: "c"}'] },
    { heading: 'Expanded JSON', lines: ['{"decoded json": 1}'] },
  ]);
});

test('reads a table a row at a time, keyed by a cell, keeping the text of controls and skipping what is hidden', async ({ page }) => {
  await page.setContent(`
    <table><tbody>
      <tr><td><img alt="An icon"></td><td><button>Key one</button></td><td>abc<span class="sr-only">copied</span><span aria-hidden="true">×</span></td></tr>
      <tr hidden><td></td><td>Hidden</td><td>def</td></tr>
      <tr><td>N/A</td><td><a href="#x">Key two</a></td><td>ghi</td></tr>
    </tbody></table>
    <style>.sr-only { position: absolute; }</style>`);
  const rows = await readShownRows(page.locator('tbody'), 'tr:not([hidden])', 2);
  expect(rows).toEqual([
    { heading: 'abc', lines: ['Key one', 'abc'] },
    { heading: 'ghi', lines: ['N/A', 'Key two', 'ghi'] },
  ]);
});
