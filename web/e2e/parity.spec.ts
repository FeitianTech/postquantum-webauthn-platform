import { expect, test } from '@playwright/test';

import { compareShownText, describeDifferences, readShownText } from './parity';

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
    '[header] only in the current UI: "8" (in "offset 8 · ${1} — map key 1 appears twice") — UNEXPLAINED',
    '[header] only in /beta: "Codec" (in "Codec") — UNEXPLAINED',
    '[header] only in /beta: "canonical" (in "canonical") — a new chip',
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
