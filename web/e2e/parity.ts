import type { Locator } from '@playwright/test';

// Does the new UI show what the current one shows? For one surface in both UIs:
// read the text a region shows, grouped by the section it sits in, and compare
// the two as multisets of words, so layout, element boundaries, separators
// ("·", "—", ":") and CSS text-transform do not count, but a missing, extra or
// doubled word does. Each difference a surface expects is listed with its reason.
// Later phases use it for their surfaces the way codec-parity.spec.ts does.

export type ShownSection = { heading: string; lines: string[] };

export type ExpectedDifference = {
  /** Which UI shows the words the other does not. */
  only: 'legacy' | 'beta';
  /** The words, as one token each. */
  token: RegExp;
  reason: string;
};

export type Difference = { section: string; only: 'legacy' | 'beta'; token: string; count: number; line: string; reason?: string };

// What is not content: controls (their labels are the UI's, not the data's),
// what assistive technology does not read, and what a page marks as chrome.
const SKIP = 'button, [aria-hidden="true"], .sr-only, [hidden], script, style, [data-parity-skip]';

/**
 * The text `region` shows, in document order, split into sections at each
 * element matching `headingSelector` (text before the first goes under "").
 * Uses textContent, so a closed <details> and CSS text-transform read as the
 * DOM holds them, and a textarea's value.
 */
export function readShownText(region: Locator, headingSelector: string): Promise<ShownSection[]> {
  return region.evaluate(
    (root, { headingSelector: selector, skip }) => {
      const sections: { heading: string; lines: string[] }[] = [{ heading: '', lines: [] }];
      const tidy = (text: string) => text.replace(/\s+/g, ' ').trim();
      const add = (text: string) => {
        for (const line of text.split('\n')) {
          if (tidy(line)) sections[sections.length - 1].lines.push(tidy(line));
        }
      };
      const walk = (node: Node) => {
        if (node.nodeType === Node.TEXT_NODE) {
          add(node.textContent ?? '');
          return;
        }
        if (!(node instanceof Element) || node.matches(skip)) return;
        if (node.matches(selector)) {
          sections.push({ heading: tidy(node.textContent ?? ''), lines: [] });
          return;
        }
        if (node instanceof HTMLTextAreaElement) {
          add(node.value);
          return;
        }
        node.childNodes.forEach(walk);
      };
      root.childNodes.forEach(walk);
      return sections.filter((section) => section.heading || section.lines.length);
    },
    { headingSelector, skip: SKIP },
  );
}

const EDGE = /^[\s:,·—•]+|[\s:,·—•]+$/g;

function tokens(line: string) {
  return line
    .normalize('NFC')
    .split(/\s+/)
    .map((token) => token.replace(EDGE, ''))
    .filter(Boolean);
}

// Each word, with the line of each time it appears.
function occurrences(lines: string[]) {
  const found = new Map<string, string[]>();
  for (const line of lines) {
    for (const token of tokens(line)) found.set(token, [...(found.get(token) ?? []), line]);
  }
  return found;
}

// The lines of `mine` left once each line of `theirs` has matched one: where the extra words are.
function unmatched(mine: string[], theirs: string[]) {
  const left = [...theirs];
  return mine.filter((line) => {
    const index = left.indexOf(line);
    if (index < 0) return true;
    left.splice(index, 1);
    return false;
  });
}

/**
 * Every word one UI shows in a section more often than the other, with the line
 * it came from. A difference an `expected` entry explains carries its reason.
 */
export function compareShownText(legacy: ShownSection[], beta: ShownSection[], expected: ExpectedDifference[] = []): Difference[] {
  const bySection = (sections: ShownSection[]) => {
    const map = new Map<string, string[]>();
    for (const section of sections) map.set(section.heading, [...(map.get(section.heading) ?? []), ...section.lines]);
    return map;
  };
  const left = bySection(legacy);
  const right = bySection(beta);
  const differences: Difference[] = [];
  for (const heading of new Set([...left.keys(), ...right.keys()])) {
    const legacyWords = occurrences(left.has(heading) ? [heading, ...left.get(heading)!] : []);
    const betaWords = occurrences(right.has(heading) ? [heading, ...right.get(heading)!] : []);
    for (const [only, mine, theirs] of [
      ['legacy', legacyWords, betaWords],
      ['beta', betaWords, legacyWords],
    ] as const) {
      for (const [token, lines] of mine) {
        const extra = lines.length - (theirs.get(token)?.length ?? 0);
        if (extra <= 0) continue;
        const line = unmatched(lines, theirs.get(token) ?? [])[0] ?? lines[0];
        const reason = expected.find((entry) => entry.only === only && entry.token.test(token))?.reason;
        differences.push({ section: heading, only, token, count: extra, line, ...(reason ? { reason } : {}) });
      }
    }
  }
  return differences;
}

/** The differences as lines for a report: explained ones with their reason. */
export function describeDifferences(differences: Difference[]) {
  return differences.map(
    ({ section, only, token, count: extra, line, reason }) =>
      `[${section || 'header'}] only in ${only === 'beta' ? '/beta' : 'the current UI'}: "${token}"${extra > 1 ? ` ×${extra}` : ''}` +
      ` (in "${line}")${reason ? ` — ${reason}` : ' — UNEXPLAINED'}`,
  );
}
