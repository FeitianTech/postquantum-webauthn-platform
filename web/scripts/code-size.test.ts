import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { MAX_FUNCTION_LINES, MAX_MODULE_LINES, checkTree, main, measureSource } from './code-size.mjs';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src');

type Measured = { name: string; lines: number };
const lengths = (text: string, path = 'a.js') =>
  Object.fromEntries(measureSource(text, path).functions.map(({ name, lines }: Measured) => [name, lines]));
const body = (lines: number) => Array.from({ length: lines }, (_, index) => `  const v${index} = ${index};`).join('\n');

describe('the web code size guard', () => {
  it('finds no function over 120 lines and no module over 400 lines in src', () => {
    expect([MAX_FUNCTION_LINES, MAX_MODULE_LINES]).toEqual([120, 400]);
    const found = checkTree(SRC);
    expect(found.modules).toBeGreaterThan(150);
    expect(found.longFunctions).toEqual([]);
    expect(found.longModules).toEqual([]);
  });
});

describe('the measure', () => {
  it('counts a function from its first line to its last, its JSDoc aside', () => {
    const text = `/**\n * Says hello.\n * @returns {string}\n */\nexport function hello() {\n${body(3)}\n}\n`;
    expect(lengths(text)).toEqual({ 'a.js::hello': 5 });
  });

  it('counts a function inside another for both', () => {
    const text = `function outer() {\n  function inner() {\n    return 1;\n  }\n  return inner();\n}\n`;
    expect(lengths(text)).toEqual({ 'a.js::outer': 6, 'a.js::outer.inner': 3 });
  });

  it('names an arrow or a function expression for what it is given, and anything else for where it is', () => {
    const text = [
      'const arrow = () => 1;',
      'const expression = function () { return 2; };',
      'const object = { property: () => 3, method() { return 4; } };',
      'class Thing {',
      '  constructor() {}',
      '  get size() { return 5; }',
      '  set size(value) {}',
      '}',
      '[1].map((x) => x).filter((y) => y);',
    ].join('\n');
    expect(measureSource(text, 'b.ts').functions.map(({ name }: Measured) => name)).toEqual([
      'b.ts::arrow',
      'b.ts::expression',
      'b.ts::property',
      'b.ts::method',
      'b.ts::constructor',
      'b.ts::size',
      'b.ts::size',
      'b.ts::<anonymous@9:9>',
      'b.ts::<anonymous@9:26>',
    ]);
  });

  it('reads TSX', () => {
    const text = 'export function View({ name }: { name: string }) {\n  return <p>{name}</p>;\n}\n';
    expect(lengths(text, 'View.tsx')).toEqual({ 'View.tsx::View': 3 });
  });

  it('counts a module\'s lines, with or without a final newline', () => {
    expect(measureSource('a;\nb;\n', 'a.js').lines).toBe(2);
    expect(measureSource('a;\nb;', 'a.js').lines).toBe(2);
  });
});

describe('the tree it reads, and the command', () => {
  let root = '';

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function tree(files: Record<string, string>) {
    root = mkdtempSync(join(tmpdir(), 'code-size-'));
    for (const [path, text] of Object.entries(files)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), text);
    }
    return root;
  }

  const long = `function long() {\n${body(MAX_FUNCTION_LINES - 1)}\n}\n`;
  const fits = `function fits() {\n${body(MAX_FUNCTION_LINES - 2)}\n}\n`;

  it('reports a function or a module over the limit, and leaves out tests and the test helpers', () => {
    const dir = tree({
      'a.js': fits,
      'deep/b.ts': long,
      'c.tsx': 'x;\n'.repeat(MAX_MODULE_LINES + 1),
      'd.test.js': long,
      'test/helper.js': long,
      'notes.md': long,
    });
    expect(checkTree(dir)).toEqual({
      modules: 3,
      longFunctions: [{ name: 'deep/b.ts::long', lines: MAX_FUNCTION_LINES + 1 }],
      longModules: [{ path: 'c.tsx', lines: MAX_MODULE_LINES + 1 }],
    });
  });

  it('says what is over the limits and fails, or says none is', () => {
    const said: string[] = [];
    expect(main([tree({ 'a.js': long, 'b.js': 'x;\n'.repeat(MAX_MODULE_LINES + 1) })], (line: string) => said.push(line))).toBe(1);
    expect(said).toEqual([
      `function over 120 lines: a.js::long (${MAX_FUNCTION_LINES + 1})`,
      `module over 400 lines: b.js (${MAX_MODULE_LINES + 1})`,
      '2 modules read; 2 over the limits',
    ]);
    rmSync(root, { recursive: true, force: true });

    said.length = 0;
    expect(main([tree({ 'a.js': fits })], (line: string) => said.push(line))).toBe(0);
    expect(said).toEqual(['1 modules read; none over the limits']);
  });
});
