#!/usr/bin/env node
// How long the web's own code is, as server/app's is held
// (tests/app/tooling/test_code_size_ratchet.py): no function over 120 lines and
// no module over 400, with no exceptions. Every .js, .ts and .tsx under src is
// read but tests and the test helpers (src/test). A function runs from its first
// line (its JSDoc aside) to its last; a function inside another counts for both.
// Each is named for where it is, `path::outer.inner`: an arrow or a function
// expression takes the name it is given, anything else `<anonymous@line:column>`.
//
//   node scripts/code-size.mjs src

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';

import ts from 'typescript';

export const MAX_FUNCTION_LINES = 120;
export const MAX_MODULE_LINES = 400;

const SOURCE = /\.(js|ts|tsx)$/;
const TEST = /\.test\.(js|ts|tsx)$/;

function isFunction(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function nameOf(node, source) {
  if (node.name && ts.isIdentifier(node.name)) return node.name.text;
  if (ts.isConstructorDeclaration(node)) return 'constructor';
  const parent = node.parent;
  if (parent && (ts.isVariableDeclaration(parent) || ts.isPropertyAssignment(parent) || ts.isPropertyDeclaration(parent))) {
    if (ts.isIdentifier(parent.name)) return parent.name.text;
  }
  const { line, character } = source.getLineAndCharacterOfPosition(node.getStart(source));
  return `<anonymous@${line + 1}:${character + 1}>`;
}

/** Each function's name and length, and the module's length, of one source text. */
export function measureSource(text, path) {
  const kind = path.endsWith('.tsx') ? ts.ScriptKind.TSX : path.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const source = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, kind);
  const lineOf = (position) => source.getLineAndCharacterOfPosition(position).line;
  const functions = [];
  const visit = (node, outer) => {
    let inner = outer;
    if (isFunction(node)) {
      const name = [...outer, nameOf(node, source)];
      functions.push({
        name: `${path}::${name.join('.')}`,
        lines: lineOf(node.getEnd()) - lineOf(node.getStart(source)) + 1,
      });
      inner = name;
    }
    ts.forEachChild(node, (child) => visit(child, inner));
  };
  visit(source, []);
  const lines = text.endsWith('\n') ? text.split('\n').length - 1 : text.split('\n').length;
  return { path, lines, functions };
}

function sources(directory, root) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return relative(root, path) === 'test' ? [] : sources(path, root);
    return SOURCE.test(entry.name) && !TEST.test(entry.name) ? [path] : [];
  });
}

/** What breaks the limits under `root`: the functions too long and the modules too long. */
export function checkTree(root) {
  const modules = sources(root, root).map((path) => measureSource(readFileSync(path, 'utf8'), relative(root, path)));
  return {
    modules: modules.length,
    longFunctions: modules.flatMap((module) => module.functions).filter(({ lines }) => lines > MAX_FUNCTION_LINES),
    longModules: modules.filter(({ lines }) => lines > MAX_MODULE_LINES).map(({ path, lines }) => ({ path, lines })),
  };
}

export function main(argv = process.argv.slice(2), log = console.log) {
  const [root = 'src'] = argv;
  const found = checkTree(root);
  for (const { name, lines } of found.longFunctions) log(`function over ${MAX_FUNCTION_LINES} lines: ${name} (${lines})`);
  for (const { path, lines } of found.longModules) log(`module over ${MAX_MODULE_LINES} lines: ${path} (${lines})`);
  const broken = found.longFunctions.length + found.longModules.length;
  log(`${found.modules} modules read; ${broken ? `${broken} over the limits` : 'none over the limits'}`);
  return broken ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  process.exitCode = main();
}
