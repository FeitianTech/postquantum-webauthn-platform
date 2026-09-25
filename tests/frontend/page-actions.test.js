import { describe, expect, it, vi } from 'vitest';

import { renderPageBody } from './page-template.js';

const SCRIPTS = '../../frontend/static/scripts';

// Actions local to an area whose module handles them without an action table
// (the Analyze Browser panel and the MDS custom-metadata panel).
const AREA_LOCAL_ACTIONS = new Set(['close', 'copy-report']);

async function loadActionTables() {
  const navigation = await import(`${SCRIPTS}/shared/ui/navigation.js`);
  return {
    navigation: navigation.navigationActions,
  };
}

// Every handler becomes a spy that records (table, name, event type, control)
// instead of doing its work.
function spyOnTables(tables, calls) {
  Object.entries(tables).forEach(([tableName, table]) => {
    Object.entries(table).forEach(([name, entry]) => {
      if (typeof entry === 'function') {
        vi.spyOn(table, name).mockImplementation(control => calls.push([tableName, name, 'click', control]));
        return;
      }
      Object.keys(entry).forEach(type => {
        vi.spyOn(entry, type).mockImplementation(control => calls.push([tableName, name, type, control]));
      });
    });
  });
}

function eventsFor(tables, name) {
  const owners = Object.entries(tables).filter(([, table]) => Object.hasOwn(table, name));
  return owners.flatMap(([, table]) => (typeof table[name] === 'function' ? ['click'] : Object.keys(table[name])));
}

describe('page actions', () => {
  // One test, so the listeners main.js puts on the document are bound once.
  it('runs exactly the owning handler for every data-action control in the page', async () => {
    const { className, markup } = renderPageBody();
    document.body.className = className;
    document.body.innerHTML = markup;

    vi.resetModules();
    const tables = await loadActionTables();
    const calls = [];
    spyOnTables(tables, calls);

    await import(`${SCRIPTS}/main.js`);
    const { initializeStickyHeader } = await import(`${SCRIPTS}/shared/ui/core.js`);
    initializeStickyHeader();

    const controls = Array.from(document.querySelectorAll('[data-action]'))
      .filter(control => !AREA_LOCAL_ACTIONS.has(control.dataset.action));
    expect(controls.length).toBeGreaterThan(0);
    expect(document.querySelectorAll('.header-mini .nav-tab[data-action]')).toHaveLength(4);

    const used = new Set();
    controls.forEach(control => {
      const name = control.dataset.action;
      const types = eventsFor(tables, name);
      expect(types, `no table handles data-action="${name}"`).not.toEqual([]);
      used.add(name);

      types.forEach(type => {
        calls.length = 0;
        if (type === 'click') {
          const target = control.querySelector('path') || control;
          target.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
        } else {
          control.dispatchEvent(new MouseEvent(type, { bubbles: false }));
        }

        const where = `${control.outerHTML.slice(0, 120)} (${type})`;
        if (control.matches(':disabled')) {
          expect(calls, where).toEqual([]);
          return;
        }
        expect(calls, where).toHaveLength(1);
        expect(calls[0][1], where).toBe(name);
        expect(calls[0][2], where).toBe(type);
        expect(calls[0][3], where).toBe(control);
      });
    });

    const unused = Object.values(tables).flatMap(table => Object.keys(table)).filter(name => !used.has(name));
    expect(unused, 'table entries no control in the page names').toEqual([]);
  });
});
