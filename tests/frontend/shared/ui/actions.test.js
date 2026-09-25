import { beforeEach, describe, expect, it, vi } from 'vitest';

import { bindActions } from '../../../../frontend/static/scripts/shared/ui/actions.js';

function hover(element, type) {
  element.dispatchEvent(new MouseEvent(type, { bubbles: false }));
}

describe('bindActions', () => {
  let area;
  let outside;

  beforeEach(() => {
    document.body.innerHTML = `
      <div id="area">
        <button type="button" data-action="go" data-where="there">
          <svg viewBox="0 0 16 16"><path d="M4 4l8 8"></path></svg>
        </button>
        <button type="button" data-action="go" disabled><svg><path d="M1 1"></path></svg></button>
        <button type="button" data-action="elsewhere">Not ours</button>
        <div class="icon" data-action="tip"><div class="popup"><span class="inner">text</span></div></div>
        <p class="plain">No action</p>
      </div>
      <div id="outside"><button type="button" data-action="go">Outside</button></div>
    `;
    area = document.getElementById('area');
    outside = document.getElementById('outside');
  });

  it('calls the named action with its control when a descendant is clicked', () => {
    const go = vi.fn();
    bindActions(area, { go });

    area.querySelector('path').dispatchEvent(new MouseEvent('click', { bubbles: true }));

    const button = area.querySelector('[data-where]');
    expect(go).toHaveBeenCalledTimes(1);
    expect(go.mock.calls[0][0]).toBe(button);
    expect(go.mock.calls[0][1]).toBeInstanceOf(MouseEvent);
    expect(go.mock.calls[0][0].dataset.where).toBe('there');
  });

  it('skips a disabled control, even through a click on its icon', () => {
    const go = vi.fn();
    bindActions(area, { go });

    area.querySelector('button[disabled] path').dispatchEvent(new MouseEvent('click', { bubbles: true }));

    expect(go).not.toHaveBeenCalled();
  });

  it('ignores names it does not own, clicks on nothing, and controls outside its root', () => {
    const go = vi.fn();
    bindActions(area, { go });

    area.querySelector('[data-action="elsewhere"]').click();
    area.querySelector('.plain').click();
    outside.querySelector('button').click();
    area.dispatchEvent(new Event('click'));

    expect(go).not.toHaveBeenCalled();
  });

  it('reads the table when the event arrives', () => {
    const table = { go: vi.fn() };
    bindActions(area, table);
    const replacement = vi.fn();
    table.go = replacement;

    area.querySelector('[data-where]').click();

    expect(replacement).toHaveBeenCalledTimes(1);
  });

  it('does not follow inherited names', () => {
    const table = Object.create({ go: vi.fn() });
    bindActions(area, table);

    area.querySelector('[data-where]').click();

    expect(Object.getPrototypeOf(table).go).not.toHaveBeenCalled();
  });

  it('runs hover handlers only for the element that names the action', () => {
    const enter = vi.fn();
    const leave = vi.fn();
    const click = vi.fn();
    bindActions(area, { tip: { mouseenter: enter, mouseleave: leave, click } });
    const icon = area.querySelector('.icon');

    hover(icon, 'mouseenter');
    hover(icon.querySelector('.popup'), 'mouseenter');
    hover(icon.querySelector('.inner'), 'mouseleave');
    hover(icon, 'mouseleave');
    icon.querySelector('.inner').click();

    expect(enter).toHaveBeenCalledTimes(1);
    expect(enter.mock.calls[0][0]).toBe(icon);
    expect(leave).toHaveBeenCalledTimes(1);
    expect(leave.mock.calls[0][0]).toBe(icon);
    expect(click).toHaveBeenCalledTimes(1);
  });

  it('treats a function as a click handler only', () => {
    const tip = vi.fn();
    bindActions(area, { tip });

    hover(area.querySelector('.icon'), 'mouseenter');

    expect(tip).not.toHaveBeenCalled();
  });

  it('adds no listener for events the table does not use', () => {
    const add = vi.spyOn(area, 'addEventListener');

    bindActions(area, { go: vi.fn() });
    bindActions(area, { tip: { mouseenter: vi.fn() } });
    bindActions(area, { broken: null, other: { click: 'not a function' } });

    expect(add.mock.calls.map(call => call[0])).toEqual(['click', 'mouseenter']);
  });

  it('removes its listeners when unbound', () => {
    const go = vi.fn();
    const enter = vi.fn();
    const unbind = bindActions(area, { go, tip: { mouseenter: enter, mouseleave: vi.fn() } });

    unbind();
    area.querySelector('[data-where]').click();
    hover(area.querySelector('.icon'), 'mouseenter');

    expect(go).not.toHaveBeenCalled();
    expect(enter).not.toHaveBeenCalled();
  });

  it('binds nothing without a root', () => {
    expect(bindActions(null, { go: vi.fn() })).toBeTypeOf('function');
    expect(bindActions(undefined, { go: vi.fn() })()).toBeUndefined();
  });

  it('works on the document, for controls spread over several areas', () => {
    const go = vi.fn();
    const unbind = bindActions(document, { go });

    area.querySelector('[data-where]').click();
    outside.querySelector('button').click();
    unbind();

    expect(go).toHaveBeenCalledTimes(2);
  });
});
