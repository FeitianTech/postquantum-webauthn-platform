import { beforeEach, describe, expect, it, vi } from 'vitest';

import { FilterDropdown, createFilterDropdown } from '../../static/scripts/advanced/mds-dropdown.js';

function setupDom() {
  document.body.innerHTML = `
    <div id="wrapper-a"><input id="input-a" /></div>
    <div id="wrapper-b"><input id="input-b" /></div>
  `;
  return {
    inputA: document.getElementById('input-a'),
    inputB: document.getElementById('input-b'),
    wrapperA: document.getElementById('wrapper-a'),
    wrapperB: document.getElementById('wrapper-b'),
  };
}

describe('mds-dropdown', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('constructs dropdown, normalizes options, and supports open/close/filter', () => {
    const { inputA, wrapperA } = setupDom();
    const onSelect = vi.fn();

    const dropdown = new FilterDropdown(inputA, onSelect, { expandDropdown: true });

    expect(wrapperA.classList.contains('mds-filter-cell')).toBe(true);
    expect(dropdown.container.classList.contains('mds-filter-dropdown--expanded')).toBe(true);

    dropdown.setOptions(['Zulu', 'alpha', 'Alpha', '', 'beta']);
    expect(dropdown.options).toEqual(['alpha', 'Alpha', 'beta', 'Zulu']);

    dropdown.open();
    expect(dropdown.container.hidden).toBe(false);
    expect(dropdown.container.classList.contains('is-open')).toBe(true);

    dropdown.filter('alp');
    expect(dropdown.filtered).toEqual(['alpha', 'Alpha']);

    dropdown.filter('no-match');
    expect(dropdown.list.textContent).toContain('No matches');

    dropdown.close();
    expect(dropdown.container.hidden).toBe(true);
    expect(dropdown.activeIndex).toBe(-1);
  });

  it('keeps dropdown closed when no options and handles empty render states', () => {
    const { inputA } = setupDom();
    const dropdown = new FilterDropdown(inputA, vi.fn());

    dropdown.open();
    expect(dropdown.container.hidden).toBe(true);

    dropdown.list = null;
    expect(() => dropdown.render()).not.toThrow();

    dropdown.list = document.createElement('ul');
    dropdown.options = [];
    dropdown.filtered = [];
    dropdown.render();
    expect(dropdown.list.children.length).toBe(0);
  });

  it('closes previously active dropdown when another opens', () => {
    const { inputA, inputB } = setupDom();
    const first = new FilterDropdown(inputA, vi.fn());
    const second = new FilterDropdown(inputB, vi.fn());

    first.setOptions(['a']);
    second.setOptions(['b']);

    first.open();
    expect(first.container.hidden).toBe(false);

    second.open();
    expect(first.container.hidden).toBe(true);
    expect(second.container.hidden).toBe(false);
  });

  it('handles keyboard navigation and enter selection', () => {
    const { inputA } = setupDom();
    const onSelect = vi.fn();
    const dropdown = new FilterDropdown(inputA, onSelect);
    dropdown.setOptions(['one', 'two']);

    const scrollSpy = vi.spyOn(HTMLElement.prototype, 'scrollIntoView').mockImplementation(() => {});

    dropdown.handleKeyDown({ key: 'ArrowDown', preventDefault: vi.fn() });
    expect(dropdown.activeIndex).toBe(0);

    dropdown.handleKeyDown({ key: 'ArrowUp', preventDefault: vi.fn() });
    expect(dropdown.activeIndex).toBe(1);

    dropdown.handleKeyDown({
      key: 'Enter',
      preventDefault: vi.fn(),
    });

    expect(inputA.value).toBe('two');
    expect(onSelect).toHaveBeenCalledWith('two');

    dropdown.open();
    dropdown.handleKeyDown({ key: 'Escape' });
    expect(dropdown.container.hidden).toBe(true);

    scrollSpy.mockRestore();
  });

  it('move handles empty item lists safely', () => {
    const { inputA } = setupDom();
    const dropdown = new FilterDropdown(inputA, vi.fn());

    dropdown.options = [];
    dropdown.filtered = [];
    dropdown.move(1);
    expect(dropdown.activeIndex).toBe(-1);
  });

  it('select and document-click interactions close and notify correctly', () => {
    const { inputA } = setupDom();
    const onSelect = vi.fn();
    const dropdown = new FilterDropdown(inputA, onSelect);
    dropdown.setOptions(['hello']);
    dropdown.open();

    dropdown.select('hello');
    expect(inputA.value).toBe('hello');
    expect(onSelect).toHaveBeenCalledWith('hello');
    expect(dropdown.container.hidden).toBe(true);

    dropdown.open();
    dropdown.handleDocumentClick({ target: document.body });
    expect(dropdown.container.hidden).toBe(true);

    dropdown.open();
    dropdown.handleDocumentClick({ target: inputA });
    expect(dropdown.container.hidden).toBe(false);
  });

  it('wires input and container event handlers and exposes factory helper', () => {
    const { inputA } = setupDom();
    const onSelect = vi.fn();

    const dropdown = createFilterDropdown(inputA, onSelect);
    expect(dropdown).toBeInstanceOf(FilterDropdown);

    dropdown.setOptions(['item-a']);

    inputA.dispatchEvent(new Event('focus'));
    expect(dropdown.container.hidden).toBe(false);

    inputA.value = 'item';
    inputA.dispatchEvent(new Event('input'));
    expect(dropdown.filtered).toEqual(['item-a']);

    const preventDefault = vi.fn();
    dropdown.container.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, cancelable: true }));

    const option = dropdown.list.querySelector('.mds-filter-dropdown__option');
    option.dispatchEvent(new MouseEvent('click', { bubbles: true }));

    expect(onSelect).toHaveBeenCalledWith('item-a');

    // exercise key path where there are no options
    const emptyInput = document.createElement('input');
    document.body.appendChild(emptyInput);
    const emptyDropdown = new FilterDropdown(emptyInput, vi.fn());
    expect(() => emptyDropdown.handleKeyDown({ key: 'ArrowDown', preventDefault })).not.toThrow();
  });
});
