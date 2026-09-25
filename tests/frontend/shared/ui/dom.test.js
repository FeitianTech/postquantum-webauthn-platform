import { describe, expect, it, vi } from 'vitest';

import { el, fragment } from '../../../../frontend/static/scripts/shared/ui/dom.js';

const PAYLOAD = '"><img src=x onerror="window.__xss=1">';

describe('el', () => {
  it('sets class, attributes, dataset, style and text without parsing any of them', () => {
    const node = el('button', {
      className: 'btn btn-small',
      attrs: { type: 'button', title: PAYLOAD, disabled: true, hidden: false, 'aria-label': null },
      dataset: { credentialId: PAYLOAD, index: 3, skipped: undefined },
      style: 'color: #0f2740;',
      text: PAYLOAD,
    });

    expect(node.tagName).toBe('BUTTON');
    expect(node.className).toBe('btn btn-small');
    expect(node.getAttribute('title')).toBe(PAYLOAD);
    expect(node.hasAttribute('disabled')).toBe(true);
    expect(node.getAttribute('disabled')).toBe('');
    expect(node.hasAttribute('hidden')).toBe(false);
    expect(node.hasAttribute('aria-label')).toBe(false);
    expect(node.dataset.credentialId).toBe(PAYLOAD);
    expect(node.dataset.index).toBe('3');
    expect('skipped' in node.dataset).toBe(false);
    expect(node.style.color).toBe('rgb(15, 39, 64)');
    expect(node.textContent).toBe(PAYLOAD);
    expect(node.querySelector('img')).toBeNull();
  });

  it('appends text, nodes and nested arrays in order and skips empty children', () => {
    const child = el('strong', { text: 'Name:' });
    const node = el('div', {}, child, ' ', PAYLOAD, 7, [el('em', { text: 'a' }), ['b', null]], undefined, false, true);

    expect(node.childNodes).toHaveLength(6);
    expect(node.firstChild).toBe(child);
    expect(node.textContent).toBe(`Name: ${PAYLOAD}7ab`);
    expect(node.querySelector('img')).toBeNull();
  });

  it('puts children after the text option', () => {
    const node = el('p', { text: 'first' }, el('span', { text: 'second' }));

    expect(node.textContent).toBe('firstsecond');
  });

  it('applies style through CSSOM, never as a style attribute a strict CSP refuses', () => {
    const setAttribute = vi.spyOn(Element.prototype, 'setAttribute');

    const node = el('p', { style: 'color: #6c757d; margin-top: 0.75rem;' });

    expect(setAttribute).not.toHaveBeenCalled();
    expect(node.style.color).toBe('rgb(108, 117, 125)');
    expect(node.style.marginTop).toBe('0.75rem');
    setAttribute.mockRestore();
  });

  it('accepts no options at all', () => {
    expect(el('div').outerHTML).toBe('<div></div>');
    expect(el('div', null, 'x').textContent).toBe('x');
  });

  it.each(['onclick', 'onError', 'ONLOAD', 'innerHTML', 'outerHTML', 'srcdoc'])(
    'refuses the %s attribute',
    (name) => {
      expect(() => el('div', { attrs: { [name]: 'window.__xss=1' } })).toThrow(/does not set/);
    },
  );
});

describe('fragment', () => {
  it('collects children the way el does', () => {
    const node = fragment(el('span', { text: 'a' }), 'b', [null, 'c']);

    expect(node).toBeInstanceOf(DocumentFragment);
    expect(node.textContent).toBe('abc');
    expect(node.childNodes).toHaveLength(3);
  });
});
