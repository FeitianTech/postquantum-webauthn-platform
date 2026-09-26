import { render, screen, within } from '@testing-library/react';

import { ValueView } from './ValueView';

function show(value: unknown, label = 'Value') {
  const { container } = render(<ValueView value={value} label={label} />);
  return container;
}

describe('a decoded value', () => {
  it.each([
    [null, 'null'],
    [undefined, 'undefined'],
    [[], '[]'],
    [{}, '{}'],
  ])('shows %j as muted text (CX-V1, CX-V4)', (value, text) => {
    const container = show(value);
    expect(container).toHaveTextContent(text);
    expect(container.firstElementChild!.className).toContain('text-ink-faint');
  });

  it('keeps a short string on its line in Geist Mono, wrapping rather than overflowing (CX-V2)', () => {
    const container = show('f8a011f3-8c0a-4d15-8006-17111f9edc7d');
    const value = container.firstElementChild!;
    expect(value.tagName).toBe('SPAN');
    expect(value.className).toContain('font-mono');
    expect(value.className).toContain('wrap-anywhere');
  });

  it('puts a long or multi-line string in a block with copy (CX-V2)', () => {
    show('a'.repeat(81), 'Credential ID');
    expect(document.querySelector('pre')!.textContent).toBe('a'.repeat(81));
    expect(screen.getByRole('button', { name: 'Copy Credential ID' })).toBeInTheDocument();
  });

  it('shows numbers and booleans as their text (CX-V3)', () => {
    expect(show(-7)).toHaveTextContent('-7');
    expect(show(true)).toHaveTextContent('true');
  });

  it('lists an array\'s items (CX-V5)', () => {
    show(['U2F_V2', 'FIDO_2_0']);
    expect(screen.getAllByRole('listitem').map((item) => item.textContent)).toEqual(['U2F_V2', 'FIDO_2_0']);
  });

  it('labels a map\'s keys, keeps keys spelled as data as written and in mono, and indents what a map holds (CX-V6, CX-X4)', () => {
    const container = show({ fmt: 'packed', '-1': 1, 'h\'01\' (bytes)': 2, flags: { UP: true }, x5c: ['a'] });
    const terms = screen.getAllByRole('term');
    expect(terms.map((term) => term.textContent)).toEqual(['Format', '-1', "h'01' (bytes)", 'Flags', 'UP', 'X5C']);
    expect(terms.map((term) => term.className.includes('font-mono'))).toEqual([false, true, true, false, true, false]);
    const nested = Array.from(container.querySelectorAll('[data-entry="nested"] > dd'));
    expect(nested).toHaveLength(2);
    nested.forEach((body) => expect(body.className).toContain('border-l'));
    // Side by side only where the map has room.
    expect(terms[0].parentElement!.className).toContain('@md:grid-cols-');
  });

  it('puts the interpretation badges before the map, each in its tone (CX-V7)', () => {
    show({ known: false, verification: 'not verified: shown only', deprecated: 'replaced' });
    const badges = document.querySelector('[data-role="badges"]') as HTMLElement;
    expect(within(badges).getByText('Unknown').className).toContain('bg-surface');
    expect(within(badges).getByText('Not verified').className).toContain('bg-warning-tint');
    expect(within(badges).getByText('Deprecated').className).toContain('bg-danger-tint');
    // The rows the badges come from stay in the list.
    expect(screen.getAllByRole('term').map((term) => term.textContent)).toEqual(['Known', 'Verification', 'Deprecated']);
  });
});
