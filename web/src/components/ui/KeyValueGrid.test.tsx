import { render, within } from '@testing-library/react';

import { KeyValueGrid } from './KeyValueGrid';

describe('KeyValueGrid', () => {
  it('lists labels and values with an optional line under the value', () => {
    render(
      <KeyValueGrid
        columns={4}
        items={[
          { key: 'name', label: 'Browser', value: 'Google Chrome', hint: 'from User-Agent Client Hints' },
          { key: 'aaguid', label: 'AAGUID', value: 'ee882879-721c-4913-9775-3dfcce97072a', mono: true },
        ]}
      />,
    );
    const list = document.querySelector('dl')!;
    expect(list.className).toContain('lg:grid-cols-4');
    const browser = list.querySelector('[data-item="name"]')!;
    expect(within(browser as HTMLElement).getByText('Browser').tagName).toBe('DT');
    expect(browser.querySelector('[data-role="value"]')).toHaveTextContent('Google Chrome');
    expect(browser.querySelector('[data-role="hint"]')).toHaveTextContent('from User-Agent Client Hints');
    expect(list.querySelector('[data-item="aaguid"] [data-role="value"]')!.className).toContain('font-mono');
    expect(list.querySelector('[data-item="aaguid"] [data-role="hint"]')).toBeNull();
  });

  it('gives an identifier two columns until a wide screen, and long text the whole row', () => {
    render(
      <KeyValueGrid
        items={[
          { key: 'aaguid', label: 'AAGUID', value: 'ee882879-721c-4913-9775-3dfcce97072a', identifier: true },
          { key: 'legal', label: 'Legal Header', value: 'Long text', wide: true, identifier: true },
          { key: 'protocol', label: 'Protocol', value: 'FIDO2' },
        ]}
      />,
    );
    const item = (key: string) => document.querySelector(`[data-item="${key}"]`)!.className;
    expect(item('aaguid')).toContain('sm:col-span-2');
    expect(item('aaguid')).toContain('wide:col-span-1');
    expect(item('legal')).toContain('col-span-full');
    expect(item('legal')).not.toContain('sm:col-span-2');
    expect(item('protocol')).not.toMatch(/col-span/);
  });
});
