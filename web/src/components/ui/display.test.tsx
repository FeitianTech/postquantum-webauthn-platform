import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { Badge, StatusChip } from './Badge';
import { Card, CardHeader } from './Card';
import { KeyValueGrid } from './KeyValueGrid';
import { TBody, THead, Table, Td, Th, Tr } from './Table';

describe('Card', () => {
  it('is a white section with a hairline, a title, a description and actions', () => {
    render(
      <Card aria-labelledby="card-title">
        <CardHeader titleId="card-title" title="Saved Credentials" description="Stored in this browser" actions={<button type="button">Clear All</button>} />
        <p>Body</p>
      </Card>,
    );
    const card = screen.getByRole('region', { name: 'Saved Credentials' });
    expect(card.className).toContain('bg-surface');
    expect(card.className).toContain('border-line');
    expect(card.className).not.toMatch(/shadow/);
    expect(within(card).getByRole('heading', { level: 3 })).toHaveTextContent('Saved Credentials');
    expect(within(card).getByText('Stored in this browser')).toBeInTheDocument();
    expect(within(card).getByRole('button', { name: 'Clear All' })).toBeInTheDocument();
  });

  it('can be another element with a level-two title and no extras', () => {
    const { container } = render(
      <Card as="div">
        <CardHeader title="Plain" titleAs="h2" />
      </Card>,
    );
    expect(container.firstElementChild?.tagName).toBe('DIV');
    expect(screen.getByRole('heading', { level: 2, name: 'Plain' })).toBeInTheDocument();
  });
});

describe('Badge and StatusChip', () => {
  it.each([
    ['accent', 'bg-accent-tint'],
    ['success', 'bg-success-tint'],
    ['warning', 'bg-warning-tint'],
    ['danger', 'bg-danger-tint'],
    ['neutral', 'bg-surface'],
  ] as const)('colours a %s badge with a tint or white, never grey', (tone, fill) => {
    render(<Badge tone={tone}>Label</Badge>);
    expect(screen.getByText('Label').className).toContain(fill);
  });

  it.each([
    ['success', 'Yes', '✓'],
    ['danger', 'No', '✕'],
    ['neutral', 'Not available in this browser', '–'],
    ['warning', 'Could not be determined', '!'],
    ['accent', 'Info', 'i'],
  ] as const)('says a %s status in words and a mark', (tone, words, mark) => {
    render(
      <StatusChip tone={tone} data-state="x">
        {words}
      </StatusChip>,
    );
    const chip = screen.getByText(words).parentElement!;
    expect(chip).toHaveAttribute('data-state', 'x');
    expect(chip).toHaveTextContent(`${words}${mark}`);
    expect(within(chip).getByText(mark)).toHaveAttribute('aria-hidden', 'true');
  });
});

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
});

describe('Table', () => {
  it('scrolls inside its own frame and marks the sorted column', async () => {
    const onSort = vi.fn();
    render(
      <Table caption="Authenticators" className="mt-2">
        <THead sticky>
          <Tr>
            <Th sort="ascending" onSort={onSort}>
              Name
            </Th>
            <Th sort="descending">Date</Th>
            <Th>AAGUID</Th>
          </Tr>
        </THead>
        <TBody>
          <Tr>
            <Td>YubiKey 5</Td>
            <Td>2024</Td>
            <Td mono truncate title="cb69481e-8ff7-4039-93ec-0a2729a154a8">
              cb69481e-8ff7-4039-93ec-0a2729a154a8
            </Td>
          </Tr>
        </TBody>
      </Table>,
    );
    const table = screen.getByRole('table', { name: 'Authenticators' });
    expect(table.parentElement!.className).toContain('overflow-x-auto');
    expect(screen.getByRole('columnheader', { name: 'Name' })).toHaveAttribute('aria-sort', 'ascending');
    expect(screen.getByRole('columnheader', { name: 'Date' })).toHaveAttribute('aria-sort', 'descending');
    expect(screen.getByRole('columnheader', { name: 'AAGUID' })).not.toHaveAttribute('aria-sort');
    await userEvent.click(screen.getByRole('button', { name: 'Name' }));
    expect(onSort).toHaveBeenCalledOnce();
    const cell = screen.getByRole('cell', { name: 'cb69481e-8ff7-4039-93ec-0a2729a154a8' });
    expect(cell.className).toContain('truncate');
    expect(cell.className).toContain('font-mono');
    expect(document.querySelector('thead')!.className).toContain('sticky');
  });
});
