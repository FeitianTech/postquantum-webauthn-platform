import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { TBody, THead, Table, Td, Th, Tr } from './Table';

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
