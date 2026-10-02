// The MDS table over the fixture's real entries (tests/fixtures/mds).
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef } from 'react';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, entryNamed } from '@/test/mds';
import { renderPage } from '@/test/page';

import { ExplorerTable } from './ExplorerTable';
import { useExplorerView } from './useExplorerView';

function Harness({ entries, onOpen }: { entries: MdsEntry[]; onOpen?: (entryId: string) => void }) {
  const view = useExplorerView(entries, 1);
  const frameRef = useRef<HTMLDivElement>(null);
  return (
    <ExplorerTable
      rows={view.rows}
      shown={view.shown}
      sort={view.sort}
      onSort={view.onSort}
      filteredColumns={new Set(['name'])}
      expanded={view.expanded}
      onToggle={view.onToggle}
      onOpen={onOpen}
      state={null}
      frameRef={frameRef}
    />
  );
}

function renderTable(entries = FIXTURE_ENTRIES, onOpen?: (entryId: string) => void) {
  return renderPage(
    <ToastProvider>
      <Harness entries={entries} onOpen={onOpen} />
    </ToastProvider>,
  );
}

const HEADERS = [
  'Icon',
  'Name',
  'Protocol',
  'Certification',
  'ID',
  'User Verification',
  'Attachment',
  'Transports',
  'Key Protection',
  'Algorithms',
  'Algorithm Info',
  'CN',
  'Date Updated',
];

const header = (name: string) => screen.getAllByRole('columnheader').find((cell) => cell.textContent?.startsWith(name))!;
const rowOf = (entry: MdsEntry) => document.querySelector<HTMLTableRowElement>(`tr[data-entry-id="${CSS.escape(entry.entryId)}"]`)!;
const cellsOf = (entry: MdsEntry) => within(rowOf(entry)).getAllByRole('cell');
const names = () => [...document.querySelectorAll('tbody tr[data-entry-id]')].map((row) => row.querySelector('a')?.textContent ?? '');

afterEach(() => {
  Reflect.deleteProperty(navigator, 'clipboard');
});

describe('the MDS table: its columns', () => {
  it('has the 13 columns, in order, with their headers', () => {
    renderTable();
    expect(screen.getAllByRole('columnheader').map((cell) => cell.querySelector('button span')?.textContent)).toEqual(HEADERS);
    expect(screen.getByRole('table', { name: 'FIDO MDS authenticators' })).toBeInTheDocument();
    // Each row is a grid on the table's columns, which the browser skips laying out while it is out of view.
    expect(rowOf(FIXTURE_ENTRIES[0])).toHaveClass('grid', '[content-visibility:auto]');
  });

  it('shows each column of an entry', () => {
    renderTable();
    const entry = entryNamed('Fixture Security Key L2');
    const cells = cellsOf(entry);
    expect(within(cells[0]).getByRole('img')).toHaveAttribute('alt', 'Fixture Security Key L2 icon');
    expect(within(cells[1]).getByRole('link', { name: 'Fixture Security Key L2' })).toHaveAttribute(
      'href',
      `#mds/aaguid:${entry.id}`,
    );
    expect(cells[2]).toHaveTextContent('FIDO2');
    expect(cells[3]).toHaveTextContent('FIDO Certified L2Fixture Security Key L2 • (FIDO20020260815002)');
    expect(cells[3]).toHaveAttribute('title', entry.certification);
    expect(within(cells[4]).getByText(entry.id).tagName).toBe('CODE');
    expect(cells[5]).toHaveTextContent('Fingerprint Internal, Passcode Internal, Presence Internal');
    expect(cells[6]).toHaveTextContent('External, Wired, Nfc');
    expect(cells[7]).toHaveTextContent('Ble, Nfc, Usb');
    expect(cells[8]).toHaveTextContent('Hardware, Secure Element');
    expect(cells[9]).toHaveTextContent('SECP256R1 Ecdsa SHA256 Raw, ED25519 Eddsa SHA512 Raw');
    expect(cells[10]).toHaveTextContent('RSASSA-PKCS1-v1_5_SHA256');
    expect(cells[11]).toHaveTextContent('Fixture RSA Attestation Root');
    expect(within(cells[12]).getByText('Aug 15, 2026')).toHaveAttribute('dateTime', '2026-08-15');
    expect(cells[12]).toHaveAttribute('title', '2026-08-15');
  });

  it('shows the U2F and UAF entries as the server spells them', () => {
    renderTable();
    const u2f = cellsOf(entryNamed('Fixture U2F Key'));
    expect(u2f[2]).toHaveTextContent('U2F');
    expect(u2f[4]).toHaveTextContent('f1d0000000000000000000000000000000000011');
    expect(within(u2f[4]).getByRole('button', { name: 'Copy key identifier' })).toBeInTheDocument();
    expect(u2f[7]).toHaveTextContent('—');
    const uaf = cellsOf(entryNamed('Fixture UAF Authenticator'));
    expect(uaf[2]).toHaveTextContent('Uaf');
    expect(within(uaf[4]).getByRole('button', { name: 'Copy AAID' })).toBeInTheDocument();
    expect(within(uaf[1]).getByRole('link')).toHaveAttribute('href', '#mds/aaid:F1D0%230012');
  });

  it('shows N/A without an icon and a dash without a certification', () => {
    renderTable();
    expect(cellsOf(entryNamed('Fixture Key Without An Icon'))[0]).toHaveTextContent('N/A');
    expect(cellsOf(entryNamed('Fixture Key Without Status Reports'))[3]).toHaveTextContent('—');
  });

  it('puts the certification in one badge, coloured by its status', () => {
    renderTable();
    const badge = (name: string) => cellsOf(entryNamed(name))[3].querySelector('span > span')!;
    expect(badge('Fixture Security Key L1')).toHaveClass('text-success');
    expect(badge('Fixture Revoked Key')).toHaveTextContent('Revoked');
    expect(badge('Fixture Revoked Key')).toHaveClass('text-danger');
    expect(badge('Fixture Uncertified Key')).toHaveTextContent('NOT FIDO Certified');
    expect(badge('Fixture Uncertified Key')).toHaveClass('text-ink-muted');
  });

  it('shows a dash for what an entry does not have', () => {
    const bare = {
      ...FIXTURE_ENTRIES[0],
      entryId: 'entry:bare',
      name: ' ',
      id: '',
      protocol: '',
      dateUpdated: '',
      userVerificationList: [],
    } as MdsEntry;
    renderTable([bare]);
    const cells = within(document.querySelector('tr[data-entry-id="entry:bare"]')!).getAllByRole('cell');
    expect(cells[1]).toHaveTextContent('—');
    expect(within(cells[1]).getByRole('button', { name: 'Show all of entry:bare' })).toBeInTheDocument();
    expect(cells[2]).toHaveTextContent('—');
    expect(cells[4]).toHaveTextContent('—');
    expect(cells[5]).toHaveTextContent('—');
    expect(cells[12]).toHaveTextContent('—');
  });

  it('marks a filtered column in its header', () => {
    renderTable();
    expect(header('Name')).toHaveTextContent('(filtered)');
    expect(header('Protocol')).not.toHaveTextContent('(filtered)');
  });
});

describe('the MDS table: rows that expand', () => {
  it('shows a long value on one line, whole in its tooltip, and every word when expanded', async () => {
    renderTable();
    const entry = entryNamed('Fixture Key With Many Attestation Roots');
    const cn = () => cellsOf(entry)[11];
    expect(cn()).toHaveClass('truncate');
    expect(cn()).toHaveAttribute('title', entry.certificateCommonNameList.join(', '));

    const toggle = within(cellsOf(entry)[1]).getByRole('button', { name: 'Show all of Fixture Key With Many Attestation Roots' });
    await userEvent.click(toggle);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
    expect(cn()).not.toHaveClass('truncate');
    expect(cn()).not.toHaveAttribute('title');
    expect(cn().querySelectorAll('span > span')).toHaveLength(15);

    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button', { name: /^Show less of/ }));
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'false');
  });

  it('wraps the certification detail when expanded', async () => {
    renderTable();
    const entry = entryNamed('Fixture Security Key L1');
    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button', { name: /^Show all of/ }));
    expect(cellsOf(entry)[3].querySelector('span > span:last-child')).not.toHaveClass('truncate');
  });
});

describe('the MDS table: sorting', () => {
  it('starts newest first, by Date Updated', () => {
    renderTable();
    expect(header('Date Updated')).toHaveAttribute('aria-sort', 'descending');
    expect(header('Name')).toHaveAttribute('aria-sort', 'none');
    expect(names()[0]).toBe('Fixture Security Key L1');
  });

  it('cycles a column ascending, descending, then back to the default', async () => {
    renderTable();
    const name = within(header('Name')).getByRole('button');
    await userEvent.click(name);
    expect(header('Name')).toHaveAttribute('aria-sort', 'ascending');
    expect(header('Date Updated')).toHaveAttribute('aria-sort', 'none');
    expect(names()[0]).toBe('Fixture Authenticator With A Deliberately Long Description, Written To Show How The Explorer Truncates A Name While Keeping It Visible.');

    await userEvent.click(name);
    expect(header('Name')).toHaveAttribute('aria-sort', 'descending');
    expect(names()[0]).toBe('Fixture Uncertified Key');

    await userEvent.click(name);
    expect(header('Name')).toHaveAttribute('aria-sort', 'none');
    expect(header('Date Updated')).toHaveAttribute('aria-sort', 'descending');
  });

  it('turns Date Updated between newest and oldest first', async () => {
    renderTable();
    await userEvent.click(within(header('Date Updated')).getByRole('button'));
    expect(header('Date Updated')).toHaveAttribute('aria-sort', 'ascending');
    await userEvent.click(within(header('Date Updated')).getByRole('button'));
    expect(header('Date Updated')).toHaveAttribute('aria-sort', 'descending');
  });
});

describe('the MDS table: its frame', () => {
  it('fades its right edge while it can scroll further that way, beside its scrollbar', () => {
    renderTable();
    const frame = document.querySelector<HTMLDivElement>('[data-mds-frame]')!;
    const fade = document.querySelector<HTMLElement>('[data-mds-fade]')!;
    const size = { scrollWidth: 2740, clientWidth: 941, offsetWidth: 958, clientHeight: 600, offsetHeight: 617 };
    for (const [key, value] of Object.entries(size)) Object.defineProperty(frame, key, { configurable: true, value });

    fireEvent.scroll(frame);
    expect(fade).toBeVisible();
    expect(fade).toHaveAttribute('aria-hidden', 'true');
    expect(fade.style.right).toBe('16px');
    expect(fade.style.bottom).toBe('16px');

    frame.scrollLeft = 2740 - 941;
    fireEvent.scroll(frame);
    expect(fade).not.toBeVisible();

    frame.scrollLeft = 0;
    Object.defineProperty(frame, 'offsetWidth', { configurable: true, value: 942 });
    Object.defineProperty(frame, 'offsetHeight', { configurable: true, value: 601 });
    fireEvent.scroll(frame);
    expect(fade.style.right).toBe('1px');
    expect(fade.style.bottom).toBe('1px');
  });
});

describe('the MDS table: column widths', () => {
  const separator = (name: string) => screen.getByRole('separator', { name: `Resize ${name} column` });
  const width = (index: number) => document.querySelector('table')!.style.getPropertyValue('--mds-columns').split(' ')[index];

  it('sets the column widths on the table, which every row lines up on, and every header but the last can be resized', () => {
    renderTable();
    expect(width(1)).toBe('280px');
    expect(document.querySelector('table')!.style.width).toBe('2740px');
    expect(screen.getAllByRole('separator')).toHaveLength(12);
    expect(separator('Name')).toHaveAttribute('title', 'Drag to resize column');
  });

  it('starts the Icon column as wide as an icon on a phone, its name read but not shown, and keeps a width a person set', () => {
    const query = vi.spyOn(window, 'matchMedia').mockImplementation(
      (media: string) => ({ matches: media === '(max-width: 639px)', media, addEventListener() {}, removeEventListener() {} }) as unknown as MediaQueryList,
    );
    renderTable();
    expect(width(0)).toBe('44px');
    expect(document.querySelector('table')!.style.width).toBe('2712px');
    expect(within(header('Icon')).getByText('Icon')).toHaveClass('max-sm:sr-only');
    expect(within(header('Name')).getByText('Name')).not.toHaveClass('max-sm:sr-only');
    expect(separator('Icon')).toHaveAttribute('aria-valuemin', '40');
    fireEvent.keyDown(separator('Icon'), { key: 'ArrowLeft' });
    expect(width(0)).toBe('40px');
    query.mockRestore();
  });

  it('narrows the Icon column when the window narrows to a phone, and widens it back', () => {
    let phone = false;
    const listeners = new Set<(event: MediaQueryListEvent) => void>();
    const query = vi.spyOn(window, 'matchMedia').mockImplementation(
      (media: string) =>
        ({
          get matches() {
            return media === '(max-width: 639px)' && phone;
          },
          media,
          addEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.add(listener),
          removeEventListener: (_type: string, listener: (event: MediaQueryListEvent) => void) => listeners.delete(listener),
        }) as unknown as MediaQueryList,
    );
    const resize = (narrow: boolean) => {
      phone = narrow;
      act(() => listeners.forEach((listener) => listener({ matches: narrow } as MediaQueryListEvent)));
    };
    const { unmount } = renderTable();
    expect(width(0)).toBe('72px');

    resize(true);
    expect(width(0)).toBe('44px');
    resize(false);
    expect(width(0)).toBe('72px');

    fireEvent.keyDown(separator('Icon'), { key: 'ArrowRight' });
    resize(true);
    expect(width(0)).toBe('88px');
    resize(false);
    expect(width(0)).toBe('88px');

    unmount();
    expect(listeners.size).toBe(0);
    query.mockRestore();
  });

  it('resizes from the keyboard, never under the minimum', () => {
    renderTable();
    fireEvent.keyDown(separator('Name'), { key: 'ArrowRight' });
    expect(width(1)).toBe('296px');
    expect(separator('Name')).toHaveAttribute('aria-valuenow', '296');
    fireEvent.keyDown(separator('Name'), { key: 'Enter' });
    expect(width(1)).toBe('296px');
    for (let step = 0; step < 20; step += 1) fireEvent.keyDown(separator('Name'), { key: 'ArrowLeft' });
    expect(width(1)).toBe('64px');
    for (let step = 0; step < 3; step += 1) fireEvent.keyDown(separator('ID'), { key: 'ArrowLeft' });
    expect(width(4)).toBe('320px');
  });

  it('resizes by dragging with the main button', () => {
    renderTable();
    const handle = separator('Protocol');
    fireEvent.pointerDown(handle, { button: 2, clientX: 100, pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 150, pointerId: 1 });
    expect(width(2)).toBe('104px');

    fireEvent.pointerDown(handle, { button: 0, clientX: 100, pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 150, pointerId: 1 });
    expect(width(2)).toBe('154px');
    fireEvent.pointerUp(handle, { clientX: 150, pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 400, pointerId: 1 });
    expect(width(2)).toBe('154px');
    fireEvent.click(handle);
    expect(header('Protocol')).toHaveAttribute('aria-sort', 'none');
  });
});

describe('the MDS table: copying an identifier', () => {
  it('copies an AAGUID whole and says so', async () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    renderTable();
    const entry = entryNamed('Fixture Security Key L1');
    await userEvent.click(within(cellsOf(entry)[4]).getByRole('button', { name: 'Copy AAGUID' }));
    expect(writeText).toHaveBeenCalledWith('f1d0f1d0-0000-4000-8000-000000000001');
    expect(within(cellsOf(entry)[4]).getByRole('status')).toHaveTextContent('AAGUID copied.');
  });

  it('says so when the clipboard refuses, and selects the value to copy by hand', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn(async () => Promise.reject(new DOMException('Denied.', 'NotAllowedError'))) },
    });
    renderTable();
    const entry = entryNamed('Fixture Security Key L1');
    await userEvent.click(within(cellsOf(entry)[4]).getByRole('button', { name: 'Copy AAGUID' }));
    // In the cell's status for a screen reader, and in a toast where it is seen.
    await waitFor(() =>
      expect(screen.getAllByText(/^Could not copy: .* It is shown in full and selected, to copy by hand\.$/)).toHaveLength(2),
    );
    expect(window.getSelection()?.toString()).toBe(entry.id);
  });
});

describe('the MDS table: opening an entry', () => {
  it('opens an entry from its name, or a click anywhere else in its row', async () => {
    const onOpen = vi.fn();
    renderTable(FIXTURE_ENTRIES, onOpen);
    const entry = entryNamed('Fixture U2F Key');
    await userEvent.click(within(cellsOf(entry)[1]).getByRole('link'));
    expect(onOpen).toHaveBeenLastCalledWith(entry.entryId);

    await userEvent.click(cellsOf(entry)[8]);
    expect(onOpen).toHaveBeenCalledTimes(2);

    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button'));
    expect(onOpen).toHaveBeenCalledTimes(2);
  });

  it('leaves a text selection alone', async () => {
    const onOpen = vi.fn();
    renderTable(FIXTURE_ENTRIES, onOpen);
    const cell = cellsOf(entryNamed('Fixture U2F Key'))[8];
    window.getSelection()!.selectAllChildren(cell);
    fireEvent.click(cell);
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('keeps the link a plain link with no opener', async () => {
    renderTable();
    const link = within(cellsOf(entryNamed('Fixture U2F Key'))[1]).getByRole('link');
    const click = new MouseEvent('click', { bubbles: true, cancelable: true });
    link.dispatchEvent(click);
    expect(click.defaultPrevented).toBe(false);
  });
});

describe('the MDS table: Back to top', () => {
  it('appears once five rows have scrolled by and takes the list back to its top', async () => {
    renderTable();
    const frame = document.querySelector<HTMLDivElement>('[data-mds-frame]')!;
    const scrollTo = vi.fn();
    frame.scrollTo = scrollTo;
    const rows = [...document.querySelectorAll<HTMLTableRowElement>('tbody tr')];
    const header = document.querySelector('thead')!;
    vi.spyOn(header, 'getBoundingClientRect').mockReturnValue({ bottom: 100 } as DOMRect);
    const fifth = vi.spyOn(rows[4], 'getBoundingClientRect').mockReturnValue({ top: 150 } as DOMRect);

    act(() => {
      frame.dispatchEvent(new Event('scroll'));
    });
    expect(screen.queryByRole('button', { name: 'Back to top of the authenticator list' })).toBeNull();

    fifth.mockReturnValue({ top: 40 } as DOMRect);
    act(() => {
      frame.dispatchEvent(new Event('scroll'));
    });
    const button = screen.getByRole('button', { name: 'Back to top of the authenticator list' });
    expect(button).toHaveAttribute('title', 'Back to top');
    await userEvent.click(button);
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: 'smooth' });
  });
});
