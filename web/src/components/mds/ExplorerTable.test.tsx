// The MDS table over the fixture's real entries (tests/fixtures/mds).
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { FIXTURE_ENTRIES, entryNamed } from '@/test/mds';
import { renderPage } from '@/test/page';

import { ExplorerTable } from './ExplorerTable';
import { useExplorerView } from './useExplorerView';
import { holdingTimers } from '@/test/timers';

function Harness({ entries, onOpen }: { entries: MdsEntry[]; onOpen?: (entryId: string) => void }) {
  const view = useExplorerView(entries, 1);
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
  'Status',
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
  it('has the 14 columns, in order, with their headers', () => {
    renderTable();
    expect(screen.getAllByRole('columnheader').map((cell) => cell.querySelector('button span')?.textContent)).toEqual(HEADERS);
    expect(screen.getByRole('table', { name: 'FIDO MDS authenticators' })).toBeInTheDocument();
    // Each row is a grid of two lines, which the browser skips laying out while it is out of view.
    expect(rowOf(FIXTURE_ENTRIES[0])).toHaveClass('grid', '[content-visibility:auto]');
  });

  it('puts the name over the ID, the status over the protocol and the transports over the attachment', () => {
    renderTable();
    const cells = cellsOf(entryNamed('Fixture Security Key L2'));
    const line = (index: number) => cells[index].className.split(' ').filter((name) => /^(md:|lg:)?row-start-/.test(name));
    expect(line(1)).toEqual(['row-start-1']);
    expect(line(5)).toEqual(['row-start-2']);
    expect(line(4)).toEqual(['row-start-3', 'md:row-start-1']);
    expect(line(2)).toEqual(['row-start-3', 'md:row-start-2']);
    expect(line(8)).toEqual(['lg:row-start-1']);
    expect(line(7)).toEqual(['lg:row-start-2']);
    // The header mirrors them.
    expect(header('Name')).toHaveClass('row-start-1', 'col-start-2');
    expect(header('ID')).toHaveClass('row-start-2', 'col-start-2');
  });

  it('hides, for the eye only, a column the window has no room for, with its header and that header\'s button', () => {
    renderTable();
    const cells = cellsOf(entryNamed('Fixture Security Key L2'));
    for (const index of [3, 9, 11, 12]) expect(cells[index].className).toBe('sr-only truncate whitespace-nowrap');
    expect(cells[6]).toHaveClass('max-[88rem]:sr-only');
    expect(cells[10]).toHaveClass('max-[72rem]:sr-only');
    expect(cells[8]).toHaveClass('max-lg:sr-only');
    for (const name of ['Icon', 'Certification', 'Key Protection', 'Algorithm Info', 'CN']) {
      expect(header(name)).toHaveClass('sr-only', '*:invisible');
    }
    expect(header('User Verification')).toHaveClass('max-[88rem]:sr-only', 'max-[88rem]:*:invisible');
    // Every header keeps its name, hidden or not.
    expect(screen.getAllByRole('columnheader').map((cell) => cell.getAttribute('aria-label'))).toEqual(
      HEADERS.map((name) => (name === 'Name' ? 'Name (filtered)' : name)),
    );
  });

  it('runs a long list onto the second line where its column has two', () => {
    renderTable();
    const cells = cellsOf(entryNamed('Fixture Security Key L2'));
    expect(cells[10].querySelector('span')).toHaveClass('line-clamp-2');
    expect(cells[6].querySelector('span')).toHaveClass('line-clamp-2');
    expect(cells[8].querySelector('span')).toBeNull();
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
    expect(cells[4]).toHaveTextContent('FIDO Certified L2');
    expect(cells[4]).toHaveAttribute('title', entry.latestStatus);
    expect(within(cells[5]).getByText(entry.id).tagName).toBe('CODE');
    expect(cells[6]).toHaveTextContent('Fingerprint Internal, Passcode Internal, Presence Internal');
    expect(cells[7]).toHaveTextContent('External, Wired, NFC');
    expect(cells[8]).toHaveTextContent('BLE, NFC, USB');
    expect(cells[9]).toHaveTextContent('Hardware, Secure Element');
    expect(cells[10]).toHaveTextContent('SECP256R1 ECDSA SHA256 Raw, Ed25519 EdDSA SHA512 Raw');
    expect(cells[11]).toHaveTextContent('RSASSA-PKCS1-v1_5_SHA256');
    expect(cells[12]).toHaveTextContent('Fixture RSA Attestation Root');
    expect(within(cells[13]).getByText('Aug 15, 2026')).toHaveAttribute('dateTime', '2026-08-15');
    expect(cells[13]).toHaveAttribute('title', '2026-08-15');
  });

  it('shows the U2F and UAF entries as the server spells them', () => {
    renderTable();
    const u2f = cellsOf(entryNamed('Fixture U2F Key'));
    expect(u2f[2]).toHaveTextContent('U2F');
    expect(u2f[5]).toHaveTextContent('f1d0000000000000000000000000000000000011');
    expect(within(u2f[5]).getByRole('button', { name: 'Copy key identifier' })).toBeInTheDocument();
    expect(u2f[8]).toHaveTextContent('—');
    const uaf = cellsOf(entryNamed('Fixture UAF Authenticator'));
    expect(uaf[2]).toHaveTextContent('UAF');
    expect(within(uaf[5]).getByRole('button', { name: 'Copy AAID' })).toBeInTheDocument();
    expect(within(uaf[1]).getByRole('link')).toHaveAttribute('href', '#mds/aaid:F1D0%230012');
  });

  it('shows N/A without an icon and a dash without a certification', () => {
    renderTable();
    expect(cellsOf(entryNamed('Fixture Key Without An Icon'))[0]).toHaveTextContent('N/A');
    expect(cellsOf(entryNamed('Fixture Key Without Status Reports'))[3]).toHaveTextContent('—');
  });

  it('puts the latest status in a badge of its own, in its tone', () => {
    renderTable();
    const badge = (name: string) => cellsOf(entryNamed(name))[4].querySelector('span')!;
    expect(badge('Fixture Security Key L2')).toHaveTextContent('FIDO Certified L2');
    expect(badge('Fixture Security Key L2')).toHaveClass('text-success');
    expect(badge('Fixture Revoked Key')).toHaveTextContent('Revoked');
    expect(badge('Fixture Revoked Key')).toHaveClass('text-danger');
    expect(badge('Fixture Uncertified Key')).toHaveClass('text-ink-muted');
    expect(cellsOf(entryNamed('Fixture Key Without Status Reports'))[4]).toHaveTextContent('—');
  });

  it('puts the level reached in one badge, coloured by what the latest status says of it', () => {
    renderTable();
    const badge = (name: string) => cellsOf(entryNamed(name))[3].querySelector('span > span')!;
    expect(badge('Fixture Security Key L1')).toHaveTextContent('FIDO Certified L1');
    expect(badge('Fixture Security Key L1')).toHaveClass('text-success');
    // Certified at L1 in 2023, revoked since: the level stays, its badge no longer green.
    expect(badge('Fixture Revoked Key')).toHaveTextContent('FIDO Certified L1');
    expect(badge('Fixture Revoked Key')).toHaveClass('text-ink-muted');
    expect(cellsOf(entryNamed('Fixture Uncertified Key'))[3]).toHaveTextContent(/^—$/);
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
    expect(cells[5]).toHaveTextContent('—');
    expect(cells[6]).toHaveTextContent('—');
    expect(cells[13]).toHaveTextContent('—');
  });

  it('marks a filtered column in its header', () => {
    renderTable();
    expect(header('Name')).toHaveTextContent('(filtered)');
    expect(header('Protocol')).not.toHaveTextContent('(filtered)');
  });
});

describe('the MDS table: rows that expand', () => {
  it('shows what has no column on a labelled line of its own when expanded, every word of it', async () => {
    renderTable();
    const entry = entryNamed('Fixture Key With Many Attestation Roots');
    const cn = () => cellsOf(entry)[12];
    expect(cn()).toHaveClass('sr-only');
    expect(cn()).toHaveAttribute('title', entry.certificateCommonNameList.join(', '));

    const toggle = within(cellsOf(entry)[1]).getByRole('button', { name: 'Show all of Fixture Key With Many Attestation Roots' });
    await userEvent.click(toggle);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
    expect(cn()).not.toHaveClass('sr-only');
    expect(cn()).not.toHaveClass('truncate');
    expect(cn()).not.toHaveAttribute('title');
    expect(cn().querySelectorAll('span > span')).toHaveLength(15);
    // The line's label is for the eye: a screen reader has the column's header.
    const label = cn().firstElementChild!;
    expect(label).toHaveTextContent('CN');
    expect(label).toHaveAttribute('aria-hidden', 'true');
    expect(cn()).toHaveClass('col-[2/-1]', 'flex');
    // What the two lines hold stays where it is, unlabelled.
    expect(cellsOf(entry)[2]).toHaveClass('md:row-start-2');
    expect(cellsOf(entry)[2].querySelector('[aria-hidden]')).toBeNull();
    // A list with a column of its own takes a line too, so its pills have the room.
    expect(cellsOf(entry)[8]).toHaveClass('col-[2/-1]');
    expect(cellsOf(entry)[8]).not.toHaveClass('max-lg:sr-only');

    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button', { name: /^Show less of/ }));
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'false');
  });

  it('shows a long identifier whole when expanded', async () => {
    renderTable();
    const entry = entryNamed('Fixture U2F Key');
    expect(within(cellsOf(entry)[5]).getByText(entry.id)).toHaveClass('truncate');
    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button', { name: /^Show all of/ }));
    expect(within(cellsOf(entry)[5]).getByText(entry.id)).toHaveClass('break-all');
    // Nothing to list: the line holds a dash.
    expect(cellsOf(entry)[8]).toHaveTextContent('Transports—');
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

describe('the MDS table: copying an identifier', () => {
  it('copies an AAGUID whole and says so', async () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
    renderTable();
    const entry = entryNamed('Fixture Security Key L1');

    await holdingTimers(async () => {
      await act(async () => fireEvent.click(within(cellsOf(entry)[5]).getByRole('button', { name: 'Copy AAGUID' })));
      expect(writeText).toHaveBeenCalledWith('f1d0f1d0-0000-4000-8000-000000000001');
      expect(within(cellsOf(entry)[5]).getByRole('status')).toHaveTextContent('AAGUID copied.');
    });
  });

  it('says so when the clipboard refuses, and selects the value to copy by hand', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn(async () => Promise.reject(new DOMException('Denied.', 'NotAllowedError'))) },
    });
    renderTable();
    const entry = entryNamed('Fixture Security Key L1');
    await userEvent.click(within(cellsOf(entry)[5]).getByRole('button', { name: 'Copy AAGUID' }));
    // In the cell's status for a screen reader, and in a toast where it is seen.
    await waitFor(() =>
      expect(screen.getAllByText(/^Could not copy: .* It is shown in full and selected, to copy by hand\.$/)).toHaveLength(2),
    );
    expect(window.getSelection()?.toString()).toBe(entry.id);
  });
});

describe('the MDS table: opening an entry', () => {
  it('opens an entry from its name, and from the link an expanded row has', async () => {
    const onOpen = vi.fn();
    renderTable(FIXTURE_ENTRIES, onOpen);
    const entry = entryNamed('Fixture U2F Key');
    await userEvent.click(within(cellsOf(entry)[1]).getByRole('link', { name: 'Fixture U2F Key' }));
    expect(onOpen).toHaveBeenLastCalledWith(entry.entryId);
    expect(within(rowOf(entry)).queryByRole('link', { name: /^Open entry/ })).toBeNull();

    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button', { name: /^Show all of/ }));
    const link = within(rowOf(entry)).getByRole('link', { name: 'Open entry: Fixture U2F Key' });
    expect(link).toHaveTextContent(/^Open entry$/);
    expect(link).toHaveAttribute('href', `#mds/${entry.entryId}`);
    await userEvent.click(link);
    expect(onOpen).toHaveBeenCalledTimes(2);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
  });

  it('expands a row, and collapses it, on a click anywhere in it but its controls', async () => {
    const onOpen = vi.fn();
    renderTable(FIXTURE_ENTRIES, onOpen);
    const entry = entryNamed('Fixture U2F Key');
    await userEvent.click(cellsOf(entry)[4]);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
    await userEvent.click(cellsOf(entry)[9]);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'false');

    // Its own button expands it once, not twice.
    await userEvent.click(within(cellsOf(entry)[1]).getByRole('button'));
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
    await userEvent.click(within(cellsOf(entry)[5]).getByRole('button', { name: 'Copy key identifier' }));
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'true');
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('leaves a text selection alone', async () => {
    renderTable();
    const entry = entryNamed('Fixture U2F Key');
    window.getSelection()!.selectAllChildren(cellsOf(entry)[4]);
    fireEvent.click(cellsOf(entry)[4]);
    expect(rowOf(entry)).toHaveAttribute('aria-expanded', 'false');
    window.getSelection()!.removeAllRanges();
  });

  it('gives an entry without a name a link to open it by, named for its ID', async () => {
    const onOpen = vi.fn();
    const nameless = { ...entryNamed('Fixture U2F Key'), name: '' } as MdsEntry;
    renderTable([nameless], onOpen);
    await userEvent.click(cellsOf(nameless)[4]);
    await userEvent.click(within(rowOf(nameless)).getByRole('link', { name: `Open entry: ${nameless.id}` }));
    expect(onOpen).toHaveBeenCalledWith(nameless.entryId);
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
  it('appears once the page has scrolled about five rows into the list, and takes the page back to its top', async () => {
    const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
    renderTable();
    const top = vi.spyOn(screen.getByRole('table'), 'getBoundingClientRect').mockReturnValue({ top: -300 } as DOMRect);
    const button = () => screen.queryByRole('button', { name: 'Back to top of the authenticator list' });

    fireEvent.scroll(window);
    expect(button()).toBeNull();

    top.mockReturnValue({ top: -321 } as DOMRect);
    fireEvent.scroll(window);
    expect(button()).toHaveAttribute('title', 'Back to top');
    // Held at the window's bottom by a sticky line, not a fixed position.
    expect(button()!.parentElement).toHaveClass('sticky', 'bottom-4', 'h-0');
    await userEvent.click(button()!);
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: 'smooth' });

    top.mockReturnValue({ top: 0 } as DOMRect);
    fireEvent.scroll(window);
    expect(button()).toBeNull();
    scrollTo.mockRestore();
  });

  it('goes back at once for a person who asked for less motion, and stops listening when the table goes', async () => {
    const scrollTo = vi.spyOn(window, 'scrollTo').mockImplementation(() => {});
    const query = vi.spyOn(window, 'matchMedia').mockImplementation((media: string) => ({ matches: true, media }) as MediaQueryList);
    const removed = vi.spyOn(window, 'removeEventListener');
    const { unmount } = renderTable();
    vi.spyOn(screen.getByRole('table'), 'getBoundingClientRect').mockReturnValue({ top: -900 } as DOMRect);
    fireEvent.scroll(window);
    await userEvent.click(screen.getByRole('button', { name: 'Back to top of the authenticator list' }));
    expect(scrollTo).toHaveBeenCalledWith({ top: 0, behavior: 'auto' });
    unmount();
    expect(removed).toHaveBeenCalledWith('scroll', expect.any(Function));
    for (const spy of [scrollTo, query, removed]) spy.mockRestore();
  });

  it('keeps the header row under the site\'s header, and the filters\' bar where that is pinned, as the page scrolls', () => {
    renderTable();
    expect(document.querySelector('thead')).toHaveClass(
      'sticky',
      'top-[calc(var(--header-height)+var(--mds-toolbar-height,0px)-1px)]',
      'max-md:sr-only',
    );
  });
});
