// The MDS filters over the fixture snapshot.
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ToastProvider } from '@/components/ui/Toast';
import { fixtureRoutes, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { MdsSection } from './MdsSection';

async function renderLoaded() {
  stubFetch(fixtureRoutes());
  renderPage(
    <ToastProvider>
      <div role="tablist" aria-label="Sections">
        <button type="button" role="tab" id="nav-tab-mds" aria-selected="true">
          FIDO MDS Authenticators
        </button>
      </div>
      <MdsSection active />
    </ToastProvider>,
  );
  await waitFor(() => expect(shownNames()).toHaveLength(32));
}

const shownNames = () =>
  [...document.querySelectorAll<HTMLTableRowElement>('tbody tr[data-entry-id]')]
    .filter((row) => !row.hidden)
    .map((row) => row.querySelector('a')?.textContent ?? '');
const count = () => screen.getByText(/^Entries:/);
const filters = () => screen.getByRole('region', { name: 'Filters' });
const combobox = (name: string) => within(filters()).getByRole('combobox', { name });
// The filters that offer a list: the sort's select is a combobox too.
const lists = () => within(filters()).getAllByRole('combobox').filter((field) => field.tagName === 'INPUT');
const search = (name: string) => within(filters()).getByRole('searchbox', { name });
const options = () => within(screen.getByRole('listbox')).getAllByRole('option').map((option) => option.textContent);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the MDS sort', () => {
  it('sorts by any column picked by name, and turns the order round', async () => {
    await renderLoaded();
    const sort = within(filters()).getByRole('combobox', { name: 'Sort' });
    expect(sort).toHaveValue('dateUpdated');
    expect(within(sort).getAllByRole('option').map((option) => option.textContent)).toHaveLength(14);

    await userEvent.selectOptions(sort, 'CN');
    expect(sort).toHaveValue('commonName');
    const first = shownNames()[0];
    await userEvent.click(within(filters()).getByRole('button', { name: 'Sort descending' }));
    expect(shownNames().at(-1)).toBe(first);
    await userEvent.click(within(filters()).getByRole('button', { name: 'Sort ascending' }));
    expect(shownNames()[0]).toBe(first);

    await userEvent.selectOptions(sort, 'Date Updated');
    expect(shownNames()[0]).toBe('Fixture Security Key L1');
    expect(within(filters()).getByRole('button', { name: 'Sort ascending' })).toBeInTheDocument();
  });

  it('follows a sort made from a header', async () => {
    await renderLoaded();
    await userEvent.click(within(screen.getAllByRole('columnheader')[1]).getByRole('button'));
    expect(within(filters()).getByRole('combobox', { name: 'Sort' })).toHaveValue('name');
    expect(within(filters()).getByRole('button', { name: 'Sort descending' })).toBeInTheDocument();
  });
});

describe('the MDS filters', () => {
  it('has the 11 filters, labelled by what they read, with their placeholders', async () => {
    await renderLoaded();
    const fields = lists().concat(within(filters()).getAllByRole('searchbox'));
    expect(fields).toHaveLength(11);
    expect(lists().map((field) => [field.getAttribute('placeholder'), field.id !== ''])).toEqual([
      ['Protocol', true],
      ['Status', true],
      ['Certification', true],
      ['User verification', true],
      ['Attachment', true],
      ['Transports', true],
      ['Key protection', true],
      ['Algorithms', true],
    ]);
    expect(within(filters()).getAllByRole('searchbox').map((field) => field.getAttribute('placeholder'))).toEqual([
      'Search name or ID',
      'Algorithm info',
      'CN',
    ]);
    expect(search('Search')).toBeInTheDocument();
    expect(search('Algorithm Info')).toBeInTheDocument();
    expect(search('CN')).toBeInTheDocument();
    expect(combobox('User Verification')).toBeInTheDocument();
  });

  it('filters as it is typed, counts what is shown, marks the columns read and offers to clear', async () => {
    await renderLoaded();
    await userEvent.type(search('Search'), '  u2f ');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture U2F Key']));
    expect(count()).toHaveTextContent('Entries: 1 of 32 total');
    for (const column of ['Name', 'ID']) {
      expect(screen.getAllByRole('columnheader').find((cell) => cell.textContent?.startsWith(column))).toHaveTextContent('(filtered)');
    }

    await userEvent.click(within(filters()).getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(shownNames()).toHaveLength(32));
    expect(search('Search')).toHaveValue('');
    expect(within(filters()).queryByRole('button', { name: 'Clear filters' })).toBeNull();
    expect(within(filters()).getByText(/^Entries:/)).toHaveTextContent('Entries: 32 of 32 total');
  });

  it('combines filters, all of which must match', async () => {
    await renderLoaded();
    await userEvent.type(combobox('Protocol'), 'FIDO2');
    await userEvent.type(search('Search'), 'Security Key');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L1', 'Fixture Security Key L2']));
  });

  it('matches a named certification level exactly, and FIDO Certified to every level reached', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Certification'));
    await userEvent.click(screen.getByRole('option', { name: 'FIDO Certified L2' }));
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L2', 'Fixture Key With Every User Verification Method']));

    await userEvent.clear(combobox('Certification'));
    await userEvent.type(combobox('Certification'), 'FIDO Certified');
    // The revoked key reached L1 before its revocation.
    await waitFor(() => expect(shownNames()).toHaveLength(29));
    expect(shownNames()).toContain('Fixture Revoked Key');
  });

  it('shows the protocol as the server spells it, and says when nothing matches', async () => {
    await renderLoaded();
    await userEvent.type(combobox('Protocol'), 'UAF');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture UAF Authenticator']));

    await userEvent.type(search('CN'), 'nothing like this');
    expect(await screen.findByText('No authenticators match the selected filters.')).toBeInTheDocument();
    expect(count()).toHaveTextContent('Entries: 0 of 32 total');
    const table = screen.getByRole('table');
    await userEvent.click(within(table).getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(shownNames()).toHaveLength(32));
  });

  it('clears a text filter with Escape', async () => {
    await renderLoaded();
    await userEvent.type(search('Search'), 'f1d0f1d0-0000-4000-8000-000000000002');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L2']));
    fireEvent.keyDown(search('Search'), { key: 'Escape' });
    expect(search('Search')).toHaveValue('');
    fireEvent.keyDown(search('Search'), { key: 'Escape' });
    expect(search('Search')).toHaveValue('');
    await waitFor(() => expect(shownNames()).toHaveLength(32));
  });

  it('keeps eight filters behind More filters, and says on the button how many of them are in use', async () => {
    await renderLoaded();
    const more = within(filters()).getByRole('button', { name: 'More filters' });
    const panel = document.getElementById(more.getAttribute('aria-controls')!)!;
    expect(more).toHaveAttribute('aria-expanded', 'false');
    expect(panel).toHaveClass('hidden');
    expect(within(panel).getAllByRole('combobox').concat(within(panel).getAllByRole('searchbox'))).toHaveLength(8);
    // The protocol, the status and the sort sit beside the search, folded with the rest on a phone only.
    const beside = combobox('Protocol').closest('.contents')!;
    expect(beside).toHaveClass('max-md:hidden');
    expect(beside).toContainElement(combobox('Status'));
    expect(beside).toContainElement(within(filters()).getByRole('combobox', { name: 'Sort' }));
    expect(panel).not.toContainElement(combobox('Protocol'));

    await userEvent.type(combobox('Protocol'), 'FIDO2');
    await userEvent.type(search('CN'), 'Fixture');
    // One count for a phone, which folds the protocol too, and one for a wider window.
    const counts = [...more.querySelectorAll('span')].map((count) => [count.textContent, count.className]);
    expect(counts).toEqual([
      ['(2)', 'md:hidden'],
      ['(1)', 'max-md:hidden'],
    ]);

    await userEvent.click(more);
    const fewer = within(filters()).getByRole('button', { name: /^Fewer filters/ });
    expect(fewer).toHaveAttribute('aria-expanded', 'true');
    expect(panel).not.toHaveClass('hidden');
    expect(panel).toHaveClass('grid');
    expect(beside).not.toHaveClass('max-md:hidden');
    await userEvent.click(fewer);
    expect(panel).toHaveClass('hidden');
  });

  it('says how tall it is while it is pinned, for the header row under it, and nothing where it is not', async () => {
    await renderLoaded();
    const height = () => document.documentElement.style.getPropertyValue('--mds-toolbar-height');
    expect(filters()).toHaveClass('lg:[@media(min-height:40rem)]:sticky', 'top-(--header-height)');
    expect(height()).toBe('0px');

    const rect = vi.spyOn(filters(), 'getBoundingClientRect').mockReturnValue({ height: 90 } as DOMRect);
    const style = vi.spyOn(window, 'getComputedStyle').mockReturnValue({ position: 'sticky' } as CSSStyleDeclaration);
    fireEvent(window, new Event('resize'));
    expect(height()).toBe('90px');
    style.mockReturnValue({ position: 'static' } as CSSStyleDeclaration);
    fireEvent(window, new Event('resize'));
    expect(height()).toBe('0px');
    style.mockRestore();
    rect.mockRestore();

    cleanup();
    expect(height()).toBe('');
  });
});

describe('an MDS filter that offers a list', () => {
  it('opens on focus with the values present, sorted, and narrows as it is typed', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Transports'));
    expect(combobox('Transports')).toHaveAttribute('aria-expanded', 'true');
    expect(options()).toEqual(['BLE', 'Hybrid', 'Internal', 'NFC', 'USB']);

    await userEvent.type(combobox('Transports'), 'n');
    expect(options()).toEqual(['Internal', 'NFC']);
    await userEvent.type(combobox('Transports'), 'zz');
    expect(within(screen.getByRole('listbox')).getByText('No matches')).toBeInTheDocument();
    expect(within(screen.getByRole('listbox')).queryAllByRole('option')).toHaveLength(0);
  });

  it('offers the static certification levels and the others present', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Certification'));
    expect(options()).toEqual(['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2']);
  });

  it('filters by the latest status, a named one exactly and FIDO Certified to every level', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Status'));
    expect(options()).toEqual(['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2', 'Not FIDO Certified', 'Revoked']);
    await userEvent.click(screen.getByRole('option', { name: 'Revoked' }));
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Revoked Key']));

    await userEvent.clear(combobox('Status'));
    await userEvent.type(combobox('Status'), 'FIDO Certified');
    await waitFor(() => expect(shownNames()).toHaveLength(28));
  });

  it('shows the user verification and algorithm lists whole, the others scrolling', async () => {
    await renderLoaded();
    await userEvent.click(combobox('User Verification'));
    expect(screen.getByRole('listbox')).not.toHaveClass('max-h-64');
    expect(options()).toHaveLength(11);
    await userEvent.click(combobox('Algorithms'));
    // Whole, but never past the window's bottom, which a pinned bar could not scroll into view.
    expect(screen.getByRole('listbox').className).toContain('max-h-[calc(100dvh-');
    await userEvent.click(combobox('Attachment'));
    expect(screen.getByRole('listbox')).toHaveClass('max-h-64');
  });

  it('moves through the list with the arrow keys, wrapping, and Enter picks', async () => {
    await renderLoaded();
    const field = combobox('Key Protection');
    field.focus();
    fireEvent.keyDown(field, { key: 'ArrowUp' });
    const listbox = screen.getByRole('listbox');
    const activeText = () => document.getElementById(field.getAttribute('aria-activedescendant')!)?.textContent;
    expect(activeText()).toBe('TEE');
    fireEvent.keyDown(field, { key: 'ArrowDown' });
    expect(activeText()).toBe('Hardware');
    fireEvent.keyDown(field, { key: 'ArrowDown' });
    expect(activeText()).toBe('Secure Element');
    expect(within(listbox).getByRole('option', { name: 'Secure Element' })).toHaveAttribute('aria-selected', 'true');
    fireEvent.keyDown(field, { key: 'Enter' });
    expect(field).toHaveValue('Secure Element');
    expect(screen.queryByRole('listbox')).toBeNull();
    await waitFor(() => expect(shownNames()).toHaveLength(30));
  });

  it('opens from ArrowDown, and leaves Enter alone with nothing chosen', async () => {
    await renderLoaded();
    const field = combobox('Attachment');
    await userEvent.click(field);
    fireEvent.keyDown(field, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).toBeNull();
    fireEvent.keyDown(field, { key: 'ArrowDown' });
    expect(screen.getByRole('listbox')).toBeInTheDocument();
    fireEvent.keyDown(field, { key: 'Escape' });
    fireEvent.keyDown(field, { key: 'Enter' });
    expect(field).toHaveValue('');
    fireEvent.keyDown(field, { key: 'Tab' });
    expect(field).toHaveValue('');
  });

  it('finds nothing to move to in a list with no match', async () => {
    await renderLoaded();
    const field = combobox('Attachment');
    await userEvent.type(field, 'zz');
    fireEvent.keyDown(field, { key: 'ArrowDown' });
    expect(field).not.toHaveAttribute('aria-activedescendant');
  });

  it('Escape closes the list, then clears the field', async () => {
    await renderLoaded();
    const field = combobox('Protocol');
    await userEvent.type(field, 'U2F');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture U2F Key']));
    fireEvent.keyDown(field, { key: 'Escape' });
    expect(screen.queryByRole('listbox')).toBeNull();
    expect(field).toHaveValue('U2F');
    fireEvent.keyDown(field, { key: 'Escape' });
    expect(field).toHaveValue('');
    fireEvent.keyDown(field, { key: 'Escape' });
    expect(field).toHaveValue('');
  });

  it('picks an option with a click, keeping the field focused, and closes when the field is left', async () => {
    await renderLoaded();
    const field = combobox('Attachment');
    await userEvent.click(field);
    await userEvent.click(screen.getByRole('option', { name: 'Internal' }));
    expect(field).toHaveValue('Internal');
    expect(field).toHaveFocus();
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Uncertified Key', 'Fixture UAF Authenticator']));

    await userEvent.click(field);
    expect(field).toHaveAttribute('aria-expanded', 'true');
    await userEvent.tab();
    // Focus is on the next filter, whose own list opens; this one's is closed.
    expect(field).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getAllByRole('listbox')).toHaveLength(1);
  });

  it('never opens an empty list', async () => {
    stubFetch(fixtureRoutes({ '/api/mds/metadata/info': () => new Promise(() => {}) }));
    renderPage(
      <ToastProvider>
        <MdsSection active />
      </ToastProvider>,
    );
    const field = combobox('Protocol');
    await userEvent.click(field);
    expect(screen.queryByRole('listbox')).toBeNull();
    fireEvent.keyDown(field, { key: 'ArrowDown' });
    expect(screen.queryByRole('listbox')).toBeNull();
  });
});
