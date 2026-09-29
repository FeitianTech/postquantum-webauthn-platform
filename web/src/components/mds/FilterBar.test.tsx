// The MDS filters over the fixture snapshot.
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
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
const search = (name: string) => within(filters()).getByRole('searchbox', { name });
const options = () => within(screen.getByRole('listbox')).getAllByRole('option').map((option) => option.textContent);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the MDS filters', () => {
  it('has the 11 filters, labelled by their column, with the current placeholders', async () => {
    await renderLoaded();
    const fields = within(filters()).getAllByRole('combobox').concat(within(filters()).getAllByRole('searchbox'));
    expect(fields).toHaveLength(11);
    expect(within(filters()).getAllByRole('combobox').map((field) => [field.getAttribute('placeholder'), field.id !== ''])).toEqual([
      ['Protocol', true],
      ['Certification', true],
      ['User verification', true],
      ['Attachment', true],
      ['Transports', true],
      ['Key protection', true],
      ['Algorithms', true],
    ]);
    expect(within(filters()).getAllByRole('searchbox').map((field) => field.getAttribute('placeholder'))).toEqual([
      'Search name',
      'AAGUID or AAID',
      'Algorithm info',
      'CN',
    ]);
    expect(search('Name')).toBeInTheDocument();
    expect(search('ID')).toBeInTheDocument();
    expect(search('Algorithm Info')).toBeInTheDocument();
    expect(search('CN')).toBeInTheDocument();
    expect(combobox('User Verification')).toBeInTheDocument();
  });

  it('filters as it is typed, counts what is shown, marks the column and says how many filters are in use', async () => {
    await renderLoaded();
    await userEvent.type(search('Name'), '  u2f ');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture U2F Key']));
    expect(count()).toHaveTextContent('Entries: 1 of 32 total');
    expect(screen.getAllByRole('columnheader').find((cell) => cell.textContent?.startsWith('Name'))).toHaveTextContent('(filtered)');
    expect(within(filters()).getByText('1 active')).toBeInTheDocument();

    await userEvent.click(within(filters()).getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(shownNames()).toHaveLength(32));
    expect(search('Name')).toHaveValue('');
    expect(within(filters()).queryByText(/active$/)).toBeNull();
  });

  it('combines filters, all of which must match', async () => {
    await renderLoaded();
    await userEvent.type(combobox('Protocol'), 'FIDO2');
    await userEvent.type(search('Name'), 'Security Key');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L1', 'Fixture Security Key L2']));
    expect(within(filters()).getByText('2 active')).toBeInTheDocument();
  });

  it('matches a named certification level exactly, and FIDO Certified to every level', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Certification'));
    await userEvent.click(screen.getByRole('option', { name: 'Revoked' }));
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Revoked Key']));

    await userEvent.clear(combobox('Certification'));
    await userEvent.type(combobox('Certification'), 'FIDO Certified L2');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L2', 'Fixture Key With Every User Verification Method']));

    await userEvent.clear(combobox('Certification'));
    await userEvent.type(combobox('Certification'), 'FIDO Certified');
    await waitFor(() => expect(shownNames()).toHaveLength(28));
  });

  it('shows the protocol as the server spells it, and says when nothing matches', async () => {
    await renderLoaded();
    await userEvent.type(combobox('Protocol'), 'Uaf');
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
    await userEvent.type(search('ID'), 'f1d0f1d0-0000-4000-8000-000000000002');
    await waitFor(() => expect(shownNames()).toEqual(['Fixture Security Key L2']));
    fireEvent.keyDown(search('ID'), { key: 'Escape' });
    expect(search('ID')).toHaveValue('');
    fireEvent.keyDown(search('ID'), { key: 'Escape' });
    expect(search('ID')).toHaveValue('');
    await waitFor(() => expect(shownNames()).toHaveLength(32));
  });

  it('shows and hides the filters on a phone', async () => {
    await renderLoaded();
    const toggle = within(filters()).getByRole('button', { name: 'Show filters' });
    const grid = document.getElementById(toggle.getAttribute('aria-controls')!)!;
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    expect(grid).toHaveClass('hidden');
    await userEvent.click(toggle);
    expect(within(filters()).getByRole('button', { name: 'Hide filters' })).toHaveAttribute('aria-expanded', 'true');
    expect(grid).not.toHaveClass('hidden');
  });
});

describe('an MDS filter that offers a list', () => {
  it('opens on focus with the values present, sorted, and narrows as it is typed', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Transports'));
    expect(combobox('Transports')).toHaveAttribute('aria-expanded', 'true');
    expect(options()).toEqual(['Ble', 'Hybrid', 'Internal', 'Nfc', 'Usb']);

    await userEvent.type(combobox('Transports'), 'n');
    expect(options()).toEqual(['Internal', 'Nfc']);
    await userEvent.type(combobox('Transports'), 'zz');
    expect(within(screen.getByRole('listbox')).getByText('No matches')).toBeInTheDocument();
    expect(within(screen.getByRole('listbox')).queryAllByRole('option')).toHaveLength(0);
  });

  it('offers the static certification statuses and the others present', async () => {
    await renderLoaded();
    await userEvent.click(combobox('Certification'));
    expect(options()).toEqual(['FIDO Certified', 'FIDO Certified L1', 'FIDO Certified L2', 'NOT FIDO Certified', 'Revoked']);
  });

  it('shows the user verification and algorithm lists whole, the others scrolling', async () => {
    await renderLoaded();
    await userEvent.click(combobox('User Verification'));
    expect(screen.getByRole('listbox')).not.toHaveClass('max-h-64');
    expect(options()).toHaveLength(11);
    await userEvent.click(combobox('Algorithms'));
    expect(screen.getByRole('listbox')).not.toHaveClass('max-h-64');
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
    expect(activeText()).toBe('Tee');
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
