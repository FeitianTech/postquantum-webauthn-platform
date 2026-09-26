// The entry view of Phase 27A over the fixture's entries.
import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { entryNamed } from '@/test/mds';
import { renderPage } from '@/test/page';

import { EntryView } from './EntryView';

describe('an MDS entry, opened from the list', () => {
  it('shows its name and identifier, with copy, and leads to the full page in the current interface', async () => {
    const onBack = vi.fn();
    const entry = entryNamed('Fixture Security Key L1');
    renderPage(<EntryView entryId={entry.entryId} entry={entry} loading={false} onBack={onBack} />);

    const heading = screen.getByRole('heading', { level: 3, name: 'Fixture Security Key L1' });
    expect(heading).toHaveFocus();
    expect(screen.getByText('AAGUID', { selector: 'dt' })).toBeInTheDocument();
    expect(screen.getByText(entry.id, { selector: 'code' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy AAGUID' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the current interface' })).toHaveAttribute('href', '/');

    const back = screen.getByRole('button', { name: 'Back' });
    expect(back).toHaveAttribute('title', 'Return to authenticator list');
    await userEvent.click(back);
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it('names the identifier by its kind', () => {
    const { unmount } = renderPage(
      <EntryView entryId="aaid:F1D0#0012" entry={entryNamed('Fixture UAF Authenticator')} loading={false} onBack={() => {}} />,
    );
    expect(screen.getByText('AAID', { selector: 'dt' })).toBeInTheDocument();
    unmount();
    renderPage(<EntryView entryId="akid:x" entry={entryNamed('Fixture U2F Key')} loading={false} onBack={() => {}} />);
    expect(screen.getByText('Key identifier', { selector: 'dt' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy key identifier' })).toBeInTheDocument();
  });

  it('calls an entry without a name an authenticator', () => {
    renderPage(<EntryView entryId="x" entry={{ ...entryNamed('Fixture U2F Key'), name: ' ' }} loading={false} onBack={() => {}} />);
    expect(screen.getByRole('heading', { level: 3, name: 'Authenticator' })).toBeInTheDocument();
  });

  it('waits for the list, then says when no entry has the identifier', () => {
    const { rerender } = renderPage(<EntryView entryId="aaguid:nope" entry={null} loading onBack={() => {}} />);
    expect(screen.getByText('Authenticator metadata is loading…')).toBeInTheDocument();
    rerender(
      <>
        <div id="app-root">
          <EntryView entryId="aaguid:nope" entry={null} loading={false} onBack={() => {}} />
        </div>
        <div id="overlay-root" />
      </>,
    );
    expect(screen.getByRole('heading', { level: 3, name: 'Authenticator not found' })).toHaveFocus();
    expect(screen.getByText('aaguid:nope', { selector: 'code' })).toBeInTheDocument();
  });
});
