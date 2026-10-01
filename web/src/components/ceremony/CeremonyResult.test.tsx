import { render, screen } from '@testing-library/react';

import { CeremonyResult } from './CeremonyResult';

// The result panel over the sentences shared/ceremony-result.js gives.
describe('the ceremony result panel', () => {
  it('stays in the page, hidden and empty, until there is something to say', () => {
    render(<CeremonyResult result={null} />);
    const panel = document.querySelector('[data-ceremony-result]')!;
    expect(panel).toHaveAttribute('role', 'status');
    expect(panel).not.toBeVisible();
    expect(panel).toBeEmptyDOMElement();

    render(<CeremonyResult result={{ title: 'Last authentication' }} />);
    expect(document.querySelectorAll('[data-ceremony-result]')[1]).not.toBeVisible();
  });

  it('gives the counter in Geist Mono and the server\'s verdict', () => {
    render(<CeremonyResult result={{ title: 'Last authentication', signCount: 6, signCountStatus: 'ok' }} />);
    expect(screen.getByText('Last authentication')).toBeVisible();
    const row = document.querySelector('[data-row="Signature counter"]')!;
    expect(row.querySelector('code')).toHaveTextContent('6');
    expect(row).toHaveTextContent('6 Higher than the last counter the server saw for this credential, as it should be.');
    expect(document.querySelector('[data-ceremony-result]')).not.toHaveAttribute('data-verdict');
  });

  it('warns, in amber with a mark, of a counter that went backwards, and says what the tab did', () => {
    render(
      <CeremonyResult result={{ title: 'Last authentication', signCountStatus: 'regressed', consequence: 'Authentication was rejected.' }} />,
    );
    const panel = document.querySelector('[data-ceremony-result]')!;
    expect(panel).toHaveAttribute('data-verdict', 'warning');
    expect(panel.className).toContain('bg-warning-tint');
    expect(panel.querySelector('svg')).not.toBeNull();
    expect(panel.querySelector('[data-row="Signature counter"]')).toHaveTextContent(
      'Not higher than the counter the server stored: the authenticator may have been cloned. Authentication was rejected.',
    );
  });

  it('gives the challenge\'s source and status when the tab asks for them', () => {
    render(<CeremonyResult result={{ showChallenge: true, challengeSource: 'server-session', challengeStatus: 'fresh' }} />);
    expect(document.querySelector('[data-row="Challenge"]')).toHaveTextContent(
      'server-session Issued by this server for this ceremony. First use.',
    );
    expect(screen.getByText('Last ceremony')).toBeVisible();
  });
});
