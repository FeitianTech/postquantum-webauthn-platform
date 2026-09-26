import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { renderPage } from '@/test/page';

import { AppShell } from './AppShell';

beforeEach(() => {
  window.history.replaceState({ fromNext: true }, '', '/beta');
});

describe('the app shell', () => {
  it('shows the title, the four sections, Analyze Browser and GitHub', () => {
    renderPage(<AppShell />);

    expect(screen.getByRole('heading', { level: 1, name: 'FIDO2/WebAuthn PQC Developer Tools' })).toBeInTheDocument();
    const tabs = within(screen.getByRole('tablist', { name: 'Sections' })).getAllByRole('tab');
    expect(tabs.map((tab) => tab.getAttribute('id'))).toEqual(['nav-tab-simple', 'nav-tab-advanced', 'nav-tab-codec', 'nav-tab-mds']);
    expect(tabs.map((tab) => tab.textContent)).toEqual([
      'Simple AuthenticationSimple Authentication',
      'Advanced AuthenticationAdvanced Authentication',
      'CodecCodec',
      'FIDO MDS AuthenticatorsFIDO MDS Authenticators',
    ]);
    const analyze = screen.getByRole('button', { name: 'Analyze Browser' });
    expect(analyze).toHaveAttribute('aria-haspopup', 'dialog');
    expect(analyze).toHaveAttribute('aria-controls', 'analyze-browser-panel');
    const github = screen.getByRole('link', { name: 'View project on GitHub' });
    expect(github).toHaveAttribute('href', 'https://github.com/FeitianTech/postquantum-webauthn-platform');
    expect(github).toHaveAttribute('target', '_blank');
    expect(github).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('keeps the footer text of the current UI', () => {
    renderPage(<AppShell />);
    const footer = screen.getByRole('contentinfo');

    expect(footer).toHaveTextContent('© 2026 Feitian Technologies Co., Ltd. All rights reserved.');
    expect(footer.textContent).toBe(
      '© 2026 Feitian Technologies Co., Ltd. All rights reserved.' +
        'This is an independent testing platform and is not affiliated with or endorsed by the FIDO Alliance, W3C, or Open Quantum Safe.',
    );
    expect(within(footer).getByText('not affiliated with or endorsed by').tagName).toBe('STRONG');
  });

  it('opens on Simple Authentication, whose note leads to the current interface', () => {
    renderPage(<AppShell />);
    const panel = screen.getByRole('tabpanel', { name: 'Simple Authentication' });

    expect(within(panel).getByRole('heading', { level: 2, name: 'Simple Authentication' })).toBeInTheDocument();
    expect(panel).toHaveTextContent('Register and authenticate with passkeys using default presets.');
    expect(panel).toHaveTextContent('Simple Authentication has not moved to the new interface yet.');
    expect(within(panel).getByRole('link', { name: 'Open the current interface' })).toHaveAttribute('href', '/');
    // The four sections' panels (the Codec's Decode and Encode panels are tabpanels too).
    expect(screen.getAllByRole('tabpanel', { hidden: true }).filter((element) => element.id.startsWith('nav-panel-'))).toHaveLength(4);
  });

  it('switches sections on the page and writes the section to the hash, keeping the history state', async () => {
    renderPage(<AppShell />);

    await userEvent.click(screen.getByRole('tab', { name: 'Codec' }));
    const panel = screen.getByRole('tabpanel', { name: 'Codec' });
    expect(panel).toHaveTextContent('Decode or encode WebAuthn payloads to inspect their underlying data formats.');
    // The Codec has moved: it leads nowhere else.
    expect(within(panel).queryByRole('link', { name: 'Open the current interface' })).toBeNull();
    expect(within(panel).getByRole('tablist', { name: 'Codec mode' })).toBeInTheDocument();
    expect(screen.queryByRole('tabpanel', { name: 'Simple Authentication' })).toBeNull();
    expect(window.location.hash).toBe('#codec');
    expect(window.location.pathname).toBe('/beta');
    expect(window.history.state).toEqual({ fromNext: true });
    expect(window.history.length).toBe(1);

    await userEvent.click(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' }));
    expect(screen.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' })).toHaveTextContent(
      'Explore the authenticators published by the FIDO Metadata Service (MDS).',
    );
  });

  it('opens the section the hash names, and follows the hash when it changes', async () => {
    window.history.replaceState(null, '', '/beta#advanced');
    renderPage(<AppShell />);

    expect(await screen.findByRole('tabpanel', { name: 'Advanced Authentication' })).toHaveTextContent(
      'Configure WebAuthn registration and authentication requests with detailed settings.',
    );
    expect(screen.getByRole('tab', { name: 'Advanced Authentication' })).toHaveAttribute('aria-selected', 'true');

    act(() => {
      window.location.hash = '#mds';
    });
    await waitFor(() => expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveAttribute('aria-selected', 'true'));

    act(() => {
      window.location.hash = '#nothing';
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' })).toHaveAttribute('aria-selected', 'true');
  });

  it('offers the sections, Analyze Browser and GitHub in a menu sheet on a phone', async () => {
    renderPage(<AppShell />);
    const menu = screen.getByRole('button', { name: 'Menu' });
    expect(menu).toHaveAttribute('aria-expanded', 'false');

    await userEvent.click(menu);
    const sheet = await screen.findByRole('dialog', { name: 'Menu' });
    expect(menu).toHaveAttribute('aria-expanded', 'true');
    expect(within(sheet).getByRole('button', { name: 'Simple Authentication' })).toHaveAttribute('aria-current', 'true');
    expect(within(sheet).getByRole('link', { name: 'View project on GitHub' })).toHaveAttribute('target', '_blank');
    expect(within(sheet).getByRole('button', { name: 'Analyze Browser' })).toHaveAttribute('aria-controls', 'analyze-browser-panel');

    await userEvent.click(within(sheet).getByRole('button', { name: 'Codec' }));
    expect(screen.getByRole('tabpanel', { name: 'Codec' })).toBeInTheDocument();
    expect(window.location.hash).toBe('#codec');
    await waitFor(() => expect(menu).toHaveFocus());

    await userEvent.click(menu);
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Menu' })).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(menu).toHaveAttribute('aria-expanded', 'false'));
  });
});
