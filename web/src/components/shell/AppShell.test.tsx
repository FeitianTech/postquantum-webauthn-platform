import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { keepRecords } from '@/test/credentials';
import { fixtureRoutes, stubFetch } from '@/test/mds';
import { renderPage } from '@/test/page';

import { AppShell } from './AppShell';

beforeEach(() => {
  window.history.replaceState({ fromNext: true }, '', '/');
  // The MDS section loads the fixture snapshot when it is first shown.
  stubFetch(fixtureRoutes());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the app shell', () => {
  // First in the file: the page has not moved from the URL it opened on.
  it('keeps the section the URL names a placeholder until its chunk arrives, then shows it without an entrance', async () => {
    window.history.replaceState({ fromNext: true }, '', '/#codec');
    renderPage(<AppShell />);
    const placeholder = screen.getByRole('tabpanel', { name: 'Codec' });

    expect(placeholder).toHaveAttribute('aria-busy', 'true');
    expect(placeholder).toBeEmptyDOMElement();
    await userEvent.keyboard('{Shift}');
    const heading = await screen.findByRole('heading', { level: 2, name: 'Codec' });
    const panel = screen.getByRole('tabpanel', { name: 'Codec' });
    expect(panel).toContainElement(heading);
    expect(panel).not.toHaveAttribute('aria-busy');
    expect(panel.className).not.toContain('animate-[section-in');
  });

  // Before the page has moved: what the URL opened is simply there.
  it('opens on the section the URL names, simply there; a section the person brings up comes in', async () => {
    window.history.replaceState({ fromNext: true }, '', '/#advanced');
    renderPage(<AppShell />);
    const advanced = screen.getByRole('tabpanel', { name: 'Advanced Authentication' });

    expect(screen.getByRole('tab', { name: 'Advanced Authentication' })).toHaveAttribute('aria-selected', 'true');
    expect(advanced.className).not.toContain('animate-[section-in');

    await userEvent.click(screen.getByRole('tab', { name: 'Codec' }));
    // The Codec's chunk arrives after the click: it comes in then.
    await screen.findByRole('heading', { level: 2, name: 'Codec' });
    expect(screen.getByRole('tabpanel', { name: 'Codec' }).className).toContain('animate-[section-in');
    await userEvent.click(screen.getByRole('tab', { name: 'Advanced Authentication' }));
    await screen.findByRole('heading', { level: 2, name: 'Advanced Authentication' });
    expect(screen.getByRole('tabpanel', { name: 'Advanced Authentication' }).className).toContain('animate-[section-in');
  });

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

  it('measures the header into --header-height, and again when its size changes', () => {
    const watching = new Map<Element, ResizeObserverCallback>();
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor(private callback: ResizeObserverCallback) {}
        observe(target: Element) {
          watching.set(target, this.callback);
        }
        unobserve() {}
        disconnect() {}
      },
    );
    let height = 61;
    const measured = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      return { height: this.matches('[data-shell-header]') ? height : 0 } as DOMRect;
    });
    const { unmount } = renderPage(<AppShell />);
    const variable = () => document.documentElement.style.getPropertyValue('--header-height');
    expect(variable()).toBe('61px');

    height = 105;
    act(() => watching.get(document.querySelector('[data-shell-header]')!)!([], {} as ResizeObserver));
    expect(variable()).toBe('105px');

    unmount();
    expect(variable()).toBe('');
    measured.mockRestore();
  });

  it('keeps the footer text the site has always had', () => {
    renderPage(<AppShell />);
    const footer = screen.getByRole('contentinfo');

    expect(footer).toHaveTextContent('© 2026 Feitian Technologies Co., Ltd. All rights reserved.');
    expect(footer.textContent).toBe(
      '© 2026 Feitian Technologies Co., Ltd. All rights reserved.' +
        'This is an independent testing platform and is not affiliated with or endorsed by the FIDO Alliance, W3C, or Open Quantum Safe.',
    );
    expect(within(footer).getByText('not affiliated with or endorsed by').tagName).toBe('STRONG');
  });

  it('opens on Simple Authentication, with the saved credentials beside it', async () => {
    renderPage(<AppShell />);
    const panel = screen.getByRole('tabpanel', { name: 'Simple Authentication' });

    expect(within(panel).getByRole('heading', { level: 2, name: 'Simple Authentication' })).toBeInTheDocument();
    expect(panel).toHaveTextContent('Register and authenticate with passkeys using default presets.');
    // Simple Authentication has moved: it leads nowhere else.
    expect(within(panel).queryByRole('link', { name: 'Open the current interface' })).toBeNull();
    expect(await within(panel).findByText('No credentials registered yet.')).toBeVisible();
    // The four sections' panels (the Codec's Decode and Encode panels are tabpanels too).
    expect(screen.getAllByRole('tabpanel', { hidden: true }).filter((element) => element.id.startsWith('nav-panel-'))).toHaveLength(4);
  });

  it('switches sections on the page and writes the section to the hash, keeping the history state', async () => {
    renderPage(<AppShell />);

    await userEvent.click(screen.getByRole('tab', { name: 'Codec' }));
    await screen.findByRole('heading', { level: 2, name: 'Codec' });
    const panel = screen.getByRole('tabpanel', { name: 'Codec' });
    expect(panel).toHaveTextContent('Decode or encode WebAuthn payloads to inspect their underlying data formats.');
    // The Codec has moved: it leads nowhere else.
    expect(within(panel).queryByRole('link', { name: 'Open the current interface' })).toBeNull();
    expect(within(panel).getByRole('tablist', { name: 'Codec mode' })).toBeInTheDocument();
    expect(screen.queryByRole('tabpanel', { name: 'Simple Authentication' })).toBeNull();
    expect(window.location.hash).toBe('#codec');
    expect(window.location.pathname).toBe('/');
    expect(window.history.state).toEqual({ fromNext: true });
    expect(window.history.length).toBe(1);

    await userEvent.click(screen.getByRole('tab', { name: 'FIDO MDS Authenticators' }));
    await screen.findByRole('heading', { level: 2, name: 'FIDO MDS Authenticators' });
    const mds = screen.getByRole('tabpanel', { name: 'FIDO MDS Authenticators' });
    expect(mds).toHaveTextContent('Explore the authenticators published by the FIDO Metadata Service (MDS).');
    // The MDS list has moved too: it loads its entries, and leads nowhere else.
    expect(within(mds).queryByRole('link', { name: 'Open the current interface' })).toBeNull();
    expect(await within(mds).findByRole('table', { name: 'FIDO MDS authenticators' })).toBeInTheDocument();
  });

  it('opens the section the hash names, and follows the hash when it changes', async () => {
    window.history.replaceState(null, '', '/#advanced');
    renderPage(<AppShell />);

    await screen.findByRole('heading', { level: 2, name: 'Advanced Authentication' });
    expect(screen.getByRole('tabpanel', { name: 'Advanced Authentication' })).toHaveTextContent(
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
  it('opens a saved credential\'s FIDO MDS entry, and Back returns to the Simple tab', async () => {
    Element.prototype.scrollIntoView = vi.fn();
    keepRecords([
      { type: 'simple', credentialId: 'AQID', email: 'alice', aaguidHex: 'f1d0f1d0000040008000000000000001', attestationSummary: { rootValid: true } },
    ]);
    renderPage(<AppShell />);
    const panel = screen.getByRole('tabpanel', { name: 'Simple Authentication' });
    const link = await within(panel).findByRole('button', { name: 'FIDO MDS' });
    expect(link).toHaveAttribute('title', 'Open authenticator metadata');

    await userEvent.click(link);
    expect(window.location.hash).toBe('#mds/aaguid:f1d0f1d0-0000-4000-8000-000000000001');
    expect(await screen.findByRole('heading', { level: 3, name: 'Fixture Security Key L1' })).toBeVisible();

    act(() => window.history.back());
    await waitFor(() => expect(screen.getByRole('tabpanel', { name: 'Simple Authentication' })).toBeVisible());
    expect(window.location.hash).toBe('');
    keepRecords();
  });
});
