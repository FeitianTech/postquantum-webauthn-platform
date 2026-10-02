import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { MonoValue } from './MonoValue';

describe('MonoValue', () => {
  const VALUE = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgk2Qr9pNdQtSK1kuCzKZyWdMWbsfL7vWUwNQ3xUCvaYYlHBP6uxT';

  function setClipboard(value: unknown) {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value });
  }

  afterEach(() => {
    vi.restoreAllMocks();
    Reflect.deleteProperty(navigator, 'clipboard');
  });

  it('copies the whole value and says so', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });
    render(<MonoValue value={VALUE} label="public key" />);

    await userEvent.click(screen.getByRole('button', { name: 'Copy public key' }));
    expect(writeText).toHaveBeenCalledWith(VALUE);
    expect(screen.getByRole('status')).toHaveTextContent('public key copied.');
  });

  it('shows the value in full and selected when copying fails', async () => {
    const writeText = vi.fn().mockRejectedValue(new DOMException('Write permission denied.', 'NotAllowedError'));
    setClipboard({ writeText });
    render(<MonoValue value={VALUE} label="public key" />);

    await userEvent.click(screen.getByRole('button', { name: 'Copy public key' }));
    expect(screen.getByRole('status')).toHaveTextContent(
      'Could not copy: NotAllowedError: Write permission denied. It is shown in full and selected, to copy by hand.',
    );
    expect(screen.getByText(VALUE).className).toContain('break-all');
    expect(window.getSelection()?.toString()).toBe(VALUE);
    await userEvent.click(screen.getByRole('button', { name: 'Show less' }));
    expect(screen.getByText(VALUE).className).toContain('truncate');
  });

  it('offers Show all when the value does not fit', async () => {
    vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(900);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(300);
    render(<MonoValue value={VALUE} label="public key" />);

    const code = screen.getByText(VALUE);
    expect(code).toHaveAttribute('title', VALUE);
    expect(screen.getByRole('button', { name: 'Show all' })).toHaveAttribute('aria-expanded', 'false');
    await userEvent.click(screen.getByRole('button', { name: 'Show all' }));
    expect(code.className).toContain('break-all');
    expect(code).not.toHaveAttribute('title');
    expect(screen.getByRole('button', { name: 'Show less' })).toHaveAttribute('aria-expanded', 'true');
  });

  it('takes Show all away once the fonts arrive and the value fits the room without it', async () => {
    // Measured first in a wider fallback font: too wide. Show all then takes 50 px.
    const scrollWidth = vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockReturnValue(330);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(300);
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(50);
    const fonts = Object.assign(new EventTarget(), { ready: new Promise<never>(() => {}) });
    Object.defineProperty(document, 'fonts', { configurable: true, value: fonts });
    try {
      render(<MonoValue value={VALUE} label="AAGUID" />);
      expect(screen.getByRole('button', { name: 'Show all' })).toBeInTheDocument();

      // In Geist Mono it is 320 px: it fits the 300 px left plus the 54 Show all takes.
      scrollWidth.mockReturnValue(320);
      act(() => {
        fonts.dispatchEvent(new Event('loadingdone'));
      });
      expect(screen.queryByRole('button', { name: 'Show all' })).toBeNull();
    } finally {
      delete (document as { fonts?: unknown }).fonts;
    }
  });

  it('says the clipboard is not available when there is none', async () => {
    setClipboard(undefined);
    render(<MonoValue value="abc" label="AAGUID" />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy AAGUID' }));
    expect(screen.getByRole('status')).toHaveTextContent('Could not copy: the clipboard is not available on this page.');
  });
});
