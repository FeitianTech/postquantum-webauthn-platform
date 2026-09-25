import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { InfoPopover } from './InfoPopover';
import { MonoValue } from './MonoValue';
import { TOAST_DURATION_MS, ToastProvider, useToast } from './Toast';

function ToastButtons() {
  const toast = useToast();
  return (
    <>
      <button type="button" onClick={() => toast({ tone: 'success', message: 'Registration successful!' })}>
        success
      </button>
      <button type="button" onClick={() => toast({ tone: 'danger', message: 'Something failed' })}>
        danger
      </button>
      <button type="button" onClick={() => toast({ message: 'Plain' })}>
        plain
      </button>
    </>
  );
}

describe('Toast', () => {
  it('shows a message with its role, dismisses it on request and after five seconds', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(
      <>
        <div id="overlay-root" />
        <ToastProvider>
          <ToastButtons />
        </ToastProvider>
      </>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'success' }));
    await userEvent.click(screen.getByRole('button', { name: 'danger' }));

    expect(screen.getByRole('status')).toHaveTextContent('Registration successful!');
    expect(screen.getByRole('status')).toHaveAttribute('data-tone', 'success');
    expect(screen.getByRole('alert')).toHaveTextContent('Something failed');
    expect(document.getElementById('overlay-root')!.querySelector('[data-toast-viewport]')).not.toBeNull();

    await userEvent.click(screen.getAllByRole('button', { name: 'Dismiss' })[1]);
    expect(screen.queryByRole('alert')).toBeNull();

    act(() => {
      vi.advanceTimersByTime(TOAST_DURATION_MS);
    });
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('keeps at most three and gives a toast without a tone the info look', async () => {
    render(
      <ToastProvider>
        <ToastButtons />
      </ToastProvider>,
    );
    for (let i = 0; i < 4; i += 1) await userEvent.click(screen.getByRole('button', { name: 'plain' }));
    expect(screen.getAllByRole('status')).toHaveLength(3);
    expect(screen.getAllByRole('status')[0]).toHaveAttribute('data-tone', 'info');
  });
});

describe('InfoPopover', () => {
  const popover = (label = 'About prf eval first') => (
    <InfoPopover label={label} en={<p>The first prf extension input to evaluate.</p>} zh={<p>要评估的第一个 prf 扩展输入。</p>} />
  );

  it('opens on hover and closes shortly after the pointer leaves', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(popover());
    const trigger = screen.getByRole('button', { name: 'About prf eval first' });

    fireEvent.mouseEnter(trigger.parentElement!);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('group', { name: 'About prf eval first' })).toBeVisible();
    fireEvent.mouseLeave(trigger.parentElement!);
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  it('opens by click or keyboard, stays while pinned, and closes on Escape without reaching a dialog around it', async () => {
    const escapes: string[] = [];
    const onDocumentEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') escapes.push(event.key);
    };
    document.addEventListener('keydown', onDocumentEscape);
    render(popover());
    const trigger = screen.getByRole('button', { name: 'About prf eval first' });

    trigger.focus();
    await userEvent.keyboard('{Enter}');
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    fireEvent.mouseLeave(trigger.parentElement!);
    expect(trigger).toHaveAttribute('aria-expanded', 'true');

    await userEvent.keyboard('{Escape}');
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(trigger).toHaveFocus();
    expect(escapes).toEqual([]);
    document.removeEventListener('keydown', onDocumentEscape);

    await userEvent.click(trigger);
    await userEvent.click(trigger);
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
  });

  it('switches between English and 中文, keeping its English height', async () => {
    render(popover());
    await userEvent.click(screen.getByRole('button', { name: 'About prf eval first' }));
    const popup = screen.getByRole('group', { name: 'About prf eval first' });
    vi.spyOn(popup, 'offsetHeight', 'get').mockReturnValue(132);

    const toggle = screen.getByRole('button', { name: 'ENG, show in Chinese' });
    expect(toggle).toHaveTextContent('ENG');
    expect(screen.getByText('The first prf extension input to evaluate.')).toBeVisible();
    await userEvent.click(toggle);
    expect(screen.getByText('要评估的第一个 prf 扩展输入。')).toBeVisible();
    expect(screen.getByText('The first prf extension input to evaluate.')).not.toBeVisible();
    expect(popup.style.minHeight).toBe('132px');
    await userEvent.click(screen.getByRole('button', { name: '中, show in English' }));
    expect(screen.getByText('The first prf extension input to evaluate.')).toBeVisible();
  });

  it('keeps one open at a time and closes on a click elsewhere', async () => {
    render(
      <>
        {popover('First')}
        {popover('Second')}
        <p>Outside</p>
      </>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'First' }));
    await userEvent.click(screen.getByRole('button', { name: 'Second' }));
    expect(screen.getByRole('button', { name: 'First' })).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('button', { name: 'Second' })).toHaveAttribute('aria-expanded', 'true');

    await userEvent.click(screen.getByText('Outside'));
    expect(screen.getByRole('button', { name: 'Second' })).toHaveAttribute('aria-expanded', 'false');
  });
});

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
    await userEvent.click(screen.getByRole('button', { name: 'Show all' }));
    expect(code.className).toContain('break-all');
    expect(code).not.toHaveAttribute('title');
  });

  it('says the clipboard is not available when there is none', async () => {
    setClipboard(undefined);
    render(<MonoValue value="abc" label="AAGUID" />);
    await userEvent.click(screen.getByRole('button', { name: 'Copy AAGUID' }));
    expect(screen.getByRole('status')).toHaveTextContent('Could not copy: the clipboard is not available on this page.');
  });
});

describe('InfoPopover placement', () => {
  const rect = (top: number, left: number, width: number, height: number) =>
    ({ top, left, width, height, bottom: top + height, right: left + width, x: left, y: top, toJSON() {} }) as DOMRect;
  const viewport = { width: 1000, height: 800 };

  it('opens below and from the left when it fits', async () => {
    const { placePopup } = await import('./InfoPopover');
    expect(placePopup(rect(120, 40, 336, 200), rect(90, 40, 20, 20), viewport)).toEqual({ side: 'bottom', align: 'start' });
  });

  it('opens above when there is no room below and more above, and from the right at the right edge', async () => {
    const { placePopup } = await import('./InfoPopover');
    expect(placePopup(rect(760, 700, 336, 200), rect(730, 700, 20, 20), viewport)).toEqual({ side: 'top', align: 'end' });
    expect(placePopup(rect(130, 40, 336, 700), rect(100, 40, 20, 20), viewport)).toEqual({ side: 'bottom', align: 'start' });
  });

  it('applies the placement it measures', async () => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
      return this.getAttribute('role') === 'group' ? rect(900, 900, 336, 200) : rect(870, 900, 20, 20);
    });
    render(<InfoPopover label="Near the corner" en={<p>English</p>} zh={<p>中文</p>} />);
    await userEvent.click(screen.getByRole('button', { name: 'Near the corner' }));

    const popup = screen.getByRole('group', { name: 'Near the corner' });
    expect(popup).toHaveAttribute('data-side', 'top');
    expect(popup).toHaveAttribute('data-align', 'end');
    expect(popup.className).toContain('bottom-full');
    vi.restoreAllMocks();
  });
});
