import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { InfoPopover } from './InfoPopover';

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
