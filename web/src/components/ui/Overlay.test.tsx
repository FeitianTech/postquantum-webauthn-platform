import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef, useState } from 'react';

import { Dialog, Drawer, OverlayBody, OverlayHeader, Sheet } from './Overlay';

function Harness({ variant = 'dialog' }: { variant?: 'dialog' | 'drawer' | 'sheet' }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const Layer = variant === 'drawer' ? Drawer : variant === 'sheet' ? Sheet : Dialog;
  return (
    <>
      <div id="app-root">
        <button ref={trigger} type="button" aria-controls="panel" onClick={() => setOpen(true)}>
          Open
        </button>
        <button type="button">Elsewhere</button>
      </div>
      <div id="overlay-root" />
      <Layer id="panel" open={open} onClose={() => setOpen(false)} labelledBy="panel-title" returnFocusTo={() => trigger.current}>
        <OverlayHeader
          titleId="panel-title"
          title="Browser Analysis"
          closeLabel="Close browser analysis"
          onClose={() => setOpen(false)}
          actions={<button type="button">Copy report</button>}
        />
        <OverlayBody>
          <button type="button" disabled>
            Disabled
          </button>
          <div hidden>
            <button type="button">Hidden</button>
          </div>
          <a href="#x">Last</a>
        </OverlayBody>
      </Layer>
    </>
  );
}

async function openIt() {
  await userEvent.click(screen.getByRole('button', { name: 'Open' }));
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });
}

describe('Overlay', () => {
  it('renders nothing but its hidden root, named by aria-controls, until it opens', () => {
    render(<Harness />);

    const root = document.getElementById('panel')!;
    expect(root).toHaveAttribute('hidden');
    expect(document.getElementById('overlay-root')).toContainElement(root);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('opens as a labelled modal dialog that takes focus, and makes the page behind inert', async () => {
    render(<Harness />);
    await openIt();

    const dialog = screen.getByRole('dialog', { name: 'Browser Analysis' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveFocus();
    expect(document.getElementById('panel')).toHaveAttribute('data-state', 'open');
    expect(document.getElementById('app-root')).toHaveAttribute('inert');
  });

  it('keeps Tab and Shift+Tab inside, skipping disabled and hidden controls', async () => {
    render(<Harness />);
    await openIt();
    const copy = screen.getByRole('button', { name: 'Copy report' });
    const close = screen.getByRole('button', { name: 'Close browser analysis' });
    const last = screen.getByRole('link', { name: 'Last' });

    await userEvent.tab();
    expect(copy).toHaveFocus();
    await userEvent.tab();
    expect(close).toHaveFocus();
    await userEvent.tab();
    expect(last).toHaveFocus();
    await userEvent.tab();
    expect(copy).toHaveFocus();
    await userEvent.tab({ shift: true });
    expect(last).toHaveFocus();

    screen.getByRole('dialog').focus();
    await userEvent.tab({ shift: true });
    expect(last).toHaveFocus();
  });

  it('closes on Escape and gives focus back to the trigger', async () => {
    render(<Harness />);
    await openIt();

    await userEvent.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Open', hidden: true })).toHaveFocus();
    expect(document.getElementById('app-root')).not.toHaveAttribute('inert');
    expect(document.getElementById('panel')).toHaveAttribute('data-state', 'closed');
  });

  it('closes from the close button and the backdrop, not from a click inside', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<Harness />);
    await openIt();

    await userEvent.click(screen.getByRole('link', { name: 'Last' }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Close browser analysis' }));
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.getElementById('panel')).toHaveAttribute('hidden');

    await openIt();
    fireEvent.click(document.querySelector('[data-overlay-backdrop]')!);
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('starts scrolled to the top each time it opens', async () => {
    render(<Harness />);
    await openIt();
    const body = document.querySelector<HTMLElement>('[data-overlay-scroll]')!;
    body.scrollTop = 120;
    await userEvent.keyboard('{Escape}');
    await openIt();
    expect(document.querySelector<HTMLElement>('[data-overlay-scroll]')!.scrollTop).toBe(0);
  });

  it.each(['drawer', 'sheet'] as const)('opens as a %s with the same behaviour', async (variant) => {
    render(<Harness variant={variant} />);
    await openIt();

    expect(document.getElementById('panel')).toHaveAttribute('data-overlay', variant);
    expect(screen.getByRole('dialog', { name: 'Browser Analysis' })).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Open' })).toHaveFocus();
  });

  it('holds focus on the panel when it has no controls, and returns focus to what had it by default', async () => {
    function Bare() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>
            Show
          </button>
          <Dialog open={open} onClose={() => setOpen(false)} label="Empty">
            <p>Nothing to press</p>
          </Dialog>
        </>
      );
    }
    render(<Bare />);
    await userEvent.click(screen.getByRole('button', { name: 'Show' }));
    await act(async () => {
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });
    const dialog = screen.getByRole('dialog', { name: 'Empty' });
    await userEvent.tab();
    expect(dialog).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Show' })).toHaveFocus();
  });
});
