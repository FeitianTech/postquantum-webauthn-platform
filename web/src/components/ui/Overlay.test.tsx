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

  it('is a layer from its first frame when it mounts open, taking focus and Escape', async () => {
    function MountedOpen() {
      const [open, setOpen] = useState(true);
      return (
        <>
          <div id="app-root" />
          <div id="overlay-root" />
          <Dialog id="panel" open={open} onClose={() => setOpen(false)} labelledBy="panel-title">
            <OverlayHeader titleId="panel-title" title="Credential Details" closeLabel="Close" onClose={() => setOpen(false)} />
          </Dialog>
        </>
      );
    }
    render(<MountedOpen />);

    const dialog = await screen.findByRole('dialog', { name: 'Credential Details' });
    expect(dialog.closest('[data-overlay-panel]') ?? dialog).toHaveFocus();
    await userEvent.keyboard('{Escape}');
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 400));
    });
    expect(screen.queryByRole('dialog')).toBeNull();
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

describe('a level inside a dialog', () => {
  it('has Back before its title, titled with where it returns to', async () => {
    const onBack = vi.fn();
    render(
      <>
        <div id="app-root" />
        <div id="overlay-root" />
        <Dialog open onClose={() => {}} labelledBy="level-title">
          <OverlayHeader
            titleId="level-title"
            title="Registration Details"
            closeLabel="Close credential details"
            onClose={() => {}}
            back={{ onBack, title: 'Return to credential details' }}
          />
        </Dialog>
      </>,
    );

    const back = await screen.findByRole('button', { name: 'Back' });
    expect(back).toHaveAttribute('title', 'Return to credential details');
    expect(back.compareDocumentPosition(screen.getByRole('heading', { name: 'Registration Details' }))).toBe(
      Node.DOCUMENT_POSITION_FOLLOWING,
    );
    await userEvent.click(back);
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});

// A question asked from inside a drawer, or a credential's details opened from
// the list in it: two layers at once.
function Stacked({ questionRootFirst = false }: { questionRootFirst?: boolean }) {
  const [drawer, setDrawer] = useState(false);
  const [question, setQuestion] = useState(false);
  const layers = [
    <Drawer key="drawer" id="drawer" open={drawer} onClose={() => setDrawer(false)} label="Saved Credentials">
      <button type="button" onClick={() => setQuestion(true)}>
        Delete credential
      </button>
      <button type="button">Clear All</button>
    </Drawer>,
    <Dialog key="question" id="question" open={question} onClose={() => setQuestion(false)} label="Delete credential?" size="sm">
      <button type="button">Cancel</button>
      <button type="button">Delete</button>
    </Dialog>,
  ];
  return (
    <>
      <div id="app-root">
        <button type="button" onClick={() => setDrawer(true)}>
          Saved Credentials
        </button>
      </div>
      <div id="overlay-root" />
      {questionRootFirst ? layers.reverse() : layers}
    </>
  );
}

async function frame() {
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });
}

async function openBoth() {
  await userEvent.click(screen.getByRole('button', { name: 'Saved Credentials' }));
  await frame();
  await userEvent.click(screen.getByRole('button', { name: 'Delete credential' }));
  await frame();
}

describe('layers over layers', () => {
  it('make the layer under the top one inert, and let Escape close the top one alone', async () => {
    render(<Stacked />);
    await openBoth();

    expect(document.getElementById('drawer')).toHaveAttribute('inert');
    expect(document.getElementById('question')).not.toHaveAttribute('inert');
    await userEvent.keyboard('{Escape}');
    expect(document.getElementById('question')).toHaveAttribute('data-state', 'closed');
    expect(document.getElementById('drawer')).toHaveAttribute('data-state', 'open');
    expect(document.getElementById('drawer')).not.toHaveAttribute('inert');
    expect(screen.getByRole('button', { name: 'Delete credential' })).toHaveFocus();
  });

  it('keep Tab inside the top layer', async () => {
    render(<Stacked />);
    await openBoth();

    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Delete' })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
  });

  it('keep the page inert until the last layer closes, then give focus back to what opened the first', async () => {
    render(<Stacked />);
    await openBoth();

    await userEvent.keyboard('{Escape}');
    expect(document.getElementById('app-root')).toHaveAttribute('inert');
    await userEvent.keyboard('{Escape}');
    expect(document.getElementById('drawer')).toHaveAttribute('data-state', 'closed');
    expect(document.getElementById('app-root')).not.toHaveAttribute('inert');
    expect(screen.getByRole('button', { name: 'Saved Credentials' })).toHaveFocus();
  });

  it('paint each layer above the one under it, whatever the order of their roots', async () => {
    render(<Stacked questionRootFirst />);
    await openBoth();

    const drawer = document.getElementById('drawer')!;
    const question = document.getElementById('question')!;
    expect(question.compareDocumentPosition(drawer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(Number(question.style.zIndex)).toBeGreaterThan(Number(drawer.style.zIndex));
  });
});
