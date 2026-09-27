import { act, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useRef, useState } from 'react';

import { renderPage } from '@/test/page';

import { ConfirmDialog } from './ConfirmDialog';

function Harness({ onConfirm }: { onConfirm: () => void }) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  return (
    <>
      <button ref={trigger} type="button" onClick={() => setOpen(true)}>
        Delete
      </button>
      <ConfirmDialog
        open={open}
        title="Delete credential"
        question="Are you sure you want to delete the credential for alice? This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={() => {
          setOpen(false);
          onConfirm();
        }}
        onCancel={() => setOpen(false)}
        returnFocusTo={() => trigger.current}
      />
    </>
  );
}

async function ask(onConfirm = vi.fn()) {
  renderPage(<Harness onConfirm={onConfirm} />);
  await userEvent.click(screen.getByRole('button', { name: 'Delete' }));
  await act(async () => {
    await new Promise((resolve) => requestAnimationFrame(resolve));
  });
  return { onConfirm, dialog: screen.getByRole('alertdialog') };
}

describe('ConfirmDialog', () => {
  it('asks the question in a narrow alert dialog, named by its title and described by the question', async () => {
    const { dialog } = await ask();
    expect(dialog).toHaveAccessibleName('Delete credential');
    expect(dialog).toHaveAccessibleDescription(/delete the credential for alice\? This action cannot be undone\./);
    expect(dialog.className).toContain('28rem');
  });

  it('starts with the focus on Cancel, so Enter does not act', async () => {
    await ask();
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();
  });

  it('acts only when the action is chosen', async () => {
    const { onConfirm, dialog } = await ask();
    const [, action] = Array.from(dialog.querySelectorAll('button')).filter((button) => button.textContent === 'Delete' || button.textContent === 'Cancel');
    await userEvent.click(action);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['Cancel', () => userEvent.click(screen.getByRole('button', { name: 'Cancel' }))],
    ['×', () => userEvent.click(screen.getByRole('button', { name: 'Close' }))],
    ['Escape', () => userEvent.keyboard('{Escape}')],
  ])('cancels on %s, giving the focus back', async (_way, cancel) => {
    const { onConfirm } = await ask();
    await cancel();
    await waitFor(() => expect(screen.queryByRole('alertdialog')).toBeNull());
    expect(screen.getByRole('button', { name: 'Delete' })).toHaveFocus();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
