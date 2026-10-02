import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

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
