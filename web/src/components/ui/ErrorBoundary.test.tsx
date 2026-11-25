import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ErrorBoundary, FailedNotice } from './ErrorBoundary';

function Broken(): never {
  throw new Error('broke');
}

describe('a part of the page that throws while rendering', () => {
  it('shows that it could not be shown, with Reload, and leaves what is beside it', () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <>
        <ErrorBoundary>
          <Broken />
        </ErrorBoundary>
        <p>Beside it</p>
      </>,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('This part could not be shown. Reload the page to try again.');
    expect(screen.getByRole('button', { name: 'Reload' })).toBeVisible();
    expect(screen.getByText('Beside it')).toBeVisible();
    // React logs the error it caught, once.
    expect(logged).toHaveBeenCalledTimes(1);
    expect(logged.mock.calls[0]).toContainEqual(new Error('broke'));
    logged.mockRestore();
  });

  it('shows its fallback when it has one, and its children while nothing throws', () => {
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const { rerender } = render(<ErrorBoundary fallback={<p>Fallback</p>}>Fine</ErrorBoundary>);
    expect(screen.getByText('Fine')).toBeVisible();

    rerender(
      <ErrorBoundary fallback={<p>Fallback</p>}>
        <Broken />
      </ErrorBoundary>,
    );
    expect(screen.getByText('Fallback')).toBeVisible();
    expect(logged).toHaveBeenCalledTimes(1);
    logged.mockRestore();
  });
});

describe('the notice of a part that did not come up', () => {
  it('reloads the page on Reload', async () => {
    const reload = vi.fn();
    vi.spyOn(window, 'location', 'get').mockReturnValue({ ...window.location, reload });
    render(<FailedNotice what="section" />);

    expect(screen.getByRole('alert')).toHaveTextContent('This section could not be shown. Reload the page to try again.');
    await userEvent.click(screen.getByRole('button', { name: 'Reload' }));
    expect(reload).toHaveBeenCalledTimes(1);
    vi.restoreAllMocks();
  });
});
