import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { CodeBlock } from './CodeBlock';
import { copyStatusText, useCopy } from './useCopy';

const EDN = '{\n  1: "a",\n  "1": "b",\n  1: "c"\n}';

function setClipboard(value: unknown) {
  Object.defineProperty(navigator, 'clipboard', { configurable: true, value });
}

// jsdom lays nothing out: say how tall the text is and how tall its box, and let
// the observer report as a browser's would.
function layOut(scrollHeight: number, clientHeight: number) {
  vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(scrollHeight);
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(clientHeight);
}

class ReportingObserver {
  static last: ReportingObserver | null = null;
  disconnected = false;
  constructor(private readonly callback: () => void) {
    ReportingObserver.last = this;
  }
  observe() {}
  report() {
    this.callback();
  }
  disconnect() {
    this.disconnected = true;
  }
}

const NoObserver = window.ResizeObserver;

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, 'clipboard');
  Object.defineProperty(window, 'ResizeObserver', { configurable: true, writable: true, value: NoObserver });
});

describe('CodeBlock', () => {
  it('shows the whole text in Geist Mono on white, wrapping instead of scrolling sideways', () => {
    render(<CodeBlock value={EDN} label="EDN (exact bytes)" />);
    const pre = document.querySelector('pre')!;
    expect(pre.textContent).toBe(EDN);
    expect(pre.className).toContain('font-mono');
    expect(pre.className).toContain('whitespace-pre-wrap');
    expect(pre.className).toContain('wrap-anywhere');
    expect(pre.parentElement!.className).toContain('bg-surface');
    expect(screen.queryByRole('button', { name: 'Show all' })).not.toBeInTheDocument();
  });

  it('starts a long text collapsed with Show all, and opens and closes it', async () => {
    layOut(900, 256);
    render(<CodeBlock value={EDN} label="EDN (exact bytes)" />);
    const pre = document.querySelector('pre')!;
    expect(pre.className).toContain('max-h-64');
    expect(pre.textContent).toBe(EDN);

    await userEvent.click(screen.getByRole('button', { name: 'Show all' }));
    expect(pre.className).not.toContain('max-h-64');
    expect(screen.getByRole('button', { name: 'Show less' })).toHaveAttribute('aria-expanded', 'true');
    await userEvent.click(screen.getByRole('button', { name: 'Show less' }));
    expect(pre.className).toContain('max-h-64');
  });

  it('measures again when its size changes, and stops watching when it goes', () => {
    Object.defineProperty(window, 'ResizeObserver', { configurable: true, writable: true, value: ReportingObserver });
    const heights = vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(100);
    vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(256);
    const { unmount } = render(<CodeBlock value={EDN} label="EDN (exact bytes)" />);
    expect(screen.queryByRole('button', { name: 'Show all' })).not.toBeInTheDocument();

    heights.mockReturnValue(900);
    act(() => ReportingObserver.last!.report());
    expect(screen.getByRole('button', { name: 'Show all' })).toBeInTheDocument();
    unmount();
    expect(ReportingObserver.last!.disconnected).toBe(true);
  });

  it('shows the whole text at once when it is not collapsible', () => {
    layOut(900, 256);
    render(<CodeBlock value={EDN} label="Raw codec output" collapsible={false} />);
    expect(document.querySelector('pre')!.className).not.toContain('max-h-64');
    expect(screen.queryByRole('button', { name: 'Show all' })).not.toBeInTheDocument();
  });

  it('copies the whole text and says so', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });
    render(<CodeBlock value={EDN} label="EDN (exact bytes)" />);

    await userEvent.click(screen.getByRole('button', { name: 'Copy EDN (exact bytes)' }));
    expect(writeText).toHaveBeenCalledWith(EDN);
    expect(screen.getByRole('status')).toHaveTextContent('EDN (exact bytes) copied.');
  });

  it('opens and selects the text when copying fails', async () => {
    layOut(900, 256);
    setClipboard({ writeText: vi.fn().mockRejectedValue(new DOMException('Write permission denied.', 'NotAllowedError')) });
    render(<CodeBlock value={EDN} label="Hex" />);

    await userEvent.click(screen.getByRole('button', { name: 'Copy Hex' }));
    expect(screen.getByRole('status')).toHaveTextContent(
      'Could not copy: NotAllowedError: Write permission denied. It is shown in full and selected, to copy by hand.',
    );
    expect(screen.getByRole('status').className).toContain('text-danger');
    expect(document.querySelector('pre')!.className).not.toContain('max-h-64');
    expect(window.getSelection()?.toString()).toBe(EDN);
  });
});

describe('useCopy', () => {
  function Probe({ text }: { text: string }) {
    const { outcome, copy } = useCopy();
    return (
      <button type="button" onClick={() => void copy(text)}>
        {outcome.state}
      </button>
    );
  }

  it('says "copied" for two seconds, then nothing', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    setClipboard({ writeText: vi.fn().mockResolvedValue(undefined) });
    render(<Probe text="a0" />);
    await userEvent.click(screen.getByRole('button'));
    expect(screen.getByRole('button')).toHaveTextContent('copied');
    act(() => vi.advanceTimersByTime(2000));
    expect(screen.getByRole('button')).toHaveTextContent('idle');
  });

  it('writes the status line for each outcome', () => {
    expect(copyStatusText('Hex', { state: 'idle' })).toBe('');
    expect(copyStatusText('Hex', { state: 'copied' })).toBe('Hex copied.');
    expect(copyStatusText('Hex', { state: 'failed', reason: 'Denied!' })).toBe(
      'Could not copy: Denied! It is shown in full and selected, to copy by hand.',
    );
    expect(copyStatusText('Hex', { state: 'failed' })).toBe(
      'Could not copy: . It is shown in full and selected, to copy by hand.',
    );
  });
});
