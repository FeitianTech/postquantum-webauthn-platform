import { act, render, screen } from '@testing-library/react';

import { useEntrance } from './entrance';

function Panel({ shown }: { shown: boolean }) {
  const entrance = useEntrance(shown);
  return <div data-testid="panel" hidden={!shown} className={entrance} />;
}

const panel = () => screen.getByTestId('panel');

describe('the entrance', () => {
  it('is none for what the page opens with, and stays so while it is shown', () => {
    const { rerender, unmount } = render(<Panel shown />);
    expect(panel()).not.toHaveAttribute('class');
    rerender(<Panel shown />);
    expect(panel()).not.toHaveAttribute('class');
    unmount();
  });

  it('plays once the history has moved, for an element shown again or mounted after', () => {
    const { rerender, unmount } = render(<Panel shown />);
    act(() => {
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    // Still shown: an animation added now would play on a still page.
    rerender(<Panel shown />);
    expect(panel()).not.toHaveAttribute('class');

    rerender(<Panel shown={false} />);
    expect(panel()).not.toHaveAttribute('class');
    rerender(<Panel shown />);
    expect(panel().className).toContain('animate-[section-in');
    expect(panel().className).toContain('motion-reduce:animate-none');
    unmount();

    render(<Panel shown />);
    expect(panel().className).toContain('animate-[section-in');
  });
});
