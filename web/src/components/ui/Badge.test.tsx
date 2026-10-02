import { render, screen, within } from '@testing-library/react';

import { Badge, StatusChip } from './Badge';

describe('Badge and StatusChip', () => {
  it.each([
    ['accent', 'bg-accent-tint'],
    ['success', 'bg-success-tint'],
    ['warning', 'bg-warning-tint'],
    ['danger', 'bg-danger-tint'],
    ['neutral', 'bg-surface'],
  ] as const)('colours a %s badge with a tint or white, never grey', (tone, fill) => {
    render(<Badge tone={tone}>Label</Badge>);
    expect(screen.getByText('Label').className).toContain(fill);
  });

  it.each([
    ['success', 'Yes', '✓'],
    ['danger', 'No', '✕'],
    ['neutral', 'Not available in this browser', '–'],
    ['warning', 'Could not be determined', '!'],
    ['accent', 'Info', 'i'],
  ] as const)('says a %s status in words and a mark', (tone, words, mark) => {
    render(
      <StatusChip tone={tone} data-state="x">
        {words}
      </StatusChip>,
    );
    const chip = screen.getByText(words).parentElement!;
    expect(chip).toHaveAttribute('data-state', 'x');
    expect(chip).toHaveTextContent(`${words}${mark}`);
    expect(within(chip).getByText(mark)).toHaveAttribute('aria-hidden', 'true');
  });
});
