import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';

import { Switch, ToggleChip } from './Switch';

function Controlled({ disabled = false }: { disabled?: boolean }) {
  const [checked, setChecked] = useState(false);
  return (
    <Switch
      label="Resident key"
      description="Require a discoverable credential"
      hint="Also called a passkey"
      checked={checked}
      onCheckedChange={setChecked}
      disabled={disabled}
    />
  );
}

describe('Switch', () => {
  it('is a labelled switch that turns on and off, by click and by keyboard', async () => {
    render(<Controlled />);
    const control = screen.getByRole('switch', { name: 'Resident key' });

    expect(control).toHaveAttribute('aria-checked', 'false');
    expect(control).toHaveAccessibleDescription('Require a discoverable credential');
    expect(control.className).toContain('bg-surface');
    await userEvent.click(control);
    expect(control).toHaveAttribute('aria-checked', 'true');
    expect(control.className).toContain('bg-accent');
    control.focus();
    await userEvent.keyboard(' ');
    expect(control).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByText('Also called a passkey')).toBeInTheDocument();
  });

  it('does nothing while disabled', async () => {
    render(<Controlled disabled />);
    const control = screen.getByRole('switch', { name: 'Resident key' });
    await userEvent.click(control);
    expect(control).toHaveAttribute('aria-checked', 'false');
  });
});

describe('ToggleChip', () => {
  function Chip() {
    const [pressed, setPressed] = useState(false);
    return (
      <ToggleChip pressed={pressed} onPressedChange={setPressed}>
        ML-DSA-65
      </ToggleChip>
    );
  }

  it('is pressed and released, with a check mark while pressed', async () => {
    const { container } = render(<Chip />);
    const chip = screen.getByRole('button', { name: 'ML-DSA-65' });

    expect(chip).toHaveAttribute('aria-pressed', 'false');
    expect(container.querySelector('svg')).toBeNull();
    await userEvent.click(chip);
    expect(chip).toHaveAttribute('aria-pressed', 'true');
    expect(chip.className).toContain('bg-accent-tint');
    expect(container.querySelector('svg')).not.toBeNull();
  });
});
