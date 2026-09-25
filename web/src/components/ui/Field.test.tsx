import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { Select, TextArea, TextField } from './Field';

describe('TextField', () => {
  it('is labelled, described by its hint, and typed into', async () => {
    render(<TextField label="Username" hint="Letters and digits" placeholder="Enter username" />);

    const input = screen.getByLabelText('Username');
    expect(input).toHaveAccessibleDescription('Letters and digits');
    await userEvent.type(input, 'alice');
    expect(input).toHaveValue('alice');
  });

  it('shows an error in place of the hint and marks the field invalid', () => {
    render(<TextField label="PRF" hint="Hex" error="Invalid hex value (exactly 32 bytes required)" />);

    const input = screen.getByLabelText('PRF');
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Invalid hex value (exactly 32 bytes required)');
    expect(screen.queryByText('Hex')).toBeNull();
    expect(input.className).toContain('border-danger');
  });

  it('has no focus effect of any kind: no ring, no outline, no border change', () => {
    render(<TextField label="Name" />);
    const input = screen.getByLabelText('Name');

    expect(input).toHaveAttribute('data-text-field');
    expect(input.className).toContain('outline-none');
    expect(input.className).not.toMatch(/(^|\s)(focus|focus-visible|focus-within|focus-or-demo):/);
  });

  it('holds a control at its right edge and can be monospaced and read-only', () => {
    render(<TextField label="AAGUID" mono readOnly value="x" trailing={<button type="button">Copy</button>} />);
    const input = screen.getByLabelText('AAGUID');
    expect(input.className).toContain('font-mono');
    expect(input.className).toContain('pr-11');
    expect(input).toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
  });
});

describe('TextArea', () => {
  it('is labelled, has no focus effect and can be monospaced', async () => {
    render(<TextArea label="Input" mono rows={3} error="Not CBOR" />);
    const area = screen.getByLabelText('Input');

    expect(area.tagName).toBe('TEXTAREA');
    expect(area).toHaveAttribute('rows', '3');
    expect(area).toHaveAttribute('data-text-field');
    expect(area.className).toContain('font-mono');
    expect(area).toHaveAccessibleDescription('Not CBOR');
    await userEvent.type(area, 'a1');
    expect(area).toHaveValue('a1');
  });
});

describe('Select', () => {
  it('is a labelled native select that keeps the keyboard focus ring', async () => {
    render(
      <Select label="Attestation" hint="What to ask for" defaultValue="none">
        <option value="none">none</option>
        <option value="direct">direct</option>
      </Select>,
    );
    const select = screen.getByLabelText('Attestation');

    expect(select).not.toHaveAttribute('data-text-field');
    expect(select).toHaveAccessibleDescription('What to ask for');
    await userEvent.selectOptions(select, 'direct');
    expect(select).toHaveValue('direct');
  });

  it('marks an error', () => {
    render(
      <Select label="Hints" error="Choose one">
        <option>a</option>
      </Select>,
    );
    expect(screen.getByLabelText('Hints')).toHaveAttribute('aria-invalid', 'true');
  });
});
