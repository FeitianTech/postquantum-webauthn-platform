import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { Button, IconButton } from './Button';
import { CloseIcon } from './icons';

describe('Button', () => {
  it.each(['primary', 'secondary', 'danger', 'quiet'] as const)('renders the %s variant as a button that clicks', async (variant) => {
    const onClick = vi.fn();
    render(
      <Button variant={variant} onClick={onClick}>
        Register
      </Button>,
    );

    const button = screen.getByRole('button', { name: 'Register' });
    expect(button).toHaveAttribute('type', 'button');
    await userEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('never uses a grey fill: secondary and danger are white with a hairline', () => {
    render(
      <>
        <Button variant="secondary">A</Button>
        <Button variant="danger">B</Button>
      </>,
    );
    expect(screen.getByRole('button', { name: 'A' }).className).toContain('bg-surface');
    expect(screen.getByRole('button', { name: 'A' }).className).toContain('border-line-strong');
    expect(screen.getByRole('button', { name: 'B' }).className).toContain('text-danger');
  });

  it('is disabled while busy, says so, and shows a spinner', async () => {
    const onClick = vi.fn();
    const { container } = render(
      <Button busy onClick={onClick}>
        Saving
      </Button>,
    );

    const button = screen.getByRole('button', { name: 'Saving' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('aria-busy', 'true');
    expect(container.querySelector('svg.animate-spin')).not.toBeNull();
    await userEvent.click(button);
    expect(onClick).not.toHaveBeenCalled();
  });

  it('takes a size and a submit type', () => {
    render(
      <Button size="sm" type="submit">
        Go
      </Button>,
    );
    const button = screen.getByRole('button', { name: 'Go' });
    expect(button).toHaveAttribute('type', 'submit');
    expect(button.className).toContain('h-8');
  });
});

describe('IconButton', () => {
  it('is named by its label, which is also its tooltip', async () => {
    const onClick = vi.fn();
    render(<IconButton label="Close browser analysis" icon={<CloseIcon />} onClick={onClick} />);

    const button = screen.getByRole('button', { name: 'Close browser analysis' });
    expect(button).toHaveAttribute('title', 'Close browser analysis');
    await userEvent.click(button);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('takes a secondary look, a small size and its own tooltip', () => {
    render(<IconButton label="Copy" title="Copy the value" icon={<CloseIcon />} variant="secondary" size="sm" />);
    const button = screen.getByRole('button', { name: 'Copy' });
    expect(button).toHaveAttribute('title', 'Copy the value');
    expect(button.className).toContain('size-8');
    expect(button.className).toContain('border-line-strong');
  });
});
