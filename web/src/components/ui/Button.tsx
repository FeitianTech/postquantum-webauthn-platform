import { type ButtonHTMLAttributes, type ReactNode, forwardRef } from 'react';

import { cx } from '@/lib/cx';

import { Spinner } from './icons';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'quiet';
export type ButtonSize = 'sm' | 'md';

type ButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'style'> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Shows a spinner and refuses clicks while the action runs. */
  busy?: boolean;
  icon?: ReactNode;
};

const BASE =
  'inline-flex shrink-0 select-none items-center justify-center gap-2 whitespace-nowrap rounded-full font-medium ' +
  'transition-[background-color,border-color,color,scale] duration-(--duration-fast) ease-standard ' +
  'disabled:cursor-not-allowed disabled:opacity-45 enabled:active-or-demo:scale-[0.97]';

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3.5 text-label',
  md: 'h-10 px-[1.125rem] text-body',
};

// No grey fill anywhere: secondary and danger are white with a hairline that
// darkens on hover; pressed gets a faint tint of their colour.
const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-white enabled:hover-or-demo:bg-accent-hover enabled:active-or-demo:bg-accent-press',
  secondary:
    'border border-line-strong bg-surface text-ink enabled:hover-or-demo:border-line-hover ' +
    'enabled:active-or-demo:bg-accent-tint',
  danger:
    'border border-danger-line bg-surface text-danger enabled:hover-or-demo:border-danger ' +
    'enabled:active-or-demo:bg-danger-tint',
  quiet: 'bg-transparent text-accent-ink enabled:hover-or-demo:bg-accent-tint enabled:active-or-demo:bg-accent-tint-strong',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', busy = false, icon, disabled, className, children, type = 'button', ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={cx(BASE, SIZES[size], VARIANTS[variant], className)}
      {...props}
    >
      {busy ? <Spinner /> : icon}
      {children}
    </button>
  );
});

type IconButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'style' | 'aria-label' | 'children'> & {
  /** The accessible name, also shown as the tooltip. */
  label: string;
  icon: ReactNode;
  size?: ButtonSize;
  variant?: 'quiet' | 'secondary';
};

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, icon, size = 'md', variant = 'quiet', className, type = 'button', title, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={title ?? label}
      className={cx(
        'inline-flex shrink-0 items-center justify-center rounded-full text-ink-muted',
        'transition-[background-color,border-color,color,scale] duration-(--duration-fast) ease-standard',
        'enabled:hover-or-demo:text-ink enabled:active-or-demo:scale-[0.94] disabled:cursor-not-allowed disabled:opacity-45',
        size === 'sm' ? 'size-8' : 'size-9',
        variant === 'secondary'
          ? 'border border-line-strong bg-surface enabled:hover-or-demo:border-line-hover'
          : 'bg-transparent enabled:hover-or-demo:bg-accent-tint enabled:hover-or-demo:text-accent-ink',
        className,
      )}
      {...props}
    >
      {icon}
    </button>
  );
});
