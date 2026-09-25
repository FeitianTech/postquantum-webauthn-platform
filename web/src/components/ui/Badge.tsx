import type { HTMLAttributes, ReactNode } from 'react';

import { cx } from '@/lib/cx';

export type Tone = 'accent' | 'success' | 'warning' | 'danger' | 'neutral';

// Tints are colours; "neutral" is white with a hairline, never a grey fill.
const TONES: Record<Tone, string> = {
  accent: 'bg-accent-tint text-accent-ink',
  success: 'bg-success-tint text-success',
  warning: 'bg-warning-tint text-warning',
  danger: 'bg-danger-tint text-danger',
  neutral: 'border border-line-strong bg-surface text-ink-muted',
};

type BadgeProps = Omit<HTMLAttributes<HTMLSpanElement>, 'style'> & { tone?: Tone };

export function Badge({ tone = 'neutral', className, children, ...props }: BadgeProps) {
  return (
    <span
      className={cx(
        'inline-flex h-[1.375rem] shrink-0 items-center gap-1 rounded-full px-2.5 text-caption font-medium whitespace-nowrap',
        TONES[tone],
        className,
      )}
      {...props}
    >
      {children}
    </span>
  );
}

// Each tone's mark, so a status never rests on colour alone.
export const STATUS_MARKS: Record<Tone, string> = {
  success: '✓',
  danger: '✕',
  neutral: '–',
  warning: '!',
  accent: 'i',
};

type StatusChipProps = BadgeProps & { children: ReactNode };

// A status in words and a mark: "Yes ✓", "No ✕", "Not available –", "Could not be determined !".
export function StatusChip({ tone = 'neutral', children, className, ...props }: StatusChipProps) {
  return (
    <Badge tone={tone} className={cx('h-6 px-2.5 text-label', className)} {...props}>
      <span>{children}</span>
      <span aria-hidden="true" className="font-bold">
        {STATUS_MARKS[tone]}
      </span>
    </Badge>
  );
}
