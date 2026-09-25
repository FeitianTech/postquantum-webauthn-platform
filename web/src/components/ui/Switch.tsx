import { type ButtonHTMLAttributes, type ReactNode, useId } from 'react';

import { cx } from '@/lib/cx';

import { CheckIcon } from './icons';

type SwitchControlProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'style' | 'onChange' | 'role'> & {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
};

// The bare switch: a button with role="switch". Off is a white track with a
// hairline (never a grey fill), on is the accent.
export function SwitchControl({ checked, onCheckedChange, className, disabled, ...props }: SwitchControlProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cx(
        'group relative inline-flex h-6 w-10 shrink-0 items-center rounded-full border',
        'transition-[background-color,border-color] duration-(--duration-base) ease-standard',
        'disabled:cursor-not-allowed disabled:opacity-45',
        checked
          ? 'border-accent bg-accent enabled:hover-or-demo:border-accent-hover enabled:hover-or-demo:bg-accent-hover'
          : 'border-line-strong bg-surface enabled:hover-or-demo:border-line-hover',
        className,
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className={cx(
          'absolute top-[2px] left-[2px] size-[18px] rounded-full border bg-white',
          'transition-[translate,border-color] duration-(--duration-base) ease-standard',
          checked ? 'translate-x-4 border-transparent' : 'border-line-hover',
        )}
      />
    </button>
  );
}

type SwitchProps = SwitchControlProps & {
  label: ReactNode;
  /** Said beside the switch, such as what "on" does. */
  description?: ReactNode;
  hint?: ReactNode;
};

// A switch in a field row: the label above, like every other control, and the
// switch in a control-height row so a grid of fields lines up.
export function Switch({ label, description, hint, className, ...props }: SwitchProps) {
  const base = useId();
  return (
    <div className={cx('flex min-w-0 flex-col gap-1.5', className)}>
      <div className="flex min-h-5 items-center">
        <span id={`${base}-label`} className="text-label font-medium text-ink">
          {label}
        </span>
      </div>
      <div className="flex h-10 items-center gap-3">
        <SwitchControl
          aria-labelledby={`${base}-label`}
          aria-describedby={description ? `${base}-description` : undefined}
          {...props}
        />
        {description ? (
          <span id={`${base}-description`} className="text-body text-ink-muted">
            {description}
          </span>
        ) : null}
      </div>
      {hint ? <p className="text-caption text-ink-muted">{hint}</p> : null}
    </div>
  );
}

type ToggleChipProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'style' | 'onChange'> & {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
};

// One member of a set that can be chosen in any combination (algorithms, hints).
export function ToggleChip({ pressed, onPressedChange, className, children, ...props }: ToggleChipProps) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={() => onPressedChange(!pressed)}
      className={cx(
        'inline-flex h-8 shrink-0 select-none items-center gap-1.5 rounded-full border px-3.5 text-label font-medium',
        'transition-[background-color,border-color,color,scale] duration-(--duration-fast) ease-standard',
        'enabled:active-or-demo:scale-[0.96] disabled:cursor-not-allowed disabled:opacity-45',
        pressed
          ? 'border-accent-line bg-accent-tint text-accent-ink enabled:hover-or-demo:border-accent'
          : 'border-line-strong bg-surface text-ink enabled:hover-or-demo:border-line-hover',
        className,
      )}
      {...props}
    >
      {pressed ? <CheckIcon size={12} strokeWidth={2.2} /> : null}
      {children}
    </button>
  );
}
