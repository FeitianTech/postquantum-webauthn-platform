import {
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
  forwardRef,
  useId,
} from 'react';

import { cx } from '@/lib/cx';

import { ChevronDownIcon } from './icons';

type RowProps = {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  /** Something beside the label, such as an InfoPopover. */
  aside?: ReactNode;
  className?: string;
};

type RowIds = { controlId: string; labelId: string; describedBy: string | undefined };

// One field row for every control: the label above, the control, then a hint or
// an error. Heights and baselines therefore line up in a grid whatever the control.
function FieldRow({
  label,
  hint,
  error,
  aside,
  className,
  children,
}: RowProps & { children: (ids: RowIds) => ReactNode }) {
  const base = useId();
  const ids: RowIds = {
    controlId: `${base}-control`,
    labelId: `${base}-label`,
    describedBy: error ? `${base}-error` : hint ? `${base}-hint` : undefined,
  };
  return (
    <div className={cx('flex min-w-0 flex-col gap-1.5', className)}>
      <div className="flex min-h-5 items-center gap-1.5">
        <label id={ids.labelId} htmlFor={ids.controlId} className="text-label font-medium text-ink">
          {label}
        </label>
        {aside}
      </div>
      {children(ids)}
      {error ? (
        <p id={`${base}-error`} className="text-caption text-danger">
          {error}
        </p>
      ) : hint ? (
        <p id={`${base}-hint`} className="text-caption text-ink-muted">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

// Text fields have no focus effect at all (data-text-field; see globals.css):
// hover darkens the hairline, an error colours it, focus changes nothing.
const TEXT_FIELD =
  'w-full min-w-0 rounded-sm border bg-surface text-body text-ink placeholder:text-ink-faint outline-none ' +
  'transition-[border-color] duration-(--duration-fast) ' +
  'disabled:cursor-not-allowed disabled:text-ink-muted read-only:text-ink-muted';

function borderFor(error: ReactNode) {
  return error ? 'border-danger' : 'border-line-strong enabled:hover-or-demo:border-line-hover';
}

type TextFieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'style' | 'id'> &
  RowProps & {
    /** A control inside the field's right edge, such as an IconButton. */
    trailing?: ReactNode;
    mono?: boolean;
  };

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { label, hint, error, aside, className, trailing, mono = false, type = 'text', ...props },
  ref,
) {
  return (
    <FieldRow label={label} hint={hint} error={error} aside={aside} className={className}>
      {(ids) => (
        <div className="relative">
          <input
            ref={ref}
            id={ids.controlId}
            type={type}
            data-text-field=""
            aria-invalid={error ? true : undefined}
            aria-describedby={ids.describedBy}
            className={cx(TEXT_FIELD, borderFor(error), 'h-10 px-3', trailing ? 'pr-11' : null, mono && 'font-mono text-label')}
            {...props}
          />
          {trailing ? <div className="absolute inset-y-0 right-1 flex items-center">{trailing}</div> : null}
        </div>
      )}
    </FieldRow>
  );
});

type TextAreaProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'style' | 'id'> & RowProps & { mono?: boolean };

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(function TextArea(
  { label, hint, error, aside, className, mono = false, rows = 6, ...props },
  ref,
) {
  return (
    <FieldRow label={label} hint={hint} error={error} aside={aside} className={className}>
      {(ids) => (
        <textarea
          ref={ref}
          id={ids.controlId}
          rows={rows}
          data-text-field=""
          aria-invalid={error ? true : undefined}
          aria-describedby={ids.describedBy}
          className={cx(
            TEXT_FIELD,
            borderFor(error),
            'block resize-y px-3 py-2.5',
            mono && 'font-mono text-[0.78125rem] leading-[1.65]',
          )}
          {...props}
        />
      )}
    </FieldRow>
  );
});

type SelectProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, 'style' | 'id'> & RowProps;

// A native select: the platform's own list, keyboard and screen-reader support.
// It is a control, so it keeps the keyboard focus ring.
export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { label, hint, error, aside, className, children, ...props },
  ref,
) {
  return (
    <FieldRow label={label} hint={hint} error={error} aside={aside} className={className}>
      {(ids) => (
        <div className="relative">
          <select
            ref={ref}
            id={ids.controlId}
            aria-invalid={error ? true : undefined}
            aria-describedby={ids.describedBy}
            className={cx(
              'h-10 w-full min-w-0 appearance-none rounded-sm border bg-surface pr-9 pl-3 text-body text-ink',
              'transition-[border-color] duration-(--duration-fast) disabled:cursor-not-allowed disabled:text-ink-muted',
              borderFor(error),
            )}
            {...props}
          >
            {children}
          </select>
          <ChevronDownIcon className="pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 text-ink-faint" />
        </div>
      )}
    </FieldRow>
  );
});

export { FieldRow };
