import { type ReactNode, useId } from 'react';

import { Button, IconButton } from '@/components/ui/Button';
import { FieldRow, Select, TextField } from '@/components/ui/Field';
import { PlusIcon, RefreshIcon } from '@/components/ui/icons';
import { InfoPopover } from '@/components/ui/InfoPopover';
import { MonoValue } from '@/components/ui/MonoValue';
import { Switch, ToggleChip } from '@/components/ui/Switch';
import { cx } from '@/lib/cx';
import { fakeCredentialSize } from '@/logic/advanced/fake-credentials.js';
import { hexInputIsValid } from '@/logic/advanced/hex-input.js';

import type { FieldAbout, FieldText } from './fieldText';

// The Advanced form's field rows: whatever the control, its label and ⓘ above
// it, the control at one height, its error below; the info popup in English and
// 中文 as the current one has it.

// One section of a form: a card of its own (no card in a card) whose fields
// sit on a grid its own width sets: one column, then two, then three.
export function FormSection({ title, children }: { title: string; children: ReactNode }) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className="@container min-w-0 rounded-lg border border-line bg-surface p-5 sm:p-6" data-form-section={title}>
      <h3 id={headingId} className="text-title-sm font-semibold text-ink">
        {title}
      </h3>
      <div className="mt-5 grid grid-cols-1 gap-x-5 gap-y-5 @lg:grid-cols-2 @3xl:grid-cols-3">{children}</div>
    </section>
  );
}

/**
 * A set held in the settings, one member toggled: the rest keep their order (an
 * edit's included); one put in goes before the first that `order` puts after it.
 */
export function toggled<T>(set: T[], member: T, pressed: boolean, order: T[]) {
  if (!pressed) return set.filter((value) => value !== member);
  if (set.includes(member)) return set;
  const at = set.findIndex((value) => order.indexOf(value) > order.indexOf(member));
  return at < 0 ? [...set, member] : [...set.slice(0, at), member, ...set.slice(at)];
}

export function About({ label, about }: { label: string; about?: FieldAbout }) {
  if (!about) return null;
  const paragraphs = (texts: string[]) => texts.map((text, index) => <p key={index} className={index ? 'mt-3' : undefined}>{text}</p>);
  return <InfoPopover label={`About ${label}`} en={paragraphs(about.en)} zh={paragraphs(about.zh)} />;
}

const aboutOf = (text: FieldText) => <About label={text.label} about={text.about} />;

/** A select with the template's options (or those given); some may be unusable, the whole locked, a note under it. */
export function SelectField({
  text,
  value,
  onChange,
  options = text.options ?? [],
  disabled,
  disabledOptions = [],
  note,
}: {
  text: FieldText;
  value: string;
  onChange: (value: string) => void;
  options?: { value: string; label: string }[];
  disabled?: boolean;
  disabledOptions?: string[];
  note?: string;
}) {
  return (
    <Select
      label={text.label}
      aside={aboutOf(text)}
      value={value}
      disabled={disabled}
      hint={note || undefined}
      onChange={(event) => onChange(event.target.value)}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value} disabled={disabledOptions.includes(option.value)}>
          {option.label}
        </option>
      ))}
    </Select>
  );
}

export function SwitchField({
  text,
  checked,
  onChange,
  disabled,
}: {
  text: FieldText;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return <Switch label={text.label} aside={aboutOf(text)} checked={checked} onCheckedChange={onChange} disabled={disabled} />;
}

/** A set of toggle chips under one label, which names the group. */
export function ChipGroupField({ text, className, children }: { text: FieldText; className?: string; children: ReactNode }) {
  return (
    <FieldRow label={text.label} aside={aboutOf(text)} group className={className}>
      {(ids) => (
        <div role="group" aria-labelledby={ids.labelId} className="flex flex-col gap-3 pt-1">
          {children}
        </div>
      )}
    </FieldRow>
  );
}

export function Chips({ label, children }: { label?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2">
      {label ? <span className="text-caption font-medium tracking-wide text-ink-muted">{label}</span> : null}
      <div className="flex flex-wrap gap-2">{children}</div>
    </div>
  );
}

export function Chip({ pressed, onChange, children }: { pressed: boolean; onChange: (pressed: boolean) => void; children: ReactNode }) {
  return (
    <ToggleChip pressed={pressed} onPressedChange={onChange}>
      {children}
    </ToggleChip>
  );
}

const DATA_INPUT = { spellCheck: false, autoCapitalize: 'off', autoComplete: 'off' } as const;

/** Bytes typed as hex, in Geist Mono, with a button that draws new ones; the error when too few. */
export function HexField({
  text,
  value,
  onChange,
  minBytes,
  onRandom,
  disabled,
  note,
}: {
  text: FieldText;
  value: string;
  onChange: (value: string) => void;
  minBytes: number;
  onRandom?: () => void;
  disabled?: boolean;
  /** A sentence under the field, when there is no error. */
  note?: string;
}) {
  return (
    <TextField
      label={text.label}
      aside={aboutOf(text)}
      placeholder={text.placeholder}
      mono
      value={value}
      disabled={disabled}
      hint={note || undefined}
      onChange={(event) => onChange(event.target.value)}
      error={hexInputIsValid(value, minBytes) ? undefined : text.error}
      trailing={
        onRandom ? <IconButton size="sm" label={text.button!} icon={<RefreshIcon />} onClick={onRandom} disabled={disabled} /> : undefined
      }
      {...DATA_INPUT}
    />
  );
}

/**
 * The length of a fake credential ID to add, with the button that adds one,
 * and the IDs added, each with its length and Delete.
 */
export function FakeCredentialField({
  text,
  length,
  onLength,
  ids,
  emptyText,
  message,
  onAdd,
  onRemove,
  className,
}: {
  text: FieldText;
  length: string;
  onLength: (length: string) => void;
  ids: string[];
  emptyText: string;
  message: { tone: 'error' | 'info'; text: string } | null;
  onAdd: () => void;
  onRemove: (index: number) => void;
  className?: string;
}) {
  return (
    <div className={cx('flex min-w-0 flex-col gap-3', className)} data-fake-credentials="">
      <TextField
        label={text.label}
        aside={aboutOf(text)}
        type="number"
        min={1}
        value={length}
        onChange={(event) => onLength(event.target.value)}
        error={message?.tone === 'error' ? message.text : undefined}
        hint={message?.tone === 'info' ? message.text : undefined}
        trailing={<IconButton size="sm" label={text.button!} icon={<PlusIcon />} onClick={onAdd} />}
      />
      {ids.length ? (
        <ul className="flex flex-col divide-y divide-line rounded-sm border border-line" aria-label={`${text.label}: IDs added`}>
          {ids.map((hex, index) => (
            <li key={`${index}-${hex}`} className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
              <MonoValue value={hex} label="fake credential ID" className="min-w-0 flex-1 basis-48" />
              <span className="text-caption text-ink-muted">{fakeCredentialSize(hex)}</span>
              <Button variant="danger" size="sm" onClick={() => onRemove(index)}>
                Delete
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-caption text-ink-muted" data-role="empty">
          {emptyText}
        </p>
      )}
    </div>
  );
}
