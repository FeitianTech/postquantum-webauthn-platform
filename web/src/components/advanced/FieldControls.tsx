import type { ReactNode } from 'react';

import { Button, IconButton } from '@/components/ui/Button';
import { FieldRow, Select, TextField } from '@/components/ui/Field';
import { PlusIcon, RefreshIcon } from '@/components/ui/icons';
import { InfoPopover } from '@/components/ui/InfoPopover';
import { MonoValue } from '@/components/ui/MonoValue';
import { Switch, ToggleChip } from '@/components/ui/Switch';
import { cx } from '@/lib/cx';

import type { FieldAbout, FieldText } from './fieldText';
import { fakeSize, hexIsValid } from './model';

// The Advanced form's field rows: whatever the control, its label and ⓘ above
// it, the control at one height, its error below; the info popup in English and
// 中文 as the current one has it.

export function About({ label, about }: { label: string; about?: FieldAbout }) {
  if (!about) return null;
  const paragraphs = (texts: string[]) => texts.map((text, index) => <p key={index} className={index ? 'mt-3' : undefined}>{text}</p>);
  return <InfoPopover label={`About ${label}`} en={paragraphs(about.en)} zh={paragraphs(about.zh)} />;
}

const aboutOf = (text: FieldText) => <About label={text.label} about={text.about} />;

export function SelectField({
  text,
  value,
  onChange,
}: {
  text: FieldText;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Select label={text.label} aside={aboutOf(text)} value={value} onChange={(event) => onChange(event.target.value)}>
      {text.options?.map((option) => (
        <option key={option.value} value={option.value}>
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
}: {
  text: FieldText;
  value: string;
  onChange: (value: string) => void;
  minBytes: number;
  onRandom?: () => void;
  disabled?: boolean;
}) {
  return (
    <TextField
      label={text.label}
      aside={aboutOf(text)}
      placeholder={text.placeholder}
      mono
      value={value}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      error={hexIsValid(value, minBytes) ? undefined : text.error}
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
              <span className="text-caption text-ink-muted">{fakeSize(hex)}</span>
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
