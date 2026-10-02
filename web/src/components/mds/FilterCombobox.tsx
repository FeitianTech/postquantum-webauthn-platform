import { NO_MATCHING_OPTIONS, matchingFilterOptions } from '@/logic/mds/explorer/options.js';
import { type KeyboardEvent, useId, useMemo, useState } from 'react';

import { TextField } from '@/components/ui/Field';
import { cx } from '@/lib/cx';

import type { ExplorerFilter } from './columns';

// A filter that offers the values present, as an
// ARIA combobox: typing narrows the list and filters at once; the arrow keys
// move through the list (wrapping), Enter picks, Escape closes the list and then
// clears the field. User Verification and Algorithms show their whole list.
export function FilterCombobox({
  filter,
  value,
  options,
  onChange,
}: {
  filter: ExplorerFilter;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const listId = `${useId()}-options`;
  const matching = useMemo(() => matchingFilterOptions(options, value), [options, value]);
  const shown = open && options.length > 0;

  const pick = (option: string) => {
    onChange(option);
    setOpen(false);
    setActive(-1);
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (!options.length) return;
      event.preventDefault();
      setOpen(true);
      const count = matching.length;
      const down = event.key === 'ArrowDown';
      setActive((index) => {
        if (!count) return -1;
        if (index < 0) return down ? 0 : count - 1;
        return (index + (down ? 1 : -1) + count) % count;
      });
    } else if (event.key === 'Enter') {
      if (shown && active >= 0 && matching[active]) {
        event.preventDefault();
        pick(matching[active]);
      }
    } else if (event.key === 'Escape') {
      if (shown) {
        event.preventDefault();
        setOpen(false);
        setActive(-1);
      } else if (value) {
        event.preventDefault();
        onChange('');
      }
    }
  };

  return (
    <div className="relative">
      <TextField
        label={filter.label}
        placeholder={filter.placeholder}
        value={value}
        role="combobox"
        aria-expanded={shown}
        aria-controls={listId}
        aria-autocomplete="list"
        aria-activedescendant={shown && active >= 0 ? `${listId}-${active}` : undefined}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => {
          onChange(event.target.value);
          setOpen(true);
          setActive(-1);
        }}
        onFocus={() => setOpen(true)}
        onClick={() => setOpen(true)}
        onBlur={() => {
          setOpen(false);
          setActive(-1);
        }}
        onKeyDown={onKeyDown}
      />
      {shown ? (
        <ul
          id={listId}
          role="listbox"
          aria-label={filter.label}
          className={cx(
            'absolute inset-x-0 top-full z-30 mt-1 rounded-sm border border-line bg-surface py-1 shadow-float',
            filter.showsWholeList ? null : 'max-h-64 overflow-y-auto overscroll-contain',
          )}
        >
          {matching.length ? (
            matching.map((option, index) => (
              <li
                key={option}
                id={`${listId}-${index}`}
                role="option"
                aria-selected={index === active}
                // Keep the focus in the field while an option is clicked.
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => pick(option)}
                className={cx(
                  'cursor-pointer px-3 py-1.5 text-body text-ink',
                  index === active ? 'bg-accent-tint text-accent-ink' : 'hover:bg-accent-tint',
                )}
              >
                {option}
              </li>
            ))
          ) : (
            <li role="presentation" className="px-3 py-1.5 text-body text-ink-muted">
              {NO_MATCHING_OPTIONS}
            </li>
          )}
        </ul>
      ) : null}
    </div>
  );
}
