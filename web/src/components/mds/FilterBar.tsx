import type { ExplorerSort } from '@/logic/mds/explorer/filter-sort.js';
import { useId, useState } from 'react';

import { Badge } from '@/components/ui/Badge';
import { Button, IconButton } from '@/components/ui/Button';
import { Select, TextField } from '@/components/ui/Field';
import { ChevronDownIcon } from '@/components/ui/icons';
import { cx } from '@/lib/cx';

import { FilterCombobox } from './FilterCombobox';
import { EXPLORER_COLUMNS, EXPLORER_FILTERS } from './columns';

type SortProps = {
  sort: ExplorerSort;
  onSortBy: (key: string) => void;
  onReverse: () => void;
};

// The sort, by name: any column, the ones a narrow window has no header for too,
// and a button that turns it round (its arrow points the way the list runs).
function SortField({ sort, onSortBy, onReverse }: SortProps) {
  const descending = sort.direction === 'desc';
  return (
    <div className="flex items-end gap-2">
      <Select label="Sort" className="min-w-0 flex-1" value={sort.key} onChange={(event) => onSortBy(event.target.value)}>
        {EXPLORER_COLUMNS.map((column) => (
          <option key={column.key} value={column.key}>
            {column.header}
          </option>
        ))}
      </Select>
      <IconButton
        variant="secondary"
        className="size-10"
        label={descending ? 'Sort ascending' : 'Sort descending'}
        icon={<ChevronDownIcon className={cx(!descending && 'rotate-180')} />}
        onClick={onReverse}
      />
    </div>
  );
}

type FilterBarProps = SortProps & {
  filters: Record<string, string>;
  options: Record<string, string[]>;
  activeFilters: number;
  onChange: (key: string, value: string) => void;
  onClear: () => void;
};

// The 11 filters, each labelled with what it reads, and the sort, above the table
// rather than squeezed into a second header row: 6 to a row on a wide screen (two
// rows), down to one on a phone, where they fold away behind a button. How many
// filters are in use, and one button that clears them all.
export function FilterBar({ filters, options, activeFilters, onChange, onClear, ...sort }: FilterBarProps) {
  const [open, setOpen] = useState(false);
  const gridId = `${useId()}-filters`;
  const titleId = `${gridId}-title`;

  return (
    <section aria-labelledby={titleId} data-mds-filters="">
      <div className="flex min-h-8 flex-wrap items-center gap-x-3 gap-y-2">
        <h3 id={titleId} className="text-title-sm font-semibold text-ink">
          Filters
        </h3>
        {activeFilters ? (
          <>
            <Badge tone="accent" data-mds-filter-count="">
              {activeFilters} active
            </Badge>
            <Button variant="quiet" size="sm" onClick={onClear}>
              Clear filters
            </Button>
          </>
        ) : null}
        <Button
          variant="secondary"
          size="sm"
          className="ml-auto menu:hidden"
          aria-expanded={open}
          aria-controls={gridId}
          onClick={() => setOpen(!open)}
        >
          {open ? 'Hide filters' : 'Show filters'}
        </Button>
      </div>
      <div
        id={gridId}
        className={cx(
          'mt-3 grid-cols-1 gap-x-4 gap-y-3 sm:grid-cols-2 lg:grid-cols-4 wide:grid-cols-6',
          open ? 'grid' : 'hidden menu:grid',
        )}
      >
        {EXPLORER_FILTERS.map((filter) =>
          filter.offersOptions ? (
            <FilterCombobox
              key={filter.key}
              filter={filter}
              value={filters[filter.key]}
              options={options[filter.key] ?? []}
              onChange={(value) => onChange(filter.key, value)}
            />
          ) : (
            <TextField
              key={filter.key}
              type="search"
              label={filter.label}
              placeholder={filter.placeholder}
              value={filters[filter.key]}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => onChange(filter.key, event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Escape' && filters[filter.key]) {
                  event.preventDefault();
                  onChange(filter.key, '');
                }
              }}
            />
          ),
        )}
        <SortField {...sort} />
      </div>
    </section>
  );
}
