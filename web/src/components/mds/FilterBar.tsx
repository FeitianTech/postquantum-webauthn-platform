import { type ExplorerSort, countActiveExplorerFilters } from '@/logic/mds/explorer/filter-sort.js';
import { type RefObject, useId, useLayoutEffect, useRef, useState } from 'react';

import { Button, IconButton } from '@/components/ui/Button';
import { Select, TextField } from '@/components/ui/Field';
import { cx } from '@/lib/cx';

import { EntryCount } from './ExplorerHeader';
import { FilterCombobox } from './FilterCombobox';
import { EXPLORER_COLUMNS, EXPLORER_FILTERS, type ExplorerFilter } from './columns';

const HEIGHT_PROPERTY = '--mds-toolbar-height';

// The bar's height while it is pinned, in --mds-toolbar-height on <html>, which
// the table's header row sits under and the filters' lists stop short of: 0 where
// the bar is not pinned (a narrow or a short window, or the list not shown).
// Measured as the site header's is (Header.tsx), through the CSSOM.
function usePinnedHeightVariable(bar: RefObject<HTMLElement | null>) {
  useLayoutEffect(() => {
    const element = bar.current!;
    const root = document.documentElement;
    const measure = () => {
      const pinned = getComputedStyle(element).position === 'sticky';
      root.style.setProperty(HEIGHT_PROPERTY, `${pinned ? element.getBoundingClientRect().height : 0}px`);
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    window.addEventListener('resize', measure);
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', measure);
      root.style.removeProperty(HEIGHT_PROPERTY);
    };
  }, [bar]);
}

type FieldProps = {
  filters: Record<string, string>;
  options: Record<string, string[]>;
  onChange: (key: string, value: string) => void;
};

// One filter: a combobox where it offers a list, else a search field that Escape clears.
function FilterField({ filter, filters, options, onChange, className }: FieldProps & { filter: ExplorerFilter; className?: string }) {
  return (
    <div className={className}>
      {filter.offersOptions ? (
        <FilterCombobox
          filter={filter}
          value={filters[filter.key]}
          options={options[filter.key]}
          onChange={(value) => onChange(filter.key, value)}
        />
      ) : (
        <TextField
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
      )}
    </div>
  );
}

type SortProps = {
  sort: ExplorerSort;
  onSortBy: (key: string) => void;
  onReverse: () => void;
};

// The sort, by name: any column, the ones the window has no header for too, and
// a button that turns it round (its arrow points the way the list runs).
function SortField({ sort, onSortBy, onReverse }: SortProps) {
  const descending = sort.direction === 'desc';
  return (
    <div className="flex items-end gap-2 max-md:col-span-2 md:w-52">
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
        icon={<span className="text-title-sm">{descending ? '↓' : '↑'}</span>}
        onClick={onReverse}
      />
    </div>
  );
}

// The search is always there; these two, and the sort, sit beside it from 768 px.
const BESIDE = new Set(['protocol', 'latestStatus']);
const [SEARCH, ...OTHERS] = EXPLORER_FILTERS;
const BESIDE_FILTERS = OTHERS.filter((filter) => BESIDE.has(filter.key));
const MORE_FILTERS = OTHERS.filter((filter) => !BESIDE.has(filter.key));

// How many of these filters are in use, said on the button that shows them.
function InUse({ of, filters, className }: { of: ExplorerFilter[]; filters: Record<string, string>; className: string }) {
  const count = countActiveExplorerFilters(Object.fromEntries(of.map((filter) => [filter.key, filters[filter.key]])));
  return count ? <span className={className}>({count})</span> : null;
}

type FilterBarProps = FieldProps &
  SortProps & {
    activeFilters: number;
    onClear: () => void;
    shown: number;
    total: number;
  };

// The list's bar: one search for the name and the ID, the protocol, the status and
// the sort beside it, and the other eight filters behind "More filters" (a phone
// keeps only the search out). The count of what is shown, and one button that
// clears every filter. From 1024 px, in a window tall enough for it, the bar
// stays under the site's header as the page scrolls, the table's header row
// under it, so a filter is never a scroll away from the rows it filters.
export function FilterBar({ filters, options, activeFilters, onChange, onClear, shown, total, ...sort }: FilterBarProps) {
  const [open, setOpen] = useState(false);
  const barRef = useRef<HTMLElement>(null);
  usePinnedHeightVariable(barRef);
  const moreId = `${useId()}-filters`;
  const field = { filters, options, onChange };

  return (
    <section
      ref={barRef}
      aria-label="Filters"
      data-mds-filters=""
      className="top-(--header-height) z-20 mt-4 bg-surface py-3 lg:[@media(min-height:40rem)]:sticky"
    >
      <div className="grid grid-cols-2 items-end gap-3 md:flex md:flex-wrap">
        <FilterField filter={SEARCH} {...field} className="col-span-2 md:min-w-56 md:flex-1" />
        <div className={open ? 'contents' : 'contents max-md:hidden'}>
          {BESIDE_FILTERS.map((filter) => (
            <FilterField key={filter.key} filter={filter} {...field} className="md:w-44" />
          ))}
          <SortField {...sort} />
        </div>
        <div className="col-span-2 flex min-h-10 flex-wrap items-center gap-x-3 gap-y-2">
          <Button variant="secondary" aria-expanded={open} aria-controls={moreId} onClick={() => setOpen(!open)}>
            {open ? 'Fewer filters' : 'More filters'}
            {/* A phone folds the protocol and the status away too. */}
            <InUse of={OTHERS} filters={filters} className="md:hidden" />
            <InUse of={MORE_FILTERS} filters={filters} className="max-md:hidden" />
          </Button>
          {activeFilters ? (
            <Button variant="quiet" size="sm" onClick={onClear}>
              Clear filters
            </Button>
          ) : null}
          <div className="max-md:ml-auto md:pl-1">
            <EntryCount shown={shown} total={total} />
          </div>
        </div>
      </div>
      <div id={moreId} className={cx('mt-3 grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4', open ? 'grid' : 'hidden')}>
        {MORE_FILTERS.map((filter) => (
          <FilterField key={filter.key} filter={filter} {...field} />
        ))}
      </div>
    </section>
  );
}
