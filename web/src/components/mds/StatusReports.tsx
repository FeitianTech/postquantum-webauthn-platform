import { MISSING_CELL_TEXT } from '@legacy/advanced/mds/explorer/rows.js';

import { MonoValue } from '@/components/ui/MonoValue';
import { TBody, THead, Table, Td, Th, Tr } from '@/components/ui/Table';

import type { StatusReportRow } from './entryModel';

// On a phone each report is a block, each value after its column's name (from
// data-label, in CSS: no text is added to the page); the roles are written out,
// since the stacked display drops a table's own.
const STACK_CELL =
  'max-sm:flex max-sm:items-baseline max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:before:w-32 max-sm:before:shrink-0 max-sm:before:text-caption max-sm:before:text-ink-muted max-sm:before:content-[attr(data-label)]';

// "Status Reports": every report, as published, in a table on the ui/Table
// primitives. Long descriptors and URLs wrap in their column.
export function StatusReports({ columns, rows }: { columns: string[]; rows: StatusReportRow[] }) {
  const [status, date, version, number, descriptor] = columns;
  return (
    <Table role="table" className="max-sm:border-0" tableClassName="max-sm:block">
      <THead role="rowgroup" className="max-sm:sr-only">
        <Tr role="row">
          {columns.map((column) => (
            <Th key={column} role="columnheader">
              {column}
            </Th>
          ))}
        </Tr>
      </THead>
      <TBody role="rowgroup" className="max-sm:block">
        {rows.map((row, index) => (
          <Tr key={index} role="row" data-report="" className="align-top max-sm:block max-sm:py-3">
            <Td role="cell" data-label={status} className={`align-top ${STACK_CELL}`}>
              <span className="font-mono text-label break-all">{row.status}</span>
            </Td>
            <Td role="cell" data-label={date} className={`align-top whitespace-nowrap ${STACK_CELL}`}>
              {row.effectiveDate}
            </Td>
            <Td role="cell" data-label={version} className={`align-top ${STACK_CELL}`}>
              {row.authenticatorVersion}
            </Td>
            <Td role="cell" data-label={number} className={`align-top ${STACK_CELL}`}>
              {row.certificateNumber === MISSING_CELL_TEXT ? (
                row.certificateNumber
              ) : (
                <MonoValue value={row.certificateNumber} label="certificate number" className="-my-1 max-w-56" />
              )}
            </Td>
            <Td role="cell" data-label={descriptor} className={`min-w-64 align-top max-sm:min-w-0 ${STACK_CELL}`}>
              {row.descriptor || row.details ? (
                <span className="block min-w-0">
                  {row.descriptor ? <span className="block [overflow-wrap:anywhere]">{row.descriptor}</span> : null}
                  {row.details ? (
                    <span className="mt-0.5 block text-caption [overflow-wrap:anywhere] text-ink-muted">{row.details}</span>
                  ) : null}
                </span>
              ) : (
                MISSING_CELL_TEXT
              )}
            </Td>
          </Tr>
        ))}
      </TBody>
    </Table>
  );
}
