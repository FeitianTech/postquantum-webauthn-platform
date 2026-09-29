import { MISSING_CELL_TEXT } from '@/logic/advanced/mds/explorer/rows.js';

import { MonoValue } from '@/components/ui/MonoValue';
import { TBody, THead, Table, Td, Th, Tr } from '@/components/ui/Table';

import type { StatusReportRow } from './entryModel';

// On a phone each report is a block, each value after its column's name (from
// data-label, in CSS: no text is added to the page); the roles are written out,
// since the stacked display drops a table's own.
const STACK_CELL =
  'max-sm:flex max-sm:items-baseline max-sm:gap-3 max-sm:px-0 max-sm:py-1 max-sm:before:w-32 max-sm:before:shrink-0 max-sm:before:text-caption max-sm:before:text-ink-muted max-sm:before:content-[attr(data-label)]';

// "Status Reports": every report, as published, in a table on the ui/Table
// primitives. Long descriptors and URLs wrap in their column; under them, the
// report's other fields and its certificate, whole with copy.
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
            {/* Wide enough for a status such as NOT_FIDO_CERTIFIED on one line,
                however much the Descriptor column holds. */}
            <Td role="cell" data-label={status} className={`min-w-44 align-top max-sm:min-w-0 ${STACK_CELL}`}>
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
              {row.descriptor || row.details || row.certificate ? (
                <span className="block min-w-0">
                  {row.descriptor ? <span className="block [overflow-wrap:anywhere]">{row.descriptor}</span> : null}
                  {row.details ? (
                    <span className="mt-0.5 block text-caption [overflow-wrap:anywhere] text-ink-muted">{row.details}</span>
                  ) : null}
                  {row.certificate ? (
                    // Cut to a short line (it would otherwise widen the column
                    // for good); once shown in full, it wraps across the cell.
                    <span data-report-certificate="" className="mt-1 flex min-w-0 items-baseline gap-2">
                      <span className="shrink-0 text-caption text-ink-muted">Certificate</span>
                      <MonoValue
                        value={row.certificate}
                        label="status report certificate"
                        className="-my-1 min-w-0 max-w-48 has-[[aria-expanded=true]]:max-w-none"
                      />
                    </span>
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
