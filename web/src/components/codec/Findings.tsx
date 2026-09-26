import { Badge } from '@/components/ui/Badge';

import type { FindingView } from './model';

// What the decoder found, one row each: the category (amber when the server
// also lists it among the malformed segments), where it is in mono (the field
// it was found in, the offset, the path), and what it says.
export function Findings({ heading, findings }: { heading: string; findings: FindingView[] }) {
  return (
    <section aria-labelledby="codec-findings-heading" data-codec-findings="">
      <h4 id="codec-findings-heading" className="text-label font-semibold text-ink">
        {heading}
      </h4>
      <ul className="mt-2 divide-y divide-line border-y border-line">
        {findings.map((finding, index) => (
          <li
            key={index}
            data-finding={finding.category ?? ''}
            className="flex min-w-0 flex-col gap-1.5 py-2.5 sm:flex-row sm:items-baseline sm:gap-3"
          >
            <div className="flex shrink-0 flex-wrap items-center gap-1.5 sm:w-64">
              {finding.category ? (
                <Badge tone={finding.malformed ? 'warning' : 'neutral'} data-role="category">
                  {finding.category}
                </Badge>
              ) : null}
              {finding.source ? (
                <code data-role="source" className="font-mono text-label text-ink wrap-anywhere">
                  {finding.source}
                </code>
              ) : null}
              {finding.offset ? (
                <code data-role="offset" className="font-mono text-label text-ink">
                  {finding.offset}
                </code>
              ) : null}
              {finding.path ? (
                <code data-role="path" className="font-mono text-label text-ink wrap-anywhere">
                  {finding.path}
                </code>
              ) : null}
            </div>
            <p data-role="message" className="min-w-0 text-body text-ink wrap-anywhere">
              {finding.message}
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
