import type { CertificateSummary as Summary, SummaryItem } from '@/logic/mds/explorer/certificate.js';

import { CodeBlock } from '@/components/ui/CodeBlock';
import { KeyValueGrid } from '@/components/ui/KeyValueGrid';
import { MonoValue } from '@/components/ui/MonoValue';

function ItemValue({ item, context }: { item: SummaryItem; context: string }) {
  const name = `${context}${item.label}`.toLowerCase();
  // An item has a value, or its lines (explorer/certificate.js).
  const value = item.value as string;
  if (item.code) return <CodeBlock value={value} label={name} />;
  if (item.lines) {
    return (
      <span className="flex flex-col">
        {item.lines.map((line, index) => (
          <span key={`${line}-${index}`}>{line}</span>
        ))}
      </span>
    );
  }
  // The serial numbers are identifiers: Geist Mono, whole, with copy.
  if (item.label.startsWith('Serial Number')) return <MonoValue value={value} label={name} />;
  return <span className="[overflow-wrap:anywhere]">{value}</span>;
}

function Items({ items, context = '' }: { items: SummaryItem[]; context?: string }) {
  return (
    <KeyValueGrid
      items={items.map((item) => ({
        key: item.label,
        label: item.label,
        value: <ItemValue item={item} context={context} />,
        plain: !item.primary,
        wide: item.code || item.label === 'Subject' || item.label === 'Issuer',
      }))}
    />
  );
}

// An id holds no space: aria-labelledby reads one as two ids ("Public Key").
function sectionId(idBase: string, title: string) {
  return `${idBase}-${title.replace(/\s+/g, '-')}`;
}

// A certificate's summary: its subject, issuer, validity and serial numbers
// first (emphasised), then its public key and its
// signature, each under its heading; long values in blocks with copy.
export function CertificateSummary({ summary, idBase }: { summary: Summary; idBase: string }) {
  return (
    <div className="space-y-8">
      {summary.items.length ? <Items items={summary.items} /> : null}
      {summary.sections.map((section) => (
        <section key={section.title} aria-labelledby={sectionId(idBase, section.title)} data-section={section.title} className="border-t border-line pt-6">
          <h4 id={sectionId(idBase, section.title)} className="text-title font-semibold text-ink">
            {section.title}
          </h4>
          <div className="mt-4">
            <Items items={section.items} context={`${section.title} `} />
          </div>
        </section>
      ))}
    </div>
  );
}
