import type { ChipList, DetailField, DetailSection } from '@/logic/mds/explorer/detail.js';
import type { MdsEntry } from '@/logic/mds/explorer/loading.js';
import { certificationParts, identifierLabel } from '@/logic/mds/explorer/rows.js';

import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { KeyValueGrid } from '@/components/ui/KeyValueGrid';
import { MonoValue } from '@/components/ui/MonoValue';

import { StatusReports } from './StatusReports';
import { UserVerification } from './UserVerification';

// Text this long, and the statement's own paragraphs, take the grid's whole width.
const WIDE_TEXT = 64;
const RUNNING_TEXT = new Set(['Description', 'Legal Header']);

function FieldValue({ field, entry }: { field: DetailField; entry: MdsEntry }) {
  if (field.codes) {
    return (
      <span className="flex flex-col gap-1">
        {field.codes.map((code) => (
          <MonoValue key={code} value={code} label="key identifier" />
        ))}
      </span>
    );
  }
  // A field without codes has a value (explorer/detail.js).
  const value = field.value as string;
  if (field.identifier) {
    // The overview's Identifier is the entry's id, named by its kind.
    const label = field.label === 'Identifier' ? identifierLabel(entry) : field.label;
    return <MonoValue value={value} label={label} />;
  }
  if (field.label === 'Certification') {
    const badge = certificationParts(entry);
    return (
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Badge tone={badge.tone}>{badge.level}</Badge>
        {badge.detail ? <span className="text-body text-ink-muted">{badge.detail}</span> : null}
      </span>
    );
  }
  return <span className="[overflow-wrap:anywhere]">{value}</span>;
}

function Fields({ fields, entry }: { fields: DetailField[]; entry: MdsEntry }) {
  return (
    <KeyValueGrid
      items={fields.map((field) => ({
        key: field.label,
        label: field.label,
        value: <FieldValue field={field} entry={entry} />,
        plain: true,
        wide: RUNNING_TEXT.has(field.label) || (field.value?.length ?? 0) > WIDE_TEXT,
        identifier: Boolean(field.identifier || field.codes),
      }))}
    />
  );
}

function Chips({ list }: { list: ChipList }) {
  return (
    <div data-chips={list.label} className="min-w-0">
      <p className="text-caption text-ink-muted">{list.label}</p>
      <ul className="mt-1.5 flex flex-wrap gap-1.5">
        {list.values.map((value, index) => (
          <li key={`${value}-${index}`} className="min-w-0">
            <Badge className="h-auto min-h-[1.375rem] py-0.5 whitespace-normal [overflow-wrap:anywhere]">{value}</Badge>
          </li>
        ))}
      </ul>
    </div>
  );
}

type CertificateActions = {
  /** Opens a certificate's page; without it the buttons wait. */
  onOpen?: (number: number, certificate: string) => void;
  /** The certificate being decoded, whose button is busy. */
  busy?: number | null;
};

function Section({
  section,
  entry,
  idBase,
  certificates,
}: {
  section: DetailSection;
  entry: MdsEntry;
  idBase: string;
  certificates: CertificateActions;
}) {
  const headingId = `${idBase}-${section.key}`;
  return (
    <section aria-labelledby={headingId} data-section={section.key} className="border-t border-line pt-6">
      <h4 id={headingId} className="text-title font-semibold text-ink">
        {section.title}
      </h4>
      <div className="mt-4 space-y-5">
        {section.fields?.length ? <Fields fields={section.fields} entry={entry} /> : null}
        {section.chipLists?.length ? (
          <div className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
            {section.chipLists.map((list) => (
              <Chips key={list.label} list={list} />
            ))}
          </div>
        ) : null}
        {section.combinations ? <UserVerification combinations={section.combinations} /> : null}
        {section.certificates ? (
          <ul className="flex flex-wrap gap-2">
            {section.certificates.map((certificate) => (
              <li key={certificate.number}>
                <Button
                  variant="secondary"
                  size="sm"
                  data-certificate={certificate.number}
                  busy={certificates.busy === certificate.number}
                  disabled={!certificates.onOpen || (certificates.busy != null && certificates.busy !== certificate.number)}
                  onClick={() => certificates.onOpen?.(certificate.number, certificate.certificate)}
                >
                  {certificate.label}
                </Button>
              </li>
            ))}
          </ul>
        ) : null}
        {section.statusReports && section.columns ? <StatusReports columns={section.columns} rows={section.statusReports} /> : null}
      </div>
    </section>
  );
}

// The page's sections, in explorer/detail.js's order, as
// sections: a heading and a hairline, never cards in cards.
export function EntrySections({
  sections,
  entry,
  idBase,
  certificates = {},
}: {
  sections: DetailSection[];
  entry: MdsEntry;
  idBase: string;
  certificates?: CertificateActions;
}) {
  return (
    <div className="mt-10 space-y-10">
      {sections.map((section) => (
        <Section key={section.key} section={section} entry={entry} idBase={idBase} certificates={certificates} />
      ))}
    </div>
  );
}
