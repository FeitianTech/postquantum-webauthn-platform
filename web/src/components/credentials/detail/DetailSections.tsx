import { type ReactNode, useState } from 'react';

import { useOpenMdsEntry } from '@/components/mds/entryLink';
import { Badge, StatusChip } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CodeBlock } from '@/components/ui/CodeBlock';
import { KeyValueGrid } from '@/components/ui/KeyValueGrid';
import { MonoValue } from '@/components/ui/MonoValue';

import { type CredentialRowView, LIST_TEXT } from '../model';
import { type Check, type CredentialDetail, DETAIL_WORDS, type Identifier, type ValueKind, valueOf } from './model';

const TONES: Record<ValueKind, 'success' | 'danger' | 'neutral'> = {
  true: 'success',
  false: 'danger',
  missing: 'neutral',
  other: 'neutral',
};

// The logic's labels end in a colon, as a line of text reads; here each labels a
// field.
function bare(label: string) {
  return label.replace(/:\s*$/, '');
}

/** A property's or a check's value: true, false, N/A or as written, with its tone and mark. */
export function ValueChip({ value }: { value: unknown }) {
  const described = valueOf(value);
  return (
    <StatusChip tone={TONES[described.kind]} data-value={described.kind}>
      {described.text}
    </StatusChip>
  );
}

/** A section of a level: a heading and a hairline, never a card in the dialog. */
export function DetailSection({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section aria-labelledby={id} data-section={title} className="min-w-0 border-t border-line pt-6">
      <h4 id={id} className="text-title font-semibold text-ink">
        {title}
      </h4>
      <div className="mt-4 space-y-5">{children}</div>
    </section>
  );
}

function CheckRow({ check }: { check: Check }) {
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-line py-2.5 first:border-t-0" data-check={check.label}>
      <span className="min-w-44 text-body text-ink">{check.label}</span>
      <ValueChip value={check.value} />
      {check.rootChecks ? (
        <span className="flex flex-wrap items-center gap-1.5" data-root-checks="">
          {check.rootChecks.map((root) => (
            <ValueChipNamed key={root.label} label={root.label} value={root.value} />
          ))}
        </span>
      ) : null}
    </li>
  );
}

// A root the Root Valid check tried, named, in its verdict's tone.
function ValueChipNamed({ label, value }: { label: string; value: unknown }) {
  const described = valueOf(value);
  return (
    <StatusChip tone={TONES[described.kind]} data-root={label}>
      {label}
      <span className="sr-only"> {described.text}</span>
    </StatusChip>
  );
}

function Properties({ detail, idBase }: { detail: CredentialDetail; idBase: string }) {
  const { properties } = detail;
  const [before, strong, after] = DETAIL_WORDS.checksNote;
  return (
    <DetailSection id={`${idBase}-properties`} title={properties.title}>
      <KeyValueGrid
        items={[
          { key: 'discoverable', label: bare(DETAIL_WORDS.discoverable), value: <ValueChip value={properties.discoverable} />, plain: true },
          { key: 'largeBlob', label: bare(DETAIL_WORDS.largeBlob), value: <ValueChip value={properties.largeBlob} />, plain: true },
          ...(properties.minPinLength !== null
            ? [{ key: 'minPinLength', label: bare(DETAIL_WORDS.minPinLength), value: String(properties.minPinLength), plain: true }]
            : []),
        ]}
      />
      <div data-checks="">
        <p className="text-body text-ink-muted">
          {before}
          <strong className="font-semibold text-ink">{strong}</strong>
          {after}
        </p>
        <ul className="mt-2">
          {properties.checks.map((check) => (
            <CheckRow key={check.label} check={check} />
          ))}
        </ul>
        {properties.warning ? (
          <p role="note" className="mt-3 rounded-sm border border-warning-line bg-warning-tint px-4 py-3 text-body text-warning" data-warning="">
            {properties.warning}
          </p>
        ) : null}
      </div>
    </DetailSection>
  );
}

// An identifier's spellings, each on a row of its own so a whole one fits.
function Spellings({ title, values, context }: { title: string; values: { label: string; value: string }[]; context: string }) {
  return (
    <div data-identifier={title} className="min-w-0">
      <p className="text-caption text-ink-muted">{bare(title)}</p>
      {/* Each spelling beside its name; on a phone under it, the copy button
          beside the name, so a whole AAGUID has the line to itself. */}
      <dl className="mt-1.5 space-y-1.5">
        {values.map((entry) => (
          <div key={entry.label} className="relative grid min-w-0 grid-cols-1 items-baseline gap-x-3 sm:grid-cols-[3rem_minmax(0,1fr)]">
            <dt className="text-label text-ink-muted max-sm:flex max-sm:min-h-8 max-sm:items-center max-sm:pr-10">{entry.label}</dt>
            <dd className="min-w-0">
              {entry.value === DETAIL_WORDS.notAvailable ? (
                <span className="text-body text-ink-muted">{entry.value}</span>
              ) : (
                <MonoValue value={entry.value} label={`${context} (${entry.label})`} wrapOnPhone />
              )}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function IdentifierBlock({ identifier }: { identifier: Identifier }) {
  if (identifier.spellings) {
    return <Spellings title={identifier.title} values={identifier.spellings} context={bare(identifier.title)} />;
  }
  return (
    <div data-identifier={identifier.title} className="min-w-0">
      <p className="text-caption text-ink-muted">{bare(identifier.title)}</p>
      <MonoValue className="mt-1.5" value={identifier.stored} label={`${bare(identifier.title)} as stored`} />
      <p className="mt-1 text-caption text-ink-muted italic">{identifier.note}</p>
    </div>
  );
}

function Aaguid({ detail, row }: { detail: CredentialDetail; row: CredentialRowView }) {
  const openMdsEntry = useOpenMdsEntry();
  const [message, setMessage] = useState<string | null>(null);
  return (
    <div className="min-w-0 space-y-2" data-aaguid="">
      <Spellings title={detail.aaguid.title} values={detail.aaguid.values} context="AAGUID" />
      {row.aaguidUnreadable ? (
        <p className="flex flex-wrap items-center gap-2 text-caption text-ink-muted" data-unreadable="aaguid">
          <Badge tone="warning">Unreadable</Badge>
          <span className="min-w-0">
            <MonoValue value={row.aaguidUnreadable} label="stored AAGUID" />
          </span>
        </p>
      ) : null}
      {row.mdsAaguid ? (
        <Button variant="secondary" size="sm" title={LIST_TEXT.openMetadata} onClick={() => setMessage(openMdsEntry(row.mdsAaguid))}>
          FIDO MDS
        </Button>
      ) : null}
      {message ? (
        <p role="status" className="text-caption text-warning">
          {message}
        </p>
      ) : null}
    </div>
  );
}

function UserInfo({ detail, row, idBase }: { detail: CredentialDetail; row: CredentialRowView; idBase: string }) {
  const { userInfo } = detail;
  return (
    <DetailSection id={`${idBase}-user`} title={userInfo.title}>
      <KeyValueGrid
        columns={2}
        items={[
          { key: 'name', label: bare(DETAIL_WORDS.name), value: userInfo.name, plain: true },
          { key: 'displayName', label: bare(DETAIL_WORDS.displayName), value: userInfo.displayName, plain: true },
        ]}
      />
      {userInfo.identifiers.map((identifier) => (
        <IdentifierBlock key={identifier.title} identifier={identifier} />
      ))}
      <Aaguid detail={detail} row={row} />
    </DetailSection>
  );
}

/**
 * The detail's level: everything detail-sections.js shows above the registration,
 * in its order, then the way to the registration's own level.
 */
export function DetailSections({
  detail,
  row,
  idBase,
  onRegistration,
}: {
  detail: CredentialDetail;
  row: CredentialRowView;
  idBase: string;
  onRegistration: () => void;
}) {
  return (
    <div className="space-y-8">
      <Properties detail={detail} idBase={idBase} />
      <UserInfo detail={detail} row={row} idBase={idBase} />
      <DetailSection id={`${idBase}-format`} title={detail.attestationFormat.title}>
        <p className="text-body-lg text-ink" data-format="">
          {detail.attestationFormat.value}
        </p>
      </DetailSection>
      {detail.authenticatorData ? (
        <DetailSection id={`${idBase}-flags`} title={detail.authenticatorData.title}>
          <KeyValueGrid
            columns={4}
            items={[
              ...detail.authenticatorData.flags.map((flag) => ({ key: flag.name, label: flag.name, value: flag.value, plain: true, mono: true })),
              { key: 'counter', label: bare(DETAIL_WORDS.signatureCounter), value: detail.authenticatorData.counter, plain: true, mono: true },
            ]}
          />
        </DetailSection>
      ) : null}
      {detail.extensions ? (
        <DetailSection id={`${idBase}-extensions`} title={detail.extensions.title}>
          <CodeBlock value={detail.extensions.text} label="client extension outputs" />
        </DetailSection>
      ) : null}
      {detail.publicKey ? (
        <DetailSection id={`${idBase}-key`} title={detail.publicKey.title}>
          <KeyValueGrid
            items={detail.publicKey.lines.map((line) => ({ key: line.label, label: bare(line.label), value: line.value, plain: true }))}
          />
        </DetailSection>
      ) : null}
      <DetailSection id={`${idBase}-registration`} title="Registration Details">
        <Button variant="secondary" size="sm" data-level-open="registration" onClick={onRegistration}>
          Show registration details
        </Button>
      </DetailSection>
    </div>
  );
}
