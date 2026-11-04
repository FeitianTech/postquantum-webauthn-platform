import type { CredentialRowView } from '@/logic/credentials/saved-list.js';

import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';

// Under an entry's header, the credentials this browser keeps whose AAGUID is
// the entry's (credentials/aaguid-credentials.js), each opening its details over
// the entry; nothing when there are none. A section as the entry's others are: a
// heading and a hairline.
export function EntrySavedCredentials({
  rows,
  idBase,
  onOpen,
}: {
  rows: CredentialRowView[];
  idBase: string;
  onOpen: (key: string) => void;
}) {
  if (!rows.length) return null;
  const headingId = `${idBase}-saved`;
  return (
    <section aria-labelledby={headingId} data-section="savedCredentials" className="mt-10 border-t border-line pt-6">
      <h4 id={headingId} className="text-title font-semibold text-ink">
        Saved Credentials
      </h4>
      <p className="mt-1 text-body text-ink-muted">Kept in this browser, with this authenticator&apos;s AAGUID.</p>
      <ul className="mt-4 flex flex-col gap-2">
        {rows.map((row) => (
          <li key={row.key} className="flex flex-wrap items-center gap-2" data-credential-key={row.key}>
            <Button variant="secondary" size="sm" onClick={() => onOpen(row.key)}>
              {row.name}
            </Button>
            {row.tags.map((tag) => (
              <Badge key={tag}>{tag}</Badge>
            ))}
          </li>
        ))}
      </ul>
    </section>
  );
}
