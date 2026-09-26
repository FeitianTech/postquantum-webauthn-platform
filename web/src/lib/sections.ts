// The four sections of the top bar, with each one's title and description as the
// current UI shows them (frontend/templates/*/tab.html). The ids are the current
// UI's tab names, and the new UI's URL hashes (#simple, #advanced, #codec, #mds).
export const SECTIONS = [
  {
    id: 'simple',
    label: 'Simple Authentication',
    description: 'Register and authenticate with passkeys using default presets.',
  },
  {
    id: 'advanced',
    label: 'Advanced Authentication',
    description: 'Configure WebAuthn registration and authentication requests with detailed settings.',
  },
  {
    id: 'codec',
    label: 'Codec',
    description: 'Decode or encode WebAuthn payloads to inspect their underlying data formats.',
  },
  {
    id: 'mds',
    label: 'FIDO MDS Authenticators',
    description: 'Explore the authenticators published by the FIDO Metadata Service (MDS).',
  },
] as const;

export type SectionId = (typeof SECTIONS)[number]['id'];

export const DEFAULT_SECTION: SectionId = 'simple';

/** A section, and what follows it in the hash: `#mds/aaguid:…` is the MDS section and an entry. */
export type Route = { section: SectionId; subPath: string };

export function routeFromHash(hash: string): Route | null {
  const raw = hash.replace(/^#/, '');
  const slash = raw.indexOf('/');
  const id = slash === -1 ? raw : raw.slice(0, slash);
  const section = SECTIONS.find((candidate) => candidate.id === id)?.id;
  if (!section) return null;
  if (slash === -1) return { section, subPath: '' };
  const rest = raw.slice(slash + 1);
  try {
    return { section, subPath: decodeURIComponent(rest) };
  } catch {
    return { section, subPath: rest };
  }
}

export function sectionFromHash(hash: string): SectionId | null {
  return routeFromHash(hash)?.section ?? null;
}

// An MDS entry's place in the URL, after the #: `mds/aaguid:…`, the id encoded
// (an AAID's # especially) with its colons kept readable.
export function entryHashPath(entryId: string) {
  return `mds/${encodeURIComponent(entryId).replace(/%3A/gi, ':')}`;
}

export const SECTION_OPTIONS = SECTIONS.map((section) => ({ value: section.id, label: section.label }));
