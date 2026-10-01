// The four sections of the top bar, with each one's title and description. The
// ids are the URL hashes (#simple, #advanced, #codec, #mds).
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

/** The top bar's name for its sections' tabs and panels (segmentIds). */
export const NAV_ID = 'nav';

/** The page's title, which the Advanced tab's requests also name their relying party with. */
export const APP_TITLE = 'FIDO2/WebAuthn PQC Developer Tools';

export const DEFAULT_SECTION: SectionId = 'simple';

/**
 * A section, and what is open in it: the hash's segments after the section's,
 * each decoded on its own. `#mds/aaguid:…/certificate/1` is the MDS section and
 * `['aaguid:…', 'certificate', '1']`.
 */
export type Route = { section: SectionId; path: string[] };

function decodeSegment(segment: string) {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

// A segment as the hash holds it: encoded (an AAID's # and any /) with its
// colons kept readable: `aaguid:…`.
function encodeSegment(segment: string) {
  return encodeURIComponent(segment).replace(/%3A/gi, ':');
}

export function routeFromHash(hash: string): Route | null {
  const [id, ...rest] = hash.replace(/^#/, '').split('/');
  const section = SECTIONS.find((candidate) => candidate.id === id)?.id;
  if (!section) return null;
  return { section, path: rest.filter(Boolean).map(decodeSegment) };
}

// A place in the URL, after the #: the section, then what is open in it.
export function hashPath(section: SectionId, path: readonly string[] = []) {
  return [section, ...path.map(encodeSegment)].join('/');
}

export function entryHashPath(entryId: string) {
  return hashPath('mds', [entryId]);
}

export const SECTION_OPTIONS = SECTIONS.map((section) => ({ value: section.id, label: section.label }));
