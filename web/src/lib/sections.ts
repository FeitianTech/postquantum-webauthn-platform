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

export function sectionFromHash(hash: string): SectionId | null {
  const id = hash.replace(/^#/, '');
  return SECTIONS.find((section) => section.id === id)?.id ?? null;
}

export const SECTION_OPTIONS = SECTIONS.map((section) => ({ value: section.id, label: section.label }));
