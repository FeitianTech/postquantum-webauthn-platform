import { SavedCredentials } from '@/components/credentials/SavedCredentials';
import { NAV_ID } from '@/components/shell/SectionPanel';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { SECTIONS } from '@/lib/sections';
import type { SectionRoute } from '@/lib/useSection';

// The Simple tab: register and authenticate with passkeys using default presets,
// beside the saved credentials both tabs share.
export function SimpleSection({ active, route }: { active: boolean; route: SectionRoute }) {
  const section = SECTIONS.find((candidate) => candidate.id === 'simple')!;
  const ids = segmentIds(NAV_ID, 'simple');

  return (
    <section
      role="tabpanel"
      id={ids.panel}
      aria-labelledby={ids.tab}
      hidden={!active}
      className="animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none"
    >
      <h2 className="text-display font-semibold text-ink">{section.label}</h2>
      <p className="mt-2 max-w-prose text-body-lg text-ink-muted">{section.description}</p>
      <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)] lg:gap-8">
        <div className="min-w-0" data-simple-column="ceremony" />
        <SavedCredentials onOpen={(key) => route.open(['credential', key])} />
      </div>
    </section>
  );
}
