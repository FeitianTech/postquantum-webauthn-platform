import { buttonClassName } from '@/components/ui/Button';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { SECTIONS, type SectionId } from '@/lib/sections';

export const NAV_ID = 'nav';

// A section that has not moved to the new interface yet: its title, its
// description, and the way to the current interface, where it works today.
export function SectionPanel({ id, active }: { id: SectionId; active: boolean }) {
  const section = SECTIONS.find((candidate) => candidate.id === id)!;
  const ids = segmentIds(NAV_ID, id);
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
      <div className="mt-8 flex max-w-2xl flex-col gap-4 rounded-lg border border-line p-6 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-body text-ink">
          {section.label} has not moved to the new interface yet. It works as before in the current interface.
        </p>
        {/* A plain link: next/link would add the /beta base path. */}
        <a href="/" className={buttonClassName({ variant: 'secondary', size: 'sm' })}>
          Open the current interface
        </a>
      </div>
    </section>
  );
}
