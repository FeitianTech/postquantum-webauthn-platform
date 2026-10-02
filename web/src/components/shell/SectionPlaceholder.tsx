import { Button } from '@/components/ui/Button';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { NAV_ID, type SectionId } from '@/lib/sections';

// A section's panel while its chunk loads: empty and busy, so the top bar's tab
// controls a panel from the first frame. If the chunk could not be loaded, it
// says so and offers to load it again.
export function SectionPlaceholder({
  id,
  active,
  failed,
  onRetry,
}: {
  id: SectionId;
  active: boolean;
  failed: boolean;
  onRetry: () => void;
}) {
  const ids = segmentIds(NAV_ID, id);
  return (
    <section role="tabpanel" id={ids.panel} aria-labelledby={ids.tab} aria-busy={!failed} hidden={!active} data-section-placeholder="">
      {failed ? (
        <div role="alert" className="flex flex-wrap items-center gap-x-4 gap-y-3 rounded-sm border border-danger-line bg-danger-tint px-4 py-3">
          <p className="text-body text-danger">This section could not be loaded. Check the connection, then try again.</p>
          <Button variant="secondary" size="sm" onClick={onRetry}>
            Try again
          </Button>
        </div>
      ) : null}
    </section>
  );
}
