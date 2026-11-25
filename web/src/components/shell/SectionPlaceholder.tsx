import { FailedNotice } from '@/components/ui/ErrorBoundary';
import { segmentIds } from '@/components/ui/SegmentedControl';
import { NAV_ID, type SectionId } from '@/lib/sections';

// A section's panel while its chunk loads: empty and busy, so the top bar's tab
// controls a panel from the first frame. If the chunk could not be loaded, it
// says so and offers to load it again; if the section threw while rendering
// ('render'), it says so and offers to reload the page.
export function SectionPlaceholder({
  id,
  active,
  failed,
  onRetry,
}: {
  id: SectionId;
  active: boolean;
  failed: boolean | 'render';
  onRetry?: () => void;
}) {
  const ids = segmentIds(NAV_ID, id);
  return (
    <section role="tabpanel" id={ids.panel} aria-labelledby={ids.tab} aria-busy={!failed} hidden={!active} data-section-placeholder="">
      {failed === 'render' ? (
        <FailedNotice what="section" />
      ) : failed ? (
        <FailedNotice text="This section could not be loaded. Check the connection, then try again." onRetry={onRetry} />
      ) : null}
    </section>
  );
}
