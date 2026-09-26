import { type ReactNode, type RefObject, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

import { useOverlayRoot } from '@/lib/useOverlayRoot';

import { BackButton } from './EntryHeader';

// The top of the page under the shell's header, which stays in view and whose
// height depends on the width (its sections wrap to a second row).
function shellHeaderBottom() {
  const header = document.querySelector('[data-shell-header]');
  return Math.max(0, Math.round(header?.getBoundingClientRect().bottom ?? 0));
}

// A page's condensed header: once its own heading has scrolled under the shell's
// header, a white bar with a hairline (no shadow: it is not a floating layer)
// stays there with Back, the title and what else the page puts in it. It is
// fixed rather than sticky, so showing it moves nothing on the page, and it is
// in the overlay layer, beside the app: a section sliding in (a transform) would
// otherwise carry it along. `active` is false while the page is covered by another.
export function CondensedBar({
  watch,
  title,
  subtitle,
  onBack,
  backTitle,
  active = true,
  children,
}: {
  watch: RefObject<HTMLElement | null>;
  title: string;
  subtitle?: string;
  onBack: () => void;
  backTitle: string;
  active?: boolean;
  children?: ReactNode;
}) {
  const root = useOverlayRoot();
  const barRef = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const target = watch.current;
    const bar = barRef.current;
    if (!target || !bar || typeof IntersectionObserver === 'undefined') return undefined;
    let observer: IntersectionObserver | null = null;
    const observe = () => {
      observer?.disconnect();
      const top = shellHeaderBottom();
      bar.style.top = `${top}px`;
      observer = new IntersectionObserver(
        ([entry]) => setShown(!entry.isIntersecting && entry.boundingClientRect.top < top),
        { rootMargin: `${-top}px 0px 0px 0px` },
      );
      observer.observe(target);
    };
    observe();
    window.addEventListener('resize', observe);
    return () => {
      window.removeEventListener('resize', observe);
      observer?.disconnect();
    };
  }, [watch, root]);

  if (!root) return null;
  return createPortal(
    <div ref={barRef} data-condensed-header="" hidden={!shown || !active} className="fixed inset-x-0 z-30 border-b border-line bg-white">
      <div className="mx-auto flex w-full max-w-page items-center gap-3 px-4 py-2 sm:px-6 lg:px-8">
        <BackButton onBack={onBack} title={backTitle} />
        <div className="min-w-0 flex-1">
          <p title={title} className="truncate text-body font-semibold text-ink">
            {title}
          </p>
          {subtitle ? (
            <p title={subtitle} className="truncate text-caption text-ink-muted">
              {subtitle}
            </p>
          ) : null}
        </div>
        {children}
      </div>
    </div>,
    root,
  );
}
