import { type ReactNode, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

import { cx } from '@/lib/cx';
import { useOverlayRoot } from '@/lib/useOverlayRoot';

import { IconButton } from './Button';
import { CloseIcon } from './icons';

export type OverlayVariant = 'dialog' | 'drawer' | 'sheet';

type OverlayProps = {
  open: boolean;
  onClose: () => void;
  /** The id of the overlay's root, which a trigger's aria-controls names. */
  id?: string;
  variant?: OverlayVariant;
  /** The id of the element that names the panel, or `label` for a name with none on screen. */
  labelledBy?: string;
  label?: string;
  /** Where focus goes when it closes; by default what had focus when it opened. */
  returnFocusTo?: () => HTMLElement | null;
  className?: string;
  children: ReactNode;
};

const EXIT_MS = 200;
const FOCUSABLE = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

export function focusableIn(panel: HTMLElement): HTMLElement[] {
  return Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (node) => !(node as HTMLButtonElement).disabled && !node.closest('[hidden]'),
  );
}

// Tab and Shift+Tab go round the panel's controls and never leave it: from the
// last to the first and back, and from the panel itself (or anywhere outside it)
// to the first (Tab) or the last (Shift+Tab).
export function keepFocusInside(event: KeyboardEvent, panel: HTMLElement) {
  const focusable = focusableIn(panel);
  if (focusable.length === 0) {
    event.preventDefault();
    panel.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const active = document.activeElement;
  const inside = active !== panel && panel.contains(active);
  if (event.shiftKey && (!inside || active === first)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && (!inside || active === last)) {
    event.preventDefault();
    first.focus();
  }
}

const PANELS: Record<OverlayVariant, string> = {
  dialog:
    'top-1/2 left-1/2 w-[min(calc(100vw-2rem),60rem)] max-h-[min(88vh,60rem)] -translate-x-1/2 -translate-y-1/2 ' +
    'group-data-[state=closed]:translate-y-[calc(-50%+0.5rem)] group-data-[state=closed]:scale-[0.98] ' +
    'group-data-[state=closed]:opacity-0',
  drawer:
    'top-3 right-3 bottom-3 w-[min(27.5rem,calc(100vw-1.5rem))] ' +
    'group-data-[state=closed]:translate-x-[calc(100%+1.5rem)]',
  sheet:
    'inset-x-3 top-3 max-h-[calc(100dvh-1.5rem)] origin-top ' +
    'group-data-[state=closed]:-translate-y-2 group-data-[state=closed]:scale-[0.98] group-data-[state=closed]:opacity-0',
};

// What every floating layer shares: rendered into #overlay-root (a sibling of
// the app, which is made inert while it is open), a scrim that closes it, the
// panel taking focus, Tab kept inside, Escape closing it, and focus given back.
// The page behind is not scroll-locked, as in the current UI.
export function Overlay({
  open,
  onClose,
  id,
  variant = 'dialog',
  labelledBy,
  label,
  returnFocusTo,
  className,
  children,
}: OverlayProps) {
  const target = useOverlayRoot();
  const [mounted, setMounted] = useState(open);
  const [shown, setShown] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  const returnFocusRef = useRef(returnFocusTo);
  onCloseRef.current = onClose;
  returnFocusRef.current = returnFocusTo;

  useEffect(() => {
    if (open) {
      setMounted(true);
      const frame = requestAnimationFrame(() => setShown(true));
      return () => cancelAnimationFrame(frame);
    }
    setShown(false);
    const timer = setTimeout(() => setMounted(false), EXIT_MS);
    return () => clearTimeout(timer);
  }, [open]);

  useEffect(() => {
    const panel = panelRef.current;
    if (!open || !mounted || !panel) return undefined;
    const giveBackTo = returnFocusRef.current?.() ?? (document.activeElement as HTMLElement | null);

    for (const scroller of panel.querySelectorAll<HTMLElement>('[data-overlay-scroll]')) scroller.scrollTop = 0;
    panel.focus({ preventScroll: true });
    const app = document.getElementById('app-root');
    const inert = app && !app.contains(panel) ? app : null;
    inert?.setAttribute('inert', '');

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onCloseRef.current();
      } else if (event.key === 'Tab') {
        keepFocusInside(event, panel);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      inert?.removeAttribute('inert');
      if (giveBackTo?.isConnected) giveBackTo.focus({ preventScroll: true });
    };
  }, [open, mounted]);

  if (!target) return null;
  return createPortal(
    <div
      id={id}
      hidden={!mounted}
      data-overlay={variant}
      data-state={shown ? 'open' : 'closed'}
      className="group fixed inset-0 z-50"
    >
      <div
        data-overlay-backdrop=""
        onClick={onClose}
        className={cx(
          'absolute inset-0 bg-scrim backdrop-blur-[3px] transition-opacity duration-(--duration-base) ease-standard',
          'group-data-[state=closed]:opacity-0',
        )}
      />
      {mounted ? (
        <div
          ref={panelRef}
          role="dialog"
          aria-modal="true"
          aria-labelledby={labelledBy}
          aria-label={labelledBy ? undefined : label}
          tabIndex={-1}
          data-overlay-panel=""
          className={cx(
            'absolute flex flex-col overflow-hidden rounded-lg bg-surface shadow-float-lg',
            'transition-[opacity,translate,scale] ease-standard',
            variant === 'drawer' ? 'duration-(--duration-slow)' : 'duration-(--duration-base)',
            PANELS[variant],
            className,
          )}
        >
          {children}
        </div>
      ) : null}
    </div>,
    target,
  );
}

type OverlayHeaderProps = {
  titleId: string;
  title: ReactNode;
  onClose: () => void;
  closeLabel: string;
  /** Controls beside the title, such as "Copy report". */
  actions?: ReactNode;
};

export function OverlayHeader({ titleId, title, onClose, closeLabel, actions }: OverlayHeaderProps) {
  return (
    <div className="flex shrink-0 items-center gap-3 border-b border-line py-3.5 pr-3.5 pl-6">
      <h2 id={titleId} className="min-w-0 flex-1 text-title font-semibold text-ink">
        {title}
      </h2>
      {actions}
      <IconButton label={closeLabel} icon={<CloseIcon />} onClick={onClose} />
    </div>
  );
}

// The part of a panel that scrolls; it is back at the top each time the panel opens.
export function OverlayBody({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div data-overlay-scroll="" className={cx('min-h-0 flex-1 overflow-y-auto px-6 py-5', className)}>
      {children}
    </div>
  );
}

export function Dialog(props: Omit<OverlayProps, 'variant'>) {
  return <Overlay {...props} variant="dialog" />;
}

export function Drawer(props: Omit<OverlayProps, 'variant'>) {
  return <Overlay {...props} variant="drawer" />;
}

export function Sheet(props: Omit<OverlayProps, 'variant'>) {
  return <Overlay {...props} variant="sheet" />;
}
