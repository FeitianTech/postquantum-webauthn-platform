import { type KeyboardEvent, type ReactNode, useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from 'react';

import { cx } from '@/lib/cx';

import { InfoIcon } from './icons';

const HIDE_DELAY_MS = 200;
const OPENED = 'info-popover-open';
const EDGE = 8;

// Below the trigger and from its left by default; above it when there is no
// room below and more above, and from its right when it would leave the screen.
export function placePopup(popup: DOMRect, trigger: DOMRect, viewport: { width: number; height: number }) {
  const roomBelow = viewport.height - trigger.bottom;
  const side = popup.bottom > viewport.height - EDGE && trigger.top > roomBelow ? 'top' : 'bottom';
  const align = popup.right > viewport.width - EDGE ? 'end' : 'start';
  return { side, align } as const;
}

type InfoPopoverProps = {
  /** What the popover explains, for the trigger's name: "About prf eval first". */
  label: string;
  en: ReactNode;
  zh: ReactNode;
};

// The info popups: an ⓘ that opens on hover, as today, and now also on click or
// Enter for keyboard users. One is open at a time; Escape or a click elsewhere
// closes it. The toggle switches between English and 中文 and reads "ENG" or "中"
// as today, and the popup keeps its English size while showing Chinese.
export function InfoPopover({ label, en, zh }: InfoPopoverProps) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [language, setLanguage] = useState<'en' | 'zh'>('en');
  const [placement, setPlacement] = useState<ReturnType<typeof placePopup>>({ side: 'bottom', align: 'start' });
  const rootRef = useRef<HTMLSpanElement>(null);
  const popupRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const close = useCallback(() => {
    clearTimeout(hideTimer.current);
    setOpen(false);
    setPinned(false);
  }, []);

  const show = () => {
    clearTimeout(hideTimer.current);
    if (!open) document.dispatchEvent(new CustomEvent(OPENED, { detail: id }));
    setOpen(true);
  };

  useEffect(() => {
    const onOtherOpened = (event: Event) => {
      if ((event as CustomEvent<string>).detail !== id) close();
    };
    document.addEventListener(OPENED, onOtherOpened);
    return () => {
      document.removeEventListener(OPENED, onOtherOpened);
      clearTimeout(hideTimer.current);
    };
  }, [id, close]);

  useLayoutEffect(() => {
    const popup = popupRef.current;
    const trigger = triggerRef.current;
    if (!open || !popup || !trigger) {
      setPlacement({ side: 'bottom', align: 'start' });
      return;
    }
    setPlacement(
      placePopup(popup.getBoundingClientRect(), trigger.getBoundingClientRect(), {
        width: window.innerWidth,
        height: window.innerHeight,
      }),
    );
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) close();
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open, close]);

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'Escape' && open) {
      // Handled here, so a dialog around the popover stays open.
      event.stopPropagation();
      event.nativeEvent.stopImmediatePropagation();
      close();
      triggerRef.current?.focus();
    }
  };

  const toggleLanguage = () => {
    const popup = popupRef.current;
    if (popup && language === 'en') popup.style.minHeight = `${popup.offsetHeight}px`;
    setLanguage(language === 'en' ? 'zh' : 'en');
  };

  return (
    <span
      ref={rootRef}
      className="relative inline-flex"
      onMouseEnter={show}
      onMouseLeave={() => {
        clearTimeout(hideTimer.current);
        hideTimer.current = setTimeout(() => {
          if (!pinned) setOpen(false);
        }, HIDE_DELAY_MS);
      }}
      onKeyDown={onKeyDown}
    >
      <button
        ref={triggerRef}
        type="button"
        aria-label={label}
        aria-expanded={open}
        aria-controls={`${id}-popup`}
        onClick={() => {
          if (open && pinned) close();
          else {
            show();
            setPinned(true);
          }
        }}
        className="inline-flex size-5 items-center justify-center rounded-full text-ink-faint transition-colors hover-or-demo:text-ink"
      >
        <InfoIcon />
      </button>
      <div
        ref={popupRef}
        id={`${id}-popup`}
        role="group"
        aria-label={label}
        hidden={!open}
        data-side={placement.side}
        data-align={placement.align}
        className={cx(
          'absolute z-40 w-[min(21rem,calc(100vw-2rem))] rounded-md border border-line',
          'bg-surface p-4 pb-11 text-label leading-[1.55] font-normal text-ink shadow-float',
          placement.side === 'top' ? 'bottom-full mb-2' : 'top-full mt-2',
          placement.align === 'end' ? 'right-[-0.75rem]' : 'left-[-0.75rem]',
        )}
      >
        <div lang="en" hidden={language !== 'en'}>
          {en}
        </div>
        <div lang="zh" hidden={language !== 'zh'}>
          {zh}
        </div>
        <button
          type="button"
          onClick={toggleLanguage}
          aria-label={language === 'en' ? 'ENG, show in Chinese' : '中, show in English'}
          className={cx(
            'absolute right-3 bottom-3 h-6 rounded-full border border-line-strong bg-surface px-2 text-caption font-semibold',
            'text-ink-muted transition-colors hover-or-demo:border-line-hover hover-or-demo:text-ink',
          )}
        >
          {language === 'en' ? 'ENG' : '中'}
        </button>
      </div>
    </span>
  );
}
