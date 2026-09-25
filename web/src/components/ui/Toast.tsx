import { type ReactNode, createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

import { cx } from '@/lib/cx';
import { useOverlayRoot } from '@/lib/useOverlayRoot';

import { IconButton } from './Button';
import { CloseIcon } from './icons';

export type ToastTone = 'info' | 'success' | 'warning' | 'danger';
export type ToastInput = { tone?: ToastTone; message: ReactNode; durationMs?: number };
type ToastEntry = ToastInput & { id: number };

// As long as today's status messages stay (shared/ui/status.js).
export const TOAST_DURATION_MS = 5000;
const MAX_TOASTS = 3;

const ToastContext = createContext<(toast: ToastInput) => void>(() => {});

export function useToast() {
  return useContext(ToastContext);
}

const DOTS: Record<ToastTone, string> = {
  info: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
};

function ToastItem({ toast, onDismiss }: { toast: ToastEntry; onDismiss: (id: number) => void }) {
  useEffect(() => {
    const timer = setTimeout(() => onDismiss(toast.id), toast.durationMs ?? TOAST_DURATION_MS);
    return () => clearTimeout(timer);
  }, [toast.id, toast.durationMs, onDismiss]);

  const tone = toast.tone ?? 'info';
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'status'}
      data-tone={tone}
      className={cx(
        'pointer-events-auto flex max-w-[min(34rem,calc(100vw-2rem))] items-center gap-3 rounded-full border border-line',
        'bg-surface py-1.5 pr-1.5 pl-4 text-label font-medium text-ink shadow-float',
        'transition-[opacity,translate] duration-(--duration-base) ease-standard starting:translate-y-2 starting:opacity-0',
      )}
    >
      <span aria-hidden="true" className={cx('size-2 shrink-0 rounded-full', DOTS[tone])} />
      <span className="min-w-0 flex-1">{toast.message}</span>
      <IconButton size="sm" label="Dismiss" icon={<CloseIcon size={14} />} onClick={() => onDismiss(toast.id)} />
    </div>
  );
}

// Floating messages at the bottom of the screen: white, with a coloured dot for
// the tone. They leave by themselves after five seconds or when dismissed.
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const next = useRef(0);
  const root = useOverlayRoot();

  const show = useCallback((toast: ToastInput) => {
    next.current += 1;
    const entry = { ...toast, id: next.current };
    setToasts((list) => [...list, entry].slice(-MAX_TOASTS));
  }, []);
  const dismiss = useCallback((id: number) => setToasts((list) => list.filter((toast) => toast.id !== id)), []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      {root
        ? createPortal(
            <div
              data-toast-viewport=""
              className="pointer-events-none fixed inset-x-0 bottom-6 z-[60] flex flex-col items-center gap-2 px-4"
            >
              {toasts.map((toast) => (
                <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
              ))}
            </div>,
            root,
          )
        : null}
    </ToastContext.Provider>
  );
}
