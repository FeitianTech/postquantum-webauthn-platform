import { Component, type ReactNode } from 'react';

import { Button } from './Button';

type NoticeProps = { what?: string; text?: string; onRetry?: () => void };

/**
 * A part of the page that did not come up, in its place: what failed (`text`,
 * else that `what` could not be shown), and Try again (`onRetry`) or Reload.
 */
export function FailedNotice({ what = 'part', text = `This ${what} could not be shown. Reload the page to try again.`, onRetry }: NoticeProps) {
  return (
    <div role="alert" className="flex flex-wrap items-center gap-x-4 gap-y-3 rounded-sm border border-danger-line bg-danger-tint px-4 py-3">
      <p className="text-body text-danger">{text}</p>
      <Button variant="secondary" size="sm" onClick={onRetry || (() => location.reload())}>
        {onRetry ? 'Try again' : 'Reload'}
      </Button>
    </div>
  );
}

// A part of the page that throws while rendering shows `fallback` in its place
// (React logs the error), and the rest of the page keeps working.
export class ErrorBoundary extends Component<{ children: ReactNode; fallback?: ReactNode }, { failed: true }> {
  static getDerivedStateFromError = () => ({ failed: true });
  render() {
    // No initial state: React holds it at null until a render error sets it.
    return this.state ? this.props.fallback || <FailedNotice /> : this.props.children;
  }
}
