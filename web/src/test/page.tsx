import { render } from '@testing-library/react';
import type { ReactNode } from 'react';

// The page as _app lays it out: the app, and the overlay layer beside it.
export function renderPage(children: ReactNode) {
  return render(
    <>
      <div id="app-root">{children}</div>
      <div id="overlay-root" />
    </>,
  );
}
