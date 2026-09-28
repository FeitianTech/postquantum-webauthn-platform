import { useEffect, useLayoutEffect } from 'react';

// useLayoutEffect in the browser (it runs before the frame is painted), and no
// warning when the page is rendered for the static export.
export const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;
