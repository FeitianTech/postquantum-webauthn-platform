import { useEffect, useState } from 'react';

// Where floating layers render: #overlay-root, beside the app (which a dialog
// makes inert), or the body when a page has none. Known only in the browser.
export function useOverlayRoot(): HTMLElement | null {
  const [root, setRoot] = useState<HTMLElement | null>(null);
  useEffect(() => {
    setRoot(document.getElementById('overlay-root') ?? document.body);
  }, []);
  return root;
}
