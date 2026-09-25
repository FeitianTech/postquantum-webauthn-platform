import { useCallback, useEffect, useState } from 'react';

import { DEFAULT_SECTION, type SectionId, sectionFromHash } from './sections';

// The chosen section, switched on the page and mirrored in the URL hash, so a
// link or a reload opens the same section. The hash is read after the page has
// hydrated (reading it while rendering would differ from the exported HTML), and
// written with replaceState so switching sections does not fill the history;
// Next's own history state is kept. Editing the hash switches too.
export function useSection(): [SectionId, (section: SectionId) => void] {
  const [section, setSection] = useState<SectionId>(DEFAULT_SECTION);

  useEffect(() => {
    const follow = () => {
      const fromHash = sectionFromHash(window.location.hash);
      if (fromHash) setSection(fromHash);
    };
    follow();
    window.addEventListener('hashchange', follow);
    return () => window.removeEventListener('hashchange', follow);
  }, []);

  const choose = useCallback((next: SectionId) => {
    setSection(next);
    const url = `${window.location.pathname}${window.location.search}#${next}`;
    window.history.replaceState(window.history.state, '', url);
  }, []);

  return [section, choose];
}
