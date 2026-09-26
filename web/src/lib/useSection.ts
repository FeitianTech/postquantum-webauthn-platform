import Router from 'next/router';
import { useCallback, useEffect, useState } from 'react';

import { DEFAULT_SECTION, type SectionId, hashPath, routeFromHash } from './sections';

// A history entry this page pushed to open something inside a section (an MDS
// entry), so the page's own Back can be the browser's.
const PUSHED = 'pqcOpened';

/** What is open inside the section (after `#section/` in the URL), and how to open and close it. */
export type SectionRoute = { subPath: string; open: (subPath: string) => void; close: () => void };

// Next's router answers Back for pages it navigated between, putting back the
// URL it remembers; this page has one route and keeps its own history in the
// hash, so the router is told to leave Back to the page. Outside Next (the unit
// tests) there is no router to tell.
function keepBackForThePage() {
  try {
    Router.beforePopState(() => false);
    return () => Router.beforePopState(() => true);
  } catch {
    return () => {};
  }
}

function writeUrl(method: 'pushState' | 'replaceState', state: unknown, path: string) {
  window.history[method](state, '', `${window.location.pathname}${window.location.search}#${path}`);
}

// The chosen section, switched on the page and mirrored in the URL hash, so a
// link or a reload opens the same section. The hash is read after the page has
// hydrated (reading it while rendering would differ from the exported HTML).
// Switching sections writes it with replaceState, so it does not fill the
// history; opening something inside a section (#mds/<entryId>) pushes an entry,
// so the browser's Back and the page's Back both close it. Next's own history
// state is kept. Editing the hash, and Back and Forward, are followed.
export function useSection(): [SectionId, (section: SectionId) => void, SectionRoute] {
  const [section, setSection] = useState<SectionId>(DEFAULT_SECTION);
  const [subPath, setSubPath] = useState('');

  useEffect(() => {
    const follow = () => {
      const route = routeFromHash(window.location.hash);
      if (!route) return;
      setSection(route.section);
      setSubPath(route.subPath);
    };
    follow();
    window.addEventListener('hashchange', follow);
    window.addEventListener('popstate', follow);
    const release = keepBackForThePage();
    return () => {
      window.removeEventListener('hashchange', follow);
      window.removeEventListener('popstate', follow);
      release();
    };
  }, []);

  const choose = useCallback((next: SectionId) => {
    setSection(next);
    setSubPath('');
    writeUrl('replaceState', window.history.state, hashPath(next));
  }, []);

  const open = useCallback(
    (next: string) => {
      setSubPath(next);
      writeUrl('pushState', { ...(window.history.state ?? {}), [PUSHED]: true }, hashPath(section, next));
    },
    [section],
  );

  const close = useCallback(() => {
    if (window.history.state?.[PUSHED]) {
      window.history.back();
      return;
    }
    setSubPath('');
    writeUrl('replaceState', window.history.state, hashPath(section));
  }, [section]);

  return [section, choose, { subPath, open, close }];
}
