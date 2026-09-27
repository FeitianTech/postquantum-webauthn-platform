import Router from 'next/router';
import { createContext, useCallback, useContext, useEffect, useState } from 'react';

import { DEFAULT_SECTION, type SectionId, hashPath, routeFromHash } from './sections';

// A history entry this page pushed to open something inside a section (an MDS
// entry, its certificate), so the page's own Back can be the browser's.
const PUSHED = 'pqcOpened';

/** What is open inside the section (the hash's segments after `#section/`), and how to open and close it. */
export type SectionRoute = {
  path: string[];
  /** Opens `path` in this section, as a history entry of its own. */
  open: (path: string[]) => void;
  /** Goes back to `parent` (the list by default): the browser's Back when this page opened what is shown. */
  close: (parent?: string[]) => void;
  /** Shows `path` in place of what the URL names (one this page does not know). */
  replace: (path: string[]) => void;
};

/** Opens `path` in another section, as a history entry of its own, so Back returns here. */
export type GoToSection = (section: SectionId, path: string[]) => void;

/** The route of a section not shown: nothing open in it, and nothing it can open. */
export const CLOSED_ROUTE: SectionRoute = { path: [], open: () => {}, close: () => {}, replace: () => {} };

const SectionNavigation = createContext<GoToSection>(() => {});

export const SectionNavigationProvider = SectionNavigation.Provider;

/** How a section opens something in another one (a saved credential's MDS entry). */
export function useSectionNavigation() {
  return useContext(SectionNavigation);
}

// Next's router answers Back for pages it navigated between, putting back the
// URL it remembers; this page has one route and keeps its own history in the
// hash, so the router is told to leave Back to the page while Back stays on this
// page's path. Back to another path (a page Next showed before this one) is
// Next's. The router asks from its popstate handler, once the URL has changed.
// Outside Next (the unit tests) there is no router to tell.
function keepBackForThePage() {
  const here = window.location.pathname;
  try {
    Router.beforePopState(() => window.location.pathname !== here);
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
// history; opening something inside a section (#mds/<entryId>, then
// #mds/<entryId>/certificate/<n>) pushes an entry, so the browser's Back and the
// page's Back both close it, one level at a time. Next's own history state is
// kept. Editing the hash, and Back and Forward, are followed.
export function useSection(): [SectionId, (section: SectionId) => void, SectionRoute, GoToSection] {
  const [section, setSection] = useState<SectionId>(DEFAULT_SECTION);
  const [path, setPath] = useState<string[]>([]);

  useEffect(() => {
    // No hash is the default section (the page's own URL, which Back returns to
    // after a section opened something in another); a hash naming no section is
    // left alone.
    const follow = () => {
      const hash = window.location.hash.replace(/^#/, '');
      const route = hash ? routeFromHash(hash) : { section: DEFAULT_SECTION, path: [] };
      if (!route) return;
      setSection(route.section);
      setPath(route.path);
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
    setPath([]);
    writeUrl('replaceState', window.history.state, hashPath(next));
  }, []);

  const go = useCallback((next: SectionId, nextPath: string[]) => {
    setSection(next);
    setPath(nextPath);
    writeUrl('pushState', { ...(window.history.state ?? {}), [PUSHED]: true }, hashPath(next, nextPath));
  }, []);

  const open = useCallback((nextPath: string[]) => go(section, nextPath), [go, section]);

  const close = useCallback(
    (parent: string[] = []) => {
      if (window.history.state?.[PUSHED]) {
        window.history.back();
        return;
      }
      setPath(parent);
      writeUrl('replaceState', window.history.state, hashPath(section, parent));
    },
    [section],
  );

  const replace = useCallback(
    (nextPath: string[]) => {
      setPath(nextPath);
      writeUrl('replaceState', window.history.state, hashPath(section, nextPath));
    },
    [section],
  );

  return [section, choose, { path, open, close, replace }, go];
}
