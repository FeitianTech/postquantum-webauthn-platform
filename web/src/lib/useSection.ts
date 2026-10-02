import Router from 'next/router';
import { createContext, useCallback, useContext, useRef, useState } from 'react';

import { noteMoved } from './entrance';
import { DEFAULT_SECTION, type SectionId, hashPath, routeFromHash } from './sections';
import { useIsomorphicLayoutEffect } from './useIsomorphicLayoutEffect';

// A history entry this page pushed to open something inside a section (an MDS
// entry, its certificate), so the page's own Back can be the browser's. Its
// value is how many such entries lead to it, one per level opened, so closing
// every level at once goes back that many.
const PUSHED = 'pqcOpened';

function pushedDepth(entry: unknown): number {
  const value = (entry as Record<string, unknown> | null)?.[PUSHED];
  return typeof value === 'number' ? value : value ? 1 : 0;
}

/** What is open inside the section (the hash's segments after `#section/`), and how to open and close it. */
export type SectionRoute = {
  path: string[];
  /** Opens `path` in this section, as a history entry of its own. */
  open: (path: string[]) => void;
  /** Goes back to `parent` (the list by default): the browser's Back when this page opened what is shown. */
  close: (parent?: string[]) => void;
  /** Shows `path` in place of what the URL names (one this page does not know). */
  replace: (path: string[]) => void;
  /** Closes every level this page opened, back to `parent` (the list by default), in one step. */
  closeAll: (parent?: string[]) => void;
};

/** Opens `path` in another section, as a history entry of its own, so Back returns here. */
export type GoToSection = (section: SectionId, path: string[]) => void;

/** The route of a section not shown: nothing open in it, and nothing it can open. */
export const CLOSED_ROUTE: SectionRoute = { path: [], open: () => {}, close: () => {}, replace: () => {}, closeAll: () => {} };

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
// link or a reload opens the same section. The exported HTML is the same for
// every hash, so it chooses no section; the hash is read once the page has
// hydrated, before that first frame is painted, so the page never shows another
// section first. Switching sections writes it with replaceState, so it does not
// fill the history; opening something inside a section (#mds/<entryId>, then
// #mds/<entryId>/certificate/<n>) pushes an entry, so the browser's Back and the
// page's Back both close it, one level at a time. Next's own history state is
// kept. Editing the hash, and Back and Forward, are followed.
export function useSection(): [SectionId | null, (section: SectionId) => void, SectionRoute, GoToSection] {
  const [section, setSection] = useState<SectionId | null>(null);
  const [path, setPath] = useState<string[]>([]);
  // Where closing every level lands, once the browser has gone back.
  const landing = useRef<string[] | null>(null);

  useIsomorphicLayoutEffect(() => {
    // No hash is the default section (the page's own URL, which Back returns to
    // after a section opened something in another). A hash naming no section
    // opens the page on the default one, and later is left alone.
    const follow = (first: boolean) => {
      const hash = window.location.hash.replace(/^#/, '');
      const route = hash ? routeFromHash(hash) : { section: DEFAULT_SECTION, path: [] };
      if (!route) {
        if (first) setSection(DEFAULT_SECTION);
        return;
      }
      const wanted = landing.current;
      landing.current = null;
      // Gone back past every level this page pushed: the first was reached by a
      // link, so it too is replaced by where closing leads.
      if (wanted && wanted.join('/') !== route.path.join('/')) {
        route.path = wanted;
        writeUrl('replaceState', window.history.state, hashPath(route.section, wanted));
      }
      setSection(route.section);
      setPath(route.path);
    };
    const followLater = () => {
      noteMoved();
      follow(false);
    };
    follow(true);
    window.addEventListener('hashchange', followLater);
    window.addEventListener('popstate', followLater);
    const release = keepBackForThePage();
    return () => {
      window.removeEventListener('hashchange', followLater);
      window.removeEventListener('popstate', followLater);
      release();
    };
  }, []);

  const choose = useCallback((next: SectionId) => {
    noteMoved();
    setSection(next);
    setPath([]);
    // Another section in this entry's place: nothing is open in it, so nothing
    // this page pushed leads to it any more.
    const { [PUSHED]: _levels, ...kept } = (window.history.state ?? {}) as Record<string, unknown>;
    writeUrl('replaceState', kept, hashPath(next));
  }, []);

  const go = useCallback((next: SectionId, nextPath: string[]) => {
    noteMoved();
    setSection(next);
    setPath(nextPath);
    const entry = window.history.state ?? {};
    writeUrl('pushState', { ...entry, [PUSHED]: pushedDepth(entry) + 1 }, hashPath(next, nextPath));
  }, []);

  // Only the section shown is given these (CLOSED_ROUTE otherwise), so they
  // are never called before a section is chosen.
  const open = useCallback((nextPath: string[]) => go(section!, nextPath), [go, section]);

  const close = useCallback(
    (parent: string[] = []) => {
      if (window.history.state?.[PUSHED]) {
        window.history.back();
        return;
      }
      noteMoved();
      setPath(parent);
      writeUrl('replaceState', window.history.state, hashPath(section!, parent));
    },
    [section],
  );

  const replace = useCallback(
    (nextPath: string[]) => {
      setPath(nextPath);
      writeUrl('replaceState', window.history.state, hashPath(section!, nextPath));
    },
    [section],
  );

  const closeAll = useCallback(
    (parent: string[] = []) => {
      const depth = pushedDepth(window.history.state);
      if (depth) {
        landing.current = parent;
        window.history.go(-depth);
        return;
      }
      replace(parent);
    },
    [replace],
  );

  return [section, choose, { path, open, close, replace, closeAll }, go];
}
