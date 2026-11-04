import { useMemo } from 'react';

import type { SectionRoute } from '@/lib/useSection';

// What is open over an entry (#mds/<entryId>/credential/<key>…) as a route of its
// own: the path after the entry's id, and each way to open or close a level
// putting the id back in front. A saved credential's details open over the entry
// with it, at their levels, as they open over the Simple and Advanced tabs.
export function useRouteUnderEntry(route: SectionRoute, entryId: string): SectionRoute {
  const { path, open, close, replace, closeAll } = route;
  return useMemo(() => {
    const under = (rest: string[] = []) => [entryId, ...rest];
    return {
      path: path.slice(1),
      open: (rest) => open(under(rest)),
      close: (parent) => close(under(parent)),
      replace: (rest) => replace(under(rest)),
      closeAll: (parent, levels) => closeAll(under(parent), levels),
    };
  }, [path, open, close, replace, closeAll, entryId]);
}
