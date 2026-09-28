import { useEffect, useState } from 'react';

// The entrance a section plays when it is shown (a short fade and rise, still
// under prefers-reduced-motion). It plays for what the person brings up (a
// tab, a link, Back), never for what the page opens with: the section the URL
// names, or an MDS entry or certificate it names, is simply there, however
// late its data arrives. Until the person first presses a key or a pointer, or
// the history moves, nothing on the page enters.
export const ENTRANCE_CLASS = 'animate-[section-in_var(--duration-slow)_var(--ease-out)] motion-reduce:animate-none';

let acted = false;
const ACTIONS = ['pointerdown', 'keydown', 'hashchange', 'popstate'] as const;

function act() {
  acted = true;
  ACTIONS.forEach((type) => window.removeEventListener(type, act, true));
}

function listen() {
  if (!acted) ACTIONS.forEach((type) => window.addEventListener(type, act, true));
}

/**
 * The entrance class for an element while it is `shown`, decided each time it
 * is shown: none when the person has done nothing yet. It never changes while
 * the element stays shown (adding an animation to a shown element plays it).
 */
export function useEntrance(shown: boolean) {
  const [showing, setShowing] = useState(() => ({ shown, enters: acted }));
  if (showing.shown !== shown) setShowing({ shown, enters: acted });
  useEffect(listen, []);
  return shown && showing.enters ? ENTRANCE_CLASS : undefined;
}
