import { type RefObject, useCallback, useEffect, useRef } from 'react';

type Left = { at: string; level: string; part: string; offset: number };

// The place a part left the details from (the URL it left, the level, the part
// and where its button sat), kept outside the dialog: over an MDS entry the
// hidden section lets the entry's page go and the details with it, and Back
// mounts them again.
let left: Left | null = null;

// How far `button` sits below the top of the view it scrolls in, in the view's
// own pixels: the dialog is scaled while it opens.
function offsetIn(button: HTMLElement, scroller: HTMLElement) {
  const view = scroller.getBoundingClientRect();
  return (button.getBoundingClientRect().top - view.top) / (view.height / scroller.offsetHeight || 1);
}

// Scrolls the view so `button` sits `offset` below its top again.
function placeAt(button: HTMLElement, offset: number) {
  const scroller = button.closest<HTMLElement>('[data-overlay-scroll]');
  if (scroller) scroller.scrollTop += offsetIn(button, scroller) - offset;
}

// What the person does to move the view themselves, anywhere in the page (a key
// that moves the focus, a drag of the scrollbar), or to change its size.
const MOVES = ['wheel', 'touchmove', 'keydown', 'pointerdown', 'resize'];

// Puts `button` back at its place, and keeps it there whenever the parts of its
// level that arrive later (a chunk's list, a value measured) change the level's
// size, however late they come on a slow device: until the person moves the
// view or the window, or leaves the level (another level, the details closed).
function keepAt(button: HTMLElement, offset: number) {
  placeAt(button, offset);
  const observer = new ResizeObserver(() => (button.isConnected && !button.closest('[hidden]') ? placeAt(button, offset) : stop()));
  const moved = new AbortController();
  const stop = () => {
    observer.disconnect();
    moved.abort();
  };
  observer.observe(button.closest<HTMLElement>('[data-level]')!);
  for (const type of MOVES) window.addEventListener(type, stop, { signal: moved.signal, passive: true, capture: true });
}

// Back from the Codec reopens the details at the level a part left from (its
// URL says which), and this puts the person where they were on it: the focus on
// the "Decode in Codec" button that left, at the place it had in the view. The
// overlay starts every opening at the top and then asks for its first focus,
// which is where the button is put back, and kept while the level's parts that
// arrive later take their room. Details mounted again
// compose their level anew: the button is put back once it is there, unless the
// person has gone to another level meanwhile. Any other opening starts as before.
export function useReturnFromCodec(levels: RefObject<HTMLElement | null>, level: string) {
  // The place this opening is to put back, until the level holds its button.
  const due = useRef<Left | null>(null);

  const leave = useCallback(
    (part: string, button: HTMLElement) => {
      const scroller = button.closest<HTMLElement>('[data-overlay-scroll]');
      left = { at: window.location.hash, level, part, offset: scroller ? offsetIn(button, scroller) : 0 };
    },
    [level],
  );

  const putBack = useCallback(() => {
    const was = due.current;
    const button = was && levels.current?.querySelector<HTMLElement>(`[data-level="${was.level}"] [data-decode="${was.part}"]`);
    if (!button) return null;
    due.current = null;
    keepAt(button, was.offset);
    return button;
  }, [levels]);

  const initialFocus = useCallback(() => {
    const was = left;
    left = null;
    due.current = was?.at === window.location.hash && was.level === level ? was : null;
    return putBack();
  }, [putBack, level]);

  useEffect(() => {
    if (due.current?.level !== level) due.current = null;
    putBack()?.focus({ preventScroll: true });
  });

  return { leave, initialFocus };
}
