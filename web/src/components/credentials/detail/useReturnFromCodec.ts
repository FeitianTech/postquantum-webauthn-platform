import { type RefObject, useCallback, useRef } from 'react';

type Left = { key: string; level: string; part: string; offset: number };

// How far `button` sits below the top of the view it scrolls in.
function offsetIn(button: HTMLElement, scroller: HTMLElement) {
  return button.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
}

// Scrolls the view so `button` sits `offset` below its top again.
function placeAt(button: HTMLElement, offset: number) {
  const scroller = button.closest<HTMLElement>('[data-overlay-scroll]');
  if (scroller) scroller.scrollTop += offsetIn(button, scroller) - offset;
}

// Back from the Codec reopens the details at the level a part left from (its
// URL says which), and this puts the person where they were on it: the focus on
// the "Decode in Codec" button that left, at the place it had in the view. The
// overlay starts every opening at the top and then asks for its first focus,
// which is where the button is put back, and again on the next frame, once the
// level's parts that arrive later have taken their room. Any other opening
// starts as before.
export function useReturnFromCodec(levels: RefObject<HTMLElement | null>, key: string, level: string) {
  const left = useRef<Left | null>(null);

  const leave = useCallback(
    (part: string, button: HTMLElement) => {
      const scroller = button.closest<HTMLElement>('[data-overlay-scroll]');
      left.current = { key, level, part, offset: scroller ? offsetIn(button, scroller) : 0 };
    },
    [key, level],
  );

  const initialFocus = useCallback(() => {
    const was = left.current;
    left.current = null;
    if (!was || was.key !== key || was.level !== level) return null;
    const button = levels.current?.querySelector<HTMLElement>(`[data-level="${was.level}"] [data-decode="${was.part}"]`) ?? null;
    if (button) {
      placeAt(button, was.offset);
      requestAnimationFrame(() => placeAt(button, was.offset));
    }
    return button;
  }, [levels, key, level]);

  return { leave, initialFocus };
}
